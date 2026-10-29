import Lean.Data.Json
import Stave.Controls.Json

/-! Differential test runner: reads an obs.v0.1 fixture file,
extracts assets, evaluates one control via the Lean model,
outputs JSON results. Fail-closed on parse errors. -/

open Lean (Json FromJson toJson)

structure DiffResult where
  controlId : String
  assetId : String
  fires : Bool
  deriving Repr

instance : Lean.ToJson DiffResult where
  toJson r := .mkObj [
    ("controlId", toJson r.controlId),
    ("assetId", toJson r.assetId),
    ("fires", toJson r.fires)
  ]

def controlObsType : String → String
  | "CTL.CLOUDTRAIL.ORG.001" => "cloudtrail"
  | "CTL.ORG.REGION.SCP.001" => "org"
  | "CTL.IAM.ROOT.MFA.001" => "iam_account"
  | "CTL.IAM.ROOT.ACCESSKEY.001" => "iam_account"
  | "CTL.CLOUDTRAIL.LOG.VALIDATION.001" => "cloudtrail"
  | "CTL.IAM.CONSOLE.MFA.001" => "iam_user"
  | "CTL.VPC.SG.UNRESTRICTED.001" => "sg"
  | "CTL.CLOUDTRAIL.REGIONAL.COVERAGE.001" => "cloudtrail"
  | "CTL.CLOUDFRONT.ACCESS.SIGNED.LONG.EXPIRY.001" => "cdn"
  | "CTL.CLOUDFRONT.VIEWER.CERT.EXPIRY.WARN.001" => "cdn"
  | "CTL.CLOUDFRONT.WAF.001" => "cdn"
  | "CTL.CLOUDFRONT.LIFECYCLE.ORPHAN.POLICY.001" => "cdn"
  | "CTL.VPC.ENDPOINT.KMS.EGRESS.001" => "vpc_endpoint"
  | "CTL.IAM.CRED.UNUSED45.001" => "iam_user"
  | "CTL.IAM.ADMIN.COUNT.001" => "iam_summary"
  | "CTL.S3.GOVERNANCE.001" => "storage"
  | _ => "unknown"

def assetMatchesControl (assetJson : Json) (controlId : String) : Bool :=
  let props := match assetJson.getObjValAs? Json "properties" with
    | .ok v => v | .error _ => .null
  let obsType := controlObsType controlId
  match obsType with
  | "cloudtrail" =>
    let auditTrail := match props.getObjValAs? Json "audit_trail" with
      | .ok v => v | .error _ => .null
    let trail := match props.getObjValAs? Json "trail" with
      | .ok v => v | .error _ => .null
    auditTrail != .null || trail != .null
  | "org" =>
    let o := match props.getObjValAs? Json "organization" with
      | .ok v => v | .error _ => .null
    o != .null
  | "iam_account" =>
    let id := match props.getObjValAs? Json "identity" with
      | .ok v => v | .error _ => .null
    match id.getObjValAs? String "kind" with
    | .ok "account" => true | _ => false
  | "iam_user" =>
    let id := match props.getObjValAs? Json "identity" with
      | .ok v => v | .error _ => .null
    match id.getObjValAs? String "kind" with
    | .ok "user" => true | _ => false
  | "sg" =>
    let n := match props.getObjValAs? Json "network" with
      | .ok v => v | .error _ => .null
    n != .null
  | "cdn" =>
    let c := match props.getObjValAs? Json "cdn" with
      | .ok v => v | .error _ => .null
    c != .null
  | "vpc_endpoint" =>
    let n := match props.getObjValAs? Json "network" with
      | .ok v => v | .error _ => .null
    match n.getObjValAs? String "kind" with
    | .ok "vpc_endpoint" => true | _ => false
  | "iam_summary" =>
    let id := match props.getObjValAs? Json "identity" with
      | .ok v => v | .error _ => .null
    match id.getObjValAs? String "kind" with
    | .ok "account_summary" => true | _ => false
  | "storage" =>
    let s := match props.getObjValAs? Json "storage" with
      | .ok v => v | .error _ => .null
    s != .null
  | _ => false

def evalAsset (assetJson : Json) (controlId : String) : Except String DiffResult := do
  let assetId ← match assetJson.getObjValAs? String "id" with
    | .ok v => pure v
    | .error _ => .error "asset missing 'id' field"
  let typedObs ← match @FromJson.fromJson? TypedObs _ assetJson with
    | .ok v => pure v
    | .error e => .error s!"FromJson failed for asset {assetId}: {e}"
  let result := evalTypedControl controlId typedObs
  pure { controlId, assetId, fires := result.outcome.fires }

def main (args : List String) : IO UInt32 := do
  match args with
  | [fixturePath, controlId] =>
    let content ← IO.FS.readFile fixturePath
    let json ← match Json.parse content with
      | .ok j => pure j
      | .error e =>
        IO.eprintln s!"JSON parse error: {e}"
        return 1
    let assets ← match json.getObjValAs? (List Json) "assets" with
      | .ok a => pure a
      | .error _ =>
        IO.eprintln "fixture missing 'assets' array"
        return 1
    let matching := assets.filter (assetMatchesControl · controlId)
    if matching.isEmpty then
      IO.eprintln s!"no assets match control {controlId} in {fixturePath}"
      return 1
    let mut results : List DiffResult := []
    let mut anyError := false
    for asset in matching do
      match evalAsset asset controlId with
      | .ok r => results := results ++ [r]
      | .error e =>
        IO.eprintln s!"eval error: {e}"
        anyError := true
    if anyError then return 1
    let jsonResults := results.map (Lean.toJson ·)
    IO.println (Json.arr jsonResults.toArray |>.compress)
    return 0
  | _ =>
    IO.eprintln "Usage: difftest <fixture.json> <controlId>"
    return 2
