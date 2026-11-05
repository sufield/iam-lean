import Stave.Extract.Asset

/-! KMS transforms — 3 jq filter equivalents:
  kms-keys, kms-key-rotation, kms-key-policy.
  Enrichment assets (rotation/policy) merge onto the base key by id. -/

open Lean (Json)

-- kms-keys.jq: .Keys[] → one base aws_kms_key per key
def transformKMSKeys (raw : Json) : List ObsAsset :=
  (getArr raw "Keys").filterMap fun key =>
    match getOptStr key "KeyArn" with
    | none => none
    | some arn => some (awsAsset arn "aws_kms_key"
        (Json.mkObj [("cryptography", Json.mkObj [
          ("kind", .str "key")
        ])]))

-- kms-key-rotation.jq: self-describing (KeyId = full ARN)
def transformKMSKeyRotation (raw : Json) (keyArn : String := "") : Option ObsAsset :=
  let k := match getOptStr raw "KeyId" with | some s => s | none => keyArn
  if k.isEmpty then none
  else
    let enabled := (getOptBool raw "KeyRotationEnabled").getD false
    some (awsAsset k "aws_kms_key"
      (Json.mkObj [("cryptography", Json.mkObj [
        ("key_rotation_enabled", .bool enabled)
      ])]))

-- kms-key-policy.jq: Policy is a JSON string; KeyArn from JSON or filename
private def hasWildcardPrincipal (statements : List Json) : Bool :=
  statements.any fun stmt =>
    let principal := getObj stmt "Principal"
    principal == .str "*" ||
    (match getOptStr principal "AWS" with
     | some "*" => true
     | _ => match principal.getObjValAs? (Array Json) "AWS" with
            | .ok arr => arr.toList.any (· == .str "*")
            | .error _ => false)

def transformKMSKeyPolicy (raw : Json) (keyArn : String := "") : Option ObsAsset :=
  let arn := match getOptStr raw "KeyArn" with | some s => s | none => keyArn
  if arn.isEmpty then none
  else
    let policyStr := (getOptStr raw "Policy").getD "{}"
    let statements := match Json.parse policyStr with
      | .ok policyJson =>
        let stmts := getArr policyJson "Statement"
        match stmts with
        | [] => match policyJson.getObjValAs? Json "Statement" with
                | .ok s => [s]
                | .error _ => []
        | _ => stmts
      | .error _ => []
    some (awsAsset arn "aws_kms_key"
      (Json.mkObj [("cryptography", Json.mkObj [
        ("policy", Json.mkObj [
          ("has_wildcard_principal", .bool (hasWildcardPrincipal statements))
        ])
      ])]))

-- kms-key-describe: describe-key output → extract ARN for base key enrichment
def transformKMSDescribeKey (raw : Json) : Option ObsAsset :=
  let km := getObj raw "KeyMetadata"
  match getOptStr km "Arn" with
  | none => none
  | some arn =>
    let enabled := (getOptBool km "Enabled").getD true
    let mgr := (getOptStr km "KeyManager").getD ""
    some (awsAsset arn "aws_kms_key"
      (Json.mkObj [("cryptography", Json.mkObj [
        ("kind", .str "key"),
        ("enabled", .bool enabled),
        ("key_manager", .str mgr)
      ])]))

-- Self-tests

#guard
  let raw := Json.mkObj [("Keys", Json.arr #[
    Json.mkObj [("KeyId", .str "abc-123"), ("KeyArn", .str "arn:aws:kms:us-east-1:123:key/abc-123")]
  ])]
  match transformKMSKeys raw with
  | [a] => a.id == "arn:aws:kms:us-east-1:123:key/abc-123" &&
            a.assetType == "aws_kms_key" &&
            a.vendor == "aws"
  | _ => false

#guard
  let raw := Json.mkObj [
    ("KeyId", .str "arn:aws:kms:us-east-1:123:key/abc"),
    ("KeyRotationEnabled", .bool true)
  ]
  match transformKMSKeyRotation raw with
  | some a => a.id == "arn:aws:kms:us-east-1:123:key/abc" && a.vendor == "aws"
  | none => false

-- No KeyArn → none
#guard (transformKMSKeyPolicy (Json.mkObj [])).isNone
