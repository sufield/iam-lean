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
def transformKMSKeyRotation (raw : Json) : Option ObsAsset :=
  match getOptStr raw "KeyId" with
  | none => none
  | some keyId =>
    let enabled := (getOptBool raw "KeyRotationEnabled").getD false
    some (awsAsset keyId "aws_kms_key"
      (Json.mkObj [("cryptography", Json.mkObj [
        ("key_rotation_enabled", .bool enabled)
      ])]))

-- kms-key-policy.jq: annotated with KeyArn, Policy is a JSON string
private def hasWildcardPrincipal (statements : List Json) : Bool :=
  statements.any fun stmt =>
    let principal := getObj stmt "Principal"
    principal == .str "*" ||
    (match getOptStr principal "AWS" with
     | some "*" => true
     | _ => match principal.getObjValAs? (Array Json) "AWS" with
            | .ok arr => arr.toList.any (· == .str "*")
            | .error _ => false)

def transformKMSKeyPolicy (raw : Json) : Option ObsAsset :=
  match getOptStr raw "KeyArn" with
  | none => none
  | some arn =>
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
