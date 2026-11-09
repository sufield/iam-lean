import Stave.Extract.Asset

/-! S3 transforms — 4 jq filter equivalents:
  s3-buckets, s3-encryption, s3-public-access-block, s3-tags.
  Enrichment assets (encryption/PAB/tags) merge onto the base bucket by id. -/

open Lean (Json)

-- s3-buckets.jq: .Buckets[] → one aws_s3_bucket per bucket
def transformS3Buckets (raw : Json) : List ObsAsset :=
  (getArr raw "Buckets").filterMap fun bucket =>
    match getOptStr bucket "Name" with
    | some name => some (awsAsset
        ("arn:aws:s3:::" ++ name)
        "aws_s3_bucket"
        (Json.mkObj [("storage", Json.mkObj [
          ("kind", .str "bucket"),
          ("name", .str name)
        ])]))
    | none => none

-- s3-encryption.jq: per-bucket encryption → merge asset
-- bucket param: fallback when JSON lacks the Bucket field (real AWS CLI output)
def transformS3Encryption (raw : Json) (bucket : String := "") : Option ObsAsset :=
  let b := match getOptStr raw "Bucket" with | some s => s | none => bucket
  if b.isEmpty then none
  else
    let rules := getArr (getObj raw "ServerSideEncryptionConfiguration") "Rules"
    let enc := match rules.head? with
      | some r => getObj r "ApplyServerSideEncryptionByDefault"
      | none => .null
    let algo := match getOptStr enc "SSEAlgorithm" with | some a => a | none => "none"
    let kmsKey := match getOptStr enc "KMSMasterKeyID" with | some k => Json.str k | none => .null
    let atRestEnabled := algo != "none"
    some (awsAsset
      ("arn:aws:s3:::" ++ b)
      "aws_s3_bucket"
      (Json.mkObj [("storage", Json.mkObj [
        ("encryption", Json.mkObj [
          ("algorithm", .str algo),
          ("kms_key_id", kmsKey),
          ("at_rest_enabled", .bool atRestEnabled)
        ])
      ])]))

-- s3-public-access-block.jq: per-bucket PAB → merge asset
def transformS3PublicAccessBlock (raw : Json) (bucket : String := "") : Option ObsAsset :=
  let b := match getOptStr raw "Bucket" with | some s => s | none => bucket
  if b.isEmpty then none
  else
    let pab := getObj raw "PublicAccessBlockConfiguration"
    let bpa := (getOptBool pab "BlockPublicAcls").getD false
    let bpp := (getOptBool pab "BlockPublicPolicy").getD false
    let ipa := (getOptBool pab "IgnorePublicAcls").getD false
    let rpb := (getOptBool pab "RestrictPublicBuckets").getD false
    some (awsAsset
      ("arn:aws:s3:::" ++ b)
      "aws_s3_bucket"
      (Json.mkObj [("storage", Json.mkObj [
        ("controls", Json.mkObj [
          ("public_access_block", Json.mkObj [
            ("block_public_acls", .bool bpa),
            ("block_public_policy", .bool bpp),
            ("ignore_public_acls", .bool ipa),
            ("restrict_public_buckets", .bool rpb)
          ]),
          ("public_access_fully_blocked", .bool (bpa && bpp && ipa && rpb))
        ])
      ])]))

-- s3-tags.jq: per-bucket tags → merge asset
def transformS3Tags (raw : Json) (bucket : String := "") : Option ObsAsset :=
  let b := match getOptStr raw "Bucket" with | some s => s | none => bucket
  if b.isEmpty then none
  else
    let tagSet := getArr raw "TagSet"
    let tagPairs := tagSet.filterMap fun t =>
      match getOptStr t "Key", getOptStr t "Value" with
      | some k, some v => some (k, Json.str v)
      | _, _ => none
    some (awsAsset
      ("arn:aws:s3:::" ++ b)
      "aws_s3_bucket"
      (Json.mkObj [("storage", Json.mkObj [
        ("tags", Json.mkObj tagPairs)
      ])]))

-- s3-versioning: per-bucket versioning status → merge asset
def transformS3Versioning (raw : Json) (bucket : String := "") : Option ObsAsset :=
  let b := match getOptStr raw "Bucket" with | some s => s | none => bucket
  if b.isEmpty then none
  else
    let status := (getOptStr raw "Status").getD ""
    let mfaDelete := (getOptStr raw "MFADelete").getD ""
    some (awsAsset
      ("arn:aws:s3:::" ++ b)
      "aws_s3_bucket"
      (Json.mkObj [("storage", Json.mkObj [
        ("versioning", Json.mkObj [
          ("enabled", .bool (status == "Enabled")),
          ("mfa_delete", .bool (mfaDelete == "Enabled"))
        ])
      ])]))

-- s3-logging: per-bucket logging config → merge asset
def transformS3Logging (raw : Json) (bucket : String := "") : Option ObsAsset :=
  let b := match getOptStr raw "Bucket" with | some s => s | none => bucket
  if b.isEmpty then none
  else
    let loggingEnabled := getObj raw "LoggingEnabled"
    some (awsAsset
      ("arn:aws:s3:::" ++ b)
      "aws_s3_bucket"
      (Json.mkObj [("storage", Json.mkObj [
        ("logging", Json.mkObj [
          ("enabled", .bool (loggingEnabled != .null))
        ])
      ])]))

-- s3-policy: per-bucket policy → derive in_transit_enforced
-- Checks for a Deny statement with Condition.Bool["aws:SecureTransport"] == "false"
def transformS3BucketPolicy (raw : Json) (bucket : String := "") : Option ObsAsset :=
  let b := match getOptStr raw "Bucket" with | some s => s | none => bucket
  if b.isEmpty then none
  else
    let stmts := getArr raw "Statement"
    let hasTlsDeny := stmts.any fun stmt =>
      let effect := (getOptStr stmt "Effect").getD ""
      let condBool := getObj (getObj stmt "Condition") "Bool"
      let secureTransport := (getOptStr condBool "aws:SecureTransport").getD ""
      effect == "Deny" && secureTransport == "false"
    some (awsAsset
      ("arn:aws:s3:::" ++ b)
      "aws_s3_bucket"
      (Json.mkObj [("storage", Json.mkObj [
        ("encryption", Json.mkObj [
          ("in_transit_enforced", .bool hasTlsDeny)
        ])
      ])]))

-- s3-lifecycle: per-bucket lifecycle config → merge asset
def transformS3Lifecycle (raw : Json) (bucket : String := "") : Option ObsAsset :=
  let b := match getOptStr raw "Bucket" with | some s => s | none => bucket
  if b.isEmpty then none
  else
    let rules := getArr raw "Rules"
    let hasLifecycle := !rules.isEmpty
    some (awsAsset
      ("arn:aws:s3:::" ++ b)
      "aws_s3_bucket"
      (Json.mkObj [("storage", Json.mkObj [
        ("lifecycle", Json.mkObj [
          ("enabled", .bool hasLifecycle)
        ])
      ])]))

-- Core lemma: awsAsset always produces correct vendor and type
theorem awsAsset_vendor (id t : String) (p : Json) :
    (awsAsset id t p).vendor = "aws" := rfl

theorem awsAsset_assetType (id t : String) (p : Json) :
    (awsAsset id t p).assetType = t := rfl

-- Self-tests with concrete JSON

#guard
  let raw := Json.mkObj [("Buckets", Json.arr #[
    Json.mkObj [("Name", .str "my-bucket")]
  ])]
  match transformS3Buckets raw with
  | [a] => a.id == "arn:aws:s3:::my-bucket" &&
            a.assetType == "aws_s3_bucket" &&
            a.vendor == "aws"
  | _ => false

#guard
  let raw := Json.mkObj [
    ("Bucket", .str "test-bucket"),
    ("PublicAccessBlockConfiguration", Json.mkObj [
      ("BlockPublicAcls", .bool true),
      ("BlockPublicPolicy", .bool true),
      ("IgnorePublicAcls", .bool true),
      ("RestrictPublicBuckets", .bool true)
    ])
  ]
  match transformS3PublicAccessBlock raw with
  | some a => a.id == "arn:aws:s3:::test-bucket" && a.vendor == "aws"
  | none => false

#guard
  let raw := Json.mkObj [
    ("Bucket", .str "test-bucket"),
    ("PublicAccessBlockConfiguration", Json.mkObj [
      ("BlockPublicAcls", .bool true),
      ("BlockPublicPolicy", .bool false),
      ("IgnorePublicAcls", .bool true),
      ("RestrictPublicBuckets", .bool true)
    ])
  ]
  match transformS3PublicAccessBlock raw with
  | some a => a.vendor == "aws"
  | none => false

#guard
  let raw := Json.mkObj [
    ("Bucket", .str "tagged-bucket"),
    ("TagSet", Json.arr #[
      Json.mkObj [("Key", .str "env"), ("Value", .str "prod")],
      Json.mkObj [("Key", .str "team"), ("Value", .str "security")]
    ])
  ]
  match transformS3Tags raw with
  | some a => a.id == "arn:aws:s3:::tagged-bucket"
  | none => false

-- Missing bucket name → none
#guard (transformS3Encryption (Json.mkObj [])).isNone
#guard (transformS3PublicAccessBlock (Json.mkObj [])).isNone
#guard (transformS3Tags (Json.mkObj [])).isNone
