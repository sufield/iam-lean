import Stave.Extract.Asset

/-! CloudTrail transform — cloudtrail-trails.jq equivalent.
.trailList[] → one aws_cloudtrail_trail per trail. -/

open Lean (Json)

def transformCloudTrailTrails (raw : Json) : List ObsAsset :=
  (getArr raw "trailList").filterMap fun trail =>
    match getOptStr trail "TrailARN" with
    | none => none
    | some arn =>
      let logValidation := (getOptBool trail "LogFileValidationEnabled").getD false
      let multiRegion := (getOptBool trail "IsMultiRegionTrail").getD false
      let globalEvents := (getOptBool trail "IncludeGlobalServiceEvents").getD false
      some (awsAsset arn "aws_cloudtrail_trail"
        (Json.mkObj [
          ("audit_trail", Json.mkObj [
            ("kind", .str "trail"),
            ("log_file_validation_enabled", .bool logValidation),
            ("multi_region_enabled", .bool multiRegion)
          ]),
          ("audit", Json.mkObj [
            ("kind", .str "trail"),
            ("cloudtrail", Json.mkObj [
              ("include_global_events", .bool globalEvents)
            ])
          ]),
          ("trail", Json.mkObj [
            ("log_file_validation_enabled", .bool logValidation)
          ])
        ]))

#guard
  let raw := Json.mkObj [("trailList", Json.arr #[
    Json.mkObj [
      ("TrailARN", .str "arn:aws:cloudtrail:us-east-1:123456789012:trail/main"),
      ("LogFileValidationEnabled", .bool true),
      ("IsMultiRegionTrail", .bool false),
      ("IncludeGlobalServiceEvents", .bool true)
    ]
  ])]
  match transformCloudTrailTrails raw with
  | [a] => a.id == "arn:aws:cloudtrail:us-east-1:123456789012:trail/main" &&
            a.assetType == "aws_cloudtrail_trail" &&
            a.vendor == "aws"
  | _ => false

-- Empty trailList → empty output
#guard (transformCloudTrailTrails (Json.mkObj [("trailList", Json.arr #[])])).isEmpty
