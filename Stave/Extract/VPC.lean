import Stave.Extract.Asset

/-! VPC transforms — describe-flow-logs output → aws_vpc assets.
Maps flow_log.enabled and related fields that Stave VPC logging controls check. -/

open Lean (Json)

-- vpc-flow-logs.jq: .FlowLogs[] grouped by ResourceId → one aws_vpc per VPC
-- Each VPC gets a single asset with flow_log.enabled derived from whether
-- any active flow log exists for that resource.
def transformVPCFlowLogs (raw : Json) (accountId : String) : List ObsAsset :=
  let flowLogs := getArr raw "FlowLogs"
  -- Group by ResourceId (VPC ID)
  let resourceIds := (flowLogs.filterMap fun fl => getOptStr fl "ResourceId").eraseDups
  if resourceIds.isEmpty then
    -- No flow logs at all — if we know the VPC ID from context, caller
    -- should provide it. Empty input → empty output.
    []
  else
    resourceIds.filterMap fun vpcId =>
      let vpcFlowLogs := flowLogs.filter fun fl =>
        (getOptStr fl "ResourceId").getD "" == vpcId
      let hasActive := vpcFlowLogs.any fun fl =>
        (getOptStr fl "FlowLogStatus").getD "" == "ACTIVE"
      let encrypted := vpcFlowLogs.any fun fl =>
        let dest := (getOptStr fl "LogDestinationType").getD ""
        -- S3 destinations can be encrypted; CloudWatch Logs are encrypted by default
        dest == "cloud-watch-logs"
      let region := match (vpcFlowLogs.head?.bind fun fl => getOptStr fl "Region") with
        | some r => r
        | none => "us-east-1"
      let arn := "arn:aws:ec2:" ++ region ++ ":" ++ accountId ++ ":vpc/" ++ vpcId
      some (awsAsset arn "aws_vpc"
        (Json.mkObj [("network", Json.mkObj [
          ("kind", .str "vpc"),
          ("flow_log", Json.mkObj [
            ("enabled", .bool hasActive),
            ("encrypted", .bool encrypted)
          ]),
          ("flowlog", Json.mkObj [
            ("is_active", .bool hasActive),
            ("captures_all", .bool hasActive)
          ])
        ])]))

-- Self-tests

#guard
  let raw := Json.mkObj [("FlowLogs", Json.arr #[
    Json.mkObj [
      ("ResourceId", .str "vpc-123"),
      ("FlowLogStatus", .str "ACTIVE"),
      ("LogDestinationType", .str "cloud-watch-logs")
    ]
  ])]
  match transformVPCFlowLogs raw "123456789012" with
  | [a] => a.assetType == "aws_vpc" && a.vendor == "aws"
  | _ => false

-- No flow logs → empty
#guard (transformVPCFlowLogs (Json.mkObj []) "123").isEmpty
#guard (transformVPCFlowLogs (Json.mkObj [("FlowLogs", Json.arr #[])]) "123").isEmpty
