import Stave.Extract.Asset

/-! CloudWatch, Config, Lambda, OpenSearch transforms —
  cloudwatch-alarms, config-recorders, lambda-functions, opensearch-domains. -/

open Lean (Json)

-- cloudwatch-alarms.jq: .MetricAlarms[] → one aws_cloudwatch_alarm per alarm
def transformCloudWatchAlarms (raw : Json) : List ObsAsset :=
  (getArr raw "MetricAlarms").filterMap fun alarm =>
    match getOptStr alarm "AlarmArn" with
    | none => none
    | some arn =>
      let alarmActions := (getArr alarm "AlarmActions").length
      let okActions := (getArr alarm "OKActions").length
      let insuffActions := (getArr alarm "InsufficientDataActions").length
      let hasAnyAction := alarmActions + okActions + insuffActions > 0
      some (awsAsset arn "aws_cloudwatch_alarm"
        (Json.mkObj [("monitoring", Json.mkObj [
          ("kind", .str "alarm"),
          ("cloudwatch", Json.mkObj [
            ("has_any_action", .bool hasAnyAction)
          ])
        ])]))

-- config-recorders.jq: .ConfigurationRecorders[] → one aws_config_recorder
-- Requires account ID for ARN construction; arn field provides region
def transformConfigRecorders (raw : Json) (account : String) : List ObsAsset :=
  (getArr raw "ConfigurationRecorders").filterMap fun rec =>
    match getOptStr rec "name" with
    | none => none
    | some name =>
      let recArn := (getOptStr rec "arn").getD ""
      let parts := recArn.splitOn ":"
      let region := if h : 3 < parts.length then parts[3] else "unknown"
      let rg := getObj rec "recordingGroup"
      let allSupported := (getOptBool rg "allSupported").getD false
      let includeGlobal := (getOptBool rg "includeGlobalResourceTypes").getD false
      some (awsAsset
        ("arn:aws:config:" ++ region ++ ":" ++ account ++ ":config-recorder/" ++ name)
        "aws_config_recorder"
        (Json.mkObj [("compliance", Json.mkObj [
          ("kind", .str "config_recorder"),
          ("config", Json.mkObj [
            ("records_all_resources", .bool (allSupported && includeGlobal))
          ])
        ])]))

-- lambda-functions.jq: .Functions[] → one aws_lambda_function per function
def transformLambdaFunctions (raw : Json) : List ObsAsset :=
  (getArr raw "Functions").filterMap fun fn =>
    match getOptStr fn "FunctionArn" with
    | none => none
    | some arn =>
      some (awsAsset arn "aws_lambda_function"
        (Json.mkObj [("function", Json.mkObj [
          ("name", match getOptStr fn "FunctionName" with | some n => .str n | none => .null),
          ("arn", .str arn),
          ("runtime", match getOptStr fn "Runtime" with | some r => .str r | none => .null),
          ("execution_role_arn", match getOptStr fn "Role" with | some r => .str r | none => .null)
        ])]))

-- opensearch-domains.jq: .DomainStatus → one aws_opensearch_domain
-- Detects wildcard principal in access policy (JSON string)
private def hasWildcardPrincipalOS (statements : List Json) : Bool :=
  statements.any fun stmt =>
    let principal := getObj stmt "Principal"
    principal == .str "*" ||
    (match getOptStr principal "AWS" with
     | some "*" => true
     | _ => match principal.getObjValAs? (Array Json) "AWS" with
            | .ok arr => arr.toList.any (· == .str "*")
            | .error _ => false)

def transformOpenSearchDomain (raw : Json) : Option ObsAsset :=
  let ds := getObj raw "DomainStatus"
  match getOptStr ds "ARN" with
  | none => none
  | some arn =>
    let auditEnabled := (getOptBool (getObj (getObj ds "LogPublishingOptions") "AUDIT_LOGS") "Enabled").getD false
    let accessPolicies := (getOptStr ds "AccessPolicies").getD ""
    let emptyPolicy := accessPolicies.toList.all Char.isWhitespace
    let wildcardAccess := if emptyPolicy then true
      else match Json.parse accessPolicies with
        | .ok policyJson =>
          let stmts := getArr policyJson "Statement"
          let stmtList := match stmts with
            | [] => match policyJson.getObjValAs? Json "Statement" with
                    | .ok s => [s]
                    | .error _ => []
            | _ => stmts
          hasWildcardPrincipalOS stmtList
        | .error _ => false
    some (awsAsset arn "aws_opensearch_domain"
      (Json.mkObj [("search_service", Json.mkObj [
        ("kind", .str "domain"),
        ("logging", Json.mkObj [
          ("audit_logs_enabled", .bool auditEnabled)
        ]),
        ("access", Json.mkObj [
          ("policy_allows_wildcard", .bool wildcardAccess)
        ])
      ])]))

-- Self-tests

#guard
  let raw := Json.mkObj [("MetricAlarms", Json.arr #[
    Json.mkObj [
      ("AlarmArn", .str "arn:aws:cloudwatch:us-east-1:123:alarm/cpu"),
      ("AlarmActions", Json.arr #[.str "arn:aws:sns:us-east-1:123:topic"]),
      ("OKActions", Json.arr #[]),
      ("InsufficientDataActions", Json.arr #[])
    ]
  ])]
  match transformCloudWatchAlarms raw with
  | [a] => a.assetType == "aws_cloudwatch_alarm" && a.vendor == "aws"
  | _ => false

#guard
  let raw := Json.mkObj [("Functions", Json.arr #[
    Json.mkObj [
      ("FunctionArn", .str "arn:aws:lambda:us-east-1:123:function:hello"),
      ("FunctionName", .str "hello"),
      ("Runtime", .str "python3.12"),
      ("Role", .str "arn:aws:iam::123:role/lambda-exec")
    ]
  ])]
  match transformLambdaFunctions raw with
  | [a] => a.id == "arn:aws:lambda:us-east-1:123:function:hello"
  | _ => false
