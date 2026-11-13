import Stave.Extract.Asset

/-! Privilege escalation extractor — pattern-match IAM permissions against
30 known escalation vectors. Pure function over already-collected IAM data.
Produces properties.identity.escalation.<vector_key>.present for per-vector
CTL.IAM.ESCALATE controls. -/

open Lean (Json)

namespace Extract.Escalation

/-- A known escalation vector with required permissions and the snake_case
    property key that controls check (e.g. "create_policy_version"). -/
structure EscalationVector where
  propertyKey : String
  requiredActions : List String
  deriving BEq

def knownVectors : List EscalationVector := [
  { propertyKey := "create_policy_version",    requiredActions := ["iam:CreatePolicyVersion"] },
  { propertyKey := "create_policy_version",    requiredActions := ["iam:SetDefaultPolicyVersion"] },
  { propertyKey := "attach_role_policy",       requiredActions := ["iam:AttachRolePolicy"] },
  { propertyKey := "create_access_key",        requiredActions := ["iam:CreateAccessKey"] },
  { propertyKey := "update_login_profile",     requiredActions := ["iam:UpdateLoginProfile"] },
  { propertyKey := "create_login_profile",     requiredActions := ["iam:CreateLoginProfile"] },
  { propertyKey := "attach_user_policy_self",  requiredActions := ["iam:AttachUserPolicy"] },
  { propertyKey := "attach_group_policy",      requiredActions := ["iam:AttachGroupPolicy"] },
  { propertyKey := "put_user_policy_self",     requiredActions := ["iam:PutUserPolicy"] },
  { propertyKey := "put_group_policy",         requiredActions := ["iam:PutGroupPolicy"] },
  { propertyKey := "put_role_policy",          requiredActions := ["iam:PutRolePolicy"] },
  { propertyKey := "add_user_to_group",        requiredActions := ["iam:AddUserToGroup"] },
  { propertyKey := "update_trust_policy",      requiredActions := ["iam:UpdateAssumeRolePolicy"] },
  { propertyKey := "editlambda",               requiredActions := ["lambda:UpdateFunctionCode"] },
  { propertyKey := "updatedevendpoint",        requiredActions := ["glue:UpdateDevEndpoint"] },
  { propertyKey := "passrole_createfunction",  requiredActions := ["lambda:CreateFunction", "iam:PassRole"] },
  { propertyKey := "passrole_runinstances",    requiredActions := ["ec2:RunInstances", "iam:PassRole"] },
  { propertyKey := "passrole_createdevendpoint", requiredActions := ["glue:CreateDevEndpoint", "iam:PassRole"] },
  { propertyKey := "passrole_createnotebook",  requiredActions := ["sagemaker:CreateNotebookInstance", "iam:PassRole"] },
  { propertyKey := "passrole_createstack",     requiredActions := ["cloudformation:CreateStack", "iam:PassRole"] },
  { propertyKey := "passrole_createpipeline",  requiredActions := ["datapipeline:CreatePipeline", "iam:PassRole"] },
  { propertyKey := "passrole_createprocessingjob", requiredActions := ["sagemaker:CreateProcessingJob", "iam:PassRole"] },
  { propertyKey := "passrole_createtrainingjob",   requiredActions := ["sagemaker:CreateTrainingJob", "iam:PassRole"] },
  { propertyKey := "passrole_sendcommand",     requiredActions := ["ssm:SendCommand"] },
  { propertyKey := "ssm_startsession",         requiredActions := ["ssm:StartSession"] },
  { propertyKey := "confused_cfn_update",      requiredActions := ["cloudformation:UpdateStack"] },
  { propertyKey := "startbuild_source_write",  requiredActions := ["codebuild:StartBuild", "iam:PassRole"] },
  { propertyKey := "send_ssh_public_key",      requiredActions := ["ec2-instance-connect:SendSSHPublicKey"] },
  { propertyKey := "sagemaker_presigned_url",  requiredActions := ["sagemaker:CreatePresignedNotebookInstanceUrl"] },
  { propertyKey := "assume_role",              requiredActions := ["sts:AssumeRole"] }
]

private def strToLower (s : String) : String :=
  String.ofList (s.toList.map Char.toLower)

/-- Check if a list of effective actions covers all required actions (case-insensitive).
Wildcard "*" matches everything. "service:*" matches all actions for that service. -/
def actionsMatch (effective : List String) (required : List String) : Bool :=
  let effLower := effective.map strToLower
  let hasWildcard := effLower.contains "*"
  required.all fun req =>
    let reqLower := strToLower req
    let svc := (reqLower.splitOn ":").head!
    hasWildcard ||
    effLower.contains reqLower ||
    effLower.contains (svc ++ ":*")

/-- A principal with its ARN, type, and effective actions. -/
structure PrincipalPerms where
  arn : String
  principalType : String
  effectiveActions : List String
  adminRoleArns : List String
  deriving BEq

/-- Find escalation vectors a principal can exploit. -/
def findEscalations (p : PrincipalPerms) : List EscalationVector :=
  knownVectors.filter fun v =>
    actionsMatch p.effectiveActions v.requiredActions

/-- Transform a list of principals into escalation observations.
    Each matching vector produces a separate asset; deep-merge by ID
    combines them into one escalation object per principal. -/
def transformEscalation (principals : List PrincipalPerms) : List ObsAsset :=
  principals.flatMap fun p =>
    let hits := findEscalations p
    hits.map fun vector =>
      awsAsset p.arn ("aws_iam_" ++ p.principalType)
        (Json.mkObj [("identity", Json.mkObj [
          ("kind", .str p.principalType),
          ("escalation", Json.mkObj [
            (vector.propertyKey, Json.mkObj [("present", .bool true)])
          ])
        ])])

end Extract.Escalation

-- Self-tests

open Extract.Escalation in
#guard actionsMatch ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"] ["iam:PassRole", "lambda:CreateFunction"] == true

open Extract.Escalation in
#guard actionsMatch ["s3:GetObject"] ["iam:PassRole"] == false

open Extract.Escalation in
#guard actionsMatch ["*"] ["iam:PassRole", "lambda:CreateFunction"] == true

open Extract.Escalation in
#guard actionsMatch ["iam:*", "lambda:*"] ["iam:PassRole", "lambda:CreateFunction"] == true

open Extract.Escalation in
#guard
  let p : PrincipalPerms := {
    arn := "arn:aws:iam::123:user/dev"
    principalType := "user"
    effectiveActions := ["iam:CreatePolicyVersion"]
    adminRoleArns := []
  }
  match findEscalations p with
  | [v] => v.propertyKey == "create_policy_version"
  | _ => false

open Extract.Escalation in
#guard
  let p : PrincipalPerms := {
    arn := "arn:aws:iam::123:user/readonly"
    principalType := "user"
    effectiveActions := ["s3:GetObject", "s3:ListBucket"]
    adminRoleArns := []
  }
  (findEscalations p).isEmpty

-- Multiple vectors match
open Extract.Escalation in
#guard
  let p : PrincipalPerms := {
    arn := "arn:aws:iam::123:user/multi"
    principalType := "user"
    effectiveActions := ["iam:CreateAccessKey", "iam:UpdateLoginProfile"]
    adminRoleArns := []
  }
  let hits := findEscalations p
  hits.length == 2

-- SetDefaultPolicyVersion triggers create_policy_version
open Extract.Escalation in
#guard
  let p : PrincipalPerms := {
    arn := "arn:aws:iam::123:user/privesc2"
    principalType := "user"
    effectiveActions := ["iam:SetDefaultPolicyVersion"]
    adminRoleArns := []
  }
  match findEscalations p with
  | [v] => v.propertyKey == "create_policy_version"
  | _ => false

-- AssumeRole vector
open Extract.Escalation in
#guard
  let p : PrincipalPerms := {
    arn := "arn:aws:iam::123:user/assumer"
    principalType := "user"
    effectiveActions := ["sts:AssumeRole"]
    adminRoleArns := []
  }
  match findEscalations p with
  | [v] => v.propertyKey == "assume_role"
  | _ => false

-- Per-vector output format
open Extract.Escalation in
#guard
  let p : PrincipalPerms := {
    arn := "arn:aws:iam::123:user/dev"
    principalType := "user"
    effectiveActions := ["iam:CreatePolicyVersion"]
    adminRoleArns := []
  }
  match transformEscalation [p] with
  | [a] =>
    let esc := getObj (getObj a.properties "identity") "escalation"
    let sub := getObj esc "create_policy_version"
    (getOptBool sub "present").getD false
  | _ => false
