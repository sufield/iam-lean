import Stave.Extract.Asset

/-! Privilege escalation extractor — pattern-match IAM permissions against
10 known escalation vectors. Pure function over already-collected IAM data.
Produces properties.identity.escalation.* for CTL.IAM.ESCALATE/POLICY controls. -/

open Lean (Json)

namespace Extract.Escalation

/-- A known escalation vector with required permissions. -/
structure EscalationVector where
  name : String
  requiredActions : List String
  deriving BEq

def knownVectors : List EscalationVector := [
  { name := "PassRoleToLambda",     requiredActions := ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"] },
  { name := "CreatePolicyVersion",  requiredActions := ["iam:CreatePolicyVersion"] },
  { name := "AttachRolePolicy",     requiredActions := ["iam:AttachRolePolicy"] },
  { name := "CreateAccessKey",      requiredActions := ["iam:CreateAccessKey"] },
  { name := "AssumeRoleChain",      requiredActions := ["sts:AssumeRole"] },
  { name := "UpdateLoginProfile",   requiredActions := ["iam:UpdateLoginProfile"] },
  { name := "EC2RunWithRole",       requiredActions := ["ec2:RunInstances", "iam:PassRole"] },
  { name := "GlueDevEndpoint",      requiredActions := ["glue:CreateDevEndpoint", "iam:PassRole"] },
  { name := "SageMakerNotebook",    requiredActions := ["sagemaker:CreateNotebookInstance", "iam:PassRole"] },
  { name := "CloudFormationRole",   requiredActions := ["cloudformation:CreateStack", "iam:PassRole"] }
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

/-- Extract action strings from a policy statement. -/
def extractActions (stmt : Json) : List String :=
  match stmt.getObjValAs? String "Action" with
  | .ok s => [s]
  | .error _ => match stmt.getObjValAs? (Array Json) "Action" with
    | .ok arr => arr.toList.filterMap fun j =>
      match j with | Json.str s => some s | _ => none
    | .error _ => []

/-- Collect all Allow actions from a policy document. -/
def collectAllowActions (policyDoc : Json) : List String :=
  let stmts := match policyDoc.getObjValAs? (Array Json) "Statement" with
    | .ok arr => arr.toList
    | .error _ => match policyDoc.getObjValAs? Json "Statement" with
      | .ok s => [s]
      | .error _ => []
  stmts.flatMap fun stmt =>
    if getOptStr stmt "Effect" == some "Allow" then extractActions stmt
    else []

/-- A principal with its ARN, type, and effective actions. -/
structure PrincipalPerms where
  arn : String
  principalType : String
  effectiveActions : List String
  adminRoleArns : List String
  deriving BEq

/-- Find escalation vectors a principal can exploit. -/
def findEscalations (p : PrincipalPerms) : List (EscalationVector × Option String) :=
  knownVectors.filterMap fun v =>
    if actionsMatch p.effectiveActions v.requiredActions then
      let targetAdmin := p.adminRoleArns.head?
      some (v, targetAdmin)
    else none

/-- Transform a list of principals into escalation observations. -/
def transformEscalation (principals : List PrincipalPerms) : List ObsAsset :=
  principals.flatMap fun p =>
    let hits := findEscalations p
    hits.map fun (vector, targetAdmin) =>
      awsAsset p.arn ("aws_iam_" ++ p.principalType)
        (Json.mkObj [("identity", Json.mkObj [
          ("kind", .str p.principalType),
          ("escalation", Json.mkObj [
            ("can_escalate_to_admin", .bool true),
            ("escalation_vector", .str vector.name),
            ("steps", Json.arr (vector.requiredActions.map Json.str).toArray),
            ("target_admin_role", match targetAdmin with | some r => .str r | none => .null),
            ("step_count", .num vector.requiredActions.length)
          ])
        ])])

end Extract.Escalation

-- Self-tests

open Extract.Escalation in
#guard actionsMatch ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"] ["iam:PassRole", "lambda:CreateFunction"] == true

open Extract.Escalation in
#guard actionsMatch ["s3:GetObject"] ["iam:PassRole"] == false

-- Wildcard covers everything
open Extract.Escalation in
#guard actionsMatch ["*"] ["iam:PassRole", "lambda:CreateFunction"] == true

-- Service wildcard
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
  | [(v, _)] => v.name == "CreatePolicyVersion"
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
