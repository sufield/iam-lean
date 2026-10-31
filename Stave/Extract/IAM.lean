import Stave.Extract.Asset

/-! IAM transforms — 9 jq filter equivalents:
  iam-roles, iam-users, iam-groups, iam-password-policy,
  iam-role-attached-policies, iam-role-tags,
  iam-group-inline, iam-user-inline, iam-inline-policy. -/

open Lean (Json)

-- iam-roles.jq: .Roles[] → one aws_iam_role per role (skip AWSServiceRole*)
private def extractTrustedServices (trustDoc : Json) : List String :=
  let stmts := getArr trustDoc "Statement"
  let services := stmts.flatMap fun stmt =>
    let principal := getObj stmt "Principal"
    match principal.getObjValAs? String "Service" with
    | .ok s => [s]
    | .error _ => match principal.getObjValAs? (Array Json) "Service" with
      | .ok arr => arr.toList.filterMap fun j =>
        match j with | .str s => some s | _ => none
      | .error _ => []
  List.eraseDups services

def transformIAMRoles (raw : Json) : List ObsAsset :=
  (getArr raw "Roles").filterMap fun role =>
    match getOptStr role "RoleName", getOptStr role "Arn" with
    | some name, some arn =>
      if "AWSServiceRole".isPrefixOf name then none
      else
        let trustDoc := getObj role "AssumeRolePolicyDocument"
        let services := extractTrustedServices trustDoc
        some (awsAsset arn "aws_iam_role"
          (Json.mkObj [("identity", Json.mkObj [
            ("kind", .str "role"),
            ("name", .str name),
            ("trusted_services", Json.arr (services.map Json.str).toArray)
          ])]))
    | _, _ => none

-- iam-users.jq: .Users[] → one base aws_iam_user per user
def transformIAMUsers (raw : Json) : List ObsAsset :=
  (getArr raw "Users").filterMap fun user =>
    match getOptStr user "UserName", getOptStr user "Arn" with
    | some name, some arn =>
      some (awsAsset arn "aws_iam_user"
        (Json.mkObj [("identity", Json.mkObj [
          ("kind", .str "user"),
          ("name", .str name),
          ("arn", .str arn)
        ])]))
    | _, _ => none

-- iam-groups.jq: .Groups[] → one base aws_iam_group per group
def transformIAMGroups (raw : Json) : List ObsAsset :=
  (getArr raw "Groups").filterMap fun group =>
    match getOptStr group "GroupName", getOptStr group "Arn" with
    | some name, some arn =>
      some (awsAsset arn "aws_iam_group"
        (Json.mkObj [("identity", Json.mkObj [("group", Json.mkObj [
          ("name", .str name)
        ])])]))
    | _, _ => none

-- iam-password-policy.jq: .PasswordPolicy → one aws_iam_password_policy
def transformIAMPasswordPolicy (raw : Json) (account : String) : Option ObsAsset :=
  let pp := getObj raw "PasswordPolicy"
  if pp == .null then none
  else some (awsAsset
    ("arn:aws:iam::" ++ account ++ ":password-policy")
    "aws_iam_password_policy"
    (Json.mkObj [("identity", Json.mkObj [
      ("kind", .str "password_policy"),
      ("password_policy", Json.mkObj [
        ("minimum_length", match getOptNat pp "MinimumPasswordLength" with | some n => .num n | none => .num 0),
        ("require_uppercase", .bool ((getOptBool pp "RequireUppercaseCharacters").getD false)),
        ("require_lowercase", .bool ((getOptBool pp "RequireLowercaseCharacters").getD false)),
        ("require_numbers", .bool ((getOptBool pp "RequireNumbers").getD false)),
        ("require_symbols", .bool ((getOptBool pp "RequireSymbols").getD false)),
        ("reuse_prevention_count", match getOptNat pp "PasswordReusePrevention" with | some n => .num n | none => .num 0),
        ("max_password_age", match getOptNat pp "MaxPasswordAge" with | some n => .num n | none => .num 0)
      ])
    ])]))

-- iam-role-attached-policies.jq: annotated with RoleArn → merge asset
def transformIAMRoleAttachedPolicies (raw : Json) : Option ObsAsset :=
  match getOptStr raw "RoleArn" with
  | none => none
  | some arn =>
    let policies := getArr raw "AttachedPolicies"
    let policyArns := policies.filterMap fun p => getOptStr p "PolicyArn"
    let isAdmin := policyArns.any (· == "arn:aws:iam::aws:policy/AdministratorAccess")
    some (awsAsset arn "aws_iam_role"
      (Json.mkObj [("identity", Json.mkObj [
        ("attached_policy_arns", Json.arr (policyArns.map Json.str).toArray),
        ("is_admin_equivalent", .bool isAdmin)
      ])]))

-- iam-role-tags.jq: annotated with RoleArn → merge asset
def transformIAMRoleTags (raw : Json) : Option ObsAsset :=
  match getOptStr raw "RoleArn" with
  | none => none
  | some arn =>
    let tags := getArr raw "Tags"
    let tagPairs := tags.filterMap fun t =>
      match getOptStr t "Key", getOptStr t "Value" with
      | some k, some v => some (k, Json.str v)
      | _, _ => none
    some (awsAsset arn "aws_iam_role"
      (Json.mkObj [("identity", Json.mkObj [
        ("tags", Json.mkObj tagPairs)
      ])]))

-- iam-group-inline.jq: GroupName-keyed → has_inline_policies
def transformIAMGroupInline (raw : Json) (account : String) : Option ObsAsset :=
  match getOptStr raw "GroupName" with
  | none => none
  | some name =>
    let hasInline := (getArr raw "PolicyNames").length > 0
    some (awsAsset
      ("arn:aws:iam::" ++ account ++ ":group/" ++ name)
      "aws_iam_group"
      (Json.mkObj [("identity", Json.mkObj [("group", Json.mkObj [
        ("has_inline_policies", .bool hasInline)
      ])])]))

-- iam-user-inline.jq: UserName-keyed → has_inline_policies
def transformIAMUserInline (raw : Json) (account : String) : Option ObsAsset :=
  match getOptStr raw "UserName" with
  | none => none
  | some name =>
    let hasInline := (getArr raw "PolicyNames").length > 0
    some (awsAsset
      ("arn:aws:iam::" ++ account ++ ":user/" ++ name)
      "aws_iam_user"
      (Json.mkObj [("identity", Json.mkObj [("policies", Json.mkObj [
        ("has_inline_policies", .bool hasInline)
      ])])]))

-- iam-inline-policy.jq: inline policy document → shadow_logic signal
private def findNotAction (stmts : List Json) : Option Json :=
  stmts.find? fun stmt => (getObj stmt "NotAction") != .null

def transformIAMInlinePolicy (raw : Json) (account : String) : Option ObsAsset :=
  let principal := match getOptStr raw "UserName" with
    | some n => n
    | none => match getOptStr raw "GroupName" with
      | some n => n
      | none => match getOptStr raw "RoleName" with
        | some n => n
        | none => ""
  if principal.isEmpty then none
  else
    let policyName := (getOptStr raw "PolicyName").getD ""
    let stmtsRaw := getObj (getObj raw "PolicyDocument") "Statement"
    let stmts := match stmtsRaw with
      | .arr a => a.toList
      | j => if j == .null then [] else [j]
    let shadowLogic := match findNotAction stmts with
      | some na =>
        let notActionVal := getObj na "NotAction"
        let actions := match notActionVal with
          | .arr a => a.toList
          | .str s => [.str s]
          | _ => []
        Json.mkObj [
          ("has_not_action", .bool true),
          ("not_action_values", Json.arr actions.toArray),
          ("effect", match getOptStr na "Effect" with | some e => .str e | none => .null),
          ("resource", getObj na "Resource")
        ]
      | none => Json.mkObj [("has_not_action", .bool false)]
    some (awsAsset
      ("arn:aws:iam::" ++ account ++ ":inline-policy/" ++ principal ++ "/" ++ policyName)
      "aws_iam_policy"
      (Json.mkObj [("identity", Json.mkObj [
        ("kind", .str "policy"),
        ("policy", Json.mkObj [
          ("shadow_logic", shadowLogic)
        ])
      ])]))

-- Self-tests

#guard
  let raw := Json.mkObj [("Roles", Json.arr #[
    Json.mkObj [
      ("RoleName", .str "MyRole"),
      ("Arn", .str "arn:aws:iam::123:role/MyRole"),
      ("AssumeRolePolicyDocument", Json.mkObj [("Statement", Json.arr #[])])
    ],
    Json.mkObj [
      ("RoleName", .str "AWSServiceRoleForSSO"),
      ("Arn", .str "arn:aws:iam::123:role/AWSServiceRoleForSSO"),
      ("AssumeRolePolicyDocument", Json.mkObj [("Statement", Json.arr #[])])
    ]
  ])]
  match transformIAMRoles raw with
  | [a] => a.id == "arn:aws:iam::123:role/MyRole" && a.assetType == "aws_iam_role"
  | _ => false

#guard
  let raw := Json.mkObj [("Users", Json.arr #[
    Json.mkObj [("UserName", .str "alice"), ("Arn", .str "arn:aws:iam::123:user/alice")]
  ])]
  match transformIAMUsers raw with
  | [a] => a.assetType == "aws_iam_user" && a.vendor == "aws"
  | _ => false

#guard
  let raw := Json.mkObj [
    ("RoleArn", .str "arn:aws:iam::123:role/Admin"),
    ("AttachedPolicies", Json.arr #[
      Json.mkObj [("PolicyArn", .str "arn:aws:iam::aws:policy/AdministratorAccess")]
    ])
  ]
  match transformIAMRoleAttachedPolicies raw with
  | some a => a.id == "arn:aws:iam::123:role/Admin" && a.vendor == "aws"
  | none => false

-- No RoleArn → none
#guard (transformIAMRoleAttachedPolicies (Json.mkObj [])).isNone
#guard (transformIAMRoleTags (Json.mkObj [])).isNone
