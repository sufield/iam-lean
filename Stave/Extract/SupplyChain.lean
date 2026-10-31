import Stave.Extract.Asset

/-! Supply chain ingress extractor — OIDC federation trust analysis.
Pure function over already-collected IAM role data.
Produces properties.identity.trust.oidc.* for CTL.IAM.TRUST.OIDC.001–003. -/

open Lean (Json)

-- String contains check via splitOn (available in this nightly)
private def strContains (haystack needle : String) : Bool :=
  (haystack.splitOn needle).length > 1

private def strHasPrefix (s pfx : String) : Bool :=
  (s.splitOn pfx).head? == some ""

private def strHasSuffix (s sfx : String) : Bool :=
  match (s.splitOn sfx).getLast? with
  | some last => last == ""
  | none => false

/-- Typed intermediate for OIDC trust analysis. -/
structure OIDCTrust where
  roleArn : String
  roleName : String
  hasOidcTrust : Bool
  provider : String
  subClaimIsScoped : Bool
  subClaimValue : String
  hasWildcardSub : Bool
  hasAdminPermissions : Bool
  deriving BEq

/-- Identify OIDC provider from the federated principal URL. -/
def identifyProvider (url : String) : String :=
  if strContains url "token.actions.githubusercontent.com" then "github"
  else if strContains url "gitlab.com" then "gitlab"
  else if strContains url "bitbucket.org" then "bitbucket"
  else if strContains url "accounts.google.com" then "google"
  else "unknown"

/-- Check if a subject condition value is a wildcard. -/
def isWildcardSub (value : String) : Bool :=
  value == "*" || strHasPrefix value "*:"

/-- Extract OIDC trust from a role's trust policy document. -/
def analyzeOIDCTrust (role : Json) : Option OIDCTrust := do
  let arn ← match getOptStr role "Arn" with | some a => pure a | none => .none
  let name ← match getOptStr role "RoleName" with | some n => pure n | none => .none
  let trustDoc := getObj role "AssumeRolePolicyDocument"
  let stmts := getArr trustDoc "Statement"
  let oidcStmt := stmts.find? fun stmt =>
    getOptStr stmt "Effect" == some "Allow" &&
    match getOptStr (getObj stmt "Principal") "Federated" with
    | some fed => strContains fed "oidc" || strContains fed "token.actions" ||
                  strContains fed "gitlab" || strContains fed "bitbucket"
    | none => false
  match oidcStmt with
  | none => .none
  | some stmt =>
    let federated := (getOptStr (getObj stmt "Principal") "Federated").getD ""
    let provider := identifyProvider federated
    let condition := getObj stmt "Condition"
    let subValue :=
      let candidates := [
        getObj condition "StringEquals",
        getObj condition "StringLike"
      ]
      let found := candidates.findSome? fun cond =>
        let keys := [
          "token.actions.githubusercontent.com:sub",
          "accounts.google.com:sub",
          "gitlab.com:sub",
          "bitbucket.org:sub"
        ]
        keys.findSome? fun k => getOptStr cond k
      found.getD ""
    let isScoped := !subValue.isEmpty && !isWildcardSub subValue
    let wildcard := !subValue.isEmpty && isWildcardSub subValue
    let attachedPolicies := getArr role "AttachedPolicies"
    let isAdmin := attachedPolicies.any fun p =>
      getOptStr p "PolicyArn" == some "arn:aws:iam::aws:policy/AdministratorAccess"
    pure {
      roleArn := arn
      roleName := name
      hasOidcTrust := true
      provider
      subClaimIsScoped := isScoped
      subClaimValue := subValue
      hasWildcardSub := wildcard
      hasAdminPermissions := isAdmin
    }

/-- Transform a list of IAM roles into OIDC trust observations. -/
def transformSupplyChain (roles : List Json) : List ObsAsset :=
  roles.filterMap fun role =>
    match analyzeOIDCTrust role with
    | none => none
    | some trust =>
      some (awsAsset trust.roleArn "aws_iam_role"
        (Json.mkObj [("identity", Json.mkObj [
          ("kind", .str "role"),
          ("trust", Json.mkObj [
            ("oidc", Json.mkObj [
              ("has_oidc_trust", .bool trust.hasOidcTrust),
              ("provider", .str trust.provider),
              ("sub_claim_scoped", .bool trust.subClaimIsScoped),
              ("sub_claim_value", .str trust.subClaimValue),
              ("has_wildcard_sub", .bool trust.hasWildcardSub),
              ("has_admin_permissions", .bool trust.hasAdminPermissions)
            ])
          ])
        ])]))

-- Proofs

theorem identifyProvider_github :
    identifyProvider "arn:aws:iam::123:oidc-provider/token.actions.githubusercontent.com" = "github" := by
  native_decide

theorem identifyProvider_gitlab :
    identifyProvider "arn:aws:iam::123:oidc-provider/gitlab.com" = "gitlab" := by
  native_decide

theorem isWildcardSub_star : isWildcardSub "*" = true := by native_decide
theorem isWildcardSub_starColon : isWildcardSub "*:ref" = true := by native_decide
theorem isWildcardSub_scopedClaim : isWildcardSub "repo:org/repo:ref:refs/heads/main" = false := by native_decide

-- Self-test: OIDC role with wildcard sub

#guard
  let role := Json.mkObj [
    ("Arn", .str "arn:aws:iam::123:role/github-deploy"),
    ("RoleName", .str "github-deploy"),
    ("AssumeRolePolicyDocument", Json.mkObj [
      ("Statement", Json.arr #[
        Json.mkObj [
          ("Effect", .str "Allow"),
          ("Principal", Json.mkObj [
            ("Federated", .str "arn:aws:iam::123:oidc-provider/token.actions.githubusercontent.com")
          ]),
          ("Action", .str "sts:AssumeRoleWithWebIdentity"),
          ("Condition", Json.mkObj [
            ("StringLike", Json.mkObj [
              ("token.actions.githubusercontent.com:sub", .str "*")
            ])
          ])
        ]
      ])
    ]),
    ("AttachedPolicies", Json.arr #[
      Json.mkObj [("PolicyArn", .str "arn:aws:iam::aws:policy/AdministratorAccess")]
    ])
  ]
  match analyzeOIDCTrust role with
  | some t => t.provider == "github" && t.hasWildcardSub == true && t.hasAdminPermissions == true
  | none => false

-- Non-OIDC role → none
#guard
  let role := Json.mkObj [
    ("Arn", .str "arn:aws:iam::123:role/lambda-exec"),
    ("RoleName", .str "lambda-exec"),
    ("AssumeRolePolicyDocument", Json.mkObj [
      ("Statement", Json.arr #[
        Json.mkObj [
          ("Effect", .str "Allow"),
          ("Principal", Json.mkObj [("Service", .str "lambda.amazonaws.com")]),
          ("Action", .str "sts:AssumeRole")
        ]
      ])
    ])
  ]
  (analyzeOIDCTrust role).isNone
