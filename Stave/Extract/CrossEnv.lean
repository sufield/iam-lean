import Stave.Extract.Asset

/-! Cross-environment extractor — BFS over sts:AssumeRole trust chains.
Detects transitive trust paths from non-production to production.
Produces properties.identity.role.cross_env.* for CTL.IAM.CROSS.ENV.001/PATH.001. -/

open Lean (Json)

namespace Extract.CrossEnv

/-- Environment classification for an AWS account. -/
inductive EnvClass where
  | production
  | staging
  | development
  | unknown
  deriving BEq, DecidableEq

def EnvClass.isLower : EnvClass → Bool
  | .development => true
  | .staging => true
  | _ => false

def EnvClass.toString : EnvClass → String
  | .production => "production"
  | .staging => "staging"
  | .development => "development"
  | .unknown => "unknown"

/-- A trust edge: role in targetAccount can be assumed from sourceAccount. -/
structure TrustEdge where
  sourceAccount : String
  targetAccount : String
  targetRoleArn : String
  deriving BEq

/-- Extract account ID from an ARN (12-digit field at position 4). -/
def arnAccount (arn : String) : String :=
  let parts := arn.splitOn ":"
  if h : 4 < parts.length then parts[4] else ""

/-- Extract trusted account IDs from a role's trust policy. -/
def extractTrustedAccounts (trustDoc : Json) : List String :=
  let stmts := getArr trustDoc "Statement"
  stmts.flatMap fun stmt =>
    if getOptStr stmt "Effect" != some "Allow" then []
    else
      let principal := getObj stmt "Principal"
      let awsPrincipals := match principal.getObjValAs? String "AWS" with
        | .ok s => [s]
        | .error _ => match principal.getObjValAs? (Array Json) "AWS" with
          | .ok arr => arr.toList.filterMap fun j =>
            match j with | Json.str s => some s | _ => none
          | .error _ => []
      awsPrincipals.filterMap fun (p : String) =>
        let acct := arnAccount p
        if acct.length == 12 then some acct else none

/-- Build trust edges from a list of roles (each with Arn + AssumeRolePolicyDocument). -/
def buildTrustGraph (roles : List Json) : List TrustEdge :=
  roles.flatMap fun role =>
    match getOptStr role "Arn" with
    | none => []
    | some arn =>
      let targetAcct := arnAccount arn
      let trustDoc := getObj role "AssumeRolePolicyDocument"
      let trusted := extractTrustedAccounts trustDoc
      trusted.filterMap fun srcAcct =>
        if srcAcct == targetAcct then none
        else some { sourceAccount := srcAcct, targetAccount := targetAcct, targetRoleArn := arn }

/-- BFS from a set of source accounts, following trust edges.
Returns all reachable (account, roleArn, hopCount, bridgeRole) tuples. -/
def bfsFromAccounts (sources : List String) (edges : List TrustEdge) (maxHops : Nat := 10) : List (String × String × Nat × Option String) :=
  let rec go (queue : List (String × Nat × Option String)) (visited : List String) (results : List (String × String × Nat × Option String)) (fuel : Nat) :=
    match fuel, queue with
    | 0, _ => results
    | _, [] => results
    | fuel + 1, (acct, hops, bridge) :: rest =>
      let newEdges := edges.filter fun e => e.sourceAccount == acct && !visited.contains e.targetAccount
      let newResults := newEdges.map fun e => (e.targetAccount, e.targetRoleArn, hops + 1, bridge)
      let newQueue := newEdges.map fun e => (e.targetAccount, hops + 1, bridge.orElse fun _ => some e.targetRoleArn)
      go (rest ++ newQueue) (visited ++ newEdges.map (·.targetAccount)) (results ++ newResults) fuel
  go (sources.map fun s => (s, 0, none)) sources [] (maxHops * edges.length + 1)

/-- Run the cross-env analysis.
envMap: account → EnvClass. roles: list of role JSON objects. -/
def analyzeCrossEnv (envMap : List (String × EnvClass)) (roles : List Json) : List ObsAsset :=
  let edges := buildTrustGraph roles
  let lowerAccounts := envMap.filter (·.2.isLower) |>.map (·.1)
  let prodAccounts := envMap.filter (·.2 == .production) |>.map (·.1)
  let reachable := bfsFromAccounts lowerAccounts edges
  let prodReachable := reachable.filter fun (acct, _, _, _) => prodAccounts.contains acct
  prodReachable.filterMap fun (_, roleArn, hops, bridge) =>
    let sourceEnv := match envMap.find? fun (a, _) => lowerAccounts.contains a with
      | some (_, e) => e.toString
      | none => "unknown"
    some (awsAsset roleArn "aws_iam_role"
      (Json.mkObj [("identity", Json.mkObj [
        ("kind", .str "role"),
        ("role", Json.mkObj [
          ("cross_env", Json.mkObj [
            ("reachable_from_lower_env", .bool true),
            ("source_env", .str sourceEnv),
            ("path_hop_count", .num hops),
            ("via_bridge_role", match bridge with | some b => .str b | none => .null)
          ])
        ])
      ])]))

end Extract.CrossEnv

open Extract.CrossEnv in
theorem arnAccount_12digit :
    arnAccount "arn:aws:iam::123456789012:role/test" = "123456789012" := by
  native_decide

open Extract.CrossEnv in
#guard
  let edges : List TrustEdge := [
    { sourceAccount := "222222222222", targetAccount := "111111111111", targetRoleArn := "arn:aws:iam::111111111111:role/deploy" }
  ]
  let results := bfsFromAccounts ["222222222222"] edges
  match results with
  | [(acct, _arn, hops, _)] => acct == "111111111111" && hops == 1
  | _ => false

open Extract.CrossEnv in
#guard
  let edges : List TrustEdge := [
    { sourceAccount := "333", targetAccount := "222", targetRoleArn := "arn:aws:iam::222:role/bridge" },
    { sourceAccount := "222", targetAccount := "111", targetRoleArn := "arn:aws:iam::111:role/deploy" }
  ]
  let results := bfsFromAccounts ["333"] edges
  results.length == 2

open Extract.CrossEnv in
#guard
  let edges : List TrustEdge := [
    { sourceAccount := "111", targetAccount := "222", targetRoleArn := "arn:aws:iam::222:role/x" }
  ]
  let results := bfsFromAccounts ["333"] edges
  results.isEmpty
