import Stave.IAM.Reachability

/-! Trust boundary predicates for cross-account and federation analysis.
Soufflé source: federation.dl (external_reach, external_transitive_reach).
Go source: internal/controls/iam/trust/ (20 trust boundary controls). -/

/-- Cross-account trust: principal in one account can assume a role
    in another account.
    Soufflé source: schema.dl:98 (cross_account_assumes). -/
def IAMGraph.crossAccountTrust (g : IAMGraph) (principalId roleId : String) : Prop :=
  let pAcct := (g.principals.find? fun p => p.id == principalId).map (·.accountId)
  let rAcct := (g.principals.find? fun p => p.id == roleId).map (·.accountId)
  match pAcct, rAcct with
  | some a, some b => a ≠ b ∧ g.hasEdge principalId roleId
  | _, _ => False

/-- Whether a trust policy has a wildcard principal (*).
    Go source: CTL.IAM.TRUST.WILDCARD.001 semantics. -/
def IAMGraph.wildcardPrincipal (g : IAMGraph) (roleId : String) : Bool :=
  g.canAssume.any fun (f, t) => t == roleId && f == "*"

/-- Whether a role requires ExternalId in its trust policy.
    Soufflé source: schema.dl:138 (has_trust_condition, condition_key contains "external").
    Go source: CTL.IAM.TRUST.CONFUSEDDEPUTY.001 semantics. -/
def IAMGraph.externalIdRequired (g : IAMGraph) (roleId : String) : Bool :=
  g.trustConditions.any fun tc =>
    tc.roleId == roleId &&
    (tc.conditionKey == "sts:ExternalId" || tc.conditionKey == "aws:ExternalId")

/-- Whether a role's trust policy respects organization boundary.
    Go source: CTL.IAM.TRUST.ORGBOUNDARY.001 semantics.
    True if all trusting principals are in the same org (modeled as
    account prefix match — simplified from real aws:PrincipalOrgID). -/
def IAMGraph.orgBoundaryRespected (g : IAMGraph) (roleId orgPrefix : String) : Bool :=
  let trusters := (g.canAssume.filter fun (_, t) => t == roleId).map (·.1)
  trusters.all fun p =>
    p == "*" || -- wildcard is handled separately
    match (g.principals.find? fun pr => pr.id == p) with
    | some pr => pr.accountId.startsWith orgPrefix
    | none => false

/-- External reachability: can an external source reach a resource
    through the IAM graph?
    Soufflé source: federation.dl:90-110 (external_transitive_reach). -/
def IAMGraph.externalReaches (g : IAMGraph) (source : String) (resource : String) : Bool :=
  g.externalTrusts.any fun et =>
    et.source == source &&
    let roleActions := g.reachableResources et.roleArn
    roleActions.any (· == resource)

/-- Unrestricted external reach: external source reaches resource via
    at least one unrestricted hop.
    Soufflé source: federation.dl:120-129 (unrestricted_external_reach). -/
def IAMGraph.unrestrictedExternalReach (g : IAMGraph) (source resource : String) : Bool :=
  g.externalTrusts.any fun et =>
    et.source == source && !et.restricted &&
    (g.reachableResources et.roleArn).any (· == resource)
