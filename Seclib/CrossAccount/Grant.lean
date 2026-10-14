import Seclib.CrossAccount.Topology

/-! Trust grant model: individual grants with conditions.
Go source: cross-account control YAMLs (CTL.*.CROSSACCOUNT.*, CTL.*.EXTERNAL.*).
Imports IAM trust predicates conceptually — keeps this module self-contained
to avoid circular deps; IAM.TrustBoundary provides the parallel IAM-level predicates. -/

/-- Conditions that constrain a cross-account trust grant.
    Go source: CTL.IAM.TRUST.EXTERNALID.001, CTL.IAM.POLICY.CONDITION.ORGID.001. -/
structure GrantConditions where
  hasExternalId : Bool := false
  hasOrgCondition : Bool := false
  hasIpCondition : Bool := false
  hasMfaRequired : Bool := false
  hasSourceArn : Bool := false
  hasSourceAccount : Bool := false
deriving DecidableEq, Repr

/-- A concrete trust grant with conditions.
    Go source: individual control YAML unsafe_predicate fields. -/
structure TrustGrant where
  source : AccountId
  target : String
  service : Service
  mechanism : Mechanism
  conditions : GrantConditions := {}
deriving Repr

/-- Target is wildcard (* or broad). Any principal from any account.
    Go source: CTL.IAM.TRUST.EXTERNAL.CLOUD.001, CTL.OPENSEARCH.POLICY.CROSSACCOUNT.WILDCARD.001. -/
def wildcardGrant (g : TrustGrant) : Bool :=
  g.target == "*" && !g.conditions.hasExternalId && !g.conditions.hasOrgCondition

/-- Grant has conditions that meaningfully constrain access.
    Go source: CTL.IAM.TRUST.EXTERNALID.001 + CTL.IAM.POLICY.CONDITION.ORGID.001. -/
def conditionedGrant (g : TrustGrant) : Bool :=
  g.conditions.hasExternalId || g.conditions.hasOrgCondition

/-- Grant target is a specific account (not wildcard).
    Go source: non-wildcard principal patterns in control predicates. -/
def scopedGrant (g : TrustGrant) : Bool :=
  g.target != "*"
