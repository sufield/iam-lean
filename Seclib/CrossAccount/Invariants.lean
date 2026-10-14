import Seclib.CrossAccount.Grant

/-! Cross-account security invariants.
Go source: cross-account control YAMLs — each invariant corresponds
to a category of controls that share the same security predicate. -/

/-- No wildcard trust grant exists for a service.
    Go source: CTL.*.POLICY.CROSSACCOUNT.WILDCARD.*, CTL.IAM.TRUST.EXTERNAL.CLOUD.001.
    Topology-level: no edge from any account grants access to * for the service. -/
def noWildcardTrust (t : Topology) (svc : Service) : Prop :=
  ∀ e ∈ t.edges, e.service == svc → e.target ≠ "*"

/-- All trust grants for a service stay within an org boundary.
    Go source: CTL.IAM.TRUST.ORGBOUNDARY.001, CTL.IAM.POLICY.CONDITION.ORGID.001.
    Simplified: all target accounts share a prefix with the source. -/
def orgBounded (t : Topology) (orgPrefix : String) : Prop :=
  ∀ e ∈ t.edges, e.target == "*" ∨ e.target.startsWith orgPrefix

/-- Every cross-account AssumeRole trust policy requires ExternalId.
    Go source: CTL.IAM.TRUST.EXTERNALID.001, CTL.IAM.TRUST.EXTERNALID.SCOPED.001. -/
def externalIdEnforced (grants : List TrustGrant) : Prop :=
  ∀ g ∈ grants, g.mechanism == .trustPolicy → g.conditions.hasExternalId

/-- No outbound-flow grant exists for a service (no data exfiltration path).
    Go source: CTL.EC2.EBS.CROSSACCOUNT.SNAPSHOT.* (attribute-share outbound controls). -/
def noExfiltration (t : Topology) (svc : Service) : Prop :=
  ∀ e ∈ t.edges, e.service == svc → e.direction ≠ .outboundFlow
