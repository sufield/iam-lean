import Seclib.Network.Verdict

/-! The 6 registered network safety properties as Props over NetGraph.
Go source: proof.go — each Prove* function.

Each property is a negative claim: the unsafe condition does NOT exist.
SAT = the property is violated (counterexample found).
UNSAT = the property holds (no counterexample in the SG-ingress model). -/

/-- All SSH paths to production traverse a bastion host.
    Go source: proof.go:53-118 -/
def bastionSsh (g : NetGraph) (port : Nat) : Prop :=
  ∀ src dst, dst ∈ g.productionHosts →
    ¬ src.isProduction → ¬ src.isBastion →
    src.id ≠ dst.id →
    g.canReach src dst port →
    src.isBastion

/-- No network path between production and development environments.
    Go source: proof.go:167-217 -/
def prodDevIsolation (g : NetGraph) : Prop :=
  (∀ src dst, src ∈ g.productionHosts → dst ∈ g.developmentHosts →
    ¬ g.canReachAny src dst) ∧
  (∀ src dst, src ∈ g.developmentHosts → dst ∈ g.productionHosts →
    ¬ g.canReachAny src dst)

/-- No host outside the database VPC can reach a database host.
    Go source: proof.go:222-290 -/
def databaseIsolation (g : NetGraph) : Prop :=
  ∀ src dst, dst ∈ g.databaseHosts →
    src.vpcId ≠ dst.vpcId →
    ¬ g.canReachAny src dst

/-- No non-bastion relay can bridge SSH to production (two-hop).
    Go source: proof.go:295-374 -/
def transitiveSsh (g : NetGraph) (port : Nat) : Prop :=
  ∀ relay dst, dst ∈ g.productionHosts →
    ¬ relay.isProduction → ¬ relay.isBastion →
    relay.id ≠ dst.id →
    g.canReach relay dst port →
    ¬ g.hasExternalIngress relay port

/-- All private subnets route internet traffic through a firewall endpoint.
    Go source: proof.go:379-425 -/
def firewallMandatory (g : NetGraph) : Prop :=
  ∀ sub, sub ∈ g.privateSubnets →
    ∀ route, route ∈ g.routesFor sub.routeTableId →
      (route.destination == "0.0.0.0/0" || route.destination == "::/0") →
      route.targetType ≠ "igw" ∨ route.targetId ∈ g.firewallEndpoints

/-- Egress classification for a host: whether its subnet has a default
    route to a sink, gated target, or neither.
    Go source: proof.go:490-522 (egress candidate classification) -/
def hostEgressClass (g : NetGraph) (h : Host) : Option RouteClass :=
  match g.findSubnet h.subnetId with
  | none => none
  | some sub =>
    let defaultRoutes := (g.routesFor sub.routeTableId).filter fun r =>
      r.destination == "0.0.0.0/0" || r.destination == "::/0"
    match defaultRoutes.find? (fun r => classifyRoute r.targetType != .nonSink) with
    | some r => some (classifyRoute r.targetType)
    | none => none

/-- Transitive egress SAT condition: isolated host reaches a sink.
    Go source: proof.go:532-557 -/
def transitiveEgressSat (g : NetGraph) : Prop :=
  ∃ iso srv, iso ∈ g.isolatedHosts ∧ ¬ srv.isIsolated ∧
    g.canReachAny iso srv ∧ hostEgressClass g srv = some .sink

/-- Transitive egress EVIDENCE_GATED condition: isolated host reaches
    a gated target. Go source: proof.go:560-584 -/
def transitiveEgressGated (g : NetGraph) : Prop :=
  ∃ iso srv, iso ∈ g.isolatedHosts ∧ ¬ srv.isIsolated ∧
    g.canReachAny iso srv ∧ hostEgressClass g srv = some .gated

/-- Full transitive-egress verdict with precedence: SAT > GATED > UNSAT.
    Go source: proof.go:465 -/
def transitiveEgressVerdict (g : NetGraph) : Verdict :=
  if g.isolatedHosts.any fun iso =>
    g.hosts.any fun srv =>
      ¬ srv.isIsolated && g.canReachAny iso srv &&
      hostEgressClass g srv == some .sink
  then .sat
  else if g.isolatedHosts.any fun iso =>
    g.hosts.any fun srv =>
      ¬ srv.isIsolated && g.canReachAny iso srv &&
      hostEgressClass g srv == some .gated
  then .evidenceGated
  else .unsat
