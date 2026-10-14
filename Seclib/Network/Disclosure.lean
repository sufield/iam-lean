import Seclib.Network.Property

/-! UNSAT interpretation: what the prover does NOT claim.
Go source: proof.go:589 (UNSAT interpretation text).

When the prover returns UNSAT, the following layers are NOT evaluated
and therefore NOT covered by the proof:
1. NACL layer — network ACLs can deny traffic the SG model allows
2. SG egress layer — only ingress rules are checked
3. IAM layer — service-level paths (Lambda invoke, SSM, S3 replication,
   VPC endpoints to request-making services)
4. Cross-region — single-region snapshot; run per region
5. Route state — blackhole routes are treated as active

A SAT counterexample may be blocked in practice by layers 1-2.
An UNSAT verdict does NOT depend on layers 1-2 (sound over SG-ingress).

This module exists to make the disclosure machine-checkable: any theorem
about UNSAT must carry these assumptions explicitly. -/

/-- The layers NOT modeled by the network prover. -/
inductive ExcludedLayer where
  | nacl
  | sgEgress
  | iamServicePath
  | crossRegion
  | routeState
deriving DecidableEq, Repr

/-- All excluded layers. -/
def allExcludedLayers : List ExcludedLayer :=
  [.nacl, .sgEgress, .iamServicePath, .crossRegion, .routeState]

/-- UNSAT is sound over the SG-ingress-only model. This is a type-level
    marker: any proof of network isolation must acknowledge it operates
    within the SG-ingress model, not the full network stack. -/
structure SgIngressOnly where
  excludedLayers : List ExcludedLayer := allExcludedLayers
