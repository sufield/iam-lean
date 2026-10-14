import Seclib.Prim.Finding

/-! Core types for chain composition semantics.
Formalizes: internal/core/controldef/chain.go (ChainDefinition,
ChainScope, Severity, EscalationThreshold) and
internal/core/evaluation/risk/chain_engine.go (FailingControl).
Vendor-neutral — no cloud provider noun appears in this module. -/

abbrev ControlId := String
abbrev ChainId := String
abbrev AssetId := String

/-- Exploitability classification.
    Go source: internal/core/evaluation/finding_risk.go:11-24 -/
inductive Exploitability where
  | exploitable
  | oneAway
  | reachable
deriving DecidableEq, Repr

/-- A chain definition: controls that co-fail to create compound risk.
    Go source: internal/core/controldef/chain.go:14-65 -/
structure ChainDef where
  id : ChainId
  controls : List ControlId
  threshold : Nat
  severity : Severity
  hMin : controls.length ≥ 2 := by omega
  hThreshPos : threshold ≥ 1 := by omega
  hThreshBound : threshold ≤ controls.length := by omega

/-- A (control, asset) pair with an active violation.
    Go source: internal/core/evaluation/risk/chain_engine.go:18-21 -/
structure FailingControl where
  controlId : ControlId
  assetId : AssetId

/-- The set of failing control IDs, ignoring asset grouping for now.
    The Go engine groups by scope/asset; the core composition predicate
    only needs the set of failing control IDs within one scope bucket. -/
def failingSet (failures : List FailingControl) : List ControlId :=
  failures.map (·.controlId)
