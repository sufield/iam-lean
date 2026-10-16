import Stave.Compose.Basic

/-! Chain composition predicate: when does a chain fire?
Formalizes the threshold logic from
internal/core/evaluation/risk/chain_engine.go:157-174
(emitChainFinding) — a chain fires when the count of its member
controls present in the failing set meets the escalation threshold. -/

/-- Count how many of the chain's controls appear in the failing set.
    Go source: chain_engine.go:166-172 (failing/holding partition) -/
def failingCount (chain : ChainDef) (failing : List ControlId) : Nat :=
  chain.controls.countP (· ∈ failing)

/-- A chain fires when enough member controls fail.
    Go source: chain_engine.go:174 — `len(failing) < chain.EscalationThreshold`
    is the skip condition; negating it gives the firing predicate. -/
def chainFires (chain : ChainDef) (failing : List ControlId) : Prop :=
  failingCount chain failing ≥ chain.threshold

instance (chain : ChainDef) (failing : List ControlId) :
    Decidable (chainFires chain failing) :=
  inferInstanceAs (Decidable (_ ≥ _))

/-- Boolean version for computation. -/
def chainFiresB (chain : ChainDef) (failing : List ControlId) : Bool :=
  decide (chainFires chain failing)

/-- The controls in the chain that are failing. -/
def controlsFailing (chain : ChainDef) (failing : List ControlId) : List ControlId :=
  chain.controls.filter (· ∈ failing)

/-- The controls in the chain that are holding (not failing). -/
def missingSafeguards (chain : ChainDef) (failing : List ControlId) : List ControlId :=
  chain.controls.filter (· ∉ failing)
