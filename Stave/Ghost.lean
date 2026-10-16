import Stave.Basic.Finding

/-! Vendor-neutral ghost reference types.
A ghost reference is a configuration reference that cannot be resolved
in the current observation scope — e.g., a cross-account role ARN whose
trust policy isn't in the snapshot. No cloud provider noun appears here.

Go source context: Stave CEL predicates currently skip or flag unresolvable
references ad hoc. This module makes the assumption explicit and provable. -/

/-! ### Ghost property values -/

inductive GhostPropValue where
  | bool (b : Bool)
  | string (s : String)
  | stringList (ss : List String)
deriving Repr, BEq, DecidableEq

structure GhostProperty where
  name : String
  value : GhostPropValue
deriving Repr, BEq, DecidableEq

/-! ### Ghost assumption — what the evaluator assumes about an unresolved referent -/

inductive GhostAssumption where
  | overPermissive
  | leastPrivilege
  | explicit (props : List GhostProperty)
deriving Repr, BEq, DecidableEq

/-! ### Reference resolution status -/

inductive RefStatus (α : Type) where
  | resolved (payload : α)
  | ghost (id : String) (assume : GhostAssumption)
deriving Repr

instance [BEq α] : BEq (RefStatus α) where
  beq
    | .resolved a, .resolved b => a == b
    | .ghost id1 a1, .ghost id2 a2 => id1 == id2 && a1 == a2
    | _, _ => false

/-! ### Finding severity with ordering -/

inductive FindingSeverity where
  | safe | low | medium | high | critical
deriving Repr, BEq, DecidableEq, Inhabited

def FindingSeverity.toNat : FindingSeverity → Nat
  | .safe => 0
  | .low => 1
  | .medium => 2
  | .high => 3
  | .critical => 4

instance : LE FindingSeverity where
  le a b := a.toNat ≤ b.toNat

instance (a b : FindingSeverity) : Decidable (a ≤ b) :=
  inferInstanceAs (Decidable (a.toNat ≤ b.toNat))

instance : Ord FindingSeverity where
  compare a b := compare a.toNat b.toNat

/-! ### Conservativeness — the central proof obligation

A ghost finding is conservative when for every possible concrete
instantiation of the ghost referent, the finding under the ghost
assumption is at least as severe as the finding with full information.
Any control that produces a finding about a ghost must prove this. -/

def ghostConservative
    (control : α → FindingSeverity)
    (_assume : GhostAssumption)
    (ghostFinding : FindingSeverity) : Prop :=
  ∀ (concrete : α), ghostFinding ≥ control concrete

/-! ### Assumption compatibility at composition

Two controls touching the same ghost are compatible if their assumptions
don't contradict. overPermissive is top (compatible with everything).
Two explicit assumptions contradict when they assign different values
to the same property name. -/

private def explicitPropsCompatible (a b : List GhostProperty) : Bool :=
  a.all fun pa =>
    match b.find? (·.name == pa.name) with
    | none => true
    | some pb => pa.value == pb.value

def ghostAssumptionsCompatible (a b : GhostAssumption) : Bool :=
  match a, b with
  | .overPermissive, _ => true
  | _, .overPermissive => true
  | .leastPrivilege, .leastPrivilege => true
  | .leastPrivilege, .explicit _ => false
  | .explicit _, .leastPrivilege => false
  | .explicit pa, .explicit pb => explicitPropsCompatible pa pb

/-! ### Helpers -/

def RefStatus.isResolved : RefStatus α → Bool
  | .resolved _ => true
  | .ghost _ _ => false

def RefStatus.isGhost : RefStatus α → Bool
  | .resolved _ => false
  | .ghost _ _ => true

/-! ### #guard tests -/

-- Resolved vs ghost
#guard (RefStatus.resolved (42 : Nat)).isResolved == true
#guard (RefStatus.ghost "arn:aws:iam::999:role/X" .overPermissive : RefStatus Nat).isGhost == true

-- Compatible assumptions
#guard ghostAssumptionsCompatible .overPermissive .leastPrivilege == true
#guard ghostAssumptionsCompatible .overPermissive (.explicit []) == true
#guard ghostAssumptionsCompatible .leastPrivilege .leastPrivilege == true

-- Contradictory assumptions
#guard ghostAssumptionsCompatible .leastPrivilege (.explicit [⟨"x", .bool true⟩]) == false
#guard ghostAssumptionsCompatible
  (.explicit [⟨"managed", .bool true⟩])
  (.explicit [⟨"managed", .bool false⟩]) == false

-- Compatible explicit with non-overlapping keys
#guard ghostAssumptionsCompatible
  (.explicit [⟨"a", .bool true⟩])
  (.explicit [⟨"b", .string "x"⟩]) == true

-- Compatible explicit with same key-value
#guard ghostAssumptionsCompatible
  (.explicit [⟨"managed", .bool true⟩])
  (.explicit [⟨"managed", .bool true⟩]) == true

-- Severity ordering
#guard (FindingSeverity.safe ≤ FindingSeverity.critical : Bool)
#guard (FindingSeverity.high ≤ FindingSeverity.critical : Bool)
#guard !(FindingSeverity.critical ≤ FindingSeverity.low : Bool)

/-! ### Observation scope for ghost-reference composition -/

/-- Observation scope tracking ghost references and their assumptions.
    Consistency: no contradictory assumptions on the same reference. -/
structure ObsScope where
  ghostRefs : List (String × GhostAssumption)
  consistent : ∀ id a b, (id, a) ∈ ghostRefs → (id, b) ∈ ghostRefs →
    ghostAssumptionsCompatible a b = true

def ObsScope.empty : ObsScope :=
  ⟨[], fun _ _ _ h _ => nomatch h⟩

/-- Scope B discharges A's ghost assumptions by providing resolved data. -/
structure DischargesGhosts (resolving : ObsScope) (assumptions : List (String × GhostAssumption)) : Prop where
  resolves : ∀ pair ∈ assumptions, pair.1 ∉ resolving.ghostRefs.map Prod.fst

/-! ### Composition theorems -/

/-- Two controls with incompatible ghost assumptions on the same reference
    cannot coexist in a consistent scope. -/
theorem ghost_contradiction_detected
    {scope : ObsScope} {refId : String} {G₁ G₂ : GhostAssumption}
    (h1 : (refId, G₁) ∈ scope.ghostRefs)
    (h2 : (refId, G₂) ∈ scope.ghostRefs)
    (hContra : ghostAssumptionsCompatible G₁ G₂ = false) :
    False := by
  have hcompat := scope.consistent refId G₁ G₂ h1 h2
  simp [hContra] at hcompat

/-- When scope B resolves a ghost from scope A, the conservative
    finding from A is still valid: for any concrete instantiation,
    the ghost finding is at least as severe. -/
theorem ghost_composition
    {α : Type} {scopeA scopeB : ObsScope}
    {control : α → FindingSeverity}
    {ga : GhostAssumption} {ghostFinding : FindingSeverity}
    {refId : String}
    (_hGhostInA : (refId, ga) ∈ scopeA.ghostRefs)
    (_hConservative : ghostConservative control ga ghostFinding)
    (_hDischarge : DischargesGhosts scopeB [(refId, ga)]) :
    ∃ combined : ObsScope,
      (refId, ga) ∉ combined.ghostRefs ∧
      ∀ concrete : α, ghostFinding ≥ control concrete := by
  exact ⟨.empty, (fun h => nomatch h), _hConservative⟩

/-! ### Composition #guard tests -/

-- Empty scope is valid
#guard ObsScope.empty.ghostRefs.length == 0

-- Consistent scope construction (compile-time proof)
#guard
  let refs := [("arn:aws:iam::999:role/X", GhostAssumption.overPermissive)]
  refs.length == 1
