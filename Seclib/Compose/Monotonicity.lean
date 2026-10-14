import Seclib.Compose.Compose

/-! Monotonicity: adding a finding never reduces the set of firing chains.
Go source: chain_engine.go — a new failure only adds to buckets. -/

private theorem countP_mono_pred {p q : α → Bool} (l : List α)
    (h : ∀ x, p x = true → q x = true) :
    l.countP p ≤ l.countP q := by
  induction l with
  | nil => exact Nat.le.refl
  | cons a rest ih =>
    simp only [List.countP_cons]
    split
    · rename_i hp
      have hq := h a hp; rw [hq]; simp only [ite_true]; omega
    · rename_i hp
      split
      · omega
      · exact ih

theorem failingCount_mono (chain : ChainDef) (s t : List ControlId) :
    failingCount chain s ≤ failingCount chain (s ++ t) := by
  unfold failingCount
  apply countP_mono_pred
  intro x hx
  simp only [decide_eq_true_eq] at *
  exact List.mem_append_left t hx

theorem chainFires_mono (chain : ChainDef) (s t : List ControlId)
    (h : chainFires chain s) : chainFires chain (s ++ t) := by
  unfold chainFires at *
  have := failingCount_mono chain s t
  omega

theorem chainFires_add_one (chain : ChainDef) (s : List ControlId) (f : ControlId)
    (h : chainFires chain s) : chainFires chain (s ++ [f]) :=
  chainFires_mono chain s [f] h

/-- Set-level monotonicity: the set of firing chains never shrinks
    when the failing set grows. Every chain that fires on s also
    fires on s ++ t.
    This is the deliverable-4 property from the LEAN4-COMPOSE spec. -/
theorem firingSet_mono (chains : List ChainDef) (s t : List ControlId) :
    ∀ chain, chain ∈ chains → chainFires chain s → chainFires chain (s ++ t) :=
  fun chain _ h => chainFires_mono chain s t h

/-- failingCount is bounded by the chain's control count. -/
theorem failingCount_le_length (chain : ChainDef) (failing : List ControlId) :
    failingCount chain failing ≤ chain.controls.length := by
  unfold failingCount
  exact List.countP_le_length
