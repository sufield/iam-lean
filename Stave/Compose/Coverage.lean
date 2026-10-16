import Stave.Compose.Compose

/-! Coverage claims: if all controls pass, chains cannot fire.
Go source: chain_engine.go:64-147 (DetectChains). -/

theorem allPass_no_fire (chain : ChainDef) (failing : List ControlId)
    (h : ∀ c, c ∈ chain.controls → c ∉ failing) :
    ¬ chainFires chain failing := by
  unfold chainFires failingCount
  have hzero : chain.controls.countP (· ∈ failing) = 0 := by
    apply List.countP_eq_zero.mpr
    intro x hx
    simp only [decide_eq_true_eq]
    exact h x hx
  have := chain.hThreshPos
  omega

theorem empty_failing_no_fire (chain : ChainDef) :
    ¬ chainFires chain [] := by
  apply allPass_no_fire
  intro _ _ hc
  exact absurd hc (by simp)

theorem coverage_soundness (chains : List ChainDef) (failing : List ControlId)
    (h : ∀ chain, chain ∈ chains →
      ∀ c, c ∈ chain.controls → c ∉ failing) :
    ∀ chain, chain ∈ chains → ¬ chainFires chain failing :=
  fun chain hc => allPass_no_fire chain failing (h chain hc)
