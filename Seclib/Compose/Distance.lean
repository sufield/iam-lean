import Seclib.Compose.Monotonicity

/-! Distance metric: how far is a chain from firing?
Go source: finding_risk.go:11-24, chain_engine.go:432 -/

def chainDistance (chain : ChainDef) (failing : List ControlId) : Nat :=
  chain.threshold - failingCount chain failing

def classify (chain : ChainDef) (failing : List ControlId) : Exploitability :=
  match chainDistance chain failing with
  | 0 => .exploitable
  | 1 => .oneAway
  | _ + 2 => .reachable

theorem classify_exploitable_of_fires (chain : ChainDef) (failing : List ControlId)
    (h : chainFires chain failing) :
    classify chain failing = .exploitable := by
  simp only [classify, chainFires, chainDistance] at *
  have : chain.threshold - failingCount chain failing = 0 := by omega
  rw [this]

theorem fires_of_classify_exploitable (chain : ChainDef) (failing : List ControlId)
    (h : classify chain failing = .exploitable) :
    chainFires chain failing := by
  simp only [classify, chainDistance] at h
  unfold chainFires
  split at h <;> simp_all
  all_goals omega

def isNearMiss (chain : ChainDef) (failing : List ControlId) : Prop :=
  chainDistance chain failing = 1 ∧ failingCount chain failing > 0

instance (chain : ChainDef) (failing : List ControlId) :
    Decidable (isNearMiss chain failing) :=
  inferInstanceAs (Decidable (_ = _ ∧ _ > _))

theorem no_nearMiss_threshold_one (chain : ChainDef) (failing : List ControlId)
    (hT : chain.threshold = 1) :
    ¬ isNearMiss chain failing := by
  simp only [isNearMiss, chainDistance, hT]
  omega

theorem chainDistance_mono (chain : ChainDef) (s t : List ControlId) :
    chainDistance chain (s ++ t) ≤ chainDistance chain s := by
  unfold chainDistance
  have := failingCount_mono chain s t
  omega

/-- Exploitability order: exploitable < oneAway < reachable.
    "Closer to firing" = lower value. -/
def Exploitability.rank : Exploitability → Nat
  | .exploitable => 0
  | .oneAway => 1
  | .reachable => 2

/-- Adding failures can only move exploitability toward exploitable
    (never away from it). Proved via the underlying distance metric. -/
theorem classify_mono_via_distance (chain : ChainDef) (s t : List ControlId)
    (h : classify chain s = .exploitable) :
    classify chain (s ++ t) = .exploitable := by
  have hf := fires_of_classify_exploitable chain s h
  exact classify_exploitable_of_fires chain (s ++ t) (chainFires_mono chain s t hf)
