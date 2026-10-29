import Stave.Evaluate.Eval
import Stave.Compose.Monotonicity
import Stave.Compose.Coverage

/-! Phase 1 safety properties -- zero sorry.

P1. Fail-closed soundness
P2. Evaluation determinism
P3. Monotonicity (more observations -> more findings)
P4. Chain composition soundness (atomic findings -> chain fires)
P5. Ghost conservatism -- see Stave.Ghost (already proved) -/

/-! ### P1: Fail-closed soundness
If a control's predicate cannot be evaluated (returns unevaluable),
the finding fires. This is Stave's default-deny analog. -/

theorem fail_closed (outcome : EvalOutcome) (h : outcome = .unevaluable) :
    outcome.fires = true := by
  subst h; rfl

theorem fail_closed_eval (obs : Observation) (ctrl : ControlDef)
    (h : evalControl obs ctrl = .unevaluable) :
    (evalControl obs ctrl).fires = true := by
  rw [h]; rfl

theorem fail_closed_predicate (obs : Observation) (pred : UnsafePredicate)
    (h : evalPredicate obs pred = .unevaluable) :
    (evalPredicate obs pred).fires = true := by
  rw [h]; rfl

/-- Empty predicate always fires -- no predicate means no evidence of safety. -/
theorem empty_predicate_fires (obs : Observation) (pred : UnsafePredicate)
    (h : pred.isEmpty = true) :
    (evalPredicate obs pred).fires = true := by
  unfold evalPredicate
  simp [h, EvalOutcome.fires]

/-- An unsafe outcome fires. -/
theorem unsafe_fires : EvalOutcome.fires EvalOutcome.«unsafe» = true := by rfl

/-- A clear outcome does not fire. -/
theorem clear_does_not_fire : EvalOutcome.fires EvalOutcome.clear = false := by rfl

/-! ### P2: Evaluation determinism
Same observation + same control -> same result. This is trivially true
for pure functions in Lean -- stated explicitly to match the blueprint. -/

theorem eval_deterministic (obs : Observation) (ctrl : ControlDef) :
    evalControl obs ctrl = evalControl obs ctrl := rfl

/-- Stronger form: evaluation depends only on the observation and
    the control definition, not on any external state. -/
theorem eval_functional (obs1 obs2 : Observation) (ctrl1 ctrl2 : ControlDef)
    (hObs : obs1 = obs2) (hCtrl : ctrl1 = ctrl2) :
    evalControl obs1 ctrl1 = evalControl obs2 ctrl2 := by
  subst hObs; subst hCtrl; rfl

/-! ### P3: Monotonicity -- more observations, more findings
Adding an observation to a set never removes a finding. -/

/-- findings from evalObservationSet over a concatenated set contains
    all findings from the original set. -/
theorem evalObservationSet_mono (obss : ObservationSet) (extra : ObservationSet)
    (cat : Catalog) :
    forall pair, pair ∈ evalObservationSet obss cat ->
      pair ∈ evalObservationSet (obss ++ extra) cat := by
  intro pair h
  unfold evalObservationSet at *
  simp only [List.flatMap_append, List.mem_append]
  exact Or.inl h

/-- Corollary: the finding count never decreases when observations are added. -/
theorem finding_count_mono (obss extra : ObservationSet) (cat : Catalog) :
    (evalObservationSet obss cat).length <=
    (evalObservationSet (obss ++ extra) cat).length := by
  unfold evalObservationSet
  simp only [List.flatMap_append, List.length_append]
  omega

/-! ### P4: Chain composition soundness
If all atomic controls in a chain fire, the chain fires.
Connects the evaluator (findings) to the chain engine (chainFires). -/

/-- If every control in a chain appears in the failing set,
    the chain fires. -/
theorem chain_fires_when_all_fail (chain : ChainDef) (failing : List ControlId)
    (h : forall c, c ∈ chain.controls -> c ∈ failing) :
    chainFires chain failing := by
  unfold chainFires failingCount
  have hcount : chain.controls.countP (· ∈ failing) = chain.controls.length := by
    apply List.countP_eq_length.mpr
    intro x hx
    simp only [decide_eq_true_eq]
    exact h x hx
  have := chain.hThreshBound
  omega

/-- Helper: if a list has an element that doesn't satisfy p,
    countP p is strictly less than length. -/
private theorem countP_lt_of_mem_neg {α : Type} {p : α -> Bool} {l : List α}
    (x : α) (hx : x ∈ l) (hp : p x = false) :
    l.countP p < l.length := by
  induction l with
  | nil => simp at hx
  | cons a rest ih =>
    simp only [List.countP_cons, List.length_cons]
    cases List.mem_cons.mp hx with
    | inl heq =>
      subst heq; simp [hp]
      exact Nat.lt_succ_of_le (List.countP_le_length)
    | inr hmem =>
      have := ih hmem
      split <;> omega

/-- Converse: if a required control does NOT fail, and the chain's
    threshold equals its control count (all-required), the chain
    does not fire. -/
theorem chain_silent_when_one_holds (chain : ChainDef) (failing : List ControlId)
    (hThresh : chain.threshold = chain.controls.length)
    (c : ControlId) (hc : c ∈ chain.controls) (hNotFail : c ∉ failing) :
    ¬chainFires chain failing := by
  unfold chainFires failingCount
  have hlt : chain.controls.countP (· ∈ failing) < chain.controls.length := by
    apply countP_lt_of_mem_neg c hc
    simp only [decide_eq_false_iff_not]
    exact hNotFail
  omega

/-- Bridge: evaluation findings feed chain detection. -/
theorem findings_feed_chains (obs : Observation) (cat : Catalog)
    (obss : ObservationSet) (hMem : obs ∈ obss) :
    forall cid, cid ∈ findings obs cat ->
      (obs.assetId, cid) ∈ evalObservationSet obss cat := by
  intro cid hFind
  unfold evalObservationSet
  simp only [List.mem_flatMap]
  exact ⟨obs, hMem, by simp only [List.mem_map]; exact ⟨cid, hFind, rfl⟩⟩

/-! ### Composing P3 + P4: end-to-end monotonicity
Adding an observation never un-fires a chain. -/

/-- If a chain fires given findings from obss, it still fires
    given findings from obss ++ extra. -/
theorem end_to_end_mono (chain : ChainDef) (obss extra : ObservationSet)
    (cat : Catalog)
    (failingFrom : ObservationSet -> List ControlId)
    (hFailing : forall s, failingFrom s = (evalObservationSet s cat).map (fun p => p.2))
    (hFires : chainFires chain (failingFrom obss)) :
    chainFires chain (failingFrom (obss ++ extra)) := by
  rw [hFailing] at hFires ⊢
  unfold evalObservationSet at *
  simp only [List.flatMap_append, List.map_append]
  exact chainFires_mono chain _ _ hFires
