import Seclib.Prim

/-! Vendor-neutral authorization primitives: Rule, appliesOf, denyOverrides.
No cloud provider noun appears in this module. -/

structure Rule where
  decision      : Effect
  applicability : Tri
  sat           : Bool

def appliesOf : Effect → Tri → Bool
  | .deny, .t => true
  | .deny, _ => false
  | .allow, .f => false
  | .allow, _ => true

def denyOverridesRules (rules : List Rule) : Bool :=
  if rules.any fun r => r.decision == .deny && r.sat && appliesOf r.decision r.applicability
  then false
  else rules.any fun r => r.decision == .allow && r.sat && appliesOf r.decision r.applicability

/-! Structural helpers -/

private theorem deny_any_rules_iff (rules : List Rule) :
    (rules.any fun r => r.decision == .deny && r.sat && appliesOf r.decision r.applicability) = true ↔
    ∃ r ∈ rules, r.decision = .deny ∧ r.sat = true ∧ appliesOf r.decision r.applicability = true := by
  simp [List.any_eq_true, Bool.and_eq_true, beq_iff_eq, and_assoc]

private theorem allow_any_rules_iff (rules : List Rule) :
    (rules.any fun r => r.decision == .allow && r.sat && appliesOf r.decision r.applicability) = true ↔
    ∃ r ∈ rules, r.decision = .allow ∧ r.sat = true ∧ appliesOf r.decision r.applicability = true := by
  simp [List.any_eq_true, Bool.and_eq_true, beq_iff_eq, and_assoc]

private theorem mem_eraseIdx_of_mem_ne {l : List α} {r : α} {i : Nat}
    (hr : r ∈ l) (hi : i < l.length) (hne : r ≠ l[i]) :
    r ∈ l.eraseIdx i := by
  induction l generalizing i with
  | nil => cases hr
  | cons a rest ih =>
    cases i with
    | zero =>
      simp only [List.eraseIdx_cons_zero]
      cases hr with
      | head => exact absurd rfl hne
      | tail _ h => exact h
    | succ j =>
      simp only [List.eraseIdx_cons_succ]
      cases hr with
      | head => exact .head ..
      | tail _ h =>
        exact .tail _ (ih h (by simp [List.length_cons] at hi; omega) (by
          simp only [List.getElem_cons_succ] at hne; exact hne))

/-! Lemma 1: Removing an allow rule narrows access -/

theorem denyOverrides_remove_allow_narrows (rules : List Rule) (i : Nat)
    (hi : i < rules.length) (hallow : (rules[i]).decision = .allow)
    (h : denyOverridesRules (rules.eraseIdx i) = true) :
    denyOverridesRules rules = true := by
  unfold denyOverridesRules at *
  by_cases hd : (rules.any fun r => r.decision == .deny && r.sat &&
      appliesOf r.decision r.applicability) = true
  · rw [deny_any_rules_iff] at hd
    obtain ⟨r, hr, hrd, hrm, hra⟩ := hd
    have hne : r ≠ rules[i] := by
      intro heq; rw [heq, hallow] at hrd; exact absurd hrd (by decide)
    have hr' : r ∈ rules.eraseIdx i := mem_eraseIdx_of_mem_ne hr hi hne
    have hde : ((rules.eraseIdx i).any fun r => r.decision == .deny && r.sat &&
        appliesOf r.decision r.applicability) = true := by
      rw [deny_any_rules_iff]; exact ⟨r, hr', hrd, hrm, hra⟩
    rw [if_pos hde] at h; exact absurd h (by decide)
  · rw [if_neg hd]
    have hde : ¬((rules.eraseIdx i).any fun r => r.decision == .deny && r.sat &&
        appliesOf r.decision r.applicability) = true := by
      intro hc; apply hd; rw [deny_any_rules_iff] at hc ⊢
      obtain ⟨r, hr, hrd, hrm, hra⟩ := hc
      exact ⟨r, List.eraseIdx_subset hr, hrd, hrm, hra⟩
    rw [if_neg hde] at h
    rw [allow_any_rules_iff] at h ⊢
    obtain ⟨r, hr, hra, hrm, hrap⟩ := h
    exact ⟨r, List.eraseIdx_subset hr, hra, hrm, hrap⟩

/-! Lemma 2: Adding a deny narrows -/

theorem denyOverrides_add_deny_narrows (rules : List Rule) (i : Nat)
    (hi : i < rules.length) (hdeny : (rules[i]).decision = .deny)
    (h : denyOverridesRules rules = true) :
    denyOverridesRules (rules.eraseIdx i) = true := by
  unfold denyOverridesRules at *
  by_cases hd : (rules.any fun r => r.decision == .deny && r.sat &&
      appliesOf r.decision r.applicability) = true
  · rw [if_pos hd] at h; exact absurd h (by decide)
  · rw [if_neg hd] at h
    have hde : ¬((rules.eraseIdx i).any fun r => r.decision == .deny && r.sat &&
        appliesOf r.decision r.applicability) = true := by
      intro hc; apply hd; rw [deny_any_rules_iff] at hc ⊢
      obtain ⟨r, hr, hrd, hrm, hra⟩ := hc
      exact ⟨r, List.eraseIdx_subset hr, hrd, hrm, hra⟩
    rw [if_neg hde]
    rw [allow_any_rules_iff] at h ⊢
    obtain ⟨r, hr, hra, hrm, hrap⟩ := h
    have hne : r ≠ rules[i] := by
      intro heq; rw [heq, hdeny] at hra; exact absurd hra (by decide)
    exact ⟨r, mem_eraseIdx_of_mem_ne hr hi hne, hra, hrm, hrap⟩

/-! Lemma 3: Conjunction of evaluation gates never widens access -/

theorem conj_narrows (a b : Bool) (h : a && b = true) : a = true ∧ b = true := by
  simp [Bool.and_eq_true] at h; exact h

/-! Lemma 4: Unknown applicability is conservative -/

theorem appliesOf_unknown_conservative (rules rules_noCtx : List Rule)
    (hlen : rules.length = rules_noCtx.length)
    (hpair : ∀ j (hj : j < rules.length),
      (rules_noCtx[j]'(hlen ▸ hj)).decision = (rules[j]).decision ∧
      (rules_noCtx[j]'(hlen ▸ hj)).sat = (rules[j]).sat ∧
      ((rules_noCtx[j]'(hlen ▸ hj)).applicability = .t ∨
       (rules_noCtx[j]'(hlen ▸ hj)).applicability = .u) ∧
      ((rules_noCtx[j]'(hlen ▸ hj)).applicability = .t →
       (rules[j]).applicability = .t))
    (h : denyOverridesRules rules = true) :
    denyOverridesRules rules_noCtx = true := by
  unfold denyOverridesRules at *
  have hNoDenyNoCtx : ¬(rules_noCtx.any fun r => r.decision == .deny && r.sat &&
      appliesOf r.decision r.applicability) = true := by
    intro hc
    rw [deny_any_rules_iff] at hc
    obtain ⟨r, hr_mem, hrd, hrm, hra⟩ := hc
    obtain ⟨k, hk, hrk⟩ := List.mem_iff_getElem.mp hr_mem
    have hk' : k < rules.length := hlen ▸ hk
    obtain ⟨hdec, hsat, _, htrans⟩ := hpair k hk'
    simp only [hrk] at hdec hsat htrans
    have hat : r.applicability = .t := by
      cases h_app : r.applicability
      · rfl
      all_goals (rw [hrd, h_app] at hra; simp [appliesOf] at hra)
    have hctx_t := htrans hat
    have hDeny : (rules.any fun r' => r'.decision == .deny && r'.sat &&
        appliesOf r'.decision r'.applicability) = true := by
      rw [deny_any_rules_iff]
      exact ⟨rules[k], List.getElem_mem hk', by rw [← hdec, hrd],
             by rw [← hsat, hrm], by rw [← hdec, hrd, hctx_t]; rfl⟩
    rw [if_pos hDeny] at h; exact absurd h (by decide)
  rw [if_neg hNoDenyNoCtx]
  by_cases hDeny : (rules.any fun r => r.decision == .deny && r.sat &&
      appliesOf r.decision r.applicability) = true
  · rw [if_pos hDeny] at h; exact absurd h (by decide)
  · rw [if_neg hDeny] at h
    rw [allow_any_rules_iff] at h ⊢
    obtain ⟨r, hr_mem, hra, hrm, hrap⟩ := h
    obtain ⟨k, hk, hrk⟩ := List.mem_iff_getElem.mp hr_mem
    have hk' : k < rules_noCtx.length := hlen ▸ hk
    obtain ⟨hdec, hsat, htu, _⟩ := hpair k hk
    simp only [hrk] at hdec hsat
    refine ⟨rules_noCtx[k], List.getElem_mem hk', ?_, ?_, ?_⟩
    · rw [hdec, hra]
    · rw [hsat, hrm]
    · rw [hdec, hra]
      rcases htu with ht | hu
      · rw [ht]; rfl
      · rw [hu]; rfl
