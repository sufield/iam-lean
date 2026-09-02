import Seclib.Prim

/-! Vendor-neutral policy evaluation: deny-overrides semantics.

All definitions and theorems are parameterized over a PolicySem
instance. No cloud provider, ARN, IAM, or vendor-specific concept
appears in this module. -/

structure PolicySem (S R Ctx : Type) where
  effect         : S → Effect
  sat            : S → R → Bool
  condEval       : Ctx → S → Tri
  noCtx          : Ctx
  cond_noCtx_tu  : ∀ s, condEval noCtx s = .t ∨ condEval noCtx s = .u
  cond_noCtx_T_imp : ∀ s ctx, condEval noCtx s = .t → condEval ctx s = .t

namespace Domain

def denyOverrides (sem : PolicySem S R Ctx) (stmts : List S) (req : R) (ctx : Ctx) : Bool :=
  let denied := stmts.any fun s =>
    sem.effect s == .deny && sem.sat s req && decide (sem.condEval ctx s = .t)
  if denied then false
  else stmts.any fun s =>
    sem.effect s == .allow && sem.sat s req && !decide (sem.condEval ctx s = .f)

/-! Structural lemmas -/

private theorem deny_any_iff (sem : PolicySem S R Ctx) (stmts : List S) (req : R) (ctx : Ctx) :
    (stmts.any fun s => sem.effect s == .deny && sem.sat s req &&
      decide (sem.condEval ctx s = .t)) = true ↔
    ∃ s ∈ stmts, sem.effect s = .deny ∧ sem.sat s req = true ∧
      sem.condEval ctx s = .t := by
  simp [List.any_eq_true, Bool.and_eq_true, and_assoc, decide_eq_true_eq, beq_iff_eq]

private theorem allow_any_iff (sem : PolicySem S R Ctx) (stmts : List S) (req : R) (ctx : Ctx) :
    (stmts.any fun s => sem.effect s == .allow && sem.sat s req &&
      !decide (sem.condEval ctx s = .f)) = true ↔
    ∃ s ∈ stmts, sem.effect s = .allow ∧ sem.sat s req = true ∧
      sem.condEval ctx s ≠ .f := by
  simp [List.any_eq_true, Bool.and_eq_true, and_assoc, beq_iff_eq, decide_eq_false_iff_not]

private theorem mem_eraseIdx_of_ne {l : List S} {x : S} {i : Nat}
    (hx : x ∈ l) (hne : ∀ (hi : i < l.length), x ≠ l[i]) : x ∈ l.eraseIdx i := by
  induction l generalizing i with
  | nil => cases hx
  | cons a l ih =>
    cases i with
    | zero =>
      simp [List.eraseIdx]
      cases hx with
      | head => exact absurd rfl (hne (by simp))
      | tail _ h => exact h
    | succ i =>
      simp [List.eraseIdx]
      cases hx with
      | head => left; rfl
      | tail _ h =>
        right; apply ih h
        intro hi heq
        exact hne (by simp; omega) heq

/-! removeAllow: removing an Allow statement narrows access -/

theorem removeAllow (sem : PolicySem S R Ctx) (stmts : List S) (i : Nat)
    (hi : i < stmts.length) (heff : sem.effect (stmts[i]'hi) = .allow)
    (req : R) (ctx : Ctx)
    (h : denyOverrides sem (stmts.eraseIdx i) req ctx = true) :
    denyOverrides sem stmts req ctx = true := by
  unfold denyOverrides at *
  simp only [] at *
  by_cases hDenyFull : (stmts.any fun s =>
      sem.effect s == .deny && sem.sat s req &&
      decide (sem.condEval ctx s = .t)) = true
  · rw [deny_any_iff] at hDenyFull
    obtain ⟨s, hs, hsd, hsm, hsc⟩ := hDenyFull
    have hne : ∀ (hi' : i < stmts.length), s ≠ stmts[i]'hi' := by
      intro hi' heq; rw [heq] at hsd; rw [heff] at hsd; exact absurd hsd (by decide)
    have hsMem : s ∈ stmts.eraseIdx i := mem_eraseIdx_of_ne hs hne
    have hDenyErased : ((stmts.eraseIdx i).any fun s =>
        sem.effect s == .deny && sem.sat s req &&
        decide (sem.condEval ctx s = .t)) = true := by
      rw [deny_any_iff]; exact ⟨s, hsMem, hsd, hsm, hsc⟩
    rw [if_pos hDenyErased] at h
    exact absurd h (by decide)
  · rw [if_neg hDenyFull]
    have hNoDenyErased : ¬((stmts.eraseIdx i).any fun s =>
        sem.effect s == .deny && sem.sat s req &&
        decide (sem.condEval ctx s = .t)) = true := by
      intro hc; apply hDenyFull
      rw [deny_any_iff] at hc ⊢
      obtain ⟨s, hs, hsd, hsm, hsc⟩ := hc
      exact ⟨s, List.eraseIdx_subset hs, hsd, hsm, hsc⟩
    rw [if_neg hNoDenyErased] at h
    rw [allow_any_iff] at h ⊢
    obtain ⟨s, hs, hsa, hsm, hsc⟩ := h
    exact ⟨s, List.eraseIdx_subset hs, hsa, hsm, hsc⟩

/-! narrow_narrows: replacing a statement with one that matches fewer
    requests narrows access. Unifies narrowActions and narrowResources. -/

theorem narrow_narrows (sem : PolicySem S R Ctx)
    (stmts : List S) (i : Nat) (hi : i < stmts.length)
    (heff : sem.effect (stmts[i]) = .allow)
    (new_s : S) (hnew_eff : sem.effect new_s = .allow)
    (hnew_cond : ∀ c, sem.condEval c new_s = sem.condEval c (stmts[i]))
    (hmono : ∀ req, sem.sat new_s req = true → sem.sat (stmts[i]) req = true)
    (req : R) (ctx : Ctx)
    (h : denyOverrides sem (stmts.set i new_s) req ctx = true) :
    denyOverrides sem stmts req ctx = true := by
  unfold denyOverrides at *
  simp only [] at *
  have deny_inv : ((stmts.set i new_s).any fun s => sem.effect s == .deny && sem.sat s req &&
      decide (sem.condEval ctx s = .t)) =
      (stmts.any fun s => sem.effect s == .deny && sem.sat s req &&
        decide (sem.condEval ctx s = .t)) := by
    apply Bool.eq_iff_iff.mpr
    rw [deny_any_iff, deny_any_iff]
    constructor
    · rintro ⟨s, hs_mem, hs_deny, hs_match, hs_cond⟩
      rcases List.mem_or_eq_of_mem_set hs_mem with hs_orig | hs_eq
      · exact ⟨s, hs_orig, hs_deny, hs_match, hs_cond⟩
      · subst hs_eq; rw [hnew_eff] at hs_deny; exact absurd hs_deny (by decide)
    · rintro ⟨s, hs_mem, hs_deny, hs_match, hs_cond⟩
      refine ⟨s, ?_, hs_deny, hs_match, hs_cond⟩
      have hne : s ≠ stmts[i] := by
        intro heq; rw [heq, heff] at hs_deny; exact absurd hs_deny (by decide)
      obtain ⟨k, hk, hsk⟩ := List.mem_iff_getElem.mp hs_mem
      have hkj : k ≠ i := by intro heq; subst heq; exact hne hsk.symm
      rw [List.mem_iff_getElem]
      exact ⟨k, by rw [List.length_set]; exact hk,
             by rw [List.getElem_set (by rw [List.length_set]; exact hk), if_neg (Ne.symm hkj)]; exact hsk⟩
  rw [deny_inv] at h
  by_cases hDeny : (stmts.any fun s => sem.effect s == .deny && sem.sat s req &&
      decide (sem.condEval ctx s = .t)) = true
  · rw [if_pos hDeny] at h; exact absurd h (by decide)
  · rw [if_neg hDeny] at *
    rw [allow_any_iff] at h ⊢
    obtain ⟨s, hs_mem, hs_allow, hs_match, hs_cond⟩ := h
    rcases List.mem_or_eq_of_mem_set hs_mem with hs_orig | hs_new
    · exact ⟨s, hs_orig, hs_allow, hs_match, hs_cond⟩
    · subst hs_new
      refine ⟨stmts[i], List.getElem_mem hi, heff, hmono req hs_match, ?_⟩
      rw [hnew_cond] at hs_cond; exact hs_cond

/-! filterMap_narrows: filterMap with effect-preserving, match-monotone
    transform narrows access -/

private theorem deny_forward (sem : PolicySem S R Ctx) (stmts : List S)
    (f : S → Option S) (req : R) (ctx : Ctx)
    (h_deny : ∀ s ∈ stmts, sem.effect s = .deny → f s = some s)
    (h : (stmts.any fun s => sem.effect s == .deny && sem.sat s req &&
      decide (sem.condEval ctx s = .t)) = true) :
    ((stmts.filterMap f).any fun s => sem.effect s == .deny && sem.sat s req &&
      decide (sem.condEval ctx s = .t)) = true := by
  rw [deny_any_iff] at h ⊢
  obtain ⟨d, hd_mem, hd_deny, hd_match, hd_cond⟩ := h
  exact ⟨d, List.mem_filterMap.mpr ⟨d, hd_mem, h_deny d hd_mem hd_deny⟩, hd_deny, hd_match, hd_cond⟩

private theorem allow_backward (sem : PolicySem S R Ctx) (stmts : List S)
    (f : S → Option S) (req : R) (ctx : Ctx)
    (h_deny : ∀ s ∈ stmts, sem.effect s = .deny → f s = some s)
    (h_mono : ∀ s s', s ∈ stmts → f s = some s' → sem.effect s = .allow →
      sem.effect s' = .allow ∧ (∀ c, sem.condEval c s' = sem.condEval c s) ∧
      (∀ r, sem.sat s' r = true → sem.sat s r = true))
    (h : ((stmts.filterMap f).any fun s => sem.effect s == .allow && sem.sat s req &&
      !decide (sem.condEval ctx s = .f)) = true) :
    (stmts.any fun s => sem.effect s == .allow && sem.sat s req &&
      !decide (sem.condEval ctx s = .f)) = true := by
  rw [allow_any_iff] at h ⊢
  obtain ⟨s', hs'_mem, hs'_allow, hs'_match, hs'_cond⟩ := h
  rw [List.mem_filterMap] at hs'_mem
  obtain ⟨s, hs_mem, hfs⟩ := hs'_mem
  by_cases hs_eff : sem.effect s = .deny
  · have := h_deny s hs_mem hs_eff; rw [hfs] at this
    cases this; rw [hs_eff] at hs'_allow; exact absurd hs'_allow (by decide)
  · have hs_allow : sem.effect s = .allow := by
      cases he : sem.effect s with | allow => rfl | deny => exact absurd he hs_eff
    obtain ⟨_, hs'_cond_eq, hs'_mono⟩ := h_mono s s' hs_mem hfs hs_allow
    refine ⟨s, hs_mem, hs_allow, hs'_mono req hs'_match, ?_⟩
    rw [hs'_cond_eq ctx] at hs'_cond; exact hs'_cond

theorem filterMap_narrows (sem : PolicySem S R Ctx)
    (stmts : List S) (f : S → Option S) (req : R) (ctx : Ctx)
    (h_deny : ∀ s ∈ stmts, sem.effect s = .deny → f s = some s)
    (h_mono : ∀ s s', s ∈ stmts → f s = some s' → sem.effect s = .allow →
      sem.effect s' = .allow ∧ (∀ c, sem.condEval c s' = sem.condEval c s) ∧
      (∀ r, sem.sat s' r = true → sem.sat s r = true))
    (h : denyOverrides sem (stmts.filterMap f) req ctx = true) :
    denyOverrides sem stmts req ctx = true := by
  unfold denyOverrides at h ⊢
  simp only [] at h ⊢
  by_cases hdf : ((stmts.filterMap f).any fun s => sem.effect s == .deny && sem.sat s req &&
      decide (sem.condEval ctx s = .t)) = true
  · rw [if_pos hdf] at h; exact absurd h (by decide)
  · rw [if_neg hdf] at h
    rw [if_neg (fun hc => hdf (deny_forward sem stmts f req ctx h_deny hc))]
    exact allow_backward sem stmts f req ctx h_deny h_mono h

/-! nocontext_conservative: if allowed under any context, allowed under noCtx -/

theorem nocontext_conservative (sem : PolicySem S R Ctx)
    (stmts : List S) (req : R) (ctx : Ctx)
    (h : denyOverrides sem stmts req ctx = true) :
    denyOverrides sem stmts req sem.noCtx = true := by
  unfold denyOverrides at *
  simp only [] at *
  have hNoDenyNoCtx : ¬(stmts.any fun s =>
      sem.effect s == .deny && sem.sat s req &&
      decide (sem.condEval sem.noCtx s = .t)) = true := by
    intro hc
    rw [deny_any_iff] at hc
    obtain ⟨s, hs, hsd, hsm, hcond⟩ := hc
    have hCtxT := sem.cond_noCtx_T_imp s ctx hcond
    have hDenyCtx : (stmts.any fun s' =>
        sem.effect s' == .deny && sem.sat s' req &&
        decide (sem.condEval ctx s' = .t)) = true := by
      rw [deny_any_iff]; exact ⟨s, hs, hsd, hsm, hCtxT⟩
    rw [if_pos hDenyCtx] at h
    exact absurd h (by decide)
  rw [if_neg hNoDenyNoCtx]
  by_cases hDeny : (stmts.any fun s =>
      sem.effect s == .deny && sem.sat s req &&
      decide (sem.condEval ctx s = .t)) = true
  · rw [if_pos hDeny] at h; exact absurd h (by decide)
  · rw [if_neg hDeny] at h
    rw [allow_any_iff] at h ⊢
    obtain ⟨s, hs, heff, hmatch, _⟩ := h
    refine ⟨s, hs, heff, hmatch, ?_⟩
    rcases sem.cond_noCtx_tu s with h_t | h_u
    · rw [h_t]; decide
    · rw [h_u]; decide

/-! grants_complete: if allowed, an Allow statement exists that matches -/

theorem grants_complete (sem : PolicySem S R Ctx)
    (stmts : List S) (req : R) (ctx : Ctx)
    (h : denyOverrides sem stmts req ctx = true) :
    ∃ s ∈ stmts, sem.effect s = .allow ∧ sem.sat s req = true
        ∧ sem.condEval ctx s ≠ .f := by
  unfold denyOverrides at h
  by_cases hd : (stmts.any fun s =>
      sem.effect s == .deny && sem.sat s req &&
      decide (sem.condEval ctx s = .t)) = true
  · rw [if_pos hd] at h; exact absurd h (by decide)
  · rw [if_neg hd] at h
    rw [allow_any_iff] at h
    exact h

end Domain
