import IamExplainer.Emit
import IamExplainer.Layers

open Lean (Json)

/-! Soundness theorems: policy transforms (T1-T3) and emitFixed
can only narrow access, never grant new permissions. All theorems
are universally quantified over the condition context. -/

def Policy.removeStmt (p : Policy) (i : Nat) : Policy :=
  { p with statements := p.statements.eraseIdx i }

def iamSem : PolicySem Statement Request CondContext where
  effect   := Statement.effect
  sat      := stmtMatches
  condEval := fun ctx s => (evalCond ctx s.condBlocks).1
  noCtx    := noContext
  cond_noCtx_tu := fun s => evalCond_noContext_tu s.condBlocks
  cond_noCtx_T_imp := fun s ctx h => evalCond_noContext_T_imp s.condBlocks ctx h

private theorem cond_bridge (s₁ s₂ : Statement) (h : s₁.condition = s₂.condition) :
    ∀ c, iamSem.condEval c s₁ = iamSem.condEval c s₂ := by
  intro c; show (evalCond c s₁.condBlocks).1 = (evalCond c s₂.condBlocks).1
  unfold Statement.condBlocks; rw [h]

theorem removeAllow_narrows (p : Policy) (i : Nat)
    (hi : i < p.statements.length)
    (heff : (p.statements[i]'hi).effect = .allow)
    (req : Request) (ctx : CondContext)
    (h : allows (p.removeStmt i) req ctx = true) :
    allows p req ctx = true :=
  Domain.removeAllow iamSem p.statements i hi heff req ctx h

theorem matchPattern_ci_congr (p s s' : String)
    (h : matchActionPattern p s = true) (heq : ciEq s s' = true) :
    matchActionPattern p s' = true := by
  unfold matchActionPattern at *
  have := ciEq_toLowerStr s s' heq
  rw [this] at h; exact h

private theorem matchActionPattern_ciEq (p ℓ a : String)
    (htl : toLowerStr ℓ = toLowerStr a) :
    matchActionPattern p ℓ = matchActionPattern p a := by
  simp [matchActionPattern, matchPattern, htl]

theorem stmtGrantsAction_ci_congr (st : Statement) (ℓ a : String)
    (h : stmtGrantsAction st ℓ = true) (heq : ciEq ℓ a = true) :
    stmtGrantsAction st a = true := by
  have htl := ciEq_toLowerStr ℓ a heq
  unfold stmtGrantsAction at *
  split at h <;> simp_all [matchActionPattern_ciEq _ _ _ htl]

theorem stmtGrantsAction_narrow (s new_stmt : Statement)
    (hnew_notactions : new_stmt.notActions = none)
    (hnew_actions : ∃ acts, new_stmt.actions = some acts ∧
      ∀ ℓ ∈ acts, '?' ∉ ℓ.toList ∧ '*' ∉ ℓ.toList ∧ stmtGrantsAction s ℓ = true)
    (a : String)
    (h : stmtGrantsAction new_stmt a = true) :
    stmtGrantsAction s a = true := by
  obtain ⟨acts, hacts_def, hacts_wf⟩ := hnew_actions
  unfold stmtGrantsAction at h
  rw [hacts_def, hnew_notactions] at h
  simp [List.any_eq_true] at h
  obtain ⟨ℓ, hℓ_mem, hℓ_match⟩ := h
  obtain ⟨hno_q, hno_star, hgrants⟩ := hacts_wf ℓ hℓ_mem
  have hci : ciEq ℓ a = true := by
    unfold matchActionPattern at hℓ_match
    have hno_star' : '*' ∉ (toLowerStr ℓ).toList := by
      simp only [toLowerStr, String.toList_map, List.mem_map]
      exact fun ⟨c, hc, heq⟩ => hno_star ((toLower_eq_star c heq) ▸ hc)
    have hno_q' : '?' ∉ (toLowerStr ℓ).toList := by
      simp only [toLowerStr, String.toList_map, List.mem_map]
      exact fun ⟨c, hc, heq⟩ => hno_q ((toLower_eq_question c heq) ▸ hc)
    have hlist := matchPatternGo_literal_eq _ _ hno_star' hno_q' hℓ_match
    simp [ciEq]; exact String.ext hlist
  exact stmtGrantsAction_ci_congr s ℓ a hgrants hci

theorem allows_replaceAllow_mono (p : Policy) (i : Nat) (hi : i < p.statements.length)
    (heff : (p.statements[i]).effect = .allow)
    (new_stmt : Statement) (hnew_eff : new_stmt.effect = .allow)
    (hnew_res : new_stmt.resources = (p.statements[i]).resources)
    (hnew_notres : new_stmt.notResources = (p.statements[i]).notResources)
    (hnew_cond : new_stmt.condition = (p.statements[i]).condition)
    (hgrants : ∀ a, stmtGrantsAction new_stmt a = true → stmtGrantsAction (p.statements[i]) a = true)
    (req : Request) (ctx : CondContext)
    (h : allows { p with statements := p.statements.set i new_stmt } req ctx = true) :
    allows p req ctx = true :=
  Domain.narrow_narrows iamSem p.statements i hi heff new_stmt hnew_eff
    (cond_bridge new_stmt (p.statements[i]) hnew_cond)
    (fun req' hmatch => by
      show stmtMatches (p.statements[i]) req' = true
      have hmatch : stmtMatches new_stmt req' = true := hmatch
      unfold stmtMatches at hmatch ⊢
      simp only [Bool.and_eq_true] at hmatch ⊢
      exact ⟨hgrants req'.action hmatch.1,
             by unfold resourceMatches at hmatch ⊢; rw [← hnew_res, ← hnew_notres]; exact hmatch.2⟩)
    req ctx h

theorem narrowActions_narrows
    (p : Policy) (i : Nat)
    (hi : i < p.statements.length)
    (heff : (p.statements[i]).effect = .allow)
    (new_stmt : Statement)
    (hnew : new_stmt.effect = .allow)
    (hnew_notactions : new_stmt.notActions = none)
    (hnew_actions : ∃ acts, new_stmt.actions = some acts ∧
      ∀ a ∈ acts, '?' ∉ a.toList ∧ '*' ∉ a.toList ∧
      stmtGrantsAction (p.statements[i]) a = true)
    (hnew_res : new_stmt.resources = (p.statements[i]).resources)
    (hnew_notres : new_stmt.notResources = (p.statements[i]).notResources)
    (hnew_cond : new_stmt.condition = (p.statements[i]).condition)
    (req : Request) (ctx : CondContext)
    (h : allows { p with statements := p.statements.set i new_stmt } req ctx = true) :
    allows p req ctx = true :=
  allows_replaceAllow_mono p i hi heff new_stmt hnew hnew_res hnew_notres hnew_cond
    (fun a ha => stmtGrantsAction_narrow (p.statements[i]) new_stmt hnew_notactions hnew_actions a ha)
    req ctx h

/-! Generalized statement replacement mono -/

theorem allows_replace_stmt_mono (p : Policy) (i : Nat) (hi : i < p.statements.length)
    (heff : (p.statements[i]).effect = .allow)
    (new_stmt : Statement) (hnew_eff : new_stmt.effect = .allow)
    (hnew_cond : new_stmt.condition = (p.statements[i]).condition)
    (hmono : ∀ req, stmtMatches new_stmt req = true → stmtMatches (p.statements[i]) req = true)
    (req : Request) (ctx : CondContext)
    (h : allows { p with statements := p.statements.set i new_stmt } req ctx = true) :
    allows p req ctx = true :=
  Domain.narrow_narrows iamSem p.statements i hi heff new_stmt hnew_eff
    (cond_bridge new_stmt (p.statements[i]) hnew_cond) hmono req ctx h

/-! NEW: narrowResources_narrows (T3) -/

theorem narrowResources_narrows
    (p : Policy) (i : Nat)
    (hi : i < p.statements.length)
    (heff : (p.statements[i]).effect = .allow)
    (new_stmt : Statement) (hnew_eff : new_stmt.effect = .allow)
    (hnew_act : new_stmt.actions = (p.statements[i]).actions)
    (hnew_notact : new_stmt.notActions = (p.statements[i]).notActions)
    (hnew_cond : new_stmt.condition = (p.statements[i]).condition)
    (hnew_notres : new_stmt.notResources = none)
    (hnew_res : ∃ rlist, new_stmt.resources = some rlist ∧
      ∀ r ∈ rlist, '*' ∉ r.toList ∧ '?' ∉ r.toList ∧
        resourceMatches (p.statements[i]) r = true)
    (req : Request) (ctx : CondContext)
    (h : allows { p with statements := p.statements.set i new_stmt } req ctx = true) :
    allows p req ctx = true := by
  apply allows_replace_stmt_mono p i hi heff new_stmt hnew_eff hnew_cond _ req ctx h
  intro req' hmatch
  unfold stmtMatches at hmatch ⊢
  simp only [Bool.and_eq_true] at hmatch ⊢
  constructor
  · unfold actionMatches stmtGrantsAction at hmatch ⊢
    rw [hnew_act, hnew_notact] at hmatch; exact hmatch.1
  · obtain ⟨rlist, hres, hrlist⟩ := hnew_res
    unfold resourceMatches at hmatch ⊢
    rw [hres, hnew_notres] at hmatch
    simp only [List.any_eq_true] at hmatch
    obtain ⟨r, hr_mem, hr_match⟩ := hmatch.2
    have ⟨hno_star, hno_q, hr_old⟩ := hrlist r hr_mem
    have heq := matchPattern_cs_literal_eq r req'.resource hno_star hno_q hr_match
    rw [← heq]; exact hr_old

/-! NEW: emitFixed_narrows (T1+T2+T3 pipeline) -/

private theorem transformStmt_deny_pres (s : Statement) (ns : List Need)
    (hd : s.effect = .deny) : (transformStmt s ns).1 = some s := by
  unfold transformStmt narrowAction
  have : (s.effect != Effect.allow) = true := by rw [hd]; decide
  simp [this]

private theorem narrowAction_preserve (stmt : Statement) (ns : List Need)
    (heff : stmt.effect = .allow) (s1 : Statement)
    (hs1 : narrowAction stmt ns = some s1) :
    s1.effect = stmt.effect ∧ s1.condition = stmt.condition ∧
    s1.resources = stmt.resources ∧ s1.notResources = stmt.notResources := by
  unfold narrowAction at hs1
  have : (stmt.effect != Effect.allow) = false := by rw [heff]; decide
  simp only [this, Bool.false_eq_true, ite_false] at hs1
  split at hs1
  · simp at hs1; subst hs1; exact ⟨rfl, rfl, rfl, rfl⟩
  · split at hs1 <;> split at hs1 <;> (try simp at hs1) <;> (try cases hs1) <;> exact ⟨rfl, rfl, rfl, rfl⟩

private theorem narrowAction_grants (stmt : Statement) (ns : List Need)
    (hns : ∀ n ∈ ns, '?' ∉ n.action.toList ∧ '*' ∉ n.action.toList)
    (heff : stmt.effect = .allow) (s1 : Statement)
    (hs1 : narrowAction stmt ns = some s1) (a : String)
    (h : stmtGrantsAction s1 a = true) :
    stmtGrantsAction stmt a = true := by
  unfold narrowAction at hs1
  have hne : (stmt.effect != Effect.allow) = false := by rw [heff]; decide
  simp only [hne, Bool.false_eq_true, ite_false] at hs1
  split at hs1
  · simp at hs1; subst hs1; exact h
  · split at hs1 <;> split at hs1 <;> (try simp at hs1) <;> (try cases hs1)
    all_goals first
      | exact h
      | (apply stmtGrantsAction_narrow stmt _ rfl ⟨_, rfl, ?_⟩ a h
         intro ℓ hℓ
         rw [List.mem_eraseDups] at hℓ
         obtain ⟨n, hn, rfl⟩ := List.mem_map.mp hℓ
         obtain ⟨hn_mem, hn_grants⟩ := List.mem_filter.mp hn
         exact ⟨(hns n hn_mem).1, (hns n hn_mem).2, hn_grants⟩)

private theorem narrowResource_preserve (s1 stmt : Statement) (ns : List Need) :
    (narrowResource s1 stmt ns).effect = s1.effect ∧
    (narrowResource s1 stmt ns).condition = s1.condition ∧
    (narrowResource s1 stmt ns).actions = s1.actions ∧
    (narrowResource s1 stmt ns).notActions = s1.notActions := by
  simp_all only [narrowResource]
  split <;> try exact ⟨rfl, rfl, rfl, rfl⟩
  split <;> try exact ⟨rfl, rfl, rfl, rfl⟩
  split <;> try exact ⟨rfl, rfl, rfl, rfl⟩
  split <;> exact ⟨rfl, rfl, rfl, rfl⟩

private theorem touchingResources_spec (stmt : Statement) (ns : List Need)
    (hall : allNeedResourcesExact stmt ns = true) (r : String)
    (hr : r ∈ touchingResources stmt ns) :
    hasWildcard r = false ∧ resourceMatches stmt r = true := by
  unfold touchingResources at hr
  rw [List.mem_eraseDups] at hr
  rw [List.mem_filterMap] at hr
  obtain ⟨n, hn_mem, hn_eq⟩ := hr
  split at hn_eq
  · rename_i hcond
    simp at hn_eq; subst hn_eq
    simp [Bool.and_eq_true] at hcond
    constructor
    · unfold allNeedResourcesExact at hall
      have h1 := List.all_eq_true.mp hall n hn_mem
      simp [hcond.1, hcond.2] at h1
      simpa [hasWildcard, Bool.or_eq_false_iff, List.any_eq_false] using h1
    · exact hcond.2
  · simp at hn_eq

private theorem narrowResource_resourceMono (s1 stmt : Statement) (ns : List Need)
    (hs1_res : s1.resources = stmt.resources)
    (hs1_notres : s1.notResources = stmt.notResources)
    (r : String) (h : resourceMatches (narrowResource s1 stmt ns) r = true) :
    resourceMatches stmt r = true := by
  have hfb : resourceMatches s1 r = true → resourceMatches stmt r = true := by
    intro h'; unfold resourceMatches at h' ⊢; rw [hs1_res, hs1_notres] at h'; exact h'
  by_cases h1 : stmt.notResources.isSome = true
  · exact hfb (by simp [narrowResource, h1] at h; exact h)
  · by_cases h2 : (touchingResources stmt ns).isEmpty = true
    · exact hfb (by simp [narrowResource, h1, h2] at h; exact h)
    · by_cases h3 : allNeedResourcesExact stmt ns = true
      · by_cases h4 : (s1.resources == some (touchingResources stmt ns)) = true
        · exact hfb (by simp [narrowResource, h1, h2, h3, h4] at h; exact h)
        · simp [narrowResource, h1, h2, h3, h4] at h
          unfold resourceMatches at h
          simp only [] at h
          rw [List.any_eq_true] at h
          obtain ⟨t, ht_mem, ht_match⟩ := h
          have ⟨hwf, hres⟩ := touchingResources_spec stmt ns h3 t ht_mem
          unfold hasWildcard at hwf
          simp [Bool.or_eq_false_iff, List.any_eq_false] at hwf
          have hno_star : '*' ∉ t.toList := fun hm => by
            have := hwf.1 _ hm; simp at this
          have hno_q : '?' ∉ t.toList := fun hm => by
            have := hwf.2 _ hm; simp at this
          have := matchPattern_cs_literal_eq t r hno_star hno_q ht_match
          rw [← this]; exact hres
      · exact hfb (by simp [narrowResource, h1, h2, h3] at h; exact h)

private theorem transformStmt_narrow (stmt : Statement) (ns : List Need)
    (hns : ∀ n ∈ ns, '?' ∉ n.action.toList ∧ '*' ∉ n.action.toList)
    (heff : stmt.effect = .allow) (s' : Statement)
    (hs' : (transformStmt stmt ns).1 = some s') :
    s'.effect = .allow ∧ s'.condition = stmt.condition ∧
    (∀ req, stmtMatches s' req = true → stmtMatches stmt req = true) := by
  unfold transformStmt at hs'
  cases hna : narrowAction stmt ns with
  | none => rw [hna] at hs'; simp at hs'
  | some s1 =>
    rw [hna] at hs'
    have hne_eff : (stmt.effect != Effect.allow) = false := by rw [heff]; decide
    simp only [hne_eff] at hs'
    have ⟨hs1_eff, hs1_cond, hs1_res, hs1_notres⟩ := narrowAction_preserve stmt ns heff s1 hna
    simp at hs'
    subst hs'
    have ⟨hs'_eff, hs'_cond, hs'_act, hs'_notact⟩ := narrowResource_preserve s1 stmt ns
    refine ⟨by rw [hs'_eff, hs1_eff, heff], by rw [hs'_cond, hs1_cond], ?_⟩
    intro req' hmatch
    unfold stmtMatches at hmatch ⊢
    simp only [Bool.and_eq_true] at hmatch ⊢
    constructor
    · unfold actionMatches at hmatch ⊢
      have hga := narrowAction_grants stmt ns hns heff s1 hna
      have : stmtGrantsAction (narrowResource s1 stmt ns) req'.action =
          stmtGrantsAction s1 req'.action := by
        simp only [stmtGrantsAction, hs'_act, hs'_notact]
      rw [this] at hmatch
      exact hga req'.action hmatch.1
    · exact narrowResource_resourceMono s1 stmt ns hs1_res hs1_notres req'.resource hmatch.2

private theorem allows_filterMap_narrows (stmts : List Statement) (f : Statement → Option Statement)
    (v : Option String) (req : Request) (ctx : CondContext)
    (h_deny : ∀ s ∈ stmts, s.effect = .deny → f s = some s)
    (h_mono : ∀ s s', s ∈ stmts → f s = some s' → s.effect = .allow →
      s'.effect = .allow ∧ s'.condition = s.condition ∧
      (∀ r, stmtMatches s' r = true → stmtMatches s r = true))
    (h : allows ⟨v, stmts.filterMap f⟩ req ctx = true) :
    allows ⟨v, stmts⟩ req ctx = true :=
  Domain.filterMap_narrows iamSem stmts f req ctx h_deny
    (fun s s' hs hfs heff =>
      let ⟨h1, h2, h3⟩ := h_mono s s' hs hfs heff
      ⟨h1, cond_bridge s' s h2, h3⟩) h

private theorem filterMap_map {α β γ : Type} (f : α → β) (g : β → Option γ) (l : List α) :
    (l.map f).filterMap g = l.filterMap (fun x => g (f x)) := by
  induction l with
  | nil => rfl
  | cons a l ih =>
    simp only [List.map_cons, List.filterMap_cons]
    split <;> simp [ih]

theorem emitFixed_narrows (p : Policy) (ns : Needs)
    (hns : ∀ n ∈ ns.needs, '?' ∉ n.action.toList ∧ '*' ∉ n.action.toList)
    (req : Request) (ctx : CondContext)
    (h : allows (emitFixed p ns).1 req ctx = true) :
    allows p req ctx = true := by
  have key : (emitFixed p ns).1 = ⟨p.version,
      p.statements.filterMap (fun s => (transformStmt s ns.needs).1)⟩ := by
    simp only [emitFixed]
    congr 1
    exact filterMap_map _ _ _
  rw [key] at h
  exact allows_filterMap_narrows p.statements _ p.version req ctx
    (fun s _ hd => transformStmt_deny_pres s ns.needs hd)
    (fun s s' hs hfs heff => transformStmt_narrow s ns.needs hns heff s' hfs)
    h

/-! Grants completeness and no-context conservatism -/

theorem grants_complete (p : Policy) (req : Request) (ctx : CondContext)
    (h : allows p req ctx = true) :
    ∃ s ∈ p.statements, s.effect = .allow ∧ stmtMatches s req = true
        ∧ (evalCond ctx s.condBlocks).1 ≠ .f :=
  Domain.grants_complete iamSem p.statements req ctx h

theorem allows_nocontext_conservative (p : Policy) (req : Request) (ctx : CondContext)
    (h : allows p req ctx = true) :
    allows p req noContext = true :=
  Domain.nocontext_conservative iamSem p.statements req ctx h

/-! Layer theorems: layered evaluation only narrows access. -/

theorem layers_narrow (p : Policy) (req : Request) (ctx : CondContext)
    (layers : Layers) (rcpSvcs : List String) (kind : DocKind)
    (h : (allowsLayered p req ctx layers rcpSvcs kind).allowed = true) :
    allows p req ctx = true := by
  unfold allowsLayered at h; split at h <;> simp_all

theorem layer_add_monotone (p : Policy) (req : Request) (ctx : CondContext)
    (rcpSvcs : List String) (kind : DocKind)
    (h : allows p req ctx = true) :
    (allowsLayered p req ctx noLayers rcpSvcs kind).allowed = true := by
  unfold allowsLayered; rw [if_pos h]
  simp [evalLayers_noLayers_blocked]

theorem layered_nocontext_conservative (p : Policy) (req : Request) (ctx : CondContext)
    (layers : Layers) (rcpSvcs : List String) (kind : DocKind)
    (h : (allowsLayered p req ctx layers rcpSvcs kind).allowed = true) :
    (allowsLayered p req noContext layers rcpSvcs kind).allowed = true := by
  have h_base := layers_narrow p req ctx layers rcpSvcs kind h
  have h_nc := allows_nocontext_conservative p req ctx h_base
  unfold allowsLayered at h ⊢
  rw [if_pos h_nc, if_pos h_base] at *
  simp only [List.isEmpty_iff] at h ⊢
  exact evalLayers_blocked_noContext_empty req ctx layers rcpSvcs kind h
