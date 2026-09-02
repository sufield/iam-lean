import IamExplainer.Match
import IamExplainer.Principal

open Lean (Json)

structure Layers where
  scps              : List Policy := []
  rcps              : List Policy := []
  boundary          : Option Policy := none
  managementAccount : Bool := false
  serviceLinked     : Bool := false

structure LayerVerdict where
  allowed     : Bool
  blockedBy   : List String
  unresolved  : List String
  notes       : List String
  warnings    : List String := []

structure LayerResult where
  blocked    : List String
  unresolved : List String
  notes      : List String
  warnings   : List String := []

private def stmtId (s : Statement) : String :=
  match s.sid with | some sid => sid | none => s!"stmt{s.index}"

private def condKeys (s : Statement) : List String :=
  match s.condition with
  | none => []
  | some j => match j with
    | .obj kvs => kvs.toList.flatMap fun (_, v) =>
      match v with | .obj inner => inner.toList.map fun (k, _) => k | _ => []
    | _ => []

private def unresTag (tag : String) (s : Statement) : String :=
  let ks := condKeys s
  if ks.isEmpty then tag else s!"{tag}:{":".intercalate ks}"

private def denyBlockedTags (ctx : CondContext) (req : Request) :
    List Statement → (Statement → String) → List String
  | [], _ => []
  | s :: rest, mkTag =>
    let b := denyBlockedTags ctx req rest mkTag
    if s.effect == .deny && stmtMatches s req && (evalCond ctx s.condBlocks).1 == .t then
      mkTag s :: b
    else b

private def denyUnresTags (ctx : CondContext) (req : Request) :
    List Statement → (Statement → String) → List String
  | [], _ => []
  | s :: rest, mkTag =>
    let u := denyUnresTags ctx req rest mkTag
    if s.effect == .deny && stmtMatches s req && (evalCond ctx s.condBlocks).1 == .u then
      unresTag (mkTag s) s :: u
    else u

private def foldDenies (ctx : CondContext) (req : Request) (stmts : List Statement)
    (mkTag : Statement → String) : List String × List String :=
  (denyBlockedTags ctx req stmts mkTag, denyUnresTags ctx req stmts mkTag)

private def evalWarnings (ctx : CondContext) (stmts : List Statement) (req : Request) : List String :=
  stmts.flatMap fun s =>
    if stmtMatches s req then (evalCond ctx s.condBlocks).2.map (·.message) else []

private def evalScpLevel (req : Request) (ctx : CondContext) (level : Nat)
    (scp : Policy) : LayerResult :=
  let hasAllow := scp.statements.any (·.effect == .allow)
  let allowOk := !hasAllow || scp.statements.any fun s =>
    s.effect == .allow && stmtMatches s req && !decide ((evalCond ctx s.condBlocks).1 = .f)
  let notes := if !hasAllow then [s!"scp:{level}:assumed-full-access"] else []
  let noAllowBlock := if !allowOk then [s!"scp:{level}:no-allow"] else []
  let (denyBlocked, denyUnres) := foldDenies ctx req scp.statements
    fun s => s!"scp:{level}:{stmtId s}"
  { blocked := noAllowBlock ++ denyBlocked, unresolved := denyUnres, notes,
    warnings := evalWarnings ctx scp.statements req }

private def actionServicePrefix (action : String) : String :=
  match (toLowerStr action).splitOn ":" with
  | svc :: _ :: _ => svc
  | _ => toLowerStr action

private def evalRcpLevel (req : Request) (ctx : CondContext) (level : Nat)
    (rcp : Policy) (services : List String) : LayerResult :=
  let svc := actionServicePrefix req.action
  if !services.contains svc then
    { blocked := [], unresolved := [s!"rcp:{level}:service-not-in-support-list"], notes := [] }
  else
    let (blocked, unres) := foldDenies ctx req rcp.statements
      fun s => s!"rcp:{level}:{stmtId s}"
    { blocked, unresolved := unres, notes := [],
      warnings := evalWarnings ctx rcp.statements req }

private def evalBoundary (req : Request) (ctx : CondContext) (kind : DocKind)
    (bnd : Policy) : LayerResult :=
  if kind != .identity then
    { blocked := [], unresolved := [], notes := [s!"boundary-skipped:{kind}"] }
  else
    let hasAllow := bnd.statements.any fun s =>
      s.effect == .allow && stmtMatches s req && !decide ((evalCond ctx s.condBlocks).1 = .f)
    let noAllowBlock := if !hasAllow then ["boundary:no-allow"] else []
    let (denyBlocked, denyUnres) := foldDenies ctx req bnd.statements
      fun s => s!"boundary:{stmtId s}"
    { blocked := noAllowBlock ++ denyBlocked, unresolved := denyUnres, notes := [],
      warnings := evalWarnings ctx bnd.statements req }

private def emptyResult : LayerResult := { blocked := [], unresolved := [], notes := [] }

def evalLayers (req : Request) (ctx : CondContext) (layers : Layers)
    (rcpServices : List String) (kind : DocKind) : LayerResult :=
  let skipScps := layers.managementAccount || layers.serviceLinked
  let scpNote : List String :=
    if layers.managementAccount then ["scp-skipped"]
    else if layers.serviceLinked then ["scp-exempt"]
    else []
  let scpResults := if skipScps then []
    else layers.scps.mapIdx fun i scp => evalScpLevel req ctx (i + 1) scp
  let rcpResults := layers.rcps.mapIdx fun i rcp =>
    evalRcpLevel req ctx (i + 1) rcp rcpServices
  let bndResult := match layers.boundary with
    | some bnd => evalBoundary req ctx kind bnd
    | none => emptyResult
  let all := scpResults ++ rcpResults ++ [bndResult]
  let blocked := all.flatMap (·.blocked)
  let unres := all.flatMap (·.unresolved)
  let notes := scpNote ++ all.flatMap (·.notes)
  -- ponytail: cross-account note when RCPs evaluate cleanly on resource policies
  let crossAcct := if kind == .resource && !layers.rcps.isEmpty &&
    rcpResults.all (·.blocked.isEmpty) && rcpResults.all (·.unresolved.isEmpty)
    then ["identity-side policy not supplied"] else []
  let evalWarns := all.flatMap (·.warnings)
  { blocked, unresolved := unres ++ crossAcct, notes, warnings := evalWarns }

def allowsLayered (p : Policy) (req : Request) (ctx : CondContext) (layers : Layers)
    (rcpServices : List String) (kind : DocKind) : LayerVerdict :=
  if allows p req ctx then
    let lr := evalLayers req ctx layers rcpServices kind
    { allowed := lr.blocked.isEmpty
      blockedBy := lr.blocked
      unresolved := lr.unresolved
      notes := lr.notes
      warnings := lr.warnings }
  else
    { allowed := false, blockedBy := [], unresolved := [], notes := [] }

def noLayers : Layers := {}

def validateScp (p : Policy) : Option String :=
  p.statements.findSome? fun s =>
    if s.principals.isSome then some s!"SCP {stmtId s}: must not contain Principal"
    else if s.notPrincipals.isSome then some s!"SCP {stmtId s}: must not contain NotPrincipal"
    else none

def validateRcp (p : Policy) : Option String :=
  p.statements.findSome? fun s =>
    if s.effect == .deny && s.principals.isNone && s.notPrincipals.isNone then
      some s!"RCP Deny {stmtId s}: must contain Principal"
    else none

/-! Layer soundness helpers -/

private theorem denyBlockedTags_noContext (ctx : CondContext) (req : Request)
    (stmts : List Statement) (mkTag : Statement → String)
    (h : denyBlockedTags ctx req stmts mkTag = []) :
    denyBlockedTags noContext req stmts mkTag = [] := by
  induction stmts with
  | nil => rfl
  | cons s rest ih =>
    simp only [denyBlockedTags] at h ⊢
    split
    · rename_i h_nc
      have h_nc_t : (evalCond noContext s.condBlocks).1 = .t := by
        have := Bool.and_eq_true_iff.mp h_nc; exact beq_iff_eq.mp this.2
      have h_ctx_t := evalCond_noContext_T_imp s.condBlocks ctx h_nc_t
      have h_ctx : (s.effect == .deny && stmtMatches s req &&
          (evalCond ctx s.condBlocks).1 == .t) = true := by
        have := Bool.and_eq_true_iff.mp h_nc
        exact Bool.and_eq_true_iff.mpr ⟨this.1, beq_iff_eq.mpr h_ctx_t⟩
      rw [if_pos h_ctx] at h; exact absurd h (List.cons_ne_nil _ _)
    · have h_rest : denyBlockedTags ctx req rest mkTag = [] := by
        split at h
        · exact absurd h (List.cons_ne_nil _ _)
        · exact h
      exact ih h_rest

private theorem foldDenies_blocked_noContext (ctx : CondContext) (req : Request)
    (stmts : List Statement) (mkTag : Statement → String)
    (h : (foldDenies ctx req stmts mkTag).1 = []) :
    (foldDenies noContext req stmts mkTag).1 = [] :=
  denyBlockedTags_noContext ctx req stmts mkTag h

theorem evalLayers_noLayers_blocked (req : Request) (ctx : CondContext)
    (rcpSvcs : List String) (kind : DocKind) :
    (evalLayers req ctx noLayers rcpSvcs kind).blocked = [] := by
  simp [evalLayers, noLayers, emptyResult]

private theorem allowOk_noContext (scp : Policy) (req : Request) (ctx : CondContext)
    (h : (scp.statements.any fun s =>
      s.effect == .allow && stmtMatches s req &&
      !decide ((evalCond ctx s.condBlocks).1 = .f)) = true) :
    (scp.statements.any fun s =>
      s.effect == .allow && stmtMatches s req &&
      !decide ((evalCond noContext s.condBlocks).1 = .f)) = true := by
  rw [List.any_eq_true] at h ⊢
  obtain ⟨s, hs, hcond⟩ := h
  refine ⟨s, hs, ?_⟩
  simp only [Bool.and_eq_true, beq_iff_eq] at hcond ⊢
  exact ⟨hcond.1, by have htu := evalCond_noContext_tu s.condBlocks; rcases htu with ht | hu <;> simp_all⟩

private theorem evalScpLevel_blocked_noContext (req : Request) (ctx : CondContext)
    (level : Nat) (scp : Policy)
    (h : (evalScpLevel req ctx level scp).blocked = []) :
    (evalScpLevel req noContext level scp).blocked = [] := by
  simp only [evalScpLevel, foldDenies] at h ⊢
  rw [List.append_eq_nil_iff] at h
  have h_deny_nc := denyBlockedTags_noContext ctx req _ _ h.2
  have h_mono := allowOk_noContext scp req ctx
  split at h <;> split <;> simp_all
  rename_i h_ctx_forall h_nc_and
  obtain ⟨s₀, hs₀, he₀⟩ := h_nc_and.1
  obtain ⟨s₁, hs₁, he₁, hm₁, hc₁⟩ := h_ctx_forall s₀ hs₀ he₀
  obtain ⟨s₂, hs₂, ⟨he₂, hm₂⟩, hcnc₂⟩ := h_mono s₁ hs₁ he₁ hm₁ hc₁
  exact hcnc₂ (h_nc_and.2 s₂ hs₂ he₂ hm₂)

private theorem evalBoundary_blocked_noContext (req : Request) (ctx : CondContext)
    (kind : DocKind) (bnd : Policy)
    (h : (evalBoundary req ctx kind bnd).blocked = []) :
    (evalBoundary req noContext kind bnd).blocked = [] := by
  unfold evalBoundary at h ⊢
  split at h
  · split
    · simp_all
    · rename_i hk1 hk2; exact absurd hk1 hk2
  · split
    · rename_i hk1 hk2; exact absurd hk2 hk1
    · simp_all
      constructor
      · obtain ⟨s, hs, he, hm, _⟩ := h.1
        exact ⟨s, hs, he, hm, by have := evalCond_noContext_tu s.condBlocks; rcases this with ht | hu <;> simp_all⟩
      · exact denyBlockedTags_noContext ctx req _ _ h.2

private theorem evalRcpLevel_blocked_noContext (req : Request) (ctx : CondContext)
    (level : Nat) (rcp : Policy) (services : List String)
    (h : (evalRcpLevel req ctx level rcp services).blocked = []) :
    (evalRcpLevel req noContext level rcp services).blocked = [] := by
  simp only [evalRcpLevel, foldDenies] at h ⊢
  split at h <;> simp_all
  exact denyBlockedTags_noContext ctx req _ _ h

private theorem flatMap_blocked_mapIdx {α : Type} (l : List α)
    (f g : Nat → α → LayerResult)
    (hf : (l.mapIdx f).flatMap (·.blocked) = [])
    (hfg : ∀ i x, (f i x).blocked = [] → (g i x).blocked = []) :
    (l.mapIdx g).flatMap (·.blocked) = [] := by
  induction l generalizing f g with
  | nil => simp
  | cons a rest ih =>
    simp only [List.mapIdx_cons, List.flatMap_cons] at hf ⊢
    rw [List.append_eq_nil_iff] at hf ⊢
    exact ⟨hfg 0 a hf.1, ih _ _ hf.2 (fun i x h => hfg (i + 1) x h)⟩

theorem evalLayers_blocked_noContext_empty (req : Request) (ctx : CondContext)
    (layers : Layers) (rcpSvcs : List String) (kind : DocKind)
    (h : (evalLayers req ctx layers rcpSvcs kind).blocked = []) :
    (evalLayers req noContext layers rcpSvcs kind).blocked = [] := by
  simp only [evalLayers] at h ⊢
  simp only [List.flatMap_append, List.flatMap_cons, List.flatMap_nil,
             List.append_nil, List.append_eq_nil_iff] at h ⊢
  obtain ⟨⟨h_scp, h_rcp⟩, h_bnd⟩ := h
  refine ⟨⟨?_, ?_⟩, ?_⟩
  · by_cases hskip : (layers.managementAccount || layers.serviceLinked) = true
    · simp [hskip] at h_scp ⊢
    · simp only [if_neg hskip] at h_scp ⊢
      exact flatMap_blocked_mapIdx _ _ _ h_scp
        (fun i x h => evalScpLevel_blocked_noContext req ctx (i + 1) x h)
  · exact flatMap_blocked_mapIdx _ _ _ h_rcp
      (fun i x h => evalRcpLevel_blocked_noContext req ctx (i + 1) x rcpSvcs h)
  · cases hb : layers.boundary with
    | none => simp [emptyResult]
    | some bnd =>
      simp only [hb] at h_bnd
      exact evalBoundary_blocked_noContext req ctx kind bnd h_bnd
