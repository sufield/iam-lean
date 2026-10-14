import Seclib.IAM.Distance

/-! Monotonicity and soundness proofs for the IAM privilege model.
Soufflé source: rules.dl (transitive_assume, effective_permission).
Go source: reasoning/souffle/iam/ (reachability semantics). -/

-- ============================================================
-- 4a. Transitivity: privilege reachability is transitive.
-- ============================================================

/-- If A can reach B and B can reach C, then A can reach C.
    Soufflé source: rules.dl:61-65 (transitive_assume recursive rule). -/
theorem priv_transitive (g : IAMGraph) (a b c : String)
    (hab : PrivReachable g a b) (hbc : PrivReachable g b c) :
    PrivReachable g a c := by
  induction hbc with
  | base h => exact .step b hab h
  | step mid _ h2 ih => exact .step mid ih h2

-- ============================================================
-- 4b. Barrier soundness: a blocked path has distance ≥ 1.
-- ============================================================

/-- A blocked escalation path is not distance-0 (not exploitable).
    Barriers demote exploitable → one-away.
    Go source: fixture partial semantics. -/
theorem barrier_demotes (g : IAMGraph) (principalId : String)
    (scenario : EscalationScenario)
    (hPath : g.escalationPath principalId scenario.primaryAction = true)
    (barrier : Barrier)
    (hBlocked : barrierBlocks g principalId scenario.primaryAction barrier = true) :
    escalationDistance g principalId scenario ≥ 1 := by
  unfold escalationDistance
  simp only [hPath]
  cases barrier with
  | mfa => simp [hBlocked]
  | scp =>
    cases hm : barrierBlocks g principalId scenario.primaryAction .mfa with
    | true => simp
    | false => simp [hBlocked]
  | permBoundary =>
    cases hm : barrierBlocks g principalId scenario.primaryAction .mfa with
    | true => simp
    | false =>
      cases hs : barrierBlocks g principalId scenario.primaryAction .scp with
      | true => simp
      | false => simp [hBlocked]
  | selfScope => simp [barrierBlocks] at hBlocked
  | missingAction => simp [barrierBlocks] at hBlocked

-- ============================================================
-- 4c. SCP monotonicity: adding an SCP Deny cannot open a
-- new escalation path. SCPs only restrict.
-- ============================================================

/-- Adding an SCP deny statement to a graph that has no escalation
    path cannot create one. SCPs only restrict, never grant.
    Soufflé source: rules.dl:190-192 (effective_permission = allow AND NOT deny). -/
theorem scp_deny_monotone (g : IAMGraph) (principalId action : String)
    (stmt : String × String)
    (hNo : g.escalationPath principalId action = false) :
    let g' := { g with scpDenyStatements := stmt :: g.scpDenyStatements }
    g'.escalationPath principalId action = false := by
  simp only [IAMGraph.escalationPath, IAMGraph.reachableActions,
             IAMGraph.transitiveAssume, IAMGraph.directActions] at hNo ⊢
  exact hNo

-- ============================================================
-- 4d. Permission boundary monotonicity: adding a permission
-- boundary cannot open a new escalation path.
-- ============================================================

/-- Adding a permission boundary action to a graph that has no
    escalation path cannot create one.
    Go source: CTL.IAM.BOUNDARY controls. -/
theorem perm_boundary_monotone (g : IAMGraph) (principalId action : String)
    (entry : String × String)
    (hNo : g.escalationPath principalId action = false) :
    let g' := { g with permBoundaryActions := entry :: g.permBoundaryActions }
    g'.escalationPath principalId action = false := by
  simp only [IAMGraph.escalationPath, IAMGraph.reachableActions,
             IAMGraph.transitiveAssume, IAMGraph.directActions] at hNo ⊢
  exact hNo

-- ============================================================
-- 4e. Composition bridge: IAM escalation as a chain step.
-- ============================================================

/-- An exploitable IAM escalation maps to Compose's .exploitable
    classification.
    Go source: finding_risk.go:11-24 (Exploitability). -/
theorem iam_exploitable_matches_compose (g : IAMGraph) (principalId : String)
    (scenario : EscalationScenario)
    (h : escalationDistance g principalId scenario = 0) :
    classifyEscalation g principalId scenario = .exploitable := by
  simp only [classifyEscalation, h]

/-- A one-away IAM escalation maps to Compose's .oneAway classification. -/
theorem iam_oneaway_matches_compose (g : IAMGraph) (principalId : String)
    (scenario : EscalationScenario)
    (h : escalationDistance g principalId scenario = 1) :
    classifyEscalation g principalId scenario = .oneAway := by
  simp only [classifyEscalation, h]
