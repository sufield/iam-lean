import Stave.Network.Property

/-! Monotonicity and soundness proofs for the network prover.
Go source: reachability.go, proof.go.

Core insight: reachability is a disjunction over SG ingress rules.
Adding rules can only add disjuncts. Removing rules can only remove them.
Therefore reachability is monotone in the rule set. -/

-- ============================================================
-- 4a. Edge monotonicity (abstract form)
-- ============================================================

/-- If `any` holds on a list, it holds on a superset (append).
    Go source: reachability.go — CanReach uses List.any; this is the
    abstract monotonicity principle underlying edge_monotone. -/
theorem List.any_of_any_append_left {l₁ l₂ : List α} {p : α → Bool}
    (h : l₁.any p = true) : (l₁ ++ l₂).any p = true := by
  rw [List.any_eq_true] at h ⊢
  obtain ⟨x, hx, hp⟩ := h
  exact ⟨x, List.mem_append_left l₂ hx, hp⟩

/-- Abstract monotonicity: if a predicate holds when checking
    `any` over a set of rules, it still holds over a superset.
    Go source: reachability.go:36-51 — core of edge_monotone. -/
theorem rule_check_mono {rules extra : List SGRule}
    {check : SGRule → Bool}
    (h : rules.any check = true) :
    (rules ++ extra).any check = true :=
  List.any_of_any_append_left h

/-- If membership is preserved, `any` is preserved.
    Go source: reachability.go:36-51
    The key invariant: adding an SG rule to a graph that already
    allows reachability cannot remove that reachability. -/
theorem canReach_mono_abstract
    (sgRules₁ sgRules₂ : String → List SGRule)
    (h_super : ∀ sg, ∀ r, r ∈ sgRules₁ sg → r ∈ sgRules₂ sg)
    (sgIds : List String) (check : SGRule → Bool)
    (h : sgIds.any (fun sg => (sgRules₁ sg).any check) = true) :
    sgIds.any (fun sg => (sgRules₂ sg).any check) = true := by
  rw [List.any_eq_true] at h ⊢
  obtain ⟨sg, hsg_mem, hsg_any⟩ := h
  refine ⟨sg, hsg_mem, ?_⟩
  rw [List.any_eq_true] at hsg_any ⊢
  obtain ⟨r, hr_mem, hr_check⟩ := hsg_any
  exact ⟨r, h_super sg r hr_mem, hr_check⟩

-- ============================================================
-- 4b. Isolation soundness
-- ============================================================

/-- If a host is tagged isolated and no host in the graph can reach
    it on any port (UNSAT), then canReachAny is false for all sources.

    Go source: graph.go:24 (IsIsolated), proof.go:588 (UNSAT) -/
theorem isolation_sound (g : NetGraph) (dst : Host)
    (_hIso : dst.isIsolated = true)
    (hUnsat : ∀ src, src ∈ g.hosts → g.canReachAny src dst = false) :
    ∀ src, src ∈ g.hosts → ¬ ReachableAny g src dst := by
  intro src hsrc hReach
  simp only [ReachableAny] at hReach
  have := hUnsat src hsrc
  rw [this] at hReach
  exact absurd hReach (by decide)

-- ============================================================
-- 4c. EVIDENCE_GATED conservatism
-- ============================================================

/-- A graph has a gated egress path if an isolated host can reach
    a host whose subnet routes to a gated target.
    Go source: proof.go:560-584 (EVIDENCE_GATED condition) -/
def hasGatedEgressPath (g : NetGraph) : Prop :=
  ∃ iso srv, iso ∈ g.isolatedHosts ∧ ¬ srv.isIsolated ∧
    g.canReachAny iso srv ∧ hostEgressClass g srv = some .gated

/-- If a gated egress path exists and no sink path exists,
    transitiveEgressVerdict returns evidenceGated, never unsat.
    Go source: proof.go:465 verdict precedence. -/
theorem gated_not_unsat (g : NetGraph)
    (hGated : g.isolatedHosts.any (fun iso =>
      g.hosts.any (fun srv =>
        ¬ srv.isIsolated && g.canReachAny iso srv &&
        hostEgressClass g srv == some .gated)) = true)
    (hNoSink : g.isolatedHosts.any (fun iso =>
      g.hosts.any (fun srv =>
        ¬ srv.isIsolated && g.canReachAny iso srv &&
        hostEgressClass g srv == some .sink)) = false) :
    transitiveEgressVerdict g = .evidenceGated := by
  unfold transitiveEgressVerdict
  simp only [hNoSink, hGated, ite_true]
  decide

/-- Contrapositive: if verdict is UNSAT, no gated path exists.
    Go source: proof.go:465 (verdict precedence). -/
theorem unsat_no_gated (g : NetGraph)
    (h : transitiveEgressVerdict g = .unsat) :
    g.isolatedHosts.any (fun iso =>
      g.hosts.any (fun srv =>
        ¬ srv.isIsolated && g.canReachAny iso srv &&
        hostEgressClass g srv == some .gated)) = false := by
  unfold transitiveEgressVerdict at h
  split at h
  · simp at h
  · split at h
    · simp at h
    · rename_i _ hng
      cases hv : g.isolatedHosts.any (fun iso =>
        g.hosts.any (fun srv =>
          decide ¬srv.isIsolated = true && g.canReachAny iso srv &&
          hostEgressClass g srv == some RouteClass.gated))
      · rfl
      · exact absurd hv hng

-- ============================================================
-- 4d. Transitivity decomposition (stretch)
-- ============================================================

/-- Transitive egress decomposes into two reachability queries:
    (1) isolated → service, (2) service has egress route.
    This is definitionally true from `transitiveEgressSat`.
    Go source: proof.go:532-557 (SAT check: canReachAnyPort then
    route classification). -/
theorem transitiveEgress_decomposition (g : NetGraph) :
    transitiveEgressSat g ↔
    ∃ iso srv, iso ∈ g.isolatedHosts ∧ ¬ srv.isIsolated ∧
      g.canReachAny iso srv ∧ hostEgressClass g srv = some .sink :=
  Iff.rfl
