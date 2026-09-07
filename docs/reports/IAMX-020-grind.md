# IAMX-020 — `grind` Tactic Refactor

Date: 2026-09-07
Toolchain: `leanprover/lean4:v4.33.1` (no bump needed; ≥ 4.22.0 gate satisfied)

## Summary

| Metric | Value |
|--------|-------|
| Theorems in scope | 30 (25 Proofs.lean + 5 Condition.lean) |
| Converted to `grind` | 5 |
| Hybrid conversions | 0 |
| Kept unchanged | 25 |
| Tactic lines before | 411 |
| Tactic lines after | 411 |
| LOC reduction | 0 (all 5 conversions were 1→1 tactic replacements) |
| `@[grind]` annotations added | 22 |
| Axioms introduced | 0 (all within approved set) |
| `sorry` / `admit` count | 0 |
| `#guard` oracle tests | 27 (unchanged, all pass) |

## Inventory — Proofs.lean (25 theorems)

| # | Theorem | Old tactic | New tactic | Lines | Method | Axioms |
|:-:|---------|-----------|-----------|:-----:|--------|--------|
| 1 | `cond_bridge` | `intro c; show …; unfold …; rw [h]` | — | 2 | KEPT | p,C,Q |
| 2 | `removeAllow_narrows` | term-mode | — | 0 | KEPT | p,C,Q |
| 3 | `matchPattern_ci_congr` | `unfold …; have := …; rw … at h; exact h` | — | 3 | KEPT | p,C,Q |
| 4 | `matchActionPattern_ciEq` | `simp [matchActionPattern, matchPattern, htl]` | `grind` | 1→1 | GRIND | p,C,Q |
| 5 | `stmtGrantsAction_ci_congr` | `have …; unfold …; split at h <;> simp_all …` | — | 3 | KEPT | p,C,Q |
| 6 | `stmtGrantsAction_narrow` | 18-line structured proof | — | 18 | KEPT | p,C,Q |
| 7 | `allows_replaceAllow_mono` | term-mode + subproof | — | 8 | KEPT | p,C,Q |
| 8 | `narrowActions_narrows` | term-mode | — | 0 | KEPT | p,C,Q |
| 9 | `allows_replace_stmt_mono` | term-mode | — | 0 | KEPT | p,C,Q |
| 10 | `narrowResources_narrows` | 16-line structured proof | — | 16 | KEPT | p,C,Q |
| 11 | `transformStmt_deny_pres` | `unfold transformStmt narrowAction; aesop (add norm simp [hd])` | `grind` | 1→1 | GRIND | p,C,Q |
| 12 | `narrowAction_preserve` | `unfold narrowAction at hs1; aesop (add norm simp [heff])` | `grind` | 1→1 | GRIND | p,C,Q |
| 13 | `narrowAction_grants` | 14-line structured proof | — | 14 | KEPT | p,C,Q |
| 14 | `narrowResource_preserve` | `simp only [narrowResource]; aesop` | `grind` | 1→1 | GRIND | p,C,Q |
| 15 | `touchingResources_spec` | 13-line structured proof | — | 13 | KEPT | p,C,Q |
| 16 | `narrowResource_resourceMono` | 23-line structured proof | — | 23 | KEPT | p,C,Q |
| 17 | `transformStmt_narrow` | 24-line structured proof | — | 24 | KEPT | p,C,Q |
| 18 | `allows_filterMap_narrows` | term-mode | — | 0 | KEPT | p,C,Q |
| 19 | `filterMap_map` | `induction l; rfl; simp only …; split <;> simp …` | — | 4 | KEPT | p |
| 20 | `emitFixed_narrows` | 7-line structured proof | — | 7 | KEPT | p,C,Q |
| 21 | `grants_complete` | term-mode | — | 0 | KEPT | p,C,Q |
| 22 | `allows_nocontext_conservative` | term-mode | — | 0 | KEPT | p,C,Q |
| 23 | `layers_narrow` | `unfold allowsLayered at h; split at h <;> simp_all` | `grind` | 1→1 | GRIND | p,C,Q |
| 24 | `layer_add_monotone` | `unfold allowsLayered; rw …; simp …` | — | 2 | KEPT | p,C,Q |
| 25 | `layered_nocontext_conservative` | 6-line structured proof | — | 6 | KEPT | p,C,Q |

Axiom key: p = `propext`, C = `Classical.choice`, Q = `Quot.sound`

## Inventory — Condition.lean (5 theorems)

| # | Theorem | Lines | Method | Axioms | Reason kept |
|:-:|---------|:-----:|--------|--------|-------------|
| 1 | `evalKeyOp_noContext` | 7 | KEPT | p,C,Q | grind cannot simplify `noContext.lookup key` |
| 2 | `evalCondInner_noContext_tu` | 7 | KEPT | p,C,Q | List induction + noContext.lookup |
| 3 | `evalCondInner_noContext_T_nil` | 8 | KEPT | p,C,Q | Requires `absurd` + noContext.lookup |
| 4 | `evalCond_noContext_tu` | 7 | KEPT | p,C,Q | List induction + noContext.lookup |
| 5 | `evalCond_noContext_T_imp` | 17 | KEPT | p,C,Q | List induction + cross-context transfer |

## Failure Analysis

### Why only 5 conversions

All 5 successful conversions share a pattern: single-step definitional unfolding + case split + simplification. These are exactly the proofs grind's congruence closure handles well.

The 25 KEPT proofs resist grind for these reasons:

| Class | Count | Blocker |
|-------|:-----:|---------|
| Term-mode (no `by`) | 6 | No tactic to replace |
| List induction | 5 | grind cannot coordinate induction hypotheses |
| Multi-step lemma chains | 5 | ciEq → toLowerStr → matchPatternGo chains |
| noContext.lookup opacity | 5 | `CondContext.lookup` not `@[grind]`; involves `List.find?` + `Option.map` |
| Existential witnesses / cross-domain | 4 | grind cannot supply existential witnesses |

### noContext.lookup — the key limitation

All 5 Condition.lean proofs (and the `layered_nocontext_conservative` proof path) require
showing `noContext.lookup key = none`. This needs unfolding `CondContext.lookup` through
`List.find?` and `Option.map`, which grind cannot do even when `noContext` itself is
`@[grind]`. Annotating `CondContext.lookup` was evaluated but would have no effect since
grind still can't reduce `[].find?` symbolically.

### Comparison to Aesop (IAMX-018)

| Metric | Aesop | grind |
|--------|:-----:|:-----:|
| Proofs converted | 6 | 5 |
| LOC saved | 26 | 0 |
| LOC reduction | 5.9% | 0% |

grind found no net line savings because Aesop had already compressed the multi-line proofs
to 1-liners. grind's value here is tactic simplification: replacing `unfold X; aesop (add
norm simp [h])` combos with a single `grind`, reducing cognitive load per proof.

### Mathlib 28% benchmark

Mathlib reports ~28% LOC reduction from grind across its corpus. This codebase sees 0%
because: (a) proofs were already compact post-Aesop, (b) the domain-specific blockers
(noContext.lookup, string matching lemma chains) affect a disproportionate share of theorems,
and (c) the codebase has only 30 in-scope theorems — too small a sample for the law of large
numbers to smooth out domain-specific resistance.

## `@[grind]` Annotations (22)

| # | File | Definition/Theorem | Kind | Rationale |
|:-:|------|-------------------|------|-----------|
| 1 | Seclib/Prim.lean | `Tri.and` | def | Three-valued AND — core building block for condition evaluation |
| 2 | Seclib/Prim.lean | `Tri.or` | def | Three-valued OR — used in condition fold logic |
| 3 | Seclib/Prim.lean | `Tri.not` | def | Three-valued NOT — used in negated operator evaluation |
| 4 | Seclib/Prim.lean | `Tri.and_tu` | thm | T/U closure under AND — key lemma for grind e-matching |
| 5 | Seclib/Prim.lean | `Tri.and_eq_t` | thm | AND-equals-T iff — characterizes when AND yields true |
| 6 | Seclib/Prim/Rule.lean | `appliesOf` | def | Effect × Tri → Bool dispatcher — needed for deny-overrides unfolding |
| 7 | Seclib/Prim/Context.lean | `noContext` | def | Empty context constructor — grind needs to unfold for noContext proofs |
| 8 | IamExplainer/Condition.lean | `evalNull` | def | Null-condition evaluator — grind unfolds during condition proofs |
| 9 | IamExplainer/Condition.lean | `evalKeyOp` | def | Key-operator evaluator — main condition evaluation entry point |
| 10 | IamExplainer/Condition.lean | `evalCondInner` | def | Per-operator condition fold — recursive structure grind unfolds |
| 11 | IamExplainer/Condition.lean | `evalCond` | def | Top-level condition evaluator — grind unfolds for condition-related proofs |
| 12 | IamExplainer/Match.lean | `matchActionPattern` | def | Case-insensitive action pattern match — needed for `matchActionPattern_ciEq` |
| 13 | IamExplainer/Match.lean | `stmtGrantsAction` | def | Statement grants action — core matching predicate |
| 14 | IamExplainer/Match.lean | `actionMatches` | def | Action matching wrapper — alias for stmtGrantsAction |
| 15 | IamExplainer/Match.lean | `resourceMatches` | def | Resource pattern matching — used in stmtMatches |
| 16 | IamExplainer/Match.lean | `stmtMatches` | def | Full statement-request matching — combines action + resource |
| 17 | IamExplainer/Match.lean | `Statement.condBlocks` | def | Condition block decoder — bridges Statement to CondBlocks |
| 18 | IamExplainer/Match.lean | `allows` | def | Policy allows predicate — top-level grant decision function |
| 19 | IamExplainer/Emit.lean | `narrowAction` | def | T1 transform: action narrowing — grind unfolds for `narrowAction_preserve` |
| 20 | IamExplainer/Emit.lean | `narrowResource` | def | T3 transform: resource narrowing — grind unfolds for `narrowResource_preserve` |
| 21 | IamExplainer/Emit.lean | `transformStmt` | def | T1+T2+T3 pipeline — grind unfolds for `transformStmt_deny_pres` |
| 22 | IamExplainer/Layers.lean | `allowsLayered` | def | Layered evaluation — grind unfolds for `layers_narrow` |

## Out-of-Scope Observations

The following proofs in files outside the ownership scope were found to be closable by `grind`
(noted for future IAMX consideration, not changed):

| File | Theorem | Current proof |
|------|---------|---------------|
| Seclib/Prim/Rule.lean | `deny_any_rules_iff` | `by aesop` (1 line) |
| Seclib/Prim/Rule.lean | `allow_any_rules_iff` | `by aesop` (1 line) |
| Seclib/Prim/Rule.lean | `conj_narrows` | multi-line |
| Seclib/Prim/Rule.lean | `denyOverrides_remove_allow_narrows` | multi-line |
| Seclib/Domain/PolicySem.lean | `narrow_narrows` (line 33) | multi-line |
| Seclib/Domain/PolicySem.lean | `filterMap_narrows` (line 40) | multi-line |

## Commit History

1. `07377df` Add @[grind] annotations to 22 definitions/theorems (build-only)
2. `67e08cf` grind: 5 theorems in Proofs.lean (1→1 lines each, tactic replacement)
3. *(this commit)* Add IAMX-020 measurement report
