# Blueprint Specification

publication: GATED

Gated HEAD: `00c3e18ca2` (2026-09-02).
Remote: `origin` = `git@github.com:bparanj/bizacademy.git` (visibility: UNKNOWN — gh CLI unavailable).

## Purpose

Lean Blueprint site (leanblueprint + doc-gen4) for the iam-explainer
formalization. Chaptered prose statements, dependency graph,
`\lean{}` links, axiom-gated `\leanok`, PDF, and API docs.

## Chapter Plan

1. **Introduction and Modeled Fragment** — what the formalization covers,
   what it does not. Three-valued condition semantics, UNKNOWN-resolves-
   toward-visibility rule. Over-approximation scope. Assumed-full-access
   note. Out of scope: identity-side cross-account, session policies.
2. **Pattern Matching** — glob matchers, case folding, literal/congruence
   lemmas (ciEq_toLowerStr, matchPatternGo_literal_eq, matchPattern_literal_mp,
   matchPattern_cs_literal_eq, toLower_eq_star, toLower_eq_question).
3. **Grant Semantics** — deny-overrides, removeAllow, narrow_narrows,
   filterMap_narrows, allows_replaceAllow_mono, stmtGrantsAction_narrow,
   stmtGrantsAction_ci_congr, matchPattern_ci_congr, removeAllow_narrows,
   narrowActions_narrows, allows_replace_stmt_mono, narrowResources_narrows,
   emitFixed_narrows, grants_complete.
4. **Conditions** — Tri type, Tri.and, Tri.or, Tri.not, Tri.and_tu,
   Tri.and_eq_t, evalCond, evalCond_noContext_tu, evalCond_noContext_T_imp,
   allows_nocontext_conservative.
5. **Control Layers** — allowsLayered, evalLayers, evalLayers_noLayers_blocked,
   evalLayers_blocked_noContext_empty, layers_narrow, layer_add_monotone,
   layered_nocontext_conservative.
6. **Emission** — emitFixed, transformStmt, narrowAction, narrowResource,
   emitFixed_narrows, grants_complete (corollary).

## Node Inventory (35 theorems/lemmas)

### Seclib/Prim.lean
- Tri.and_tu
- Tri.and_eq_t

### Seclib/Prim/Glob.lean
- ciEq_toLowerStr
- matchPatternGo_literal_eq
- matchPattern_literal_mp
- matchPattern_cs_literal_eq
- toLower_eq_star
- toLower_eq_question

### Seclib/Prim/Rule.lean
- denyOverrides_remove_allow_narrows
- denyOverrides_add_deny_narrows
- conj_narrows
- appliesOf_unknown_conservative

### Seclib/Domain/PolicySem.lean
- removeAllow
- narrow_narrows
- filterMap_narrows
- nocontext_conservative
- grants_complete (generic)

### IamExplainer/Proofs.lean
- removeAllow_narrows
- matchPattern_ci_congr
- stmtGrantsAction_ci_congr
- stmtGrantsAction_narrow
- allows_replaceAllow_mono
- narrowActions_narrows
- allows_replace_stmt_mono
- narrowResources_narrows
- emitFixed_narrows
- grants_complete (corollary)
- allows_nocontext_conservative
- layers_narrow
- layer_add_monotone
- layered_nocontext_conservative

### IamExplainer/Condition.lean
- evalCond_noContext_tu
- evalCond_noContext_T_imp

### IamExplainer/Layers.lean
- evalLayers_noLayers_blocked
- evalLayers_blocked_noContext_empty

## Major Definitions

- matchPattern, matchPatternGo, ciEq, toLowerStr (Seclib/Prim/Glob.lean)
- Tri.and, Tri.or, Tri.not (Seclib/Prim.lean)
- appliesOf, denyOverridesRules (Seclib/Prim/Rule.lean)
- denyOverrides [generic] (Seclib/Domain/PolicySem.lean)
- stmtGrantsAction, allows, stmtMatches, matchActionPattern, resourceMatches (IamExplainer/Match.lean)
- evalCond, evalCondInner (IamExplainer/Condition.lean)
- allowsLayered, evalLayers, noLayers (IamExplainer/Layers.lean)
- emitFixed (IamExplainer/Emit.lean)
- scopeOf (IamExplainer/Principal.lean)
- iamSem, Policy.removeStmt (IamExplainer/Proofs.lean)

## Status Conventions

- `\leanok` — axiom-clean: declaration passes `#print axioms` with only
  propext, Classical.choice, Quot.sound. No sorryAx, ofReduceBool, trustCompiler.
- `\notready` — stated but not proved (none expected at gated HEAD).
- Every `\lean{Name}` must point to an existing declaration.
- Gate A enforces `\leanok` ↔ axiom-clean.
- Gate B enforces theorem parity: every theorem in the tree appears in
  exactly one `\lean{}` reference.

## CI Gates

Gate A (axiom-gated \leanok): every \leanok'd declaration is probed via
`lake env lean --run` with `#print axioms`; taint list = sorryAx,
ofReduceBool, trustCompiler.

Gate B (parity): every `theorem` name across Seclib/ and IamExplainer/
appears in exactly one `\lean{}` reference in blueprint/src/*.tex.

Both gates implemented in `scripts/blueprint_gates.sh`.
