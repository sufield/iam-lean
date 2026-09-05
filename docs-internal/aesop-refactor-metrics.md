# Aesop Refactor Metrics

Date: 2026-09-05

## Summary

| Metric | Value |
|--------|-------|
| Total theorems | 64 |
| Proofs converted | 6 |
| Tactic lines before | 437 |
| Tactic lines after | 411 |
| Lines saved | 26 |
| Reduction | 5.9% |
| Axioms introduced | 0 (all within approved set) |
| Sorry count | 0 |
| #guard count | 27 (unchanged) |

## Per-File Breakdown

| File | Proof | Before | After | Saved | Method |
|------|-------|:------:|:-----:|:-----:|--------|
| Proofs.lean | `transformStmt_deny_pres` | 3 | 1 | 2 | `unfold; aesop (add norm simp [hd])` |
| Proofs.lean | `narrowAction_preserve` | 6 | 1 | 5 | `unfold at; aesop (add norm simp [heff])` |
| Proofs.lean | `narrowResource_preserve` | 5 | 1 | 4 | `simp only [narrowResource]; aesop` |
| Rule.lean | `deny_any_rules_iff` | 8 | 1 | 7 | `simp [List.any_eq_true, ...]` |
| Rule.lean | `allow_any_rules_iff` | 8 | 1 | 7 | `simp [List.any_eq_true, ...]` |
| Glob.lean | `matchPattern_literal_mp` | 4 | 3 | 1 | Inline `have` chain |

## Proofs Not Converted (by class)

| Class | Count | Reason |
|-------|:-----:|--------|
| P1 already 1-line | 11 | No reduction possible (`by simp`, `by cases`, etc.) |
| P2 (list induction) | 11 | Aesop can't coordinate induction + multi-lemma cons cases |
| P5 (creative) | 27 | Existential witnesses, cross-domain reasoning |
| TERM (delegation) | 6 | Already term-mode, 0 tactic lines |
| P1 private helpers | 3 | Private visibility blocks Aesop rule registration; manual unfold chains not shorter with aesop |

## Axiom Verification

All converted theorems verified with `#print axioms`:

| Theorem | Axioms |
|---------|--------|
| `transformStmt_deny_pres` | propext, Classical.choice, Quot.sound |
| `narrowAction_preserve` | propext, Classical.choice, Quot.sound |
| `narrowResource_preserve` | propext, Classical.choice, Quot.sound |
| `deny_any_rules_iff` | propext, Quot.sound |
| `allow_any_rules_iff` | propext, Quot.sound |
| `matchPattern_literal_mp` | propext, Classical.choice, Quot.sound |

No new axioms beyond the pre-existing approved set (propext, Classical.choice, Quot.sound).

## Build Impact

| Metric | Pre-Aesop | Post-Aesop |
|--------|:---------:|:----------:|
| Incremental build (Proofs.lean) | ~1.5s | ~1.6s |
| Full clean build | ~13s | ~75s (Aesop compilation) |
| Cached rebuild | <1s | ~1s |

The full clean build increase is entirely from compiling Aesop itself (382 modules). Incremental builds (the normal dev loop) are unchanged.

## IAMRules.lean Rule Set

```lean
attribute [aesop safe cases] Tri Effect
attribute [aesop safe constructors] And
attribute [aesop norm simp] Tri.and_eq_t
attribute [aesop unsafe 75% apply] Tri.and_tu
attribute [aesop unsafe 75% apply] evalCond_noContext_tu
attribute [aesop unsafe 75% apply] evalCond_noContext_T_imp
```

## Commit History

1. `98fe823` Add Aesop dependency (build-only)
2. `fc366c1` Add IAMRules.lean (build-only)
3. `d1b57db` Convert 3 P1 proofs in Proofs.lean (-10 lines)
4. `fc668cb` Simplify 2 iff proofs in Rule.lean (-14 lines)
5. `00f89d9` Compress 1 proof in Glob.lean (-1 line)
