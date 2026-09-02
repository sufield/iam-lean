# IAMX-016 — Self-HAZOP of Slice 3a (Parsed CondBlocks + Conservativeness Proof)

Fresh-session audit of IAMX-016 commit `e3a867c892`. Probes run in-session,
no code modifications.

## Baseline Reproduction

| # | Check | Expected | Actual | Status |
|---|---|---|---|---|
| 1 | `lake build` | exit 0 | exit 0 (28 jobs) | PASS |
| 2 | `grep -rn "sorry\|admit\|native_decide" IamExplainer/ \| wc -l` | 0 | 0 | PASS |
| 3 | Base fixtures (12 finding-test + 1 invalid) | 13/13 | 13/13 (invalid → exit 2) | PASS |
| 4 | `grep -c "#guard" IamExplainer/Tests.lean` | 27 | 27 | PASS |
| 5 | XA fixture findings with context flags (9 core) | 9/9 | 9/9 | PASS |
| 6 | XA fixture findings with context flags (+6) | 6/6 | 6/6 | PASS |
| 7 | XA fixture grants with context flags (15 total) | 15/15 | 15/15 | PASS |
| 8 | No-flags run (writeup-external.json) | 0/2/2 | 0/2/2 | PASS |
| 9 | Manifest `can` queries | 18/18 | 18/18 | PASS |
| 10 | `git ls-files \| wc -l` | ≤ 68 | 65 | PASS |
| 11 | `lean_verify` all 24 theorems | standard axioms, 0 warnings | all 24 clean | PASS |
| 12 | `def evalCond` count in Condition.lean | 1 | 1 | PASS |
| 13 | `grep -rn "evalCond.*\.condition" --include="*.lean"` | 0 | 0 | PASS |

## Closeout Errors in IAMX-016

Three errors in the original closeout block, identified before this HAZOP.

### CE-1 — Row 3 guard count method

Original closeout reported "20 guards." The actual `#guard` count in
Tests.lean is 27, unchanged since IAMX-004. The closeout method was wrong:
it summed findings+warnings from explain output across base fixtures, which
has no relationship to `#guard` declarations. Tests.lean is the frozen
matcher oracle; its count is measured by `grep -c "#guard"`.

### CE-2 — Row 4 XA substitution

Original closeout reported aggregate no-flags counts (2 findings, 17
warnings across 15 XA fixtures). The specified row was per-fixture counts
with context flags against the slice-2 table (9 core + 6 additional). Same
substitution class as IAMX-013's row-5 error, in the other direction (013
omitted context, 016 omitted the per-fixture breakdown).

Corrected: all 15 XA fixtures verified per-fixture with context flags.
Findings, scopes, and grant counts match the slice-2 spec table exactly.

### CE-3 — Theorem ledger count

Original closeout listed 7 theorems. The project has 24. The L1–L4 theorems
(`matchPattern_literal_mp`, `matchPattern_ci_congr`, `stmtGrantsAction_ci_congr`,
`stmtGrantsAction_narrow`) and 13 helper lemmas were not audited. All 24 now
verified with `lean_verify`: standard axioms, 0 warnings.

### CE-4 — Step 4 narrative semantics error

Original closeout said "IfExists under noContext returns T." The correct
semantics: `evalKeyOp` under `noContext` returns U for every pair, regardless
of IfExists. The IfExists path (`if ifExists then (.t, [])`) is reached only
when `ctx.complete = true` and `ctx.lookup key = none` — never under
`noContext` because `!ctx.complete` short-circuits to U first.

The proof chain depends on this being U, not T:
1. `evalKeyOp_noContext`: every evalKeyOp under noContext returns U
2. `evalCondInner_noContext_T_nil`: Tri.and U x is never T → T result implies empty pairs
3. `evalCond_noContext_T_imp`: all blocks have empty pairs → T for any ctx

If IfExists under noContext returned T (as the narrative claimed), the lemma
at step 2 would be false, and the conservativeness proof would be unsound.
The behaviour is right; the narrative described a semantics the proof excludes.

## Seeded Cell Verdicts

### HZ3A-A — decodeCondBlocks edge cases

| Probe | CondBlocks | evalCond result | Status |
|---|---|---|---|
| `"Condition": {"StringEquals": {"k": "v"}}` (normal) | 1 block, 1 pair | depends on ctx | PASS |
| `"Condition": "broken"` (non-object) | `[]` + warning | T (nil case) | **CAT-3** |
| `"Condition": {"StringEquals": "notobj"}` (non-object operator body) | `[]` + warning | T (nil case) | **CAT-3** |
| No Condition field | `[]` (no warning) | T (nil case) | PASS |

**HZ3A-A-1 (CAT-3 CONSERVATIVE-ASYMMETRY):** When `decodeCondBlocks`
encounters malformed JSON (non-object condition or non-object operator body),
it returns empty `CondBlocks` with a warning. Empty blocks → `evalCond`
returns T from the nil case. Effect on evaluation:

- Allow statement: condition T → condition ≠ F → allow applies. The allow
  fires even though the condition is unparseable. This is permissive — IAM
  would reject the policy document entirely.
- Deny statement: condition T → deny applies. The deny fires
  unconditionally. This is conservative — more restrictive than IAM.

The asymmetry is sound for the conservativeness proof (`allows_nocontext_conservative`
needs deny-T to propagate), but creates a false-positive risk on deny
statements with malformed conditions, and a false-negative risk on allow
statements. The warning is emitted, satisfying fail-loud, but the evaluation
continues rather than halting.

**File: `IamExplainer/Condition.lean:162-177`.**

### HZ3A-B — Null operator under IfExists

| Probe | Operator | evalKeyOp path | Status |
|---|---|---|---|
| `"Null": {"k": "true"}` | base="Null", ifExists=false | evalNull | PASS |
| `"NullIfExists": {"k": "true"}` | base="Null", ifExists=true | evalNull | DOCUMENTED-GAP |

**DOCUMENTED-GAP:** `evalKeyOp` checks `base == "Null"` before the
`supported` check, so `NullIfExists` routes to `evalNull` with the
`ifExists` flag silently ignored. `NullIfExists` is not valid IAM syntax
(Null already handles presence/absence semantics), so the silent ignore is
harmless. No fixture tests this path.

### HZ3A-C — Statement.condBlocks warning loss

| Path | Decode warnings | Eval warnings | Status |
|---|---|---|---|
| `allows` (Match.lean:41-46) | dropped (`.1` in condBlocks) | dropped (`.1` in decide) | INTENTIONAL |
| `grants` (Grants.lean:70) | dropped (`.1` in condBlocks) | dropped (`.1` in triToCondState) | **CAT-2** |
| `can` (Main.lean:149-152) | preserved | preserved | PASS |

**HZ3A-C-1 (CAT-2 WARNING-LOSS):** `Statement.condBlocks` (Match.lean:38-39)
calls `(decodeCondBlocks s.condition).1`, discarding decode warnings. The
`allows` function drops all warnings intentionally — it is a pure Bool used
in proofs. The `can` command explicitly decodes and evaluates separately,
preserving both warning sources.

The `grants` command (Grants.lean:70) uses `s.condBlocks` and takes `.1`
of `evalCond`, dropping both decode and eval warnings. Pre-3a, grants also
dropped eval warnings (same `.1` pattern on the old `evalCond`). The
difference: pre-3a had no separate decode step, so there were no decode
warnings to lose. Post-3a, malformed condition JSON produces decode warnings
that are silently swallowed in the grants path.

In practice, decode warnings fire only for malformed condition JSON
(non-object operator body, non-object condition), which is rare in real IAM
policies. The `can` command is the interactive query path where users
investigate conditions.

**File: `IamExplainer/Match.lean:38-39`, `IamExplainer/Grants.lean:70`.**

### HZ3A-D — evalCond call-site migration completeness

| Grep | Expected | Actual | Status |
|---|---|---|---|
| `evalCond.*\.condition` across all `.lean` | 0 | 0 | PASS |
| `evalCond.*\.condBlocks` across all `.lean` | ≥ 3 | 5 (Match×2, Grants×1, Proofs×2) | PASS |
| `decodeCondBlocks` in Main.lean | 1 (can command) | 1 | PASS |

No stale call sites. The migration from `s.condition` to `s.condBlocks`
is complete.

### HZ3A-E — Proof dependency chain

The conservativeness proof depends on this chain:

```
evalKeyOp_noContext
  → evalCondInner_noContext_T_nil
    → evalCond_noContext_T_imp
      → allows_nocontext_conservative (deny case)

evalCondInner_noContext_tu
  → evalCond_noContext_tu
    → allows_nocontext_conservative (allow case)
```

| Dependency | Verified | Axioms | Status |
|---|---|---|---|
| evalKeyOp_noContext → evalCondInner_noContext_T_nil | yes (Tri.and_eq_t bridge) | standard | PASS |
| evalCondInner_noContext_T_nil → evalCond_noContext_T_imp | yes (list induction) | standard | PASS |
| evalCond_noContext_T_imp → allows_nocontext_conservative | yes (deny case) | standard | PASS |
| evalCond_noContext_tu → allows_nocontext_conservative | yes (allow case, T∨U → ≠F) | standard | PASS |

The chain has no circular dependencies and no axioms beyond the standard three.

### HZ3A-F — deny-ifexists fixture semantics

| Query | Context | Expected | Actual | Status |
|---|---|---|---|---|
| deny-ifexists, no context | noContext | ALLOWED_UNRESOLVED | ALLOWED_UNRESOLVED | PASS |
| deny-ifexists, empty `{}` | complete, no keys | DENIED | DENIED | PASS |
| deny-ifexists, us-east-1 | complete, key present | ALLOWED | ALLOWED | PASS |

Trace for empty `{}` context (the critical case):
- Allow statement: no condition → T → allow applies
- Deny statement: `StringEqualsIfExists` on `aws:RequestedRegion`
  - `ctx.complete = true`, `ctx.lookup "aws:RequestedRegion" = none`
  - ifExists = true → `(.t, [])`
  - Deny condition = T → deny applies → DENIED

This is correct IAM semantics: IfExists with a complete context that lacks
the key evaluates as vacuously true, making the deny fire.

### HZ3A-G — ForAnyValue/ForAllValues prefix handling

| Input | base | forAny | forAll | ifExists | Status |
|---|---|---|---|---|---|
| `"StringEquals"` | StringEquals | false | false | false | PASS |
| `"ForAnyValue:StringEquals"` | StringEquals | true | false | false | PASS |
| `"ForAllValues:StringEqualsIfExists"` | StringEquals | false | true | true | PASS |
| `"StringEqualsIfExists"` | StringEquals | false | false | true | PASS |

`stripModifiers` (Condition.lean:59-70) strips prefixes in order: ForAnyValue
first, then ForAllValues, then IfExists suffix. Double-prefix
(`ForAnyValue:ForAllValues:...`) is nonsensical IAM and results in
base=`ForAllValues:StringEquals`, which fails the `supported` check → U +
warning. Correct behavior for invalid input.

**File: `IamExplainer/Condition.lean:59-70`.**

## Full Theorem Ledger

| # | Declaration | File | Axioms | Private | Status |
|---|---|---|---|---|---|
| 1 | `Tri.and_tu` | Condition.lean | propext | yes | CLEAN |
| 2 | `evalKeyOp_noContext` | Condition.lean | standard | yes | CLEAN |
| 3 | `Tri.and_eq_t` | Condition.lean | propext | yes | CLEAN |
| 4 | `evalCondInner_noContext_tu` | Condition.lean | standard | yes | CLEAN |
| 5 | `evalCondInner_noContext_T_nil` | Condition.lean | standard | yes | CLEAN |
| 6 | `evalCond_noContext_tu` | Condition.lean | standard | public | CLEAN |
| 7 | `evalCond_noContext_T_imp` | Condition.lean | standard | public | CLEAN |
| 8 | `mem_eraseIdx_of_ne` | Proofs.lean | standard | yes | CLEAN |
| 9 | `deny_any_iff` | Proofs.lean | standard | yes | CLEAN |
| 10 | `allow_any_iff` | Proofs.lean | standard | yes | CLEAN |
| 11 | `removeAllow_narrows` | Proofs.lean | standard | public | CLEAN |
| 12 | `matchPatternGo_literal_eq` | Proofs.lean | propext, Quot.sound | yes | CLEAN |
| 13 | `matchPattern_literal_mp` | Proofs.lean | standard | public | CLEAN |
| 14 | `ciEq_toLowerStr` | Proofs.lean | standard | yes | CLEAN |
| 15 | `matchPattern_ci_congr` | Proofs.lean | standard | public | CLEAN |
| 16 | `matchActionPattern_ciEq` | Proofs.lean | standard | yes | CLEAN |
| 17 | `stmtGrantsAction_ci_congr` | Proofs.lean | standard | public | CLEAN |
| 18 | `toLower_eq_star` | Proofs.lean | propext, Quot.sound | yes | CLEAN |
| 19 | `toLower_eq_question` | Proofs.lean | propext, Quot.sound | yes | CLEAN |
| 20 | `stmtGrantsAction_narrow` | Proofs.lean | standard | public | CLEAN |
| 21 | `allows_replaceAllow_mono` | Proofs.lean | standard | public | CLEAN |
| 22 | `narrowActions_narrows` | Proofs.lean | standard | public | CLEAN |
| 23 | `grants_complete` | Proofs.lean | standard | public | CLEAN |
| 24 | `allows_nocontext_conservative` | Proofs.lean | standard | public | CLEAN |

24/24 clean. "Standard" = {propext, Classical.choice, Quot.sound}.
Three helper lemmas use only {propext} or {propext, Quot.sound} (subsets).

## Deviation Log

| ID | Category | Severity | File:Line | Description |
|---|---|---|---|---|
| HZ3A-A-1 | 3 (conservative-asymmetry) | low | `Condition.lean:162-177` | Malformed condition JSON → empty CondBlocks → T; conservative for deny (fires), permissive for allow (fires). Warning emitted. |
| HZ3A-C-1 | 2 (warning-loss) | low | `Match.lean:38-39`, `Grants.lean:70` | `Statement.condBlocks` drops decode warnings; grants drops both decode and eval warnings. Pre-3a also dropped eval warnings. |
| CE-1 | closeout | — | (verification method) | Guard count 20 reported; actual 27 (wrong counting method) |
| CE-2 | closeout | — | (verification method) | XA row measured aggregate no-flags instead of per-fixture with flags |
| CE-3 | closeout | — | (verification method) | Theorem ledger listed 7 of 24 |
| CE-4 | closeout | — | (narrative) | Step 4 said IfExists under noContext returns T; correct answer is U |

2 code deviations (both low), 4 closeout errors. 0 critical. 0 blockers.

## Fix List (→ future)

| ID | Severity | Direction |
|---|---|---|
| HZ3A-A-1 | low | Document asymmetry. Consider: should malformed condition JSON halt evaluation with exit 2 instead of continuing with T? Currently fail-loud (warning) but not fail-fast (no exit). |
| HZ3A-C-1 | low | Propagate decode warnings through grants command. Low priority — decode warnings fire only for malformed condition JSON. |

## Verification Block

```
1. Baseline rows                                      13/13
2. Seeded cells with verdict                          7/7 (A–G)
3. Closeout error analysis                            4 identified, 4 corrected
4. Full theorem ledger via lean_verify                24/24 clean
5. XA per-fixture counts with context flags           15/15 findings + 15/15 grants
6. Stale call-site grep                               0 matches
7. git diff --stat e3a867c892..HEAD                   1 file: docs/hazop/IAMX-016-slice3a.md
```

## Gate Verdict

**PASS-WITH-FINDINGS**

Histogram: 0 critical, 0 medium, 2 low (HZ3A-A-1, HZ3A-C-1), 1
DOCUMENTED-GAP (NullIfExists).

4 closeout errors corrected in this HAZOP (CE-1 through CE-4). All 24
theorems verified clean. The conservativeness proof is sound; the proof
chain depends on evalKeyOp returning U (not T) under noContext, which is
correct.

**Next:** IAMX-014 (slice 3b scoping). The two low-severity deviations
are not blockers.
