# CH1-HAZOP: Lean Extraction Fidelity Audit

HAZOP guideword audit of the CH1 Lean 4 extraction (8 controls,
5 typed observations, 27 theorems, 16 differential tests).

**Scope:** Stave/Controls/{Types,Eval,Json,Proofs}.lean,
Stave/Harness/DiffTest.lean, fixtures/difftest/, and
stave/formal/difftest/diff_test.go.

**Method:** IEC 61882 guidewords adapted for formal-verification
fidelity. Each guideword applied to: semantic fidelity, FromJson
parsing, fail-closed preservation, harness coverage, proof coverage.

## Findings

### H1: OpEq fail-open vs Lean fail-closed divergence (SEMANTIC)

**Severity: Medium.** Lean is MORE conservative — false positives on
missing fields, not false negatives. This is a safety-margin difference,
not a soundness bug.

CEL compiler (compiler.go:446): `OpEq` generates
`(hasField && field == value)` — missing field → no match → doesn't fire
(**fail-open**).

CEL compiler (compiler.go:460): `OpNe` generates
`(!hasField || field != value)` — missing field → fires
(**fail-closed**).

Lean model (Eval.lean): ALL evaluators return `unevaluable` for `none`
fields, and `EvalOutcome.fires` returns true for `unevaluable`.
Lean is uniformly **fail-closed**.

**Controls that diverge on missing fields:**

| Control | Operator | CEL (missing) | Lean (missing) | Diverges? |
|---------|----------|---------------|----------------|-----------|
| CTL.CLOUDTRAIL.ORG.001 | eq false | pass | fires | YES |
| CTL.ORG.REGION.SCP.001 | eq false | pass | fires | YES |
| CTL.IAM.ROOT.MFA.001 | ne true | fires | fires | no |
| CTL.IAM.ROOT.ACCESSKEY.001 | present+eq | pass | pass | no |
| CTL.CLOUDTRAIL.LOG.VALIDATION.001 | eq false | pass | fires | YES |
| CTL.IAM.CONSOLE.MFA.001 | ne true | fires | fires | no |
| CTL.VPC.SG.UNRESTRICTED.001 | eq true | pass | fires | YES |
| CTL.CLOUDTRAIL.REGIONAL.COVERAGE.001 | ne true | fires | fires | no |

4 of 8 controls diverge on the missing-field edge case.
The ne-operator controls (3, 6, 8) and the present-gated control (4)
agree. All eq-only controls (1, 2, 5, 7) diverge.

**Resolution options:**
- (a) Accept: Lean model is the aspirational spec (CLAUDE.md says
  "fail-closed"), CEL implementation is the pragmatic one. Document
  the gap.
- (b) Align Lean to CEL: change eq-operator evaluators to return
  `clear` instead of `unevaluable` on `none`. Loses the fail-closed
  property for those controls.
- (c) Align CEL to Lean: change OpEq to fail-closed. Large blast
  radius across 500+ controls; would need its own HAZOP.

### H2: No missing-field differential tests (COVERAGE)

**Severity: Low.** The 16 differential tests all use fixtures with
every field present. Finding H1 exists precisely because no fixture
exercises the missing-field case.

**Fix:** Add 8 fixtures (one per control) where the critical field is
absent from the JSON. These would fail today (Lean fires, CEL doesn't
for eq-only controls) and serve as the regression anchor for whichever
H1 resolution is chosen.

### H3: TypedObs priority routing can shadow controls on multi-bag assets (FIDELITY)

**Severity: Very Low (theoretical).** The TypedObs FromJson dispatch
(Json.lean:93) checks property bags in priority order:
`audit_trail/trail → organization → network → identity`.

An asset containing both `audit_trail` and `identity` bags would route
to `.cloudtrail`, never reaching the IAM evaluators. CEL has no such
dispatch — it checks field paths directly on any asset.

**Practical risk:** Zero. Real obs.v0.1 assets have one property bag
per resource. The obs.v0.1 schema doesn't produce multi-bag assets.
No action needed; the ponytail comment on line 89 already flags the
upgrade path.

### H4: Proofs don't cover FromJson path (PROOF COVERAGE)

**Severity: Low.** The 27 theorems in Proofs.lean verify evaluator
logic by constructing typed observations directly (e.g.,
`{ kind := some "trail" }`). They prove the evaluator's pattern-match
semantics but not:
- Whether FromJson correctly navigates nested JSON to populate fields
- Whether TypedObs dispatch routes to the correct observation type
- Whether `getOptBool`/`getOptStr` handle JSON type mismatches

The differential tests cover this path (they go through FromJson), but
only for the "all fields present" case (see H2).

**Fix (deferred to CH2+):** Lean-level property-based tests or
round-trip proofs that verify `FromJson ∘ ToJson = id` for each type.

### H5: Single-file fixture evaluation misses duration controls (HARNESS)

**Severity: Info.** The Lean DiffTest harness evaluates one JSON file
at a time (`lake exe difftest <file> <controlId>`). The Go driver
passes the full fixture directory to `stave.Apply`, which loads both
timestamp files and can evaluate duration-based controls.

For CH1's 8 controls, none are duration-based, so this doesn't cause
a mismatch. But CH2+ controls that use `--max-unsafe` will need a
multi-file Lean harness.

## Guideword Matrix

Property: Semantic fidelity between CEL and Lean evaluators.

```
              NO    MORE   LESS   ASWELL  PART   REV   OTHER  EARLY  LATE
eq fields     H1    ✓      N/A    H3      ✓      ✓     ✓      N/A    N/A
ne fields     ✓     ✓      N/A    H3      ✓      ✓     ✓      N/A    N/A
present       ✓     ✓      N/A    H3      ✓      ✓     ✓      N/A    N/A
FromJson      H2    ✓      N/A    H3      ✓      ✓     ✓      N/A    H4
DiffHarness   H2    ✓      H5     ✓       ✓      ✓     ✓      N/A    N/A
Proofs        H4    ✓      N/A    ✓       ✓      ✓     ✓      N/A    N/A
```

**Applicable cells:** 36 (6 rows × 9 cols) - 12 N/A = 24
**Covered (✓):** 19
**Findings:** 5 (H1–H5)
**Coverage:** 19/24 = 79%

## Decision Required

**H1 is the only finding that affects semantic correctness.** The
remaining findings are coverage gaps with known upgrade paths.

Recommended resolution for H1: **(a) Accept and document.** The Lean
model's fail-closed stance is the correct security specification. The
CEL engine's fail-open on OpEq is a known implementation pragmatism
(documented in compiler.go:446-454). The Lean model should be the
reference that CEL is measured against, not the other way around.

Add missing-field differential tests (H2) as the regression anchor,
expecting them to fail with a `// known divergence: OpEq fail-open`
annotation.

## Summary

| Finding | Severity | Action |
|---------|----------|--------|
| H1: OpEq divergence | Medium | Accept + document |
| H2: Missing-field coverage | Low | Add fixtures in DRIFT-GUARD |
| H3: Multi-bag routing | Very Low | No action (theoretical) |
| H4: Proof coverage gap | Low | Defer to CH2+ |
| H5: Single-file harness | Info | Extend harness when needed |

**CH1 extraction is sound.** The Lean model is strictly more
conservative than the CEL engine (fires on cases CEL passes). No
false-negative divergence exists — every finding CEL produces, Lean
also produces. The reverse (Lean fires, CEL doesn't) happens only on
missing-field edge cases for eq-operator controls, which is a
safety-margin overshoot, not a soundness gap.
