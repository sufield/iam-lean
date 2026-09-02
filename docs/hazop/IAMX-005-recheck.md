# IAMX-005 — Recheck of IAMX-002 Deviations

**Audit target:** commit `a3b648b`
**Date:** 2026-08-31
**Scope:** Verify all 13 IAMX-002 deviations are resolved before dependency audit (IAMX-007).

---

## Baseline

| Check | Expected | Actual | Match |
|---|---|---|---|
| `lake build` | exit 0 | exit 0 | YES |
| sorry/admit count | 0 | 0 | YES |
| `#guard` count | 27 | 27 | YES |
| Public theorem count | 7 | 7 | YES |
| Total theorem count (public + private) | 13 | 13 | YES |
| Axiom check (all 7 public) | standard only | propext, Classical.choice, Quot.sound | YES |

---

## Fixture Verification

All counts match `docs/spec/slice1.md` expected-counts table.

| Fixture | Expected | Actual | Match |
|---|---|---|---|
| writeup-wildcards | 3 / exit 1 | 3 / exit 1 | YES |
| remediated-wildcards | 0 / exit 0 | 0 / exit 0 | YES |
| partial-wildcards | 1 / exit 1 | 1 / exit 1 | YES |
| writeup-complement | 3 / exit 1 | 3 / exit 1 | YES |
| remediated-complement | 0 / exit 0 | 0 / exit 0 | YES |
| partial-complement | 2 / exit 1 | 2 / exit 1 | YES |
| writeup-passrole | 2 / exit 1 | 2 / exit 1 | YES |
| remediated-passrole | 0 / exit 0 | 0 / exit 0 | YES |
| partial-passrole | 1 / exit 1 | 1 / exit 1 | YES |
| writeup-passrole-viawildcard | 3 / exit 1 | 3 / exit 1 | YES |
| writeup-notaction-passrole | 3 / exit 1 | 3 / exit 1 | YES |
| partial-notaction-passrole | 2 / exit 1 | 2 / exit 1 | YES |
| bad-effect | — / exit 2 | — / exit 2 | YES |

13/13 fixtures match.

---

## Deviation Recheck

| HZ-ID | Severity | IAMX-002 Finding | Resolution | Status |
|---|---|---|---|---|
| HZ-00 | NOTE | Self-certified deviation in spec table | Spec table amended (writeup-wildcards=3 under ratified semantics); theorem count corrected to 13 (7 public + 6 private) | RESOLVED |
| HZ-01 | HIGH | PASSROLE fires on writeup-wildcards (stale spec) | Spec ratified with PASSROLE semantic matching; `writeup-passrole-viawildcard` fixture added for `iam:*` | RESOLVED |
| HZ-02 | CRITICAL | PASSROLE fail-open on NotAction escape | `stmtGrantsAction` (Match.lean:42-46) handles NotAction complement: `!(nacts.any (matchActionPattern · action))`. Fixtures `writeup-notaction-passrole` (3 findings) and `partial-notaction-passrole` (2 findings) pin the behavior | RESOLVED |
| HZ-03 | MODERATE | Deny interplay ambiguity | Spec documents: "Controls fire per-statement. A Deny statement in the same policy does not suppress findings on Allow statements." (slice1.md:32-33) | RESOLVED |
| HZ-04 | CRITICAL | `narrowActions_narrows` does not exist | Theorem exists at Proofs.lean:212-229. Well-founded recursion on `(ps.length + vs.length, vs.length)` replaces fuel parameter. Verified: standard axioms only | RESOLVED |
| HZ-05 | HIGH | CLOSED theorems in Proofs.lean (tests in wrong module) | Tests.lean exists with 27 `#guard` statements. Proofs.lean has 0 `native_decide` calls | RESOLVED |
| HZ-06 | HIGH | Tests.lean missing | `IamExplainer/Tests.lean` exists, 27 `#guard` statements (spec requires ≥ 6) | RESOLVED |
| HZ-07 | NOTE | Theorem count grep inflated | Accurate count: 13 declarations (7 public theorems, 6 private theorems). No comment false-positives | RESOLVED |
| HZ-08 | NOTE | SERVICEWILDCARD under-detection on partial wildcards | Documented as known gap in spec (slice1.md:43-45) | RESOLVED |
| HZ-09 | HIGH | Silent type coercion drops (.toOption) | `tryField` (Policy.lean:48-54) replaces `.toOption` for Action/NotAction/Resource/NotResource parsing; type mismatches produce `ParseWarning` | RESOLVED |
| HZ-10 | HIGH | Action+NotAction both present: silent acceptance | Warning emitted at Policy.lean:76: "Action and NotAction are mutually exclusive". Same for Resource+NotResource (line 78) | RESOLVED |
| HZ-11 | MODERATE | Missing Resource key: silent pass | Warning emitted at Policy.lean:80: "Allow without Resource (required in identity-based policies)" | RESOLVED |
| HZ-12 | NOTE | Duplicate Sids: no warning | Warning emitted at Policy.lean:112: `Duplicate Sid "{sid}" at statement {i}` | RESOLVED |

13/13 deviations resolved.

---

## Key Structural Fixes Since IAMX-002

1. **Matcher rewrite** (HZ-04 blocker): `matchPatternGo` uses well-founded
   recursion on `(ps.length + vs.length, vs.length)` with `matchPatternGo.induct`
   for proofs. No fuel parameter, no `.go` inner function.

2. **Proof chain L1→L6**: 7 public theorems build a complete narrowing proof
   from literal match (L1) through the gate theorem (L6). All use only
   `propext`, `Classical.choice`, `Quot.sound`.

3. **`stmtGrantsAction` unification** (HZ-02): Single function handles both
   Action and NotAction paths, consumed by both `checkPassRole` and `allows`.

4. **Parser warnings** (HZ-09/10/11/12): `tryField` + explicit validation
   replaces silent `.toOption` drops.

---

## Verdict

**PASS**

All 13 IAMX-002 deviations resolved. Both CRITICAL gates cleared:
- HZ-02: NotAction PASSROLE detection confirmed by 2 pinning fixtures.
- HZ-04: `narrowActions_narrows` exists, verified with standard axioms only.

IAMX-007 (cslib/Mathlib feasibility audit) precondition satisfied.
