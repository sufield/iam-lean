# IAMX-007 — cslib / Mathlib Feasibility Audit

**Audit target:** commit `a3b648b`
**Date:** 2026-08-31
**Precondition:** IAMX-005 PASS (verified)
**Spike:** `../cslibspike/` (sibling directory, `lake new cslibspike`)
**cslib version:** `v4.33.1` (pinned tag, not `rev = "main"`)

---

## 1. LOC Baseline

| File | Lines | Category |
|---|---|---|
| IamExplainer/Match.lean | 65 | mixed |
| IamExplainer/Proofs.lean | 229 | mixed |
| IamExplainer/Tests.lean | 67 | NO-SUBSTITUTE |
| IamExplainer/Checks.lean | 166 | NO-SUBSTITUTE |
| IamExplainer/Policy.lean | 117 | NO-SUBSTITUTE |
| IamExplainer/Report.lean | 61 | NO-SUBSTITUTE |
| Main.lean | 43 | NO-SUBSTITUTE |
| **Total** | **748** | |

### Partition

| Category | Lines | Content |
|---|---|---|
| REPLACEABLE-CANDIDATE | 145 | Matcher functions (29), matcher/list lemmas (116) |
| NO-LIBRARY-SUBSTITUTE | 603 | JSON decode, controls, report, CLI, domain proofs, tests |

**Breakdown of REPLACEABLE-CANDIDATE (145 lines):**

- Match.lean 8–36 (29 lines): `toLowerStr`, `matchPatternGo`, `matchPattern`,
  `matchActionPattern`, `matchResourcePattern`
- Proofs.lean 9–29 (21 lines): `mem_eraseIdx_of_ne` (list membership after eraseIdx)
- Proofs.lean 69–163 (95 lines): `ciEq`, `matchPatternGo_literal_eq`,
  `matchPattern_literal_mp`, `ciEq_toLowerStr`, `matchPattern_ci_congr`,
  `matchActionPattern_ciEq`, `toLower_eq_star`, `toLower_eq_question`,
  `stmtGrantsAction_narrow`

---

## 2. Declaration Inventory

### Match.lean

| Declaration | Lines | Span | Replaceable? |
|---|---|---|---|
| `toLowerStr` | 8–9 | 2 | YES (stdlib `String.map Char.toLower`) |
| `matchPatternGo` | 11–27 | 17 | NO (see §4) |
| `matchPattern` | 29–30 | 2 | NO (wraps matchPatternGo) |
| `matchActionPattern` | 32–33 | 2 | NO (toLowerStr + matchPattern) |
| `matchResourcePattern` | 35–36 | 2 | NO (= matchPattern) |
| `Request` | 38–40 | 3 | NO (domain type) |
| `stmtGrantsAction` | 42–46 | 5 | NO (domain logic) |
| `actionMatches` | 48–49 | 2 | NO (= stmtGrantsAction) |
| `resourceMatches` | 51–55 | 5 | NO (domain logic) |
| `stmtMatches` | 57–58 | 2 | NO (domain logic) |
| `allows` | 60–65 | 6 | NO (domain logic) |

### Proofs.lean

| Declaration | Lines | Span | Replaceable? |
|---|---|---|---|
| `Policy.removeStmt` | 6–7 | 2 | NO (domain) |
| `mem_eraseIdx_of_ne` (private) | 9–29 | 21 | PARTIAL (see §4) |
| `removeAllow_narrows` | 31–67 | 37 | NO (domain proof) |
| `ciEq` | 69–70 | 2 | YES (trivial, depends on toLowerStr) |
| `matchPatternGo_literal_eq` (private) | 72–76 | 5 | NO (functional induction on our matchPatternGo) |
| `matchPattern_literal_mp` (L1) | 78–85 | 8 | NO (depends on matchPatternGo_literal_eq) |
| `ciEq_toLowerStr` (private) | 87–89 | 3 | YES (trivial simp) |
| `matchPattern_ci_congr` (L2) | 91–96 | 6 | NO (depends on matchActionPattern) |
| `matchActionPattern_ciEq` (private) | 98–101 | 4 | NO (depends on matchActionPattern) |
| `stmtGrantsAction_ci_congr` (L3) | 103–108 | 6 | NO (domain) |
| `toLower_eq_star` (private) | 110–123 | 14 | NO (wildcard char preservation) |
| `toLower_eq_question` (private) | 125–138 | 14 | NO (wildcard char preservation) |
| `stmtGrantsAction_narrow` (L4) | 140–163 | 24 | NO (domain) |
| `allows_replaceAllow_mono` (L5) | 165–210 | 46 | NO (domain) |
| `narrowActions_narrows` (L6) | 212–229 | 18 | NO (gate theorem) |

---

## 3. Toolchain & Cost Table

| Metric | Value |
|---|---|
| Repo toolchain | `leanprover/lean4:v4.33.1` |
| cslib v4.33.1 toolchain | `leanprover/lean4:v4.33.1` |
| **Toolchain delta** | **0 (identical)** |
| `lake update` + cache download | 2m 38s |
| `lake build` (full import, from cache) | ~9 min (first build); ~2.4s (warm) |
| `.lake` size (repo, no Mathlib) | 234 MB |
| `.lake` size (spike, with Mathlib) | **7.5 GB** (32× increase) |
| LSP startup, `import Cslib` (warm) | ~2.4s |
| LSP startup, `import Mathlib.Computability.RegularExpressions` (warm) | ~1.2s |
| Network transfer (cache) | ~8690 files from lakecache.blob.core.windows.net |

---

## 4. Mapping Table

### 4a. Matcher replacement: `matchPatternGo` → Mathlib `RegularExpression.rmatch`

**Status: NOT VIABLE**

Mathlib's `RegularExpression α` has constructors: `zero`, `epsilon`, `char a`,
`union`, `comp` (concatenation), `star`. There is **no "any character" (dot)
constructor**.

IAM glob semantics:
- `*` = match any sequence of characters (including empty)
- `?` = match any single character

Both require expressing "any character" as a `RegularExpression Char`.
The only option is `union` over all valid `Char` values (~143,859 Unicode
codepoints). This is:
1. **Computationally impractical** for `rmatch` evaluation
2. **Proof-impractical** — every lemma about the compiled regex would need to
   reason about a 143K-way union
3. **Semantically wrong** — our glob matcher is a direct structural recursion,
   not a regex compilation; functional induction (`matchPatternGo.induct`) gives
   us proofs for free that a regex compilation layer would require re-proving

**Verified by `#check`:**
- `@RegularExpression.rmatch` ✓ (exists, type: `RegularExpression α → List α → Bool`)
- `@RegularExpression.matches'` ✓ (exists, `Language α`)
- `@RegularExpression.star` ✓
- `@RegularExpression.char` ✓
- No `dot`, `anyChar`, or `wildcard` constructor exists

**Lines removed:** 0
**Glue lines added:** ~30+ (glob-to-regex compiler with 143K-union anyChar)
**Net delta:** +30 or more
**#check status:** VERIFIED (constructors exist; no dot constructor — NOT-FOUND)

### 4b. Matcher replacement: `matchPatternGo` → cslib automata

**Status: NOT VIABLE**

cslib's `DA` (deterministic automaton) and `NA` (nondeterministic automaton)
are theoretical structures for language-theory proofs:
- `DA.FinAcc` provides word acceptance, but constructing a DFA from a glob
  pattern requires a full NFA→DFA construction pipeline
- The automata use `ωSequence` (infinite sequences) internally
- No "compile glob to automaton" or "compile regex to automaton" function exists

The effort to build a glob→NFA→DFA pipeline with proven correctness would
exceed the entire current codebase (748 lines).

**Lines removed:** 0
**Glue lines added:** 200+ (conservative estimate for glob→NFA→DFA + correctness proof)
**Net delta:** +200 or more
**#check status:** `DA`, `NA`, `DA.FinAcc` — NOT-FOUND under expected names
(cslib uses module-scoped `@[expose] public section` — names not directly accessible)

### 4c. `mem_eraseIdx_of_ne` → Mathlib List lemma

**Status: NOT-FOUND**

Our theorem: if `x ∈ l` and `x ≠ l[i]` then `x ∈ l.eraseIdx i`.

Mathlib has:
- `List.eraseIdx_subset` ✓ — reverse direction (eraseIdx is subset of original)
- `List.mem_or_eq_of_mem_set` ✓ — for `set`, not `eraseIdx`
- `List.mem_eraseIdx` — NOT-FOUND
- `List.mem_eraseIdx_of_ne` — NOT-FOUND

No Mathlib lemma replaces our 21-line proof.

**Lines removed:** 0
**Lines added:** 0
**Net delta:** 0
**#check status:** NOT-FOUND

### 4d. `toLowerStr` / `ciEq` / `ciEq_toLowerStr`

**Status: TRIVIAL — NOT WORTH REPLACING**

These are 2 + 2 + 3 = 7 lines total. `toLowerStr` is `s.map Char.toLower`
(stdlib). `ciEq` and `ciEq_toLowerStr` are 2-line definitions/lemmas.
No Mathlib import needed for these.

**Lines removed:** 7
**Lines added:** 0 (use stdlib inline)
**Net delta:** -7

### 4e. `allows`, `stmtGrantsAction`, L3, L4, L6

**Status: NO CHANGE expected, confirmed**

These are domain-specific functions and theorems about IAM policy semantics.
No library could provide these.

**Lines removed:** 0
**Lines added:** 0
**Net delta:** 0

---

## 5. Mapping Summary

| Row | Declaration(s) | Library replacement | Lines removed | Lines added | Net | #check |
|---|---|---|---|---|---|---|
| 4a | matchPatternGo, matchPattern, matchActionPattern, matchResourcePattern + all matcher lemmas (L1, L2, toLower_star/question, stmtGrantsAction_narrow) | Mathlib RegularExpression.rmatch | 0 | 30+ | **+30** | VERIFIED (no dot constructor) |
| 4b | matchPatternGo → cslib DA/NA | cslib automata | 0 | 200+ | **+200** | NOT-FOUND |
| 4c | mem_eraseIdx_of_ne | Mathlib List.mem_eraseIdx_of_ne | 0 | 0 | 0 | NOT-FOUND |
| 4d | toLowerStr, ciEq, ciEq_toLowerStr | stdlib String.map | 7 | 0 | -7 | N/A (stdlib) |
| 4e | allows, stmtGrantsAction, L3, L4, L5, L6, removeAllow_narrows | none | 0 | 0 | 0 | N/A |
| **Total** | | | **7** | **30+** | **+23 or more** | |

**Net LOC delta: +23 or more** (increases, does not decrease)

---

## 6. Equivalence Testing

**Not performed.** The glob-to-regex compilation path (§4a) is not viable due to
the missing "any character" constructor. There is no library-backed matcher to
test the 27 pins against.

**Pins passing on library matcher:** 0/27 (no library matcher exists to test)

---

## 7. Proof-Impact Matrix

| Theorem | Under adoption | Effort (lines) |
|---|---|---|
| T1 `removeAllow_narrows` | UNCHANGED | 0 |
| L1 `matchPattern_literal_mp` | REPROVE (new matcher API) | 20+ |
| L2 `matchPattern_ci_congr` | REPROVE | 15+ |
| L3 `stmtGrantsAction_ci_congr` | UNCHANGED | 0 |
| L4 `stmtGrantsAction_narrow` | REPROVE (depends on L1) | 30+ |
| L5 `allows_replaceAllow_mono` | UNCHANGED | 0 |
| L6 `narrowActions_narrows` | UNCHANGED (depends on L4/L5 interface, not matcher) | 0 |
| `mem_eraseIdx_of_ne` (survivor) | UNCHANGED (no library replacement found) | 0 |
| `matchPatternGo_literal_eq` (survivor) | REPROVE (core of L1 proof) | 10+ |
| **Total re-proof effort** | | **75+ lines** |

Under adoption, 4 of 8 proofs need REPROVE. The functional induction lemma
`matchPatternGo.induct` — which our proofs use — would not exist for a
library-provided matcher. Re-proving over `RegularExpression.rmatch` semantics
would require building a glob-compile correctness theorem first (~30 lines),
then reproving L1/L2/L4/matchPatternGo_literal_eq over that theorem.

---

## 8. cslib-Module Consumer List

| cslib module (non-Mathlib) | Plausible consumer | Slice |
|---|---|---|
| `Cslib.Computability.Automata.DA` | Pattern subsumption (is glob A ⊆ glob B?) | slice 2 |
| `Cslib.Computability.Automata.NA` | NFA construction for glob patterns | slice 2 |
| `Cslib.Computability.Languages.RegularLanguage` | Prove glob language is regular | slice 2 |
| `Cslib.Computability.Languages.MyhillNerode` | Minimal DFA for patterns | slice 2 |
| `Cslib.Logics.Propositional` | (none — unrelated) | — |
| `Cslib.Foundations.*` | (none — general infrastructure) | — |

**Slice-1 consumers: 0.** All plausible consumers are slice-2 features
(pattern subsumption, overlap detection, minimal narrowing).

---

## 9. Cost Summary

| Dimension | Current (no lib) | With cslib/Mathlib |
|---|---|---|
| `.lake` size | 234 MB | 7.5 GB (+32×) |
| First build (cache download + build) | < 30s | ~12 min |
| Warm rebuild | < 1s | ~1–2s |
| LOC (matcher + proofs) | 145 | 168+ (+23) |
| Re-proof effort | 0 | 75+ lines |
| Toolchain delta | — | 0 |
| Narrow-import LSP startup | — | ~1.2s (warm) |

---

## Verdict

**REJECT**

Reasons:

1. **Net LOC delta > 0.** The mapping table shows +23 lines minimum. No row
   in the mapping removes more than it adds. The only deletion (4d: 7 trivial
   lines) is overwhelmed by the glob-to-regex glue (4a: +30 minimum).

2. **Pins: 0/27.** No library-backed matcher exists to test — Mathlib's
   `RegularExpression` lacks an "any character" constructor, making glob-to-regex
   compilation impractical over `Char`. cslib automata provide theoretical
   language constructions, not a drop-in decidable matcher.

3. **No slice-1 cslib consumer.** Every cslib module with a plausible consumer
   (automata, regular languages, Myhill-Nerode) targets slice-2 features.

4. **7.5 GB dependency for 0 lines removed.** The `.lake` grows 32× for a
   dependency that replaces nothing in the current codebase.

The current matcher (`matchPatternGo` with well-founded recursion) is the right
architecture for this problem: it gives us functional induction for proofs
(`matchPatternGo.induct`), handles IAM glob semantics directly (no compilation
step), and needs 0 bytes of external dependency.

**When to revisit:** IAMX-008 is moot. Revisit when slice-2 scoping requires
pattern subsumption (`glob A ⊆ glob B?`), overlap detection, or minimal
narrowing — these need regular-language theory that cslib's automata provide.
At that point, the cost (7.5 GB, reproof effort) is justified by the feature.

---

## Verification

```
1. LOC baseline rows = 7 files, total 748, subtotals 145 REPLACEABLE + 603 NO-SUBSTITUTE
2. Mapping rows: 4a VERIFIED (no dot), 4b NOT-FOUND, 4c NOT-FOUND, 4d N/A, 4e N/A
3. Pins passing on library matcher: 0/27 (no library matcher to test)
4. Cost table rows:
   - update + cache: 2m 38s
   - build (from cache): ~9 min first / ~2s warm
   - .lake size: 7.5 GB
   - LSP full-import start: ~2.4s warm
   - LSP narrow-import start: ~1.2s warm
   - toolchain delta: 0
   (7 rows, all measured)
5. Proof-impact rows: 8 (T1, L1, L2, L3, L4, L5, L6, mem_eraseIdx_of_ne + matchPatternGo_literal_eq)
6. cslib-module consumer list: 4 plausible (all slice-2), 0 slice-1
7. git diff: 2 files (docs/hazop/IAMX-005-recheck.md, docs/audits/IAMX-007-cslib.md)
8. Verdict: REJECT
```
