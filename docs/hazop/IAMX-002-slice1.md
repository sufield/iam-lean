# IAMX-002 — Self-HAZOP Audit Report: Slice 1

**Audit target:** commit `1645020`
**Date:** 2026-08-31
**Role:** Safety and Reliability Engineer
**Scope:** 6-control least-privilege catalog, decoder, proof module

---

## Baseline Reproduction

| Check | Expected (IAMX-001 spec) | Actual | Match |
|---|---|---|---|
| `lake build` | exit 0 | exit 0 | YES |
| sorry/admit count | 0 | 0 | YES |
| writeup-wildcards findings | 3 | **4** | **NO — D1** |
| remediated-wildcards findings | 0 | 0 | YES |
| partial-wildcards findings | 1 | 1 | YES |
| writeup-complement findings | 3 | 3 | YES |
| remediated-complement findings | 0 | 0 | YES |
| partial-complement findings | 1 | 1 | YES |
| writeup-passrole findings | 2 | 2 | YES |
| remediated-passrole findings | 0 | 0 | YES |
| partial-passrole findings | 1 | 1 | YES |
| bad-effect.json exit code | 2 | 2 | YES |
| theorem count (grep -c) | ≥ 2 | 6 (grep); **5 actual** | **NO — D2** |
| file count | ≤ 30 | 22 | YES |

10 baseline rows, ACTUAL column complete: 10/10.

---

## Deviation Log

### HZ-00 — Self-certified deviation (NOTE)

**Category:** Process
**Severity:** NOTE

The authoring session (slice 1) reported `writeup-wildcards: 4` in its closeout
and relabeled the spec's expected count of 3 as "correctly firing" without
formally amending the spec table or recording a deviation. The grep-based
theorem count of 6 was also accepted without noting that one match is a
comment (line 3: `"Soundness theorems for remediation narrowing"`), inflating
5 actual theorems to 6.

**Fix direction (→ IAMX-003):** Amend spec table row for wildcards to 4/0/1;
correct theorem count to 5.

---

### HZ-01 — PASSROLE fires on writeup-wildcards S1 (stale spec table) (HIGH)

**Category:** 1 — spec↔implementation mismatch
**Severity:** HIGH

The spec's wildcards fixture row expected 3 findings. Actual: 4.
The 4th finding is `LP.ESCALATE.PASSROLE.001` on statement `AdminAccess`
(`Action:"*"`, `Resource:"*"`).

**Root cause:** `checkPassRole` (Checks.lean:140) uses
`matchActionPattern a "iam:PassRole"` which is SEMANTIC — `"*"` pattern-matches
`"iam:PassRole"`. This is correct behavior (Action `*` does grant iam:PassRole),
but the spec table was written assuming SYNTACTIC matching.

**Evidence:** Probe A confirms: `Action:["iam:*"]`, `Resource:"*"` → PASSROLE fires
(3 findings: SERVICEWILDCARD + RESOURCE.WILDCARD + PASSROLE). Semantic resolution
confirmed.

**Suppression check:** PASSROLE is correctly NOT suppressed by ADMIN.EQUIV.
In `evaluate` (Checks.lean:168-169), when `admin` is non-empty, `pr` is still
included: `admin ++ na ++ nr ++ pr`. This aligns with spec: suppression only
covers SERVICEWILDCARD + RESOURCE.WILDCARD.

**Fix direction (→ IAMX-003):** Amend spec table wildcards row to 4/0/1. Add
`fixtures/writeup-iam-star.json` (Action `iam:*`) as a pinning fixture for
semantic PASSROLE.

---

### HZ-02 — PASSROLE fail-open on NotAction escape (CRITICAL)

**Category:** 4 — fail-open inversion
**Severity:** CRITICAL

`Allow NotAction:["s3:*"] Resource:"*"` semantically grants `iam:PassRole`
(all actions except `s3:*` are allowed). PASSROLE does not fire.

**Root cause:** `checkPassRole` (Checks.lean:137-138) inspects only `s.actions`:
```
match s.actions with
| none => []
| some acts => ...
```
When `s.actions = none` (NotAction is used instead), it returns `[]` immediately.
The control never consults `s.notActions` or the semantic `actionMatches`/`allows`
evaluator.

**Probe B evidence:**
```json
{"Statement":[{"Effect":"Allow","NotAction":["s3:*"],"Resource":"*"}]}
```
→ 2 findings (RESOURCE.WILDCARD + NOTACTION.ALLOW), 0 PASSROLE findings.

The NOTACTION.ALLOW control fires (correctly), but PASSROLE — the escalation
vector — is missed. An attacker with this policy can call `iam:PassRole`
unconstrained.

**Fix direction (→ IAMX-003):** Extend `checkPassRole` to detect PassRole grant
through NotAction. Either: (a) use `actionMatches` semantic evaluator, or
(b) add a `notActions` branch that checks whether `iam:PassRole` is NOT in the
excluded set.

---

### HZ-03 — Deny interplay ambiguity (MODERATE)

**Category:** 1 — spec↔implementation (ambiguity)
**Severity:** MODERATE

**Probe C:** Allow `iam:PassRole Resource:*` + Deny `iam:PassRole Resource:*` →
PASSROLE fires (+ RESOURCE.WILDCARD on the Allow). The checks are per-statement
static analysis with no cross-statement deny modeling.

The spec is silent on deny interaction. The `allows` function in Match.lean:57-62
models deny correctly (deny-first evaluation), but `checkPassRole` doesn't use it.

This is a deliberate over-approximation (note in Match.lean:5-7: "statements
carrying a Condition are treated as if the condition holds"). However, deny
interaction is not even mentioned in the spec's "fires when" column.

**Fix direction (→ IAMX-003):** Document in spec: "controls fire per-statement;
deny does not suppress findings. False-positive suppression deferred to slice 2."

---

### HZ-04 — `narrowActions_narrows` does not exist (CRITICAL)

**Category:** 1 — spec↔implementation mismatch
**Severity:** CRITICAL

The theorem `narrowActions_narrows` — the specified slice-2 soundness contract
for action-narrowing — does not exist anywhere in the codebase.

```
$ grep -rn "narrowActions_narrows\|narrowActions" IamExplainer/
(no output)

$ lake env lean /tmp/hazop-probes/axioms2.lean
error: Unknown identifier `narrowActions_narrows`
```

The comment at Proofs.lean:72-77 acknowledges the blocker:
> "the full inductive proof of matchPattern reflexivity resists due to
> fuel-parameter threading in matchPatternGo.go"

What exists instead: `matchPattern_refl_examples` — a CLOSED theorem proving
reflexivity on 4 literal cases via `native_decide`. This is not the universal
contract.

**Verdict:** The specified soundness contract does not exist. CRITICAL.

**Fix direction (→ IAMX-003):** Acknowledge absence in spec. Document the
fuel-threading blocker as the reason.
**Matcher evidence (→ IAMX-004):** The blocker is in Match.lean:13
(`matchPatternGo.go` — the `.go` inner function uses a `fuel` parameter that
threads through recursive calls, preventing structural recursion proofs).
See Matcher Evidence section below.

---

### HZ-05 — CLOSED theorems in Proofs.lean (tests in wrong module) (HIGH)

**Category:** 2 — D2 class drift
**Severity:** HIGH

Three of the five theorems in Proofs.lean are CLOSED (representative/literal
cases proved by `native_decide`), not UNIVERSAL proofs:

| # | Theorem | Line | Class | Tainted |
|---|---------|------|-------|---------|
| 1 | `mem_eraseIdx_of_ne` | 12 | UNIVERSAL | No (structural induction) |
| 2 | `removeAllow_narrows` | 34 | UNIVERSAL | **Yes** (`native_decide.ax_1_2`) |
| 3 | `matchPattern_refl_examples` | 78 | **CLOSED** | **Yes** (`native_decide.ax_1_1`) |
| 4 | `matchActionPattern_case_insensitive` | 83 | **CLOSED** | **Yes** (`native_decide.ax_1_1`) |
| 5 | `matchResourcePattern_case_sensitive` | 86 | **CLOSED** | **Yes** (`native_decide.ax_1_1`) |

Theorems 3–5 are tests by another name. The spec places `#guard` facts in
Tests.lean. These should be migrated to `#guard` statements in Tests.lean.

**Count:** 3 CLOSED theorems that belong in Tests.lean.

**Fix direction (→ IAMX-003):** Create Tests.lean, migrate theorems 3–5 as
`#guard` statements. Leave theorems 1–2 (UNIVERSAL) in Proofs.lean.

---

### HZ-06 — Tests.lean missing (HIGH)

**Category:** 2 — D2 structural
**Severity:** HIGH

The spec requires `#guard` facts in Tests.lean with count ≥ 6. The file does
not exist.

```
$ find . -name "Tests.lean" -o -name "Test*.lean"
(no output)
$ grep -c "#guard" IamExplainer/Proofs.lean
0
```

**Fix direction (→ IAMX-003):** Create `IamExplainer/Tests.lean`. Migrate
CLOSED theorems as `#guard` statements, add guards for the 6+ control behaviors.

---

### HZ-07 — Theorem count grep inflated (NOTE)

**Category:** 2 — D2 metric
**Severity:** NOTE

`grep -c "theorem" IamExplainer/Proofs.lean` returns 6. Actual theorem
declarations: 5. The 6th match is the comment at line 3:
`"Soundness theorems for remediation narrowing"`.

**Fix direction (→ IAMX-003):** Use `grep -c "^theorem\|^private theorem"`
for accurate counts. Correct closeout to 5.

---

### HZ-08 — SERVICEWILDCARD under-detection on partial wildcards (NOTE)

**Category:** 1 — spec↔implementation (spec-correct gap)
**Severity:** NOTE

`Action:["s3:Get*"]` produces 0 findings. SERVICEWILDCARD fires only on
`"*"` or `svc:*` form (Checks.lean:79: `isBareWildcard a || (a.endsWith ":*" && a.length > 2)`).

`s3:Get*` is a wildcard-bearing action that grants a class of permissions
(all `s3:Get*` operations), but it matches neither `*` (bare wildcard) nor
the `svc:*` pattern (which requires the wildcard to be the entire action
suffix after `:*`).

This is spec-correct — the "fires when" clause says `*` or `svc:*`. But it
is a detection surface gap: real-world policies frequently use `s3:Get*` or
`s3:Put*` patterns.

**Fix direction (→ IAMX-003):** Document as known gap. Consider adding a
lower-severity control for partial action wildcards in a future slice.

---

### HZ-09 — Silent type coercion drops (HIGH)

**Category:** 5 — type coercion / 4 — fail-open
**Severity:** HIGH

Invalid `Action` values are silently dropped to `none` instead of producing
exit 2 or a warning:

| Input | Expected | Actual |
|---|---|---|
| `Action: null` | exit 2 or warning | silently `actions = none`; 1 finding (RESOURCE.WILDCARD only) |
| `Action: 123` | exit 2 or warning | silently `actions = none`; 1 finding |
| `Action: [["s3:*"]]` | exit 2 or warning | silently `actions = none`; 1 finding |
| `Version: 2012` | warning | silently `version = none`; normal parse |

**Root cause:** `parseStatement` (Policy.lean:54-57) uses `.toOption` on the
`strOrArray?` result, converting any parse error to `none`:
```lean
let actions := (j.getObjVal? "Action" >>= strOrArray?).toOption
```

This `.toOption` pattern is applied to Action, NotAction, Resource, and
NotResource (lines 54-57). All four fields silently drop on type mismatch.

A silent drop means a statement with `Action: 123` is treated as having no
Action field — no action-related controls fire, masking potential violations.

**Fix direction (→ IAMX-003):** Replace `.toOption` with explicit error handling.
Parse errors on Action/Resource/NotAction/NotResource should either exit 2 or
produce a warning.

---

### HZ-10 — Action+NotAction both present: silent acceptance (HIGH)

**Category:** 4 — fail-open
**Severity:** HIGH

A statement with both `Action` and `NotAction` is silently accepted by the
decoder. IAM does not permit this combination.

**Probe evidence:** `Action:["s3:GetObject"], NotAction:["s3:PutObject"], Resource:"*"`
→ 2 findings (RESOURCE.WILDCARD + NOTACTION.ALLOW). No error, no warning.

The checks operate independently: `checkServiceWildcard` inspects `s.actions`,
`checkNotAction` inspects `s.notActions`. The semantic evaluator
`actionMatches` (Match.lean:43) handles this with `| _, _ => false` (both
present = no match), but this function is NOT used by any check — it's only
used by the `allows` evaluator.

Similarly, `Resource + NotResource` both present would be silently accepted
(same decoder pattern).

**Fix direction (→ IAMX-003):** Add decoder validation: error or warning when
both Action+NotAction or Resource+NotResource are present.

---

### HZ-11 — Missing Resource key: silent pass (MODERATE)

**Category:** 4 — fail-open
**Severity:** MODERATE

`Allow Action:["s3:GetObject"]` with no Resource key → 0 findings, exit 0.
In identity-based IAM policies, Resource is required.

The decoder silently accepts the missing key (`resources = none`). All resource
checks (`checkAdminEquiv`, `checkResourceWildcard`) treat `none` as "no resource
to check" and return `[]`. No control fires, no warning emitted.

**Fix direction (→ IAMX-003):** Warn on missing Resource for Allow statements
(Resource is required in identity-based policies; resource-based policies use
Principal instead).

---

### HZ-12 — Duplicate Sids: no warning (NOTE)

**Category:** 3 — aggregation/shape
**Severity:** NOTE

Two statements with `Sid: "DupSid"` are accepted without warning. IAM requires
unique Sids within a policy. The findings reference both as "DupSid", making
them indistinguishable in the output.

**Fix direction (→ IAMX-003):** Add a warning for duplicate Sids.

---

## Axiom-Taint Table

| # | Declaration | File:Line | Class | Axiom Set | Tainted |
|---|---|---|---|---|---|
| 1 | `mem_eraseIdx_of_ne` (private) | Proofs.lean:12 | UNIVERSAL | Not inspectable (private); by code inspection: propext, Quot.sound (standard); no native_decide | No |
| 2 | `removeAllow_narrows` | Proofs.lean:34 | UNIVERSAL | propext, Classical.choice, Quot.sound, `native_decide.ax_1_2` | **Yes** |
| 3 | `matchPattern_refl_examples` | Proofs.lean:78 | CLOSED | propext, Classical.choice, Quot.sound, `native_decide.ax_1_1` | **Yes** |
| 4 | `matchActionPattern_case_insensitive` | Proofs.lean:83 | CLOSED | propext, Classical.choice, Quot.sound, `native_decide.ax_1_1` | **Yes** |
| 5 | `matchResourcePattern_case_sensitive` | Proofs.lean:86 | CLOSED | propext, Classical.choice, Quot.sound, `native_decide.ax_1_1` | **Yes** |

`removeAllow_narrows` is UNIVERSAL but tainted: the `native_decide` at
Proofs.lean:50 evaluates `(Effect.allow == Effect.deny)` — a decidable Bool
equality. The taint is benign (it's evaluating a concrete `BEq` instance, not
a proof obligation), but the axiom dependency is real.

---

## `narrowActions_narrows` Verdict

**ABSENT.** The theorem does not exist. The specified slice-2 soundness contract
was never written. The closest approximation is `matchPattern_refl_examples` —
a CLOSED theorem proving reflexivity on 4 literal inputs via `native_decide`.
This is not a universal narrowing guarantee.

The comment at Proofs.lean:72-77 documents the blocker: fuel-parameter threading
in `matchPatternGo.go` prevents structural recursion proofs for `matchPattern`
reflexivity.

---

## Probe Summary

| Probe | Input | Expected | Actual | Verdict |
|---|---|---|---|---|
| A (iam:* semantic) | `Action:["iam:*"], Resource:"*"` | PASSROLE fires if semantic | PASSROLE fires (3 findings) | SEMANTIC confirmed |
| B (NotAction escape) | `NotAction:["s3:*"], Resource:"*"` | PASSROLE fires (semantic grant) | PASSROLE does NOT fire (2 findings) | **DEVIATION (HZ-02)** |
| C (Deny interplay) | Allow+Deny iam:PassRole | spec silent | PASSROLE fires (2 findings) | Ambiguity (HZ-03) |
| D1 (lowercase key) | Condition `iam:passedtoservice` | suppresses PASSROLE condition | 0 findings — suppressed | NO-DEVIATION |
| D2 (IfExists key) | Condition `StringEqualsIfExists` | suppresses PASSROLE condition | 0 findings — suppressed | NO-DEVIATION |
| admin-mixed | `Action:["*","s3:GetObject"], Resource:"*"` | ADMIN.EQUIV fires | fires (2: ADMIN+PASSROLE) | NO-DEVIATION |
| svc-partial | `Action:["s3:Get*"]` | spec-correct silence | 0 findings | NO-DEVIATION (gap: HZ-08) |
| res-mixed | `Resource:["arn:...", "*"]` | RESOURCE.WILDCARD fires | 1 finding | NO-DEVIATION |
| case-action | `Action:["S3:GETOBJECT"]` | no control fires | 0 findings | NO-DEVIATION |
| cond-non-pr | `Action:"*", Resource:"*", Condition(aws:SourceIp)` | non-PR controls unaffected | 2 findings (ADMIN+PASSROLE) | NO-DEVIATION |
| single-object | Statement as object | same as array | 2 findings | NO-DEVIATION |
| single-array | Statement as 1-elem array | same as object | 2 findings | NO-DEVIATION |
| empty-stmt | `Statement: []` | pass or error | pass, 0 findings | NO-DEVIATION |
| dup-sids | Two `Sid:"DupSid"` | warn | no warning | DEVIATION (HZ-12) |
| no-resource | Action, no Resource | exit 2 or warn | 0 findings, exit 0 | DEVIATION (HZ-11) |
| no-action | Resource:"*", no Action | resource checks fire | 1 finding | NO-DEVIATION |
| both-act-notact | Action + NotAction | error or warn | silent, 2 findings | DEVIATION (HZ-10) |
| action-null | `Action: null` | exit 2 or warn | silent drop | DEVIATION (HZ-09) |
| action-number | `Action: 123` | exit 2 or warn | silent drop | DEVIATION (HZ-09) |
| action-nested | `Action: [["s3:*"]]` | exit 2 or warn | silent drop | DEVIATION (HZ-09) |
| version-number | `Version: 2012` | warn | silent drop | DEVIATION (HZ-09) |

Probes run: 22. Blanks: 0.

---

## Scorecard

| Severity | Count | IDs |
|---|---|---|
| CRITICAL | 2 | HZ-02, HZ-04 |
| HIGH | 5 | HZ-01, HZ-05, HZ-06, HZ-09, HZ-10 |
| MODERATE | 2 | HZ-03, HZ-11 |
| NOTE | 4 | HZ-00, HZ-07, HZ-08, HZ-12 |
| **Total** | **13** | |

---

## Gate Verdict

**BLOCKED**

Two CRITICAL deviations in gate-qualifying categories:

1. **HZ-02** (category 4, fail-open): PASSROLE does not fire on NotAction escape
   path. Real privilege escalation vector undetected.
2. **HZ-04** (category 1, spec↔implementation): `narrowActions_narrows` soundness
   contract does not exist. The specified proof obligation was never attempted.

IAMX-003 must close both CRITICAL deviations before any new control authoring.

---

## Fix List (→ IAMX-003)

Ordered CRITICAL → NOTE. Each entry is `{HZ-id, severity, one-line fix direction}`.

| # | HZ-ID | Severity | Fix Direction |
|---|---|---|---|
| 1 | HZ-02 | CRITICAL | Extend `checkPassRole` to detect PassRole grant through NotAction path |
| 2 | HZ-04 | CRITICAL | Acknowledge `narrowActions_narrows` absence in spec; document fuel-threading blocker |
| 3 | HZ-01 | HIGH | Amend spec table wildcards row to 4/0/1; add `iam:*` pinning fixture |
| 4 | HZ-05 | HIGH | Create Tests.lean; migrate 3 CLOSED theorems as `#guard` statements |
| 5 | HZ-06 | HIGH | Populate Tests.lean with ≥ 6 `#guard` facts per spec |
| 6 | HZ-09 | HIGH | Replace `.toOption` in parseStatement with explicit error handling for type mismatches |
| 7 | HZ-10 | HIGH | Add decoder validation for Action+NotAction / Resource+NotResource mutual exclusion |
| 8 | HZ-03 | MODERATE | Document deny-interaction scope in spec ("per-statement static; deny doesn't suppress") |
| 9 | HZ-11 | MODERATE | Warn on Allow statement with missing Resource key |
| 10 | HZ-00 | NOTE | Amend spec table wildcards; correct theorem count to 5 |
| 11 | HZ-07 | NOTE | Use `^theorem\|^private theorem` grep for accurate counts |
| 12 | HZ-08 | NOTE | Document `s3:Get*` as known detection gap; consider partial-wildcard control |
| 13 | HZ-12 | NOTE | Add warning for duplicate Sids |

---

## Matcher Evidence (→ IAMX-004)

### Fuel-threading blocker

**Location:** `IamExplainer/Match.lean:13` — `matchPatternGo.go` inner function.

```lean
def matchPatternGo (ps vs : List Char) : Bool :=
  go ps vs (ps.length + vs.length + 1)
where
  go : List Char → List Char → Nat → Bool
    ...
  star : List Char → List Char → Nat → Bool
    | _, _, 0 => false
    | ps, [], fuel => go ps [] fuel
    | ps, v :: vs, fuel + 1 => go ps (v :: vs) (fuel + 1) || star ps vs fuel
```

The `fuel` parameter (Match.lean:13: `ps.length + vs.length + 1`) is a natural
number that decreases on each recursive call. The `.go` and `star` functions
are mutually recursive with fuel threading. This prevents Lean's structural
recursion checker from establishing termination for a universal `matchPattern`
reflexivity proof.

The `star` function (Match.lean:27) uses `fuel + 1` pattern matching and
passes `fuel` (decremented) back to `go`, creating a well-foundedness
obligation that the current Lean termination checker cannot discharge
automatically.

### Matcher-related deviations from sweep

- **HZ-01:** PASSROLE semantic resolution depends on `matchActionPattern`
  correctness. Verified for `iam:*` and `*` patterns.
- **HZ-02:** PASSROLE's reliance on `s.actions` (not `actionMatches`) means
  the matcher is bypassed entirely for NotAction paths — this is a check-level
  bug, not a matcher bug.
- **HZ-04:** `narrowActions_narrows` absence. The theorem would require
  `matchPattern_refl` (universal reflexivity), which is blocked by the fuel
  threading.

### Recommendation

Refactor `matchPatternGo` to use well-founded recursion (e.g., `WellFoundedRelation`
on `(ps.length + vs.length, vs.length)` lexicographic order) so that
`matchPattern_refl` can be proved universally, enabling `narrowActions_narrows`.

---

## Closeout

- **Deviation histogram:** CRITICAL: 2, HIGH: 5, MODERATE: 2, NOTE: 4 (total: 13)
- **Gate verdict:** BLOCKED (HZ-02 category-4, HZ-04 category-1)
- **Fix List:** 13 entries, ordered by severity → IAMX-003
- **Matcher Evidence:** fuel-threading blocker at Match.lean:13, 3 related deviations → IAMX-004
- **Probes run:** 22
- **`narrowActions_narrows` verdict:** ABSENT — the specified soundness contract does not exist
- **Repo state:** commit 1645020 unchanged; 1 file added (this report)
