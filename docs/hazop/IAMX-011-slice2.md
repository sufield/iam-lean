# IAMX-011 — Self-HAZOP of Slice 2 (External Access)

Fresh-session read-only audit of the IAMX-010 commits (slice 2), ending at
`0ef3e363ad`. Probes in `/tmp/hazop2/`, no code modifications.

## Baseline Reproduction

| # | Check | Expected | Actual | Status |
|---|---|---|---|---|
| 1 | `git log --oneline -15` chain 005→010 present | chain present | present (6 commits) | PASS |
| 2 | `git status --porcelain \| wc -l` | 0 | 0 | PASS |
| 3 | `lake build` | exit 0 | exit 0 (24 jobs) | PASS |
| 4 | `grep -rn "sorry\|admit\|native_decide" IamExplainer/ \| wc -l` | 0 | 0 | PASS |
| 5 | `git diff --stat` Match.lean across slice 2 | 0 files | 0 files | PASS |
| 6 | Slice-1 fixtures: 12 finding-test + 1 invalid = 13 | 13/13 | 13/13 | PASS |
| 7 | XA fixture finding counts (9 fixtures) | 9/9 | 9/9 | PASS |
| 8 | XA fixture grant scopes (9 fixtures) | 9/9 | 9/9 | PASS |
| 9 | No-flags run | 0 findings, 2 warnings, 2 UNVERIFIED grants | exact match | PASS |
| 10 | `grep -c "#guard" IamExplainer/Tests.lean` | 27 | 27 | PASS |
| 11 | `git ls-files \| wc -l` | 45 | **46** | NOTE |

**NOTE (row 11):** 46 files vs spec's 45. The extra file is `.mcp.json`
(commit `7d79597d15`), a tooling configuration artifact. Not a deviation.

## Seeded Cell Verdicts

### HZ2-A — Bare account id → root normalization

| Probe | Findings | Grant principal | Scope | Status |
|---|---|---|---|---|
| `"AWS": "444455556666"` (bare 12-digit) | ROOT.EXTERNAL | `arn:aws:iam::444455556666:root` | CROSS_ORG | PASS |
| `"AWS": "arn:aws:iam::444455556666:root"` (ARN) | ROOT.EXTERNAL | `arn:aws:iam::444455556666:root` | CROSS_ORG | PASS |
| `"AWS": "44445555666"` (11-digit) | (none) | `44445555666` | UNVERIFIED | **CAT-4** |
| `"AWS": "4444555566677"` (13-digit) | (none) | `4444555566677` | UNVERIFIED | **CAT-4** |

**HZ2-A-1 (CAT-4 FAIL-OPEN):** 11-digit and 13-digit strings silently bypass
`isBareAccountId` (length ≠ 12), fall through to `{ typ := .aws, value := s }`
at `Principal.lean:33`. `accountId` extraction fails (not a bare id, not an
ARN), so `scopeOf` returns UNVERIFIED with no warning. No error, no validation
message. The string is treated as an AWS principal with an unparseable account
id. **File: `IamExplainer/Principal.lean:27-33`.**

Bare 12-digit vs ARN: identical findings and grants. **PASS.**

### HZ2-B — OrgPaths and PrincipalOrgID variations

| Probe | Expected (per spec) | Actual | Status |
|---|---|---|---|
| `aws:PrincipalOrgPaths` string, ours | — | PUBLIC.FENCED, scope PUBLIC | DEFERRED-SLICE3 |
| `aws:PrincipalOrgPaths` array, ours | — | PUBLIC.FENCED, scope PUBLIC | DEFERRED-SLICE3 |
| `aws:PrincipalOrgPaths` foreign | — | PUBLIC.FENCED, scope PUBLIC | DEFERRED-SLICE3 |
| `aws:PrincipalOrgPaths` malformed (no `/`) | — | PUBLIC.FENCED, scope PUBLIC | DEFERRED-SLICE3 |
| `aws:PrincipalOrgID` array `[ours, foreign]` | — | 0 findings, scope IN_ORG | **CAT-1** |

**DEFERRED-SLICE3:** `condOrgId` (`Principal.lean:88-105`) only looks for
`aws:PrincipalOrgID`, not `aws:PrincipalOrgPaths`. The spec scope table
(slice2.md:17) mentions only `aws:PrincipalOrgID`. OrgPaths support is
slice-3 territory.

**HZ2-B-1 (CAT-1 SPEC-SILENCE):** `condOrgId` extracts `a[0]?` from an
OrgID array (`Principal.lean:101`), silently ignoring subsequent elements.
With `["o-ours1234", "o-foreign999"]`, only `o-ours1234` is checked →
scope IN_ORG. The foreign org id in position [1] is invisible.
**File: `IamExplainer/Principal.lean:101`.**

### HZ2-C — Partial-context matrix

Context flags: `A` = `--account 111122223333`, `L` = `--accounts accounts.txt`,
`O` = `--org-id o-ours1234`.

#### writeup-external.json (statements: S0=AWS root 444455556666, S1=wildcard+foreign org fence)

| A | L | O | Findings | S0 scope | S1 scope | Warnings | Invariants |
|---|---|---|---|---|---|---|---|
| - | - | - | (none) | UNVERIFIED | UNVERIFIED | 2: S0 --account, S1 --account | INV1 ✓ INV2 ✓ INV3 ✓ |
| - | - | O | ORGID.FOREIGN | UNVERIFIED | CROSS_ORG | 1: S0 --account | INV1 ✓ INV2 ✓ INV3 ✓ |
| - | L | - | (none) | UNVERIFIED | UNVERIFIED | 2: S0 --account, S1 --account | INV1 ✓ INV2 ✓ INV3 ✓ |
| - | L | O | ORGID.FOREIGN | UNVERIFIED | CROSS_ORG | 1: S0 --account | INV1 ✓ INV2 ✓ INV3 ✓ |
| A | - | - | ROOT.EXTERNAL, PUBLIC.FENCED | CROSS_ORG | PUBLIC | 0 | INV1 ✓ INV2 ✓ INV3 — |
| A | - | O | ROOT.EXTERNAL, ORGID.FOREIGN | CROSS_ORG | CROSS_ORG | 0 | INV1 ✓ INV2 ✓ INV3 — |
| A | L | - | ROOT.EXTERNAL, PUBLIC.FENCED | CROSS_ORG | PUBLIC | 0 | INV1 ✓ INV2 ✓ INV3 — |
| A | L | O | ROOT.EXTERNAL, ORGID.FOREIGN | CROSS_ORG | CROSS_ORG | 0 | INV1 ✓ INV2 ✓ INV3 — |

#### writeup-trust.json (statements: S0=AWS bare 444455556666, S1=Federated OIDC)

| A | L | O | Findings | S0 scope | S1 scope | Warnings | Invariants |
|---|---|---|---|---|---|---|---|
| - | - | - | FEDERATED.UNSCOPED | UNVERIFIED | FEDERATED | 1: S0 --account | INV1 ✓ INV2 ✓ INV3 ✓ |
| - | - | O | FEDERATED.UNSCOPED | UNVERIFIED | FEDERATED | 1: S0 --account | INV1 ✓ INV2 ✓ INV3 ✓ |
| - | L | - | FEDERATED.UNSCOPED | UNVERIFIED | FEDERATED | 1: S0 --account | INV1 ✓ INV2 ✓ INV3 ✓ |
| - | L | O | FEDERATED.UNSCOPED | UNVERIFIED | FEDERATED | 1: S0 --account | INV1 ✓ INV2 ✓ INV3 ✓ |
| A | - | - | ROOT.EXTERNAL, EXTERNALID.ABSENT, FEDERATED.UNSCOPED | CROSS_ORG | FEDERATED | 0 | INV1 ✓ INV2 ✓ INV3 — |
| A | - | O | ROOT.EXTERNAL, EXTERNALID.ABSENT, FEDERATED.UNSCOPED | CROSS_ORG | FEDERATED | 0 | INV1 ✓ INV2 ✓ INV3 — |
| A | L | - | ROOT.EXTERNAL, EXTERNALID.ABSENT, FEDERATED.UNSCOPED | CROSS_ORG | FEDERATED | 0 | INV1 ✓ INV2 ✓ INV3 — |
| A | L | O | ROOT.EXTERNAL, EXTERNALID.ABSENT, FEDERATED.UNSCOPED | CROSS_ORG | FEDERATED | 0 | INV1 ✓ INV2 ✓ INV3 — |

**Invariant definitions:**
- INV1: A control whose definition needs an absent flag never fires.
- INV2: No row is classified SAME_ACCOUNT or IN_ORG without the flag that justifies it.
- INV3: Every UNVERIFIED row has exactly one warning naming the missing flag.

All 16 rows satisfy INV1 and INV2. INV3 holds on all 8 UNVERIFIED rows.
The 8 non-UNVERIFIED rows have no UNVERIFIED scopes, so INV3 is not applicable.

**Matrix status: PASS** — no invariant violations.

### HZ2-D — Principal types the fixtures skipped

| Probe | Scope | Findings | Grant rows | Status |
|---|---|---|---|---|
| `{"Service": "lambda.amazonaws.com"}` | SERVICE | 0 | 1 (SERVICE) | PASS |
| `{"CanonicalUser": "<64hex>"}` | CROSS_ORG | 0 | 1 (CROSS_ORG) | **CAT-1** |
| `{"AWS": ["111122223333", "444455556666"]}` | SAME_ACCOUNT, CROSS_ORG | ROOT.EXTERNAL ×1 | 2 | PASS |

**HZ2-D-1 (CAT-1 SPEC-GAP):** CanonicalUser scope. Spec (slice2.md:51) says
"treated as AWS principal" but implementation handles it as a separate
PrincipalType at `Principal.lean:119-121`: any `account.isSome` → CROSS_ORG,
regardless of whether the canonical user belongs to the same account.
CanonicalUser has no account-id extraction path. The spec defines no scope
for CanonicalUser. **File: `IamExplainer/Principal.lean:119-121`.**

### HZ2-E — Kind detection edges

| Probe | Kind | Findings | Status |
|---|---|---|---|
| Trust-shaped + `Resource: "*"` | RESOURCE | LP.RESOURCE.WILDCARD, ROOT.EXTERNAL | PASS |
| Mixed (identity + resource stmts) | MIXED | ROOT.EXTERNAL (no MIXED warning) | **CAT-1** |
| Principal with no Action | RESOURCE | ROOT.EXTERNAL | PASS |

**HZ2-E-1 (CAT-1 SPEC↔IMPL):** Spec (slice2.md:10) says MIXED kind
produces a "warning, evaluated as RESOURCE." Implementation detects MIXED
correctly but emits no warning. No warning generation code exists for the
MIXED case anywhere in the codebase. **File: (missing from all of
XAChecks.lean, Report.lean, Main.lean).**

**Trust+Resource:** `stmtIsTrustShaped` requires `resources.isNone &&
notResources.isNone` (`Principal.lean:153`), so `Resource: "*"` degrades to
RESOURCE kind. TRUST.EXTERNALID.ABSENT correctly does not fire (guarded by
`kind == .trust`). **PASS per spec.**

**No-Action:** Statement with Principal and no Action → actions default to
`["*"]` in grants, kind RESOURCE. ROOT.EXTERNAL fires. Functionally correct
though semantically debatable (an actionless statement is invalid IAM JSON,
but no parse error is raised). DOCUMENTED-GAP: invalid-document detection
deferred.

### HZ2-F — Suppression interplay

| Probe | Findings | Status |
|---|---|---|
| `*` + foreign org + extra condition key | ORGID.FOREIGN (1 finding) | PASS |
| External role ARN (not root) + foreign org | (none) | **CAT-1** |
| Own-account role + foreign org | (none) | **CAT-1** |

**HZ2-F-1 (CAT-1 SPEC↔IMPL):** ORGID.FOREIGN fires only for wildcard
principals (`p.typ == .wildcard` at `XAChecks.lean:56`). Spec
(slice2.md:31) says it fires when "aws:PrincipalOrgID/OrgPaths present and
≠ --org-id" with no restriction to wildcard principals. A non-root external
role ARN fenced by a foreign org-id → 0 findings. **File:
`IamExplainer/XAChecks.lean:56`.**

**HZ2-F-2 (CAT-1 INTENTIONAL?):** Own-account role + foreign org-id condition
→ 0 findings, scope SAME_ACCOUNT. `scopeOf` classifies by account-id match,
ignoring the condition entirely for non-wildcard principals. The foreign
org-id in the condition is invisible. Spec fires ORGID.FOREIGN "regardless of
principal" — is this intended? If not, the control has a false-negative gap
on non-wildcard principals.
**File: `IamExplainer/XAChecks.lean:56`, `IamExplainer/Principal.lean:122-131`.**

### HZ2-G — Federated scoping depth

| Probe | Findings | Status |
|---|---|---|
| OIDC `:sub` with `StringLike`, value `repo:*` | 0 | DOCUMENTED-GAP |
| OIDC `:sub` with wrong case (`Token...Com:Sub`) | 0 | PASS |
| SAML provider (no `:sub` semantics) | FEDERATED.UNSCOPED | **CAT-1** |

**DOCUMENTED-GAP:** `:sub` present → structurally scoped, 0 findings.
Value-level evaluation (`repo:*` is over-broad) deferred to slice 3.
No report text says "fence present, not evaluated" because no finding is
emitted — the absence is the signal.

**HZ2-G-1 (CAT-1 SPEC↔IMPL):** FEDERATED.UNSCOPED fires on SAML providers.
Spec (slice2.md:32) says "Federated OIDC principal with no `<provider>:sub`
condition key." SAML principals use `SAML:aud`/`SAML:iss`, not `:sub`. The
`hasFedSubKey` function (`XAChecks.lean:25-29`) extracts the provider name
from the ARN path and checks for `<provider>:sub`. For a SAML provider
`ExampleProvider`, it checks for `ExampleProvider:sub`, which is not a real
SAML condition key. False positive on SAML.
**File: `IamExplainer/XAChecks.lean:25-29`.**

**Case insensitivity:** `condHasKey` uses `toLowerStr` comparison
(`XAChecks.lean:21`), so `Token...Com:Sub` matches
`token...com:sub`. **PASS.**

### HZ2-H — grants_complete

**Statement (verbatim from `IamExplainer/Proofs.lean:231-233`):**

```lean
theorem grants_complete (p : Policy) (req : Request)
    (h : allows p req = true) :
    ∃ s ∈ p.statements, s.effect = .allow ∧ stmtMatches s req = true
```

**Hypotheses:**
1. `p : Policy` — the policy
2. `req : Request` — the request
3. `h : allows p req = true` — the policy allows the request

No hypothesis beyond the modeled fragment. The conclusion witnesses an
allow statement that matches the request.

**Axiom audit (all Proofs.lean public declarations):**

| Declaration | Axioms | Status |
|---|---|---|
| `removeAllow_narrows` | propext, Classical.choice, Quot.sound | CLEAN |
| `matchPattern_literal_mp` | propext, Classical.choice, Quot.sound | CLEAN |
| `matchPattern_ci_congr` | propext, Classical.choice, Quot.sound | CLEAN |
| `stmtGrantsAction_ci_congr` | propext, Classical.choice, Quot.sound | CLEAN |
| `stmtGrantsAction_narrow` | propext, Classical.choice, Quot.sound | CLEAN |
| `allows_replaceAllow_mono` | propext, Classical.choice, Quot.sound | CLEAN |
| `narrowActions_narrows` | propext, Classical.choice, Quot.sound | CLEAN |
| `grants_complete` | propext, Classical.choice, Quot.sound | CLEAN |

8 declarations, all standard axioms only. 0 sorryAx, 0 ofReduceBool,
0 trustCompiler.

**Instantiation:** Concrete example (`testPolicy` with one Allow for
`s3:GetObject`, `testReq` matching) elaborates successfully with
`grants_complete testPolicy testReq (by native_decide)`. Note: `decide`
does not reduce (`allows` involves string matching that doesn't normalize
at kernel level); `native_decide` is required, which introduces
`Lean.ofReduceBool` at the call site. The theorem itself remains clean.

### HZ2-I — NotPrincipal and Deny rows

| Probe | Findings | Grant rows | Status |
|---|---|---|---|
| Allow + NotPrincipal | NOTPRINCIPAL.ALLOW | 1 (PUBLIC) | PASS |
| Deny + NotPrincipal (guardrail shape) | 0 | 0 | PASS |
| writeup-trust + added Deny statement | ROOT.EXTERNAL, EXTERNALID.ABSENT, FEDERATED.UNSCOPED | 2 (Allow stmts only) | PASS |

Deny statements produce 0 findings and 0 grant rows in all probes. Findings
on Allow statements in the same policy are unaffected. **PASS.**

### HZ2-J — Demo reproduction

All 11 sections of `docs/demo/external-access.md` reproduced:

| # | Section | Finding IDs | Grant Scopes | Match |
|---|---|---|---|---|
| 1 | writeup-public explain | PUBLIC, NOTPRINCIPAL.ALLOW | — | ✓ |
| 2 | writeup-public grants | — | PUBLIC, PUBLIC | ✓ |
| 3 | remediated-public explain | (none) | — | ✓ |
| 4 | remediated-public grants | — | SAME_ACCOUNT | ✓ |
| 5 | partial-public explain | PUBLIC.FENCED | — | ✓ |
| 6 | partial-public grants | — | PUBLIC | ✓ |
| 7 | writeup-external explain | ROOT.EXTERNAL, ORGID.FOREIGN | — | ✓ |
| 8 | writeup-external grants | — | CROSS_ORG, CROSS_ORG | ✓ |
| 9 | remediated-external explain | (none) | — | ✓ |
| 10 | remediated-external grants | — | IN_ORG | ✓ |
| 11 | partial-external explain | ROOT.EXTERNAL | — | ✓ |
| — | partial-external grants | — | CROSS_ORG, CROSS_ORG | ✓ |
| — | writeup-trust explain | ROOT.EXTERNAL, EXTERNALID.ABSENT, FEDERATED.UNSCOPED | — | ✓ |
| — | writeup-trust grants | — | CROSS_ORG, FEDERATED | ✓ |
| — | remediated-trust explain | (none) | — | ✓ |
| — | remediated-trust grants | — | CROSS_ORG, FEDERATED | ✓ |
| — | partial-trust explain | EXTERNALID.ABSENT | — | ✓ |
| — | partial-trust grants | — | CROSS_ORG | ✓ |
| — | No-flags explain | 0 findings, 2 warnings | — | ✓ |
| — | No-flags grants | — | UNVERIFIED, UNVERIFIED | ✓ |
| — | Slice-1 RAM | ADMIN.EQUIV, SERVICEWILDCARD, RESOURCE.WILDCARD | — | ✓ |

**11/11 sections match.** The RAM block (section 11) documents that live
capture requires AWS access (`aws ram get-permission`). The "cannot see"
section lists 5 categories (RAM shares, credential copies, KMS grants, S3
ACLs, account-level settings).

## Deviation Log

| ID | Category | Severity | File:Line | Description |
|---|---|---|---|---|
| HZ2-A-1 | 4 (fail-open) | medium | `Principal.lean:27-33` | Non-12-digit numeric strings silently treated as AWS principals with unparseable account id → UNVERIFIED scope, no warning |
| HZ2-B-1 | 1 (spec-silence) | low | `Principal.lean:101` | `condOrgId` takes first element of OrgID array, silently ignoring subsequent elements |
| HZ2-E-1 | 1 (spec↔impl) | low | (missing) | Spec says MIXED kind produces a warning; no warning generation code exists |
| HZ2-F-1 | 1 (spec↔impl) | medium | `XAChecks.lean:56` | ORGID.FOREIGN restricted to wildcard principals; spec has no such restriction |
| HZ2-F-2 | 1 (spec↔impl) | medium | `XAChecks.lean:56`, `Principal.lean:122-131` | Own-account role + foreign org condition → 0 findings; spec fires ORGID.FOREIGN unconditionally |
| HZ2-G-1 | 1 (spec↔impl) | medium | `XAChecks.lean:25-29` | FEDERATED.UNSCOPED fires on SAML providers; spec restricts to OIDC |
| HZ2-D-1 | 1 (spec-gap) | low | `Principal.lean:119-121` | CanonicalUser scope undefined in spec; implementation assigns CROSS_ORG unconditionally |

7 deviations: 1 category-4, 6 category-1. 0 category-4 critical. 0 blockers.

## Fix List (→ IAMX-012)

| ID | Severity | Direction |
|---|---|---|
| HZ2-A-1 | medium | Validate principal string format; warn on non-12-digit non-ARN AWS principal values |
| HZ2-B-1 | low | Document or handle multi-element OrgID arrays (check all elements, not just first) |
| HZ2-E-1 | low | Add MIXED-kind warning to explain output matching spec |
| HZ2-F-1 | medium | Decide: extend ORGID.FOREIGN to non-wildcard principals, or narrow the spec |
| HZ2-F-2 | medium | Same as HZ2-F-1 — spec vs impl alignment on org-id checking scope |
| HZ2-G-1 | medium | Guard FEDERATED.UNSCOPED to OIDC providers only (check ARN for `oidc-provider`) |
| HZ2-D-1 | low | Define CanonicalUser scope in spec (likely CROSS_ORG with documented rationale) |

## grants_complete Statement (verbatim)

```lean
theorem grants_complete (p : Policy) (req : Request)
    (h : allows p req = true) :
    ∃ s ∈ p.statements, s.effect = .allow ∧ stmtMatches s req = true
```

## Verification Block

```
1. Baseline rows with ACTUAL                                     8/8 (rows 1-8 of baseline; rows 9-11 are non-ACTUAL supplementary)
2. Seeded cells with verdict                                     10/10 (A–J)
3. Partial-context matrix rows                                   16, all three invariants stated per row
4. Deviation log entries with file:line evidence                 7
5. Axiom-taint rows = Proofs.lean declarations                   8 = 8
6. Instantiation example elaborates                              exit 0 (native_decide)
7. Demo blocks reproduced                                        11/11
8. git diff --stat 0ef3e363ad..HEAD                              1 file: docs/hazop/IAMX-011-slice2.md
9. Gate verdict line with histogram                              below
```

## Gate Verdict

**PASS-WITH-FINDINGS**

Histogram: 0 critical, 3 medium (HZ2-A-1, HZ2-F-1/F-2, HZ2-G-1), 3 low
(HZ2-B-1, HZ2-E-1, HZ2-D-1), 4 DEFERRED-SLICE3, 2 DOCUMENTED-GAP.

No critical category-1 or category-4 deviations. The single category-4
(HZ2-A-1) is medium severity: malformed principal strings are an unlikely
input in practice (AWS rejects non-12-digit account ids in policy documents).

**Next:** IAMX-012 if fixes desired (scoped to Fix List above). Otherwise
slice-3 scoping: condition value operators, SCP/RCP layer, OrgPaths support.
Separately: Stave gap-audit for the 5 "cannot see" categories.
