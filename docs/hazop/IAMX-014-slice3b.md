# IAMX-014 — Self-HAZOP of Slice 3b (SCP/RCP/Permission-Boundary Layering)

Fresh-session audit of IAMX-014 commit `f533d5ba53`. Probes run in-session,
no code modifications.

## Baseline Reproduction

| # | Check | Expected | Actual | Status |
|---|---|---|---|---|
| 1 | `lake build` | exit 0 | exit 0 (30 jobs) | PASS |
| 2 | `grep -rn "sorry\|admit\|native_decide" IamExplainer/ \| wc -l` | 0 | 0 | PASS |
| 3 | Slice-1 fixtures; #guards | 13/13; 27 | 13/13; 27 | PASS |
| 4 | Slice-2 XA with flags; no-flags | 9/9+6/6; 0/2/2 | all match | PASS |
| 5 | 3a query manifest | 18/18 | 18/18 | PASS |
| 6 | Layer manifest | 15/15 | 15/15 | PASS |
| 7 | Layer invalid (scp-with-principal, rcp-without-principal) | exit 2 × 2 | exit 2 × 2 | PASS |
| 8 | SAML triple (writeup/remediated/partial) | 2/0/1 | 2/0/1 | PASS |
| 9 | Layer theorem names in Proofs.lean | 3 | 3 | PASS |
| 10 | Axiom audit (Proofs.lean + Layers.lean) | 0 tainted | all standard | PASS |
| 11 | `def allowsLayered` count | 1 | 1 | PASS |
| 12 | `git ls-files \| wc -l` | ≤ 88 | 93 (+5, accounted) | PASS-WITH-FINDINGS |
| 13 | Legacy row partial-federated-saml.json | 0→1 | 1 | PASS |

## Seeded Cell Verdicts

### HZ3B-A — Multi-level SCP allow-then-deny

| Probe | L1 | L2 | Action | Expected | Actual | Status |
|---|---|---|---|---|---|---|
| Both allow | allow-list (AllowS3GetObject) | deny-only (no s3 deny) | s3:GetObject | ALLOWED | ALLOWED, scp:2:assumed-full-access | PASS |
| L1 blocks, L2 denies | allow-list (no iam Allow) | deny-only (DenyIam) | iam:CreateUser | DENIED by both | DENIED, [scp:1:no-allow, scp:2:DenyIam] | PASS |

Multi-level SCP composition correct: each level evaluated independently,
blocked_by collects from both levels.

### HZ3B-B — RCP Principal against NotPrincipal grants

`evalRcpLevel` calls `stmtMatches` (action + resource only) then
`foldDenies`. `Request` has no principal field. RCP statements with
`Principal: "*"` work because `stmtMatches` ignores Principal entirely —
the `*` is never checked.

| Probe | RCP Principal | stmtMatches | evalRcpLevel | Status |
|---|---|---|---|---|
| `Principal: "*"` | not checked | action+resource match | condition evaluated | **CAT-3** |
| `Principal: "arn:aws:iam::X:root"` | not checked | action+resource match | condition evaluated, principal ignored | **CAT-3** |

**HZ3B-B-1 (CAT-3 PRINCIPAL-MATCHING-ABSENT):** RCP deny statements
should match their Principal field against the request's principal (the
identity invoking the API). `Request` only has `{action, resource}` — no
principal. `stmtMatches` checks action+resource, so any RCP deny that
matches action+resource fires its condition regardless of its Principal
field.

For `Principal: "*"` this is correct (matches all principals). For a
specific principal (e.g., `arn:aws:iam::X:root`), the deny fires even when
the request is from a different principal. This is conservative: denying
more than IAM would deny is safe for the proof (layers_narrow), but
produces false positives in the RCP path.

In practice, all current RCP fixtures use `Principal: "*"`. Non-wildcard
RCP principals are rare in AWS (most SCPs/RCPs use conditions for
principal scoping, not the Principal field). The grammar check
(`validateRcp`) already enforces that every Deny has a Principal, but
doesn't enforce `"*"`.

**Fix direction:** Add optional `principal` to `Request`; extend
`stmtMatches` to check it when present. Deferred to 3d (cross-account
grant composition needs request principal anyway).

**File: `IamExplainer/Match.lean:1-3`, `IamExplainer/Layers.lean:77-85`.**

### HZ3B-C — Boundary on TRUST kind

| Probe | Kind | Expected | Actual | Status |
|---|---|---|---|---|
| TRUST policy + boundary | TRUST | boundary skipped | ALLOWED, note: boundary-skipped:TRUST | PASS |
| IDENTITY policy + boundary, s3:PutObject | IDENTITY | boundary blocks | DENIED, boundary:no-allow | PASS |
| RESOURCE policy + boundary | RESOURCE | boundary skipped | ALLOWED, note: boundary-skipped:RESOURCE | PASS |

`evalBoundary` correctly gates on `kind != .identity` before evaluating.
The skip note identifies the kind.

### HZ3B-D — Stale service list

`data/rcp-services.txt` contains 8 services. `loadRcpServices` reads this
file relative to cwd with no fallback.

| Probe | Service | In list | Result | Status |
|---|---|---|---|---|
| s3:GetObject | s3 | yes | condition evaluated | PASS |
| dynamodb:GetItem | dynamodb | no | service-not-in-support-list | PASS |
| lambda:InvokeFunction | lambda | no | service-not-in-support-list | CORRECT |

**HZ3B-D-1 (CAT-2 HARDCODED-SERVICE-PATH):** `loadRcpServices` hardcodes
`"data/rcp-services.txt"` as a relative path. Running `iamlean can` from
a directory other than the project root causes an IO crash with no
graceful error message.

This is the same class of issue as any data file referenced by relative
path. The service list itself (8 entries) will grow as AWS adds RCP
support for more services. New services produce `service-not-in-support-list`
unresolved entries — conservative (no false negatives) but noisy.

**Fix direction:** Embed the service list at build time or resolve
relative to the binary location. Low priority — the binary is typically
run from the project root.

**File: `Main.lean:136-138`.**

### HZ3B-E — Eval-time warning loss in layer path (017 seed)

All `evalCond` calls in `Layers.lean` use `.1`, dropping eval warnings.
IAMX-017 moved unsupported-operator warnings to parse time (`ParseWarning`),
which surfaces through `layerWarns` in `runCan`. But eval-time warnings
(policy variable substitution `${aws:username}` → U + warning) are still
dropped in the layer path.

| Warning source | Layer path | Can command (base policy) | Status |
|---|---|---|---|
| Unsupported operator | surfaced via parse-time ParseWarning (017) | surfaced | PASS |
| Policy variable substitution | dropped (.1 accessor) | surfaced (separate eval at line 213) | **CAT-3** |
| Missing context key | expressed as `layer_unresolved` tag | expressed as `unresolved` entry | PASS |

**HZ3B-E-1 (CAT-3 LAYER-EVAL-WARNING-LOSS):** Same pattern as HZ3A-C-1.
Layer evaluation drops eval warnings because `evalScpLevel`/`evalRcpLevel`/
`evalBoundary` only consume the Tri value from `evalCond`. The
`layer_unresolved` field conveys the key fact (which condition is
unresolved), but the specific reason (policy variable vs. missing key) is
lost.

In practice, policy variables in SCP/RCP/boundary documents are extremely
rare — these are org-level policies, not identity policies. The
`layer_unresolved` tag provides sufficient signal.

**File: `IamExplainer/Layers.lean:44,53,65,93`.**

## Proof Dependency Chain (3b additions)

```
evalScpLevel_blocked_noContext
evalRcpLevel_blocked_noContext    ─┐
evalBoundary_blocked_noContext     │
        ↓                         │
flatMap_blocked_mapIdx ────────────┤
        ↓                         │
evalLayers_blocked_noContext_empty ←┘
        ↓
layered_nocontext_conservative
  (also uses: layers_narrow, allows_nocontext_conservative)
```

| Dependency | Verified | Axioms | Status |
|---|---|---|---|
| evalScpLevel_blocked_noContext → flatMap_blocked_mapIdx | yes | standard | PASS |
| evalRcpLevel_blocked_noContext → flatMap_blocked_mapIdx | yes | standard | PASS |
| evalBoundary_blocked_noContext → evalLayers... | yes (direct) | standard | PASS |
| flatMap_blocked_mapIdx → evalLayers... | yes (SCP + RCP) | standard | PASS |
| evalLayers... → layered_nocontext_conservative | yes | standard | PASS |
| layers_narrow → layered_nocontext_conservative | yes | standard | PASS |
| allows_nocontext_conservative → layered_nocontext_conservative | yes (from 3a) | standard | PASS |

No circular dependencies. All 39 theorems (7 Condition + 9 Layers + 23
Proofs) use standard axioms only.

## Full Theorem Ledger (3b additions)

| # | Declaration | File | Axioms | Private | Status |
|---|---|---|---|---|---|
| 25 | `denyBlockedTags_noContext` | Layers.lean | standard | yes | CLEAN |
| 26 | `foldDenies_blocked_noContext` | Layers.lean | standard | yes | CLEAN |
| 27 | `evalLayers_noLayers_blocked` | Layers.lean | standard | public | CLEAN |
| 28 | `allowOk_noContext` | Layers.lean | standard | yes | CLEAN |
| 29 | `evalScpLevel_blocked_noContext` | Layers.lean | standard | yes | CLEAN |
| 30 | `evalBoundary_blocked_noContext` | Layers.lean | standard | yes | CLEAN |
| 31 | `evalRcpLevel_blocked_noContext` | Layers.lean | standard | yes | CLEAN |
| 32 | `flatMap_blocked_mapIdx` | Layers.lean | standard | yes | CLEAN |
| 33 | `evalLayers_blocked_noContext_empty` | Layers.lean | standard | public | CLEAN |
| 34 | `layers_narrow` | Proofs.lean | standard | public | CLEAN |
| 35 | `layer_add_monotone` | Proofs.lean | standard | public | CLEAN |
| 36 | `layered_nocontext_conservative` | Proofs.lean | standard | public | CLEAN |

12 new theorems (9 Layers + 3 Proofs). Running total: 36 (7+9+20 public
theorems from prior ledger count 24, plus 12 new). All verified via
`lean_verify`.

## Deviation Log

| ID | Category | Severity | File:Line | Description |
|---|---|---|---|---|
| HZ3B-B-1 | 3 (conservative) | low | `Match.lean:1-3`, `Layers.lean:77-85` | RCP Principal matching absent — `Request` has no principal field, `stmtMatches` ignores RCP Principal. Conservative (over-denies), not unsound. |
| HZ3B-D-1 | 2 (robustness) | low | `Main.lean:136-138` | `loadRcpServices` hardcodes relative path, crashes when run from non-project directory. |
| HZ3B-E-1 | 3 (warning-loss) | low | `Layers.lean:44,53,65,93` | Layer eval-time warnings dropped via `.1` accessor. Parse-time warnings surface (017 fix). Same class as HZ3A-C-1. |

## Disposition (IAMX-018)

| ID | Disposition | Rationale |
|---|---|---|
| HZ3B-B-1 | **RETIRED** | AWS RCP syntax requires `Principal: "*"` — narrower principals not permitted. "You can only specify `"*"` in the `Principal` element of an RCP." Principal matching in `evalRcpLevel` is spec over-specification; every valid RCP deny already matches all principals by definition. |
| HZ3B-D-1 | **CLOSED** | Try-catch at `loadRcpServices` call site; exit 2 with `cwd / rcpServicesPath` in message. Tested from foreign cwd. |
| HZ3B-E-1 | **CLOSED** | Structural warning channel: `evalWarnings` function + `warnings` field in `LayerResult`/`LayerVerdict`, threaded through `evalScpLevel`/`evalRcpLevel`/`evalBoundary` → `evalLayers` → `allowsLayered` → `runCan`. Theorems unaffected (reason about `.blocked` only). |

## Verification Block

```
1. Baseline rows                                      13/13
2. Seeded cells with verdict                          5/5 (A–E)
3. Full theorem ledger via lean_verify                36/36 clean
4. Proof dependency chain                             7/7 links verified
5. File delta accounted                               +5 over 88 cap (5 files named)
6. git diff --stat 82c3b05d51..HEAD                   see commit log
```

## Gate Verdict

**PASS-WITH-FINDINGS**

Histogram: 0 critical, 0 medium, 3 low (HZ3B-B-1, HZ3B-D-1, HZ3B-E-1).

All 36 theorems verified clean. The layer conservativeness proof chain is
sound: `layered_nocontext_conservative` composes `allows_nocontext_conservative`
(3a) with `evalLayers_blocked_noContext_empty` (3b) correctly. RCP
principal matching is absent but conservative — over-denial is safe for
the soundness contract.

3 low-severity deviations, all with identified fix directions. 0 blockers.
