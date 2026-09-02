# Slice 3c Specification — `emit-fixed` with Need-Set Ingestion

## Purpose

Given an identity policy and a need-set (the actions and resources the
workload actually uses), emit a remediated policy using only transforms
with a closed narrowing theorem. The output provably never grants what
the input didn't, and reports every need the input never granted rather
than adding it.

## Need-Set Format

```json
{"needs": [{"action": "s3:GetObject", "resource": "arn:aws:s3:::app-logs"}, ...]}
```

Actions must be wildcard-free literals: `*` or `?` in an action → exit 2.
Resources may carry wildcards; only wildcard-free resources participate
in T3 (resource narrowing).

## Transforms (per Allow statement; Deny statements never touched)

### T1 NarrowActions

When a statement has wildcard actions (`*`, `svc:*`) or uses NotAction,
replace with the explicit list of granted need actions. The replacement
statement has `actions := some literals`, `notActions := none`, all other
fields preserved.

Applies when `literals ≠ []`.

Theorem: `narrowActions_narrows` — each literal is wildcard-free (validated
at input), granted by the original statement (checked by `stmtGrantsAction`),
resources/notResources/condition preserved.

### T2 (deferred)

When `literals = []` (no needed action is granted by the statement),
the statement is kept unchanged — the need set describes what the workload
uses, not an exhaustive policy constraint. Statements irrelevant to the
need set serve other workloads and should not be removed.

The `removeAllow_narrows` theorem remains available for future use when
an exhaustive mode is added.

### T3 NarrowResources

When all needs touching a statement have wildcard-free resources, replace
the statement's resource patterns with those exact resources.

When any touching need has a wildcard resource, the statement keeps its
original resources and the report says `resource narrowing withheld`.

NotResource statements: untouched, reported as `manual` residual.

Theorem: `narrowResources_narrows` — replacing resource patterns with
wildcard-free literals each matched by the old patterns (case-sensitive
`matchPattern`) narrows `allows`.

### Literal-only statements

Statements with only literal actions and literal resources: untouched
(already as narrow as the needs require).

## Cross-Checks (post-emission, fail-loud)

- **C1 Need coverage**: ∀ need, `allows fixed need noContext = true`;
  a failing need was never granted by the original (by `emitFixed_narrows`)
  → listed in `needs_not_granted`, never added.
- **C2 Findings**: LP findings on the fixed policy. Residuals listed with
  reason (`manual: condition insertion`, `manual: NotResource`,
  `withheld: wildcard resource`).
- **C3 Idempotence**: `emitFixed fixed needs = fixed` (structural equality).
- **C4 Output validity**: `explain fixed` parses (exit 0 or 1, never 2).

## Command Interface

```
iamlean emit-fixed <policy> --needs <file> [--format json] [--out fixed.json]
```

- Only IDENTITY-kind policies accepted. RESOURCE / TRUST → exit 2 with
  "principal narrowing unproven; not supported".
- Output: the fixed policy plus a report.

### Report Shape

```json
{
  "fixed_policy": { ... },
  "transforms": [{"statement": "Sid", "type": "T1|T2|T3", "detail": "..."}],
  "residual_findings": [{"id": "LP.XXX", "statement": "Sid", "reason": "manual|withheld"}],
  "needs_not_granted": [{"action": "...", "resource": "..."}],
  "withheld": [{"statement": "Sid", "reason": "wildcard resource in need"}],
  "idempotent": true
}
```

## Theorems

1. `narrowResources_narrows` — replacing an Allow statement's resource
   patterns with wildcard-free literals each matched by the old patterns
   narrows `allows`.
2. `emitFixed_narrows` — ∀ p needs r ctx, `allows (emitFixed p needs).1 r ctx
   = true → allows p r ctx = true`.

## Expected Counts

| # | Policy | Needs | Fixed Shape | Findings | Report |
|---|---|---|---|---|---|
| 1 | writeup-wildcards | ListBucket+GetObject on exact ARNs | Actions narrowed, Resources narrowed | 3→0 | needs 2/2, withheld 0 |
| 2 | writeup-wildcards | Same actions, GetObject on glob ARN | Actions narrowed, Resources kept | 3→2 (RESOURCE.WILDCARD ×2) | withheld 2 |
| 3 | writeup-complement | GetObject+PutObject on exact ARNs | NotAction→Action; NotResource untouched | 3→1 (NOTRESOURCE manual) | residual manual 1 |
| 4 | writeup-passrole | PassRole on exact role ARN | Resource narrowed | 2→1 (PASSROLE condition manual) | residual manual 1 |
| 5 | remediated-wildcards | dynamodb:GetItem on table ARN | unchanged | 0→0 | needs_not_granted 1 |
| 6 | writeup-wildcards | s3:Get* (wildcard action) | — | exit 2 | — |
| 7 | writeup-trust (TRUST) | any | — | exit 2 | — |

Idempotence: 5/5 on all emitted policies.

## Verification

```bash
1.  lake build                                                      # exit 0
2.  grep -rn "sorry\|admit\|native_decide" IamExplainer/ | wc -l    # 0
3.  Slice-1; #guards                                                 # 13/13; 27
4.  XA; 3a manifest; 3b manifest                                     # unchanged
5.  Emit table rows: fixed shape + findings orig → fixed              # 5/5
6.  Need coverage; withheld / manual / not_granted counts             # per table
7.  Idempotence                                                       # 5/5
8.  Invalid rows (wildcard action; TRUST kind)                         # exit 2; exit 2
9.  Theorems present                                                   # narrowResources_narrows, emitFixed_narrows
10. Declarations + axiom audit                                         # 0 tainted
11. grep -rn "def emitFixed" IamExplainer/ | wc -l                     # 1
12. git ls-files | wc -l                                               # <= 112
13. claude mcp list | grep -c lean-lsp                                 # 1
```
