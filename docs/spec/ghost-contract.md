# Ghost Reference — Go Integration Contract

Specification for wiring ghost-reference annotations between the Stave Go
core and the Lean evaluator. No Go code changes in this document — this is
the contract that a separate Go implementation prompt consumes.

## 1. Observation contract extension

### Ghost-annotated fields

For every reference field in the collector contract (`data/collector-contract.yaml`)
that carries an ARN or reference to another asset, the collector MAY annotate it
with ghost metadata when the reference cannot be resolved in the current snapshot.

**New fields per reference:**

| Field | Type | Description |
|---|---|---|
| `_ghost` | boolean | `true` when the referent is not in the snapshot scope |
| `_ghost_kind` | string enum | Discriminator: `managed_policy`, `cross_account_role`, `service_linked_role`, `cross_account_resource`, `unmodeled_service` |
| `_ghost_arn` | string | The ARN that could not be resolved |
| `_ghost_account` | string | (cross_account_role only) The foreign account ID |
| `_ghost_service_principal` | string | (service_linked_role only) The service principal |

### Collector contract fields that carry resolvable references

Walked from `data/collector-contract.yaml` — fields whose postcondition
references an ARN or cross-account principal:

| Collector contract field | Reference type | Ghost-eligible |
|---|---|---|
| `access.*.policy_allows_*` | Boolean (derived) | No — already collapsed to bool |
| `trust_policy_json` (via schema) | IAM policy document | Yes — principal ARNs within |
| `resource_policy_json` (via schema) | Resource policy document | Yes — principal ARNs within |
| `kms_key_arn` fields | KMS key ARN | Yes — cross-account KMS |
| `role_arn` fields | IAM role ARN | Yes — cross-account roles |
| `s3_bucket_arn` / destination fields | S3 bucket ARN | Yes — cross-account buckets |
| `lambda_function_arn` fields | Lambda ARN | Yes — cross-account Lambda |
| `sns_topic_arn` fields | SNS topic ARN | Yes — cross-account SNS |

**Boolean-collapsed fields** (`policy_allows_*`) are NOT ghost-eligible — the
collector already evaluated the policy and produced a boolean. Ghost annotations
apply to the raw reference, not the derived boolean.

## 2. Go-side responsibility

The Go collection hexagon sets `_ghost: true` when it encounters a reference
it cannot resolve in the current snapshot scope. Specifically:

1. **During observation loading**: when a property references an ARN and the
   corresponding asset is not in the snapshot, annotate the field.
2. **Pass-through to evaluator**: the annotated observation JSON is passed to
   the Lean evaluator unchanged. The Go core does not interpret `_ghost`
   fields — it passes them through.
3. **CEL evaluator parity**: the Go CEL evaluator SHOULD treat `_ghost: true`
   fields equivalently to the Lean evaluator's `RefStatus.ghost` branch.
   The CEL predicate should emit the same severity as the Lean control's
   ghost branch for the same input.

## 3. Lean-side responsibility

1. **Parser** (`IamExplainer/Ghost/Parse.lean`): `parseRefStatus` reads the
   ghost annotation and constructs `RefStatus α`.
2. **Control evaluation**: ghost-aware controls pattern-match on `RefStatus`
   (see `IamExplainer/Ghost/XAGhost.lean` for the reference implementation).
3. **Finding metadata**: the Lean evaluator returns findings that carry the
   ghost assumption as metadata, so the Go output formatter can say
   "this finding assumes the cross-account role is over-permissive."

## 4. Dual-evaluator parity

When both the Go CEL evaluator and the Lean evaluator run on the same
ghost-annotated observation:

- Their findings MUST agree on severity for the ghost reference.
- Disagreement = bug, surfaced by construction.
- The parity gate runs as a contract test at the Go↔Lean seam.

This is the same principle as the LEAN-EXTRACT CH4 dual-evaluator design.

## 5. Existing Go ghost handling mapped to Lean assumptions

Walked the Stave Go codebase. Current ghost-like handling:

### 5a. Explicit ghost-reference controls

The Go core already uses `has_ghost_*` fields in ~15 controls:

| Go field pattern | Example controls | Current behavior | Lean GhostAssumption |
|---|---|---|---|
| `has_ghost_trigger` | CTL.COGNITO.GHOST.* | Flag: Lambda trigger references deleted function | `overPermissive` |
| `has_ghost_rotation_lambda` | secret rotation controls | Flag: rotation references deleted Lambda | `overPermissive` |
| `has_ghost_principal` | secret policy controls | Flag: policy references deleted principal | `overPermissive` |
| `has_ghost_recorder_role` | Config recorder controls | Flag: recorder references deleted IAM role | `overPermissive` |
| `has_ghost_delivery_s3` | Config delivery controls | Flag: delivery channel references deleted S3 bucket | `overPermissive` |
| `has_ghost_delivery_sns` | Config delivery controls | Flag: delivery channel references deleted SNS topic | `overPermissive` |
| `has_ghost_rule_lambda` | Config custom rule controls | Flag: rule references deleted Lambda | `overPermissive` |
| `has_ghost_remediation_*` | Config remediation controls | Flag: remediation references deleted SSM/role | `overPermissive` |
| `has_ghost_s3` | GuardDuty/Macie export | Flag: export destination is deleted S3 bucket | `overPermissive` |
| `has_ghost_target` | EventBridge target controls | Flag: target references deleted resource | `overPermissive` |

**Assessment:** All existing ghost controls are **conservative** — they flag
(finding) when the reference is broken. This maps to `overPermissive` in the
Lean model: assume worst case, emit a finding. No existing control silently
skips a ghost reference (which would be the dangerous `leastPrivilege`
assumption).

### 5b. Cross-account handling

`internal/platform/providers/aws/iam/cross_account.go`:
- Cross-account resource policy grants require identity ∧ resource policy
  (stricter than same-account identity ∨ resource policy).
- When a cross-account principal's identity policy is not in scope, the
  Go code conservatively includes the resource policy grant.
- Maps to: `crossAccountRole` → `overPermissive`.

### 5c. Degraded chain edges

`internal/app/eval/graph_findings.go`:
- Assets with `is_expired=true` or `is_dormant=true` are marked as degraded.
- Chain edges through degraded assets still produce findings but carry a
  degraded annotation.
- Maps to: a different concern (asset lifecycle, not reference resolution),
  but the pattern is analogous — conservative treatment of uncertain state.

### 5d. Empty/nil policy documents

Multiple CEL predicates check for nil or empty policy documents:
- `internal/adapters/cel/env.go`: helper for empty-vs-error policy distinction.
- Various `*_test.go`: empty policy = safe (no grants), not a ghost.
- **Assessment:** empty policy is NOT a ghost reference — it's a resolved
  value that happens to be empty. The distinction matters: `RefStatus.resolved ""`
  is correct, not `RefStatus.ghost`.

### 5e. Exposure mapper ghost grants

`internal/core/evaluation/exposure/mapper.go`:
- Grants with empty `StatementIDs` are called "ghost grants" — they represent
  access that exists but cannot be traced to a specific policy statement.
- Maps to: a different use of "ghost" (untraceable, not unresolvable).
  The Lean `RefStatus.ghost` is specifically about unresolvable references,
  not untraceable grants. These are parallel concepts, not the same.

## 6. Contract test specification

### Input: ghost-annotated observation JSON

```json
{
  "principal": {
    "AWS": "arn:aws:iam::999888777666:role/Audit",
    "_ghost": true,
    "_ghost_kind": "cross_account_role",
    "_ghost_arn": "arn:aws:iam::999888777666:role/Audit",
    "_ghost_account": "999888777666"
  }
}
```

### Expected Lean output

```json
{
  "finding": {
    "severity": "critical",
    "ghost_assumption": "overPermissive",
    "ghost_ref_id": "arn:aws:iam::999888777666:role/Audit",
    "explanation": "Cross-account role trust policy not in snapshot; assumed over-permissive"
  }
}
```

### Contract tests at the two seams

1. **Observation ingress**: ghost-annotated JSON → `parseRefStatus` → `RefStatus.ghost`
   with correct `AwsGhostKind` and `GhostAssumption`. Test fixtures in
   `fixtures/xa/ghost-*.json`.

2. **Evaluation egress**: `RefStatus.ghost` input → ghost-aware control →
   finding with severity and ghost metadata. Verified by `#guard` tests
   in `IamExplainer/Ghost/XAGhost.lean`.
