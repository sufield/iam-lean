# Slice 3b Specification — SCP / RCP / Permission-Boundary Layering

## Layer Semantics

### SCP (Service Control Policy)

Levels ordered root → account. Each `--scp <file>` is one level. A level
ALLOWS if some Allow statement matches (action, resource) and applies
(condition ≠ F). A level DENIES if some Deny statement matches and
applies (condition = T). Grant survives SCPs iff every level allows and
no level denies.

- No Allow statement in a level → assumed FullAWSAccess, with note
  `scp:<level>:assumed-full-access`.
- Deny condition = U → `layer_unresolved` with the condition key(s).
- Grammar: SCP with Principal or NotPrincipal → exit 2.
- Skipped under `--management-account` (note: `scp-skipped`) or for
  service-linked-role principals (`/aws-service-role/` in ARN path;
  note: `scp-exempt`).

### RCP (Resource Control Policy)

Deny-only. Each `--rcp <file>` is one level. Blocked iff some Deny
statement matches action, resource, and applies (T).

- AWS requires `Principal: "*"` in RCPs — narrower principals not
  permitted. Principal matching is therefore a no-op (every valid RCP
  deny matches all principals by definition). HZ3B-B-1 RETIRED.
- Action service prefix not in `data/rcp-services.txt` → `unresolved:
  rcp:<level>:service-not-in-support-list`.
- Deny condition = U → `layer_unresolved`.
- Grammar: RCP statement without Principal → exit 2.

### Permission Boundary

Applies to IDENTITY-kind grants only (note and skip for RESOURCE/TRUST).
Blocked iff no boundary Allow matches-and-applies
(`boundary:no-allow`) or a boundary Deny matches-and-applies (T).

### Cross-Account Resource-Policy Grants

`unresolved: identity-side policy not supplied` always (deferred to 3d).

### Verdict Rule

- DENIED: base `allows` is false OR some layer blocks with certainty.
- ALLOWED: base allows, no layer blocks, and `unresolved` is empty.
- ALLOWED_UNRESOLVED: otherwise.

## Output Fields

- `blocked_by[]`: identifiers — `scp:<level>:<Sid|index>`,
  `scp:<level>:no-allow`, `rcp:<level>:<Sid|index>`,
  `boundary:<Sid|index>`, `boundary:no-allow`.
- `layer_unresolved[]`: same identifiers plus the condition key(s).
- `notes[]`: `scp-skipped`, `scp-exempt`, `scp:<level>:assumed-full-access`,
  `boundary-skipped:<kind>`, `identity-side policy not supplied`.

## Theorems

1. `layers_narrow`: allowsLayered allowed=true → allows p r ctx = true.
2. `layer_add_monotone`: adding a layer document never widens.
3. `layered_nocontext_conservative`: allowsLayered with ctx → with noContext.

## SAML Control (rider)

XA.FEDERATED.SAML.UNSCOPED.001 (high): SAML provider ARN (`:saml-provider/`),
`sts:AssumeRoleWithSAML` granted, neither `SAML:aud` nor `SAML:sub` (ci)
present as condition key.

Legacy row moved: `partial-federated-saml.json` 0 → 1.

## Expected Counts

### Layer manifest (`fixtures/layers/queries.jsonl`, 15 queries + 2 invalid)

| # | Scenario | Action | Layers | Context | Expected | blocked_by | layer_unresolved |
|---|---|---|---|---|---|---|---|
| 1 | deny-scp-conditional | s3:GetObject | scp L1 | org:o-ours1234 | ALLOWED | [] | [] |
| 2 | deny-scp-conditional | s3:GetObject | scp L1 | org:o-foreign999 | DENIED | [scp:1:DenyOutsideOrg] | [] |
| 3 | deny-scp-conditional | s3:GetObject | scp L1 | (none) | ALLOWED_UNRESOLVED | [] | [scp:1:DenyOutsideOrg:aws:PrincipalOrgID] |
| 4 | allow-list-scp | s3:PutObject | scp L1 | — | DENIED | [scp:1:no-allow] | [] |
| 5 | allow-list-scp | s3:GetObject | scp L1 | — | ALLOWED | [] | [] |
| 6 | deny-only-level | s3:GetObject | scp L1 | — | ALLOWED | [] | [] |
| 7 | deny-only-level | iam:CreateUser | scp L1 | — | DENIED | [scp:1:DenyIam] | [] |
| 8 | rcp-org-fence | s3:GetObject | rcp L1 | org:o-foreign999 | DENIED | [rcp:1:DenyOutsideOrg] | [] |
| 9 | rcp-org-fence | s3:GetObject | rcp L1 | org:o-ours1234 | ALLOWED_UNRESOLVED | [] | [identity-side policy not supplied] |
| 10 | rcp-org-fence | dynamodb:GetItem | rcp L1 | org:o-foreign999 | ALLOWED_UNRESOLVED | [] | [rcp:1:service-not-in-support-list] |
| 11 | boundary | s3:PutObject | boundary | — | DENIED | [boundary:no-allow] | [] |
| 12 | boundary | s3:GetObject | boundary | — | ALLOWED | [] | [] |
| 13 | boundary-resource | s3:GetObject | boundary | — | ALLOWED | [] | [] |
| 14 | management-account | s3:GetObject | scp L1, mgmt | org:o-foreign999 | ALLOWED | [] | [] |
| 15 | service-linked | s3:GetObject | scp L1, slr | org:o-foreign999 | ALLOWED | [] | [] |

### SAML fixtures

| Fixture | Expected findings |
|---|---|
| writeup-saml.json | 2 (SAML.UNSCOPED + FEDERATED.UNSCOPED) |
| remediated-saml.json | 0 |
| partial-saml.json | 1 (SAML.UNSCOPED) |

### Legacy row moved

| Fixture | Was | Now |
|---|---|---|
| partial-federated-saml.json | 0 | 1 (SAML.UNSCOPED fires) |

## Verification

```bash
1.  lake build                                                     # exit 0 ✓
2.  grep -rn "sorry\|admit\|native_decide" IamExplainer/ | wc -l   # 0 ✓
3.  Slice-1 fixtures; #guards                                       # 13/13; 27 ✓
4.  Slice-2 XA with flags; no-flags                                 # 9/9+6/6; 0/2/2 ✓
5.  3a query manifest                                               # 18/18 ✓
6.  Layer manifest (15 queries)                                     # 15/15 ✓
7.  Layer invalid (scp-with-principal, rcp-without-principal)        # exit 2, exit 2 ✓
8.  SAML triple (writeup/remediated/partial)                        # 2/0/1 ✓
9.  grep -c "theorem layers_narrow\|layer_add_monotone\|layered_nocontext_conservative" Proofs.lean  # 3 ✓
10. Axiom audit, all Proofs.lean + Layers.lean theorems             # 0 tainted ✓
11. grep -rn "def allowsLayered" IamExplainer/ | wc -l              # 1 ✓
12. git ls-files | wc -l                                            # 93 (cap 88, +5)
13. partial-federated-saml.json legacy row                          # 0→1 ✓
```

### Row 12 delta

Pre-014 baseline: 69 files. Added 24 (predicted 19). 5 over
cap 88:

| # | File | Reason |
|---|---|---|
| 1 | `fixtures/layers/org-foreign.json` | Context file — 3b queries reference files, not inline JSON |
| 2 | `fixtures/layers/org-ours.json` | Same |
| 3 | `fixtures/layers/boundary-resource-policy.json` | Boundary-skip-for-resource-kind coverage (row 13) |
| 4 | `fixtures/xa/writeup-saml.json` | SAML writeup new (prediction counted partial+remediated only) |
| 5 | `fixtures/layers/invalid/rcp-without-principal.json` | Spec counted "2 invalid" as +1 file, actually +2 |

## Invariants (carried forward)

- Slice-1: 13/13 fixtures, 27 #guards.
- Slice-2 XA: 9/9 + 6/6 with flags (partial-federated-saml = 1).
- No-flags: 0/2/2.
- 3a manifest: 18/18 (unchanged — `can` without layer flags = same behavior).
