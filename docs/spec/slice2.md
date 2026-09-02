# Slice 2 Specification — External Access Explain

## Document Kinds

| Kind | Detection rule |
|---|---|
| IDENTITY | No statement carries Principal or NotPrincipal |
| TRUST | Every statement carries Principal, actions ⊆ {sts:AssumeRole*, sts:TagSession, sts:SetSourceIdentity}, no Resource |
| RESOURCE | Principal + Resource |
| MIXED | Mix of identity and resource statements → warning ("document mixes identity and resource-policy statements; evaluating as RESOURCE"), evaluated as RESOURCE |

## Scope Classes

| Scope | Condition |
|---|---|
| SAME_ACCOUNT | Principal account = `--account` |
| IN_ORG | Principal account ∈ `--accounts`, or `*` fenced by aws:PrincipalOrgID = `--org-id` |
| CROSS_ORG | AWS principal account ∉ accounts, or `*` fenced by foreign org id |
| PUBLIC | `*` with no org fence; NotPrincipal grants |
| FEDERATED | Federated principal |
| SERVICE | Service principal |
| UNVERIFIED | Classification needs a flag that was not supplied |

## XA Control Catalog

| ID | Severity | Fires when |
|---|---|---|
| XA.PRINCIPAL.PUBLIC.001 | critical | scope PUBLIC and no Condition |
| XA.PRINCIPAL.PUBLIC.FENCED.001 | medium | scope PUBLIC and a Condition is present |
| XA.PRINCIPAL.ROOT.EXTERNAL.001 | high | CROSS_ORG AWS principal in `:root` form |
| XA.ORGID.FOREIGN.001 | critical | aws:PrincipalOrgID present and ANY listed id ≠ `--org-id`; fires regardless of principal type; suppresses PUBLIC.FENCED on same statement |
| XA.FEDERATED.UNSCOPED.001 | high | Federated OIDC principal (ARN contains `:oidc-provider/`) with no `<provider>:sub` condition key |
| XA.TRUST.EXTERNALID.ABSENT.001 | high | kind TRUST, CROSS_ORG AWS principal, sts:AssumeRole granted, no `sts:ExternalId` key |
| XA.NOTPRINCIPAL.ALLOW.001 | critical | Allow with NotPrincipal |

### Suppression rules

- XA.ORGID.FOREIGN.001 suppresses XA.PRINCIPAL.PUBLIC.FENCED.001 on the same statement.
- Slice-1 LP controls fire on all kinds. HZ-11's "Allow without Resource" warning
  is suppressed for kind TRUST.
- UNVERIFIED scope never produces a finding; it produces exactly one warning per
  statement naming the missing flag.

## Principal Normalization

- Bare 12-digit account id → `arn:aws:iam::<id>:root`
- `"*"` → wildcard principal (scope PUBLIC unless fenced)
- `{"AWS": s|[s]}` → list of AWS principals (each normalized); non-ARN, non-12-digit strings → parse error (exit 2)
- `{"Federated": s|[s]}` → list of Federated principals
- `{"Service": s|[s]}` → list of Service principals
- `{"CanonicalUser": s|[s]}` → scope UNVERIFIED, warning ("canonical user id is not resolvable to an account from the document")

## OrgID Array Semantics (R2)

`aws:PrincipalOrgID` may be a string or array (StringEquals semantics: any-of).
- ORGID.FOREIGN fires if ANY listed id ≠ `--org-id`.
- Scope IN_ORG requires ALL listed ids = `--org-id`.

## Context Inputs

All optional, all fail-loud when absent:
- `--account <id>`: owner of the document
- `--accounts <file>`: one account id per line ("us")
- `--org-id o-xxxx`: our organization

Absent context → scope UNVERIFIED + warning naming the missing flag.

## Expected Counts

Context for all runs: `--account 111122223333 --accounts fixtures/context/accounts.txt --org-id o-ours1234`.
accounts.txt contains: 111122223333, 222233334444.

| Fixture | Kind | Findings | Finding IDs | Grants | Grant Scopes |
|---|---|---|---|---|---|
| xa/writeup-public.json | RESOURCE | 2 | PUBLIC, NOTPRINCIPAL.ALLOW | 2 | PUBLIC, PUBLIC |
| xa/remediated-public.json | RESOURCE | 0 | — | 1 | SAME_ACCOUNT |
| xa/partial-public.json | RESOURCE | 1 | PUBLIC.FENCED | 1 | PUBLIC |
| xa/writeup-external.json | RESOURCE | 2 | ROOT.EXTERNAL, ORGID.FOREIGN | 2 | CROSS_ORG, CROSS_ORG |
| xa/remediated-external.json | RESOURCE | 0 | — | 1 | IN_ORG |
| xa/partial-external.json | RESOURCE | 1 | ROOT.EXTERNAL | 2 | CROSS_ORG, CROSS_ORG |
| xa/writeup-trust.json | TRUST | 3 | ROOT.EXTERNAL, EXTERNALID.ABSENT, FEDERATED.UNSCOPED | 2 | CROSS_ORG, FEDERATED |
| xa/remediated-trust.json | TRUST | 0 | — | 2 | CROSS_ORG, FEDERATED |
| xa/partial-trust.json | TRUST | 1 | EXTERNALID.ABSENT | 1 | CROSS_ORG |

| xa/writeup-orgid-array.json | RESOURCE | 1 | ORGID.FOREIGN | 1 | CROSS_ORG |
| xa/remediated-orgid-array.json | RESOURCE | 0 | — | 1 | IN_ORG |
| xa/partial-orgid-principal.json | RESOURCE | 1 | ORGID.FOREIGN | 1 | CROSS_ORG |
| xa/partial-federated-saml.json | TRUST | 0 | — | 1 | FEDERATED |
| xa/partial-canonicaluser.json | RESOURCE | 0 | — | 1 | UNVERIFIED (warning) |
| xa/writeup-mixed.json | RESOURCE (MIXED) | 1 | PUBLIC | 1 | PUBLIC (warning: mixed) |

### Invalid principal (exit 2)

| xa/invalid/bad-principal.json | — | — | — | — | exit 2 |

### No-flags run (writeup-external.json, no --account/--accounts/--org-id)

| Findings | Warnings | Grants | Grant Scopes |
|---|---|---|---|
| 0 | 2 | 2 | UNVERIFIED, UNVERIFIED |

## Soundness Contract Addition

`grants_complete`: `allows p req = true → ∃ s ∈ p.statements, s.effect = .allow ∧ stmtMatches s req = true`

Allow-side completeness: every allowed request is witnessed by an allow
statement. Grant rows are a pure data transformation from allow statements
(one row per principal), so completeness at the statement level guarantees
completeness of the grant decomposition.

Axioms: propext, Classical.choice, Quot.sound (standard only).

## Verification Block

```bash
lake build                                                        # exit 0
grep -rn "sorry\|admit\|native_decide" IamExplainer/ | wc -l      # 0
# Slice-1: 13/13 fixtures, 27 #guards
# XA: 9/9 fixture finding counts
# XA: 9/9 fixture grant scopes
# No-flags: 0 findings, 2 warnings, 2 UNVERIFIED grants
# grants_complete: closed, standard axioms
```
