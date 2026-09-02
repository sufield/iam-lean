# External Access Demo Script

Context for all runs:

```bash
CTX="--account 111122223333 --accounts fixtures/context/accounts.txt --org-id o-ours1234"
```

## 1. writeup-public (RESOURCE)

```bash
iamlean explain fixtures/xa/writeup-public.json $CTX --format json
```

Expected findings: `XA.PRINCIPAL.PUBLIC.001`, `XA.NOTPRINCIPAL.ALLOW.001`

```bash
iamlean grants fixtures/xa/writeup-public.json $CTX --format json
```

Expected grants: 2 rows, scopes PUBLIC, PUBLIC

## 2. remediated-public (RESOURCE)

```bash
iamlean explain fixtures/xa/remediated-public.json $CTX --format json
```

Expected findings: (none)

```bash
iamlean grants fixtures/xa/remediated-public.json $CTX --format json
```

Expected grants: 1 row, scope SAME_ACCOUNT

## 3. partial-public (RESOURCE)

```bash
iamlean explain fixtures/xa/partial-public.json $CTX --format json
```

Expected findings: `XA.PRINCIPAL.PUBLIC.FENCED.001`

```bash
iamlean grants fixtures/xa/partial-public.json $CTX --format json
```

Expected grants: 1 row, scope PUBLIC

## 4. writeup-external (RESOURCE)

```bash
iamlean explain fixtures/xa/writeup-external.json $CTX --format json
```

Expected findings: `XA.PRINCIPAL.ROOT.EXTERNAL.001`, `XA.ORGID.FOREIGN.001`

```bash
iamlean grants fixtures/xa/writeup-external.json $CTX --format json
```

Expected grants: 2 rows, scopes CROSS_ORG, CROSS_ORG

## 5. remediated-external (RESOURCE)

```bash
iamlean explain fixtures/xa/remediated-external.json $CTX --format json
```

Expected findings: (none)

```bash
iamlean grants fixtures/xa/remediated-external.json $CTX --format json
```

Expected grants: 1 row, scope IN_ORG

## 6. partial-external (RESOURCE)

```bash
iamlean explain fixtures/xa/partial-external.json $CTX --format json
```

Expected findings: `XA.PRINCIPAL.ROOT.EXTERNAL.001`

```bash
iamlean grants fixtures/xa/partial-external.json $CTX --format json
```

Expected grants: 2 rows, scopes CROSS_ORG, CROSS_ORG

## 7. writeup-trust (TRUST)

```bash
iamlean explain fixtures/xa/writeup-trust.json $CTX --format json
```

Expected findings: `XA.PRINCIPAL.ROOT.EXTERNAL.001`, `XA.TRUST.EXTERNALID.ABSENT.001`, `XA.FEDERATED.UNSCOPED.001`

```bash
iamlean grants fixtures/xa/writeup-trust.json $CTX --format json
```

Expected grants: 2 rows, scopes CROSS_ORG, FEDERATED

## 8. remediated-trust (TRUST)

```bash
iamlean explain fixtures/xa/remediated-trust.json $CTX --format json
```

Expected findings: (none) — two external grants, zero findings.

```bash
iamlean grants fixtures/xa/remediated-trust.json $CTX --format json
```

Expected grants: 2 rows, scopes CROSS_ORG, FEDERATED

## 9. partial-trust (TRUST)

```bash
iamlean explain fixtures/xa/partial-trust.json $CTX --format json
```

Expected findings: `XA.TRUST.EXTERNALID.ABSENT.001`

```bash
iamlean grants fixtures/xa/partial-trust.json $CTX --format json
```

Expected grants: 1 row, scope CROSS_ORG

## 10. No-flags run

```bash
iamlean explain fixtures/xa/writeup-external.json --format json
iamlean grants fixtures/xa/writeup-external.json --format json
```

Expected: 0 findings, 2 warnings ("scope UNVERIFIED — supply --account to classify"),
2 grants with scope UNVERIFIED.

## 11. Slice-1 on a RAM managed-permission (identity policy, no Principal)

```bash
iamlean explain fixtures/writeup-wildcards.json --format json
```

Expected: 3 LP findings (ADMIN.EQUIV, SERVICEWILDCARD, RESOURCE.WILDCARD).
Demonstrates: slice-1 least-privilege controls run on any policy document;
RAM managed-permissions are identity-shaped (no Principal) and go through the
same explain path.

Requires AWS access for live capture: `aws ram get-permission --permission-arn <arn> --query 'permission.permission'`

## What this tool cannot see from a document

1. **RAM share associations** — live in the sharing account, not in the policy document.
2. **Cross-account credential copies** — IAM access keys, certificates copied to other accounts.
3. **KMS grants** — separate API (`kms:CreateGrant`), not a policy document.
4. **S3 ACLs** — XML format, not IAM policy JSON.
5. **Account-level settings** — S3 Block Public Access, account contact info shared via Organizations.
