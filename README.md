# IAM Explainer

A least-privilege and external-access analyzer for AWS IAM policy JSON. Feed it any policy document — identity, trust, or resource — and get back findings with severity, explanation, and fix suggestions.

Written in Lean 4 with machine-checked proofs that every suggested fix narrows the original policy (never grants new access).

## Setup

```sh
# Install Lean 4 (v4.33.1+): https://lean-lang.org/lean4/doc/quickstart.html

# Build
lake build

# Add to PATH for this session
export PATH="$PWD/.lake/build/bin:$PATH"

# Verify it works
iamlean explain fixtures/writeup-wildcards.json
```

## Commands

### explain — Analyze a policy

```sh
# Identity policy — least-privilege checks
iamlean explain fixtures/writeup-wildcards.json

# Trust/resource policy — add context for scope classification
iamlean explain fixtures/xa/writeup-trust.json \
  --account 111122223333 \
  --accounts fixtures/context/accounts.txt \
  --org-id o-ours1234

# Without context flags, scopes are UNVERIFIED (warnings, no findings)
iamlean explain fixtures/xa/writeup-external.json
```

### grants — Show who gets access

```sh
# List every grant row with principal, scope, actions, and conditions
iamlean grants fixtures/xa/writeup-trust.json \
  --account 111122223333 \
  --accounts fixtures/context/accounts.txt \
  --org-id o-ours1234 \
  --format json | jq '.grants[] | {principal, scope, actions}'
```

### Context flags

All optional. Absent flags produce UNVERIFIED scope with a warning — never a finding.

| Flag | Purpose |
|---|---|
| `--account <id>` | Owner of the policy document |
| `--accounts <file>` | File with one account ID per line (known accounts) |
| `--org-id o-xxxx` | Your AWS organization ID |

## Workflow: Analyze, Fix, Verify

```sh
# 1. Analyze — see what's wrong
iamlean explain fixtures/writeup-wildcards.json

# 2. Fix — compare the bad policy to its remediated version
diff fixtures/writeup-wildcards.json fixtures/remediated-wildcards.json

# 3. Verify — confirm the fixed policy passes
iamlean explain fixtures/remediated-wildcards.json
```

## Fixtures

Each scenario has a `writeup-` (findings), `remediated-` (clean), and `partial-` (boundary) variant.

```sh
# Admin equivalent — Action:"*" + Resource:"*" (critical)
iamlean explain fixtures/writeup-wildcards.json
diff fixtures/writeup-wildcards.json fixtures/remediated-wildcards.json
iamlean explain fixtures/remediated-wildcards.json

# NotAction escape — Allow + NotAction grants everything else (high)
iamlean explain fixtures/writeup-complement.json
diff fixtures/writeup-complement.json fixtures/remediated-complement.json
iamlean explain fixtures/remediated-complement.json

# Unscoped PassRole — no resource or condition constraint (high)
iamlean explain fixtures/writeup-passrole.json
diff fixtures/writeup-passrole.json fixtures/remediated-passrole.json
iamlean explain fixtures/remediated-passrole.json

# NotAction lets iam:PassRole through (high)
iamlean explain fixtures/writeup-notaction-passrole.json

# PassRole via wildcard action pattern (high)
iamlean explain fixtures/writeup-passrole-viawildcard.json

# Boundary cases — mix of good and bad statements
iamlean explain fixtures/partial-wildcards.json
iamlean explain fixtures/partial-complement.json
iamlean explain fixtures/partial-passrole.json
iamlean explain fixtures/partial-notaction-passrole.json

# --- External access fixtures (trust + resource policies) ---
CTX="--account 111122223333 --accounts fixtures/context/accounts.txt --org-id o-ours1234"

# Public access — Principal:"*" with no condition (critical)
iamlean explain fixtures/xa/writeup-public.json $CTX
iamlean explain fixtures/xa/remediated-public.json $CTX
iamlean explain fixtures/xa/partial-public.json $CTX

# Cross-org access — external root principal (high)
iamlean explain fixtures/xa/writeup-external.json $CTX
iamlean explain fixtures/xa/remediated-external.json $CTX

# Trust policy — confused deputy, unscoped federation (high)
iamlean explain fixtures/xa/writeup-trust.json $CTX
iamlean explain fixtures/xa/remediated-trust.json $CTX

# OrgID array — mixed org ids in condition (critical)
iamlean explain fixtures/xa/writeup-orgid-array.json $CTX
iamlean explain fixtures/xa/remediated-orgid-array.json $CTX

# ORGID.FOREIGN on non-wildcard principals
iamlean explain fixtures/xa/partial-orgid-principal.json $CTX

# SAML provider — no finding (OIDC-only control)
iamlean explain fixtures/xa/partial-federated-saml.json $CTX

# CanonicalUser — UNVERIFIED scope with warning
iamlean explain fixtures/xa/partial-canonicaluser.json $CTX

# Mixed document (identity + resource statements) — warning
iamlean explain fixtures/xa/writeup-mixed.json $CTX

# Invalid input — malformed policy (exit 2)
iamlean explain fixtures/invalid/bad-effect.json
iamlean explain fixtures/xa/invalid/bad-principal.json $CTX

# JSON output — add --format json to any command
iamlean explain fixtures/writeup-wildcards.json --format json | jq '.counts'
```

## What It Checks

### Least-Privilege Controls (LP)

| Control ID | Severity | What it catches |
|---|---|---|
| LP.ADMIN.EQUIV.001 | critical | `Action: "*"` + `Resource: "*"` — full admin equivalent |
| LP.ACTION.SERVICEWILDCARD.001 | high | `Action: "s3:*"` — service-level wildcard |
| LP.RESOURCE.WILDCARD.001 | high | `Resource: "*"` — applies to all resources |
| LP.NOTACTION.ALLOW.001 | high | `Allow` + `NotAction` — implicitly allows everything else |
| LP.NOTRESOURCE.ALLOW.001 | medium | `Allow` + `NotResource` — implicitly scopes to everything else |
| LP.ESCALATE.PASSROLE.001 | high | `iam:PassRole` without resource scoping or `iam:PassedToService` condition |

### External Access Controls (XA)

| Control ID | Severity | What it catches |
|---|---|---|
| XA.PRINCIPAL.PUBLIC.001 | critical | `Principal: "*"` with no Condition — world-accessible |
| XA.PRINCIPAL.PUBLIC.FENCED.001 | medium | `Principal: "*"` with a Condition — public but gated |
| XA.PRINCIPAL.ROOT.EXTERNAL.001 | high | Cross-org AWS principal in `:root` form |
| XA.ORGID.FOREIGN.001 | critical | `aws:PrincipalOrgID` present but doesn't match `--org-id` |
| XA.FEDERATED.UNSCOPED.001 | high | Federated OIDC principal with no `<provider>:sub` condition |
| XA.TRUST.EXTERNALID.ABSENT.001 | high | Trust policy allows `sts:AssumeRole` to cross-org principal without `sts:ExternalId` |
| XA.NOTPRINCIPAL.ALLOW.001 | critical | `Allow` + `NotPrincipal` — grants to everyone except the listed principal |

## Soundness Certificate

`lake build` does two things: compiles the binary and type-checks every theorem in `IamExplainer/Proofs.lean`. If a proof is wrong, the build fails. A successful build is the certificate.

The proofs guarantee that every fix iamlean suggests can only narrow the original policy — it will never grant new access. Specifically:

| Theorem | Guarantee |
|---|---|
| `removeAllow_narrows` | Removing an Allow statement cannot grant new access |
| `stmtGrantsAction_narrow` | Replacing wildcard actions with literal action names cannot grant new access |
| `narrowActions_narrows` | Narrowing actions in an Allow statement preserves the allow-set monotonicity |
| `grants_complete` | Every allowed request is witnessed by an Allow statement — grant rows cannot miss an access path |

These are mathematical proofs verified by Lean's type checker against the same `Policy`, `Statement`, and `allows` definitions the analyzer uses at runtime.
