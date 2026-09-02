# SECLIB — Vendor-Neutral Security Library

## Layer Map

```
Seclib/
├── Prim.lean          Tri (three-valued logic) + Effect (allow/deny)
├── Prim/
│   ├── Finding.lean   Severity, Evidence, Fix, Finding types
│   ├── Glob.lean      Case folding, glob matching, string lemmas
│   └── Rule.lean      Rule, appliesOf, denyOverridesRules, 4 generic lemmas
├── Domain/
│   └── PolicySem.lean PolicySem structure + abstract denyOverrides + 5 theorems
└── Domain.lean        Umbrella import

IamExplainer/          Vendor-specific (AWS IAM) layer
├── Policy.lean        Statement, Policy types (imports Effect from Seclib.Prim)
├── Condition.lean     Condition evaluation (imports Tri, Glob from Seclib.Prim)
├── Match.lean         stmtMatches, allows
├── Proofs.lean        iamSem : PolicySem, cond_bridge, 5 corollary theorems
└── ...                Checks, Grants, Layers, Emit, etc.
```

## Membership Test

```
grep -riE "aws|arn|iam|statement|policy|principal|scp|rcp|saml|oidc" Seclib/Prim/
```

Expected: 0 hits. Enforced at every commit touching `Seclib/Prim/`.

## Name Decision

`Seclib` — "security library." Short, grep-friendly, no vendor noun.
`Prim` — primitives. Contains only types and lemmas that apply to any
deny-overrides authorization system, not just AWS IAM.

## Generic Lemmas (Rule.lean)

| Lemma | Security Property |
|---|---|
| `denyOverrides_remove_allow_narrows` | Removing an allow can only narrow access |
| `denyOverrides_add_deny_narrows` | Adding a deny can only narrow access |
| `conj_narrows` | Conjunction of gates never widens |
| `appliesOf_unknown_conservative` | Unknown applicability over-approximates |

## Import Direction

`Seclib/` never imports `IamExplainer/`. Enforced by:
```
grep -rn "import IamExplainer" Seclib/ | wc -l  # must be 0
```
