# Slice 3a Specification — Condition Semantics + `can` Query

## Modeled-Fragment Change

Slices 1–2 treat conditions as always satisfied — a deliberate
over-approximation for security. Slice 3a replaces this with three-valued
evaluation (T / F / U) and one rule: UNKNOWN resolves in the direction
that keeps the grant visible.

- **Allow** applies when its condition is T or U (grant-preserving)
- **Deny** applies only when its condition is T (conservative)

`allows_nocontext_conservative` is the theorem that makes this a guarantee:
the no-context report never hides a grant that some complete context would
allow.

## Three-Valued Type (`Tri`)

| Value | Meaning |
|---|---|
| T | Condition satisfied — decidable from context |
| F | Condition not satisfied — decidable from context |
| U | Unknown — key absent from context, or unsupported operator |

Kleene semantics: `and`, `or`, `not` follow standard three-valued truth
tables.

| and | T | F | U |
|---|---|---|---|
| T | T | F | U |
| F | F | F | F |
| U | U | F | U |

| or | T | F | U |
|---|---|---|---|
| T | T | T | T |
| F | T | F | U |
| U | T | U | U |

| not | |
|---|---|
| T | F |
| F | T |
| U | U |

## Operator Table

Shipped operators (12):

| Operator | Match semantics | Missing key (complete ctx) | Missing key (no ctx) |
|---|---|---|---|
| StringEquals | exact match | F | U |
| StringNotEquals | negated exact | T | U |
| StringEqualsIgnoreCase | exact, case-insensitive | F | U |
| StringNotEqualsIgnoreCase | negated, case-insensitive | T | U |
| StringLike | `matchPattern` (case-sensitive) | F | U |
| StringNotLike | negated `matchPattern` | T | U |
| ArnEquals | exact match | F | U |
| ArnNotEquals | negated exact | T | U |
| ArnLike | `matchPattern` (case-sensitive) | F | U |
| ArnNotLike | negated `matchPattern` | T | U |
| Bool | string comparison "true"/"false" | F | U |
| Null | `true` → T if key absent, F if present; `false` → reverse | decidable | U (no ctx) |

Deferred operators → U + warning naming the operator:

- NumericEquals, NumericNotEquals, NumericLessThan, NumericLessThanEquals,
  NumericGreaterThan, NumericGreaterThanEquals
- DateEquals, DateNotEquals, DateLessThan, DateLessThanEquals,
  DateGreaterThan, DateGreaterThanEquals
- IpAddress, NotIpAddress
- BinaryEquals

Policy-variable substitution (`${aws:username}`) → U + warning.

## Operator Modifiers

### IfExists suffix

Any operator may carry the `IfExists` suffix (e.g., `StringEqualsIfExists`).
When the condition key is absent from a complete context, the result is T
(vacuously true) instead of applying the operator's missing-key rule. Under
no-context, IfExists still returns U.

### ForAnyValue / ForAllValues prefix

Quantifiers over multi-valued context keys:

- `ForAnyValue:Op` — T if any context value satisfies Op; F if none do;
  U if any value returns U.
- `ForAllValues:Op` — T if all context values satisfy Op (or the context
  value list is empty); F if any value fails; U if any value returns U.

## Context Input (`--context`)

`--context <file>` — flat JSON object mapping keys to `string | [string] | bool`.

**Completeness rule:** A supplied context is complete — a key absent from it
is ABSENT (so `Null` is decidable). No `--context` means every key lookup
returns U. Two modes only.

## Statement Applicability

```
applies (s : Statement) (ctx : CondContext) : Bool :=
  match s.effect, evalCond ctx s.condition with
  | .allow, .f => false
  | .allow, _  => true
  | .deny,  .t => true
  | .deny,  _  => false
```

## `allows` with Context

```lean
def allows (p : Policy) (req : Request) (ctx : CondContext) : Bool :=
  let denied := p.statements.any fun s =>
    s.effect == .deny && stmtMatches s req && evalCond ctx s.condition == .t
  if denied then false
  else p.statements.any fun s =>
    s.effect == .allow && stmtMatches s req && evalCond ctx s.condition != .f
```

`noContext` is the context where every lookup returns U.

## `can` Command

```
iamlean can <policy> --action A --resource R [--context F] [--format json]
```

JSON output: `{verdict, deciding_statements, unresolved, warnings}`

| Verdict | Meaning |
|---|---|
| ALLOWED | Access allowed, condition decidable |
| DENIED | Access denied, condition decidable |
| ALLOWED_UNRESOLVED | Allow applied through U, or Deny withheld through U |

`deciding_statements[]` — statements whose match + condition contributed.
`unresolved[]` — `{key, operator}` pairs that could not be evaluated.

## Evaluator Design

ONE evaluator `evalCond : CondContext → Option Json → Tri` in `Condition.lean`.

- Operator blocks AND across keys
- Values OR within a key (StringEquals any-of semantics)
- Key comparison case-insensitive
- Value comparison per operator

## Theorems (Proofs.lean)

### Restated with `ctx` parameter (universally quantified)

| Theorem | Line (pre-3a) | Status |
|---|---|---|
| `removeAllow_narrows` | 31 | restate |
| `allows_replaceAllow_mono` | 165 | restate |
| `narrowActions_narrows` | 212 | restate |
| `grants_complete` | 231 | restate |

### New

`allows_nocontext_conservative`:
```lean
theorem allows_nocontext_conservative (p : Policy) (req : Request) (ctx : CondContext)
    (h : allows p req ctx = true) :
    allows p req noContext = true
```

The no-context report never hides a grant that some complete context would
allow. Proof: under noContext, every condition evaluates to U, so no Deny
applies (U ≠ T) and every action/resource-matching Allow applies (U ≠ F).

Axioms: propext, Classical.choice, Quot.sound (standard only).

## Grant Rows

Grant rows gain `condition_state: T | F | U | NONE`. NONE means the
statement has no Condition block. Scope classification unchanged. Existing
XA grant rows are invariant.

## Fixtures — `fixtures/cond/`

| Policy | Statements | Queries → Expected |
|---|---|---|
| mfa.json | Allow s3:* on bucket, Bool aws:MultiFactorAuthPresent true | no ctx → ALLOWED_UNRESOLVED; {mfa:true} → ALLOWED; {mfa:false} → DENIED |
| deny-outside-org.json | Allow s3:*; Deny * StringNotEquals aws:PrincipalOrgID o-ours1234 | no ctx → ALLOWED_UNRESOLVED; {org:o-ours1234} → ALLOWED; {org:o-foreign999} → DENIED |
| vpce.json | Allow s3:GetObject, StringLike aws:SourceVpce "vpce-0a*" | {vpce:vpce-0abc} → ALLOWED; {vpce:vpce-1x} → DENIED; no ctx → ALLOWED_UNRESOLVED |
| orgpaths.json | Allow, ForAnyValue:StringLike aws:PrincipalOrgPaths ["o-ours1234/*/ou-abc/*"] | {paths:[matching]} → ALLOWED; {paths:[non-matching]} → DENIED |
| ifexists.json | Allow, StringEqualsIfExists aws:RequestedRegion us-east-1 | {} (complete, key absent) → ALLOWED; {region:eu-west-1} → DENIED; no ctx → ALLOWED_UNRESOLVED |
| unsupported.json | Allow, IpAddress aws:SourceIp 10.0.0.0/8 | {ip:10.1.2.3} → ALLOWED_UNRESOLVED + warning naming IpAddress |

15 queries + 1 invalid (`invalid/bad-condition.json`, Condition value is a string → exit 2).

## Invariant Rows

Every slice-1 / slice-2 fixture count, grant scope, and the no-flags run
are unchanged. Conditions never change control firing in this slice.

## Verification

```bash
1.  lake build                                                     # exit 0
2.  grep -rn "sorry\|admit\|native_decide" IamExplainer/ | wc -l   # 0
3.  Slice-1 fixtures; #guards                                       # 13/13; 27
4.  Slice-2: 9 XA + 6 new XA, no-flags run                         # 9/9+9/9; 6/6; 0/2/2
5.  Query manifest                                                  # 15/15
6.  fixtures/cond/invalid/bad-condition.json                        # exit 2
7.  Unsupported-operator warning on unsupported.json                # 1, names "IpAddress"
8.  grep -c "theorem allows_nocontext_conservative" Proofs.lean     # 1
9.  Every pre-existing theorem name still present                   # N/N
10. Axiom audit, all Proofs.lean declarations                       # 0 tainted
11. grep -rn "def evalCond" IamExplainer/ | wc -l                   # 1
12. git ls-files | wc -l                                            # <= 66
13. claude mcp list | grep -c lean-lsp                              # 1
```
