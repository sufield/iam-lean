# Slice 1 Specification (Living Spec-of-Record)

Ratified post-IAMX-002 audit. Supersedes the frozen IAMX-001 tables.

## Control Catalog

| ID | Fires when | Severity |
|---|---|---|
| LP.ADMIN.EQUIV.001 | Allow + Action `*` + Resource `*` | critical |
| LP.ACTION.SERVICEWILDCARD.001 | Allow + Action is `*` or `svc:*` (suppressed when ADMIN.EQUIV fires on same statement) | high |
| LP.RESOURCE.WILDCARD.001 | Allow + Resource `*` (suppressed when ADMIN.EQUIV fires on same statement) | high |
| LP.NOTACTION.ALLOW.001 | Allow + NotAction present | high |
| LP.NOTRESOURCE.ALLOW.001 | Allow + NotResource present | medium |
| LP.ESCALATE.PASSROLE.001 | Allow + `stmtGrantsAction s "iam:PassRole"` + (Resource `*` OR no `iam:PassedToService` condition key). Suppressed when ADMIN.EQUIV fires on same statement. | high |

### Ratified semantics (IAMX-002 D1)

ESCALATE.PASSROLE.001 is SEMANTIC — it fires when the statement GRANTS
iam:PassRole, whether via Action patterns or NotAction complement.
`stmtGrantsAction` is the single grant-logic function consumed by both
the PASSROLE check and the `allows` semantic evaluator.

### Suppression rule

When LP.ADMIN.EQUIV.001 fires on a statement, the following are suppressed
on that same statement: LP.ACTION.SERVICEWILDCARD.001,
LP.RESOURCE.WILDCARD.001, LP.ESCALATE.PASSROLE.001. NOTACTION and
NOTRESOURCE are never suppressed.

### Deny interaction

Controls fire per-statement. A Deny statement in the same policy does not
suppress findings on Allow statements. False-positive suppression via
cross-statement deny modeling deferred to slice 2.

### Condition key matching

The `iam:PassedToService` condition key is matched case-insensitively at
the operator-map depth (the key inside the operator object, e.g.,
`StringEquals.{"iam:PassedToService": ...}`).

### Known detection gaps

- `s3:Get*` / partial action wildcards: SERVICEWILDCARD fires only on bare
  `*` or `svc:*` form. Partial wildcards like `s3:Get*` are not detected.
  Consider a lower-severity control in a future slice.

## Expected Counts

All counts derived from fixture contents on disk under ratified semantics.

| Fixture | Findings | Exit |
|---|---|---|
| writeup-wildcards | 3 | 1 |
| remediated-wildcards | 0 | 0 |
| partial-wildcards | 1 | 1 |
| writeup-complement | 3 | 1 |
| remediated-complement | 0 | 0 |
| partial-complement | 2 | 1 |
| writeup-passrole | 2 | 1 |
| remediated-passrole | 0 | 0 |
| partial-passrole | 1 | 1 |
| writeup-passrole-viawildcard | 3 | 1 |
| writeup-notaction-passrole | 3 | 1 |
| partial-notaction-passrole | 2 | 1 |
| invalid/bad-effect | — | 2 |

### Derivation notes

- **writeup-wildcards (3):** S1 AdminAccess fires ADMIN.EQUIV (suppresses
  SERVICEWILDCARD, RESOURCE.WILDCARD, PASSROLE). S2 S3Full fires
  SERVICEWILDCARD + RESOURCE.WILDCARD. Total: 1 + 2 = 3.
- **partial-complement (2):** S2 NotActionScoped has NotAction:["sts:*"].
  `sts:*` does not match `iam:PassRole`, so PassRole IS granted via
  complement. NOTACTION + PASSROLE = 2.
- **writeup-passrole-viawildcard (3):** Action:["iam:*"] matches
  iam:PassRole semantically. SERVICEWILDCARD + RESOURCE.WILDCARD + PASSROLE.
- **writeup-notaction-passrole (3):** NotAction:["s3:*"] does not exclude
  iam:PassRole. NOTACTION + RESOURCE.WILDCARD + PASSROLE.
- **partial-notaction-passrole (2):** NotAction:["iam:*"] DOES exclude
  iam:PassRole. PASSROLE must NOT fire. NOTACTION + RESOURCE.WILDCARD.

## Soundness Contract

The soundness contract guarantees that two classes of policy remediation —
statement removal and action narrowing — can only narrow the set of
requests a policy allows. The proofs are machine-checked in Lean 4 with
no sorry, no native_decide on untrusted data, and no custom axioms.

### Theorem inventory

Declarations live in `IamExplainer/Proofs.lean` (T/L series) and
`IamExplainer/Layers.lean` (Y series).

| # | Declaration | Kind | File | Line | Role |
|---|---|---|---|---|---|
| — | `Policy.removeStmt` | def | Proofs | 10 | Statement removal helper |
| — | `mem_eraseIdx_of_ne` | private theorem | Proofs | 13 | List membership after eraseIdx |
| — | `deny_any_iff` | private theorem | Proofs | 35 | Deny-any Bool↔∃ |
| — | `allow_any_iff` | private theorem | Proofs | 42 | Allow-any Bool↔∃ |
| T1 | `removeAllow_narrows` | theorem | Proofs | 49 | Removing an Allow narrows the policy |
| — | `ciEq` | def | Proofs | 86 | Case-insensitive string equality |
| — | `matchPatternGo_literal_eq` | private theorem | Proofs | 89 | Wildcard-free glob match implies list equality |
| L1 | `matchPattern_literal_mp` | theorem | Proofs | 95 | Literal match implies `ciEq` |
| — | `ciEq_toLowerStr` | private theorem | Proofs | 104 | Extract `toLowerStr` equality from `ciEq` |
| L2 | `matchPattern_ci_congr` | theorem | Proofs | 108 | `matchActionPattern` congruence under `ciEq` |
| — | `matchActionPattern_ciEq` | private theorem | Proofs | 115 | `matchActionPattern` respects `toLowerStr` equality |
| L3 | `stmtGrantsAction_ci_congr` | theorem | Proofs | 120 | Grant congruence under `ciEq` |
| — | `toLower_eq_star` | private theorem | Proofs | 127 | `Char.toLower c = '*' → c = '*'` |
| — | `toLower_eq_question` | private theorem | Proofs | 142 | `Char.toLower c = '?' → c = '?'` |
| L4 | `stmtGrantsAction_narrow` | theorem | Proofs | 157 | Statement-level action narrowing (combines L1+L3) |
| L5 | `allows_replaceAllow_mono` | theorem | Proofs | 182 | Generic Allow replacement monotonicity |
| L6 | `narrowActions_narrows` | theorem | Proofs | 235 | **Gate theorem**: action narrowing narrows the policy |
| T2 | `grants_complete` | theorem | Proofs | 255 | Allowed ⟹ witnessing Allow statement exists |
| T3 | `allows_nocontext_conservative` | theorem | Proofs | 269 | No-context never hides a ctx-allowed grant |
| Y1 | `evalLayers_noLayers_blocked` | theorem | Layers | 182 | Empty layers produce no blocks |
| Y2 | `evalLayers_blocked_noContext_empty` | theorem | Layers | 252 | Layer blocks preserved under ctx→noContext |
| T4 | `layers_narrow` | theorem | Proofs | 303 | Layered allowed ⟹ base `allows` |
| T5 | `layer_add_monotone` | theorem | Proofs | 309 | Adding layers never widens access |
| T6 | `layered_nocontext_conservative` | theorem | Proofs | 316 | Layered no-context conservative |

### Gate theorem statement

```lean
theorem narrowActions_narrows
    (p : Policy) (i : Nat)
    (hi : i < p.statements.length)
    (heff : (p.statements[i]).effect = .allow)
    (new_stmt : Statement)
    (hnew : new_stmt.effect = .allow)
    (hnew_notactions : new_stmt.notActions = none)
    (hnew_actions : ∃ acts, new_stmt.actions = some acts ∧
      ∀ a ∈ acts, '?' ∉ a.toList ∧ '*' ∉ a.toList ∧
      stmtGrantsAction (p.statements[i]) a = true)
    (hnew_res : new_stmt.resources = (p.statements[i]).resources)
    (hnew_notres : new_stmt.notResources = (p.statements[i]).notResources)
    (hnew_cond : new_stmt.condition = (p.statements[i]).condition)
    (req : Request) (ctx : CondContext)
    (h : allows { p with statements := p.statements.set i new_stmt } req ctx = true) :
    allows p req ctx = true
```

Hypotheses: the replacement statement is Allow, uses `actions` (not
`notActions`), every action string is a wildcard-free literal that the
original statement already grants, resources/notResources/condition are
preserved. Conclusion: every request allowed by the narrowed policy was
already allowed by the original. Universally quantified over context.

### Axiom transcript

Every public declaration uses only the three standard Lean axioms:

```
'removeAllow_narrows'       depends on axioms: [propext, Classical.choice, Quot.sound]
'matchPattern_literal_mp'   depends on axioms: [propext, Classical.choice, Quot.sound]
'matchPattern_ci_congr'     depends on axioms: [propext, Classical.choice, Quot.sound]
'stmtGrantsAction_ci_congr' depends on axioms: [propext, Classical.choice, Quot.sound]
'stmtGrantsAction_narrow'   depends on axioms: [propext, Classical.choice, Quot.sound]
'allows_replaceAllow_mono'  depends on axioms: [propext, Classical.choice, Quot.sound]
'narrowActions_narrows'     depends on axioms: [propext, Classical.choice, Quot.sound]
```

No `sorryAx`, no `Lean.ofReduceBool`, no `Lean.trustCompiler`.

### Proof architecture notes

- **Well-founded recursion**: `matchPatternGo` uses well-founded
  recursion on `(ps.length + vs.length, vs.length)`. Proofs over it use
  functional induction (`matchPatternGo.induct`), not structural induction.

- **Case sensitivity**: `matchPattern` is case-sensitive. `matchActionPattern`
  pre-lowers both arguments via `toLowerStr`. L2 is stated over
  `matchActionPattern` (not `matchPattern`) because case-sensitive
  `matchPattern` does not respect `ciEq`.

- **Wildcard preservation under toLower**: L4 needs `'*' ∉ (toLowerStr ℓ).toList`
  from `'*' ∉ ℓ.toList`. This requires proving `Char.toLower` is a fixed
  point on `'*'` and `'?'` — done via `UInt32.toNat` arithmetic and `omega`.

- **Resource equality hypotheses**: The gate theorem requires
  `hnew_res` and `hnew_notres` because action narrowing alone cannot
  guarantee resource matching transfers. These are always satisfiable
  by the fix emitter (which preserves resources when narrowing actions).

### Tests.lean — representative-case guards

27 `#guard` statements covering `matchPattern`, `matchActionPattern`,
`stmtGrantsAction`, and `allows` behavior. Migrated from Proofs.lean
(IAMX-003 HZ-05) plus control-behavior guards.

## Verification Block

```bash
lake build                                                        # exit 0
grep -rn "sorry\|admit" IamExplainer/ Main.lean | wc -l           # 0
# All 13 fixtures vs table above                                  # 13/13 exact
fixtures/invalid/bad-effect.json                                  # exit 2
grep -cE "^(theorem|private theorem|protected theorem) " IamExplainer/Proofs.lean # 10
# Axiom check on every public declaration                         # 0 sorryAx/ofReduceBool/trustCompiler
grep -c "#guard" IamExplainer/Tests.lean                          # 27
grep -rn "def stmtGrantsAction" IamExplainer/ | wc -l             # 1
```
