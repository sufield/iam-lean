# Ghost References — Type Signatures and Proof Obligations

Spec-of-record for the GHOST-REF formalization. All types live in
`Seclib/Ghost.lean` (vendor-neutral) and `IamExplainer/Ghost/` (AWS-specific).

## Core types (Seclib.Ghost)

```
inductive RefStatus (α : Type) where
  | resolved (payload : α)
  | ghost (id : String) (assume : GhostAssumption)

inductive GhostAssumption where
  | overPermissive
  | leastPrivilege
  | explicit (props : List GhostProperty)

inductive FindingSeverity where
  | safe | low | medium | high | critical
```

## Conservativeness proof obligation

Every control that produces a finding about a ghost reference must prove:

```
def ghostConservative
    (control : α → FindingSeverity)
    (assume  : GhostAssumption)
    (ghostFinding : FindingSeverity) : Prop :=
  ∀ (concrete : α), ghostFinding ≥ control concrete
```

**Consequence:** emitting `critical` under `overPermissive` is always
conservative — `critical` is the top of the severity lattice.

## Assumption table

| AWS ghost kind | Default assumption | Rationale |
|---|---|---|
| `managedPolicyArn` | `overPermissive` | AWS-managed policy content not visible |
| `crossAccountRole` | `overPermissive` | Trust policy not in snapshot |
| `serviceLinkedRole` | `explicit [("awsManaged", true)]` | Known-safe by construction |
| `crossAccountResource` | `overPermissive` | Resource policy not in snapshot |
| `unmodeledService` | `overPermissive` | No schema = no verification |

## Composition

### Contradiction detection (PROVED)

Two controls with incompatible assumptions on the same reference cannot
coexist in a consistent observation scope:

```
theorem ghost_contradiction_detected
    {scope : ObsScope} {refId : String} {G₁ G₂ : GhostAssumption}
    (h1 : (refId, G₁) ∈ scope.ghostRefs)
    (h2 : (refId, G₂) ∈ scope.ghostRefs)
    (hContra : ghostAssumptionsCompatible G₁ G₂ = false) :
    False
```

### Cross-scope composition (DEFERRED)

When scope B resolves a ghost from scope A, the conservative finding
remains valid. Deferred until cross-account observation merging ships.

```
theorem ghost_composition
    {α : Type} {scopeA scopeB : ObsScope}
    {control : α → FindingSeverity}
    {ga : GhostAssumption} {ghostFinding : FindingSeverity}
    {refId : String}
    (_hGhostInA : (refId, ga) ∈ scopeA.ghostRefs)
    (_hConservative : ghostConservative control ga ghostFinding)
    (_hDischarge : DischargesGhosts scopeB [(refId, ga)]) :
    ∃ combined : ObsScope,
      (refId, ga) ∉ combined.ghostRefs ∧
      ∀ concrete : α, ghostFinding ≥ control concrete
```

## Retrofit pattern

To retrofit a control from `α → FindingSeverity` to `RefStatus α → FindingSeverity`:

1. Pattern-match on `resolved` vs `ghost`.
2. For `resolved`: run existing logic.
3. For `ghost`: emit the maximum severity the control can produce.
4. Prove `ghostConservative` — typically one line via `critical_is_top`.

Reference implementation: `IamExplainer/Ghost/XAGhost.lean`.
