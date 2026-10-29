# STAVE-LEAN-KERNEL: Cedar-Pattern Lean 4 Formalization for Stave

## Blueprint

AWS Cedar: executable Lean 4 model of an authorization policy evaluator, alongside production Rust code. Lean model proves safety/security properties. Differential testing (100M random inputs nightly) keeps model and production in sync. Model is ~10x smaller than production code and doubles as the specification.

Stave adaptation: executable Lean 4 model of the cloud configuration verification engine, alongside production Go/CEL code. Lean model proves safety/security properties of controls and chains. Differential testing keeps model and Go production in sync. securitylib is the vendor-agnostic primitive layer (Cedar has no analog — they verify one language; we verify across heterogeneous providers).

## What this chain owns

1. The executable Lean 4 model of Stave's core evaluation: control evaluation, chain composition, and finding classification
2. Proofs of the safety properties that make Stave trustworthy
3. The differential testing harness between Go/CEL and Lean
4. The integration seam (contract testing at two boundaries: observation documents in, evaluation results out)

## Phase 1 Safety Properties

| ID | Property | Status |
|----|----------|--------|
| P1 | Fail-closed soundness | `Stave/Evaluate/Proofs.lean` |
| P2 | Evaluation determinism | `Stave/Evaluate/Proofs.lean` |
| P3 | Monotonicity (observations → findings) | `Stave/Evaluate/Proofs.lean` + `Stave/Compose/Monotonicity.lean` |
| P4 | Chain composition soundness | `Stave/Compose/Coverage.lean` + `Stave/Evaluate/Proofs.lean` |
| P5 | Ghost conservatism | `Stave/Ghost.lean` (complete) |

## Module Map

```
Stave/
├── Basic/           Tri, Effect, Rule, Finding, Glob, Context
├── Evaluate/        Phase 1 core — evaluator model + proofs
│   ├── Observation  obs.v0.1 property bag model
│   ├── Eval         Executable predicate evaluator (fail-closed)
│   └── Proofs       P1–P4 proved, zero sorry
├── Compose/         Chain composition + monotonicity (existing)
├── Ghost/           Ghost references + conservatism (existing, P5)
├── Schema/          Control/predicate AST + catalog types (existing)
├── IAM/             AWS IAM domain (existing)
├── Network/         Network reachability domain (existing)
├── CrossAccount/    Cross-account trust domain (existing)
└── Domain/          Policy semantics (existing)
```

## Migration Order

| Step | Lab | Known answers | Gate |
|------|-----|---------------|------|
| 1 | IAM Vulnerable | 30 paths | All 30 fire in Lean |
| 2 | CloudGoat | 13 findings, 1 compound chain | All 13 + chain fires |
| 3 | DVCA | 255 violations, 25 compound chains | All 255 + 25 chains |
| 4 | SadCloud | 992 violations, 84 compound chains | All 992 + 84 chains |
