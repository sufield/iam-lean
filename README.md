# stave-lean

Lean 4 verification kernel for [Stave](https://github.com/sufield/stave).
Machine-checked proofs that Stave's cloud security properties hold:
composition monotonicity, network reachability, IAM privilege analysis,
cross-account trust boundaries, and CEL predicate type safety.

If it builds, the proofs hold.

## Structure

```
Stave/
  Basic/          Shared types: ControlId, Finding, Verdict, AssetType
  Compose/        P1 — composition monotonicity, chain distance
  Network/        P2 — network reachability, disclosure
  IAM/            P3 — IAM privilege reachability, trust boundaries
  CrossAccount/   P4 — cross-account grant topology
  Schema/         P5 — CEL predicate type system, contract properties
  Domain/         Policy semantics
  Ghost/          SMT / Datalog ghost references
Bridge.lean       JSONL contract test bridge imports
```

## Setup

```sh
# Install Lean 4: https://lean-lang.org/lean4/doc/quickstart.html

# Build and verify all proofs
make lean-build

# Check for incomplete proofs (sorry)
make lean-verify

# List all modules
make lean-catalog
```

## Bridge Checkers

Each extraction has a contract test bridge that parses JSONL from the
Go engine and re-checks verdicts in Lean:

```sh
lake env bridge-check         data/compose-bridge.jsonl
lake env network-bridge-check data/network-bridge.jsonl
lake env iam-bridge-check     data/iam-bridge.jsonl
lake env xaccount-bridge-check data/xaccount-bridge.jsonl
lake env celtype-bridge-check  data/schema-bridge.jsonl
```

## Soundness

`lake build` type-checks every theorem. A successful build is the
certificate. The proofs guarantee monotonicity (narrowing observations
never creates new findings) and completeness (every reachable state is
witnessed by a finding).
