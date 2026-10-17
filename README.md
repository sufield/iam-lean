# iam-lean

Lean 4 verification kernel for [Stave](https://github.com/sufield/stave).
Machine-checked proofs that Stave's cloud security properties hold:
- composition monotonicity
- network reachability
- IAM privilege analysis
- cross-account trust boundaries
- CEL predicate type safety.

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

This project uses the **Lean 4 nightly toolchain** to leverage modern proof automation (including `grind`) and verified external kernel checking.

### 1. Install & Set Nightly Toolchain

Ensure `elan` is up to date and set the nightly toolchain:

```sh
# Update elan
elan self update

# Install and activate Lean nightly
elan toolchain install leanprover/lean4:nightly
elan override set leanprover/lean4:nightly

# Resolve package dependencies
lake update
```

*(Optional prerequisite: if running sandboxed multi-kernel checking, install `bubblewrap` / `bwrap` via your system package manager).*

### 2. Build and Verify

```sh
# Build and type-check all proofs
make lean-build
# or: lake build

# Check for incomplete proofs (sorry)
make lean-verify

# List all modules
make lean-catalog
```

## Multi-Kernel Paranoid Check

To independently replay and verify all proofs across all external kernels bundled with Lean (`lean4lean`, `nanoda`, `con-leche`, `con-ron`, and `leanchecker-paranoid`):

```sh
lake check --paranoid
```

*(In container/CI environments lacking unprivileged user namespaces for bubblewrap, you can pass `--inadvisably-no-sandbox` if the environment is trusted).*

## Bridge Checkers

Each extraction has a contract test bridge that parses JSONL from the
Go engine and re-checks verdicts in Lean:

```sh
lake env bridge-check          data/compose-bridge.jsonl
lake env network-bridge-check  data/network-bridge.jsonl
lake env iam-bridge-check      data/iam-bridge.jsonl
lake env xaccount-bridge-check data/xaccount-bridge.jsonl
lake env celtype-bridge-check  data/schema-bridge.jsonl
```

## Soundness

`lake build` type-checks every theorem against the Lean kernel. For maximum assurance, `lake check --paranoid` replays all exported proof terms through multiple independently developed verified kernels.

The proofs guarantee monotonicity (narrowing observations never creates new findings) and completeness (every reachable state is witnessed by a finding).
