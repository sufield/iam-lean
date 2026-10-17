| # | Title | Description |
|---|---|---|
| **1** | **Environment Setup & Kernel Build** | Set up the Lean 4 nightly toolchain with `elan`, resolve dependencies using `lake update`, and build the kernel to confirm all base proofs pass. |
| **2** | **Core Domain Primitives & Three-Valued Logic** | Explore `Stave/Basic/` to understand fundamental types (`ControlId`, `Finding`, `Verdict`, `AssetType`) and formalize three-valued Kleene logic (`Tri`: `.t`, `.f`, `.u`). |
| **3** | **Ingesting Engine Findings: The Bridge CLI** | Learn how `Bridge.lean` and `bridge-cli` ingest JSONL logs from the Go engine, parse findings, and validate engine verdicts against Lean types. |
| **4** | **Modeling Network & VPC Scope Boundaries** | Formalize subnet isolation, private endpoints, and disclosure barriers in `Stave/Network/` to prove that reachability is strictly constrained by VPC boundaries. |
| **5** | **IAM Policy Evaluation & Trust Boundaries** | Model identity-based and resource-based policies in `Stave/IAM/`, proving that cross-boundary assumption requires explicit trust policies without wildcards. |
| **6** | **Bilateral Grants in Cross-Account Topologies** | Formalize two-sided account boundaries in `Stave/CrossAccount/` to mathematically prove that access cannot cross tenants unless both sides grant permission. |
| **7** | **CEL Predicate Semantics & Type Safety** | Explore `Stave/Schema/` to prove type safety, preservation, and non-null contract properties for Common Expression Language (CEL) policy predicates. |
| **8** | **Proving Composition Monotonicity (Property 1)** | Walk through `Stave/Compose/` to prove that adding observations or expanding the infrastructure graph never invalidates existing findings or chain distances. |
| **9** | **Automated Proofs with the `grind` Tactic** | Use Lean 4's `grind` engine to automatically discharge complex equational and forward-reasoning goals across policy transition graphs. |
| **10** | **Multi-Kernel Paranoid Verification in CI** | Set up sandboxed external verification (`lake check --paranoid`) to replay and validate all proofs across independent checkers (`lean4lean`, `nanoda`, `con-leche`). |
