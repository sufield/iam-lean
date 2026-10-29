# securitylib extraction backlog — CH1

Types and definitions in `Stave/` that are candidates for extraction
to a shared securitylib. Vendor-neutral types that formalize security
concepts (findings, severity, evidence, ghost assumptions) belong in a
reusable library; domain-specific types (IAM graphs, network topology)
stay in the Stave kernel.

| Type/Def | File | Candidate for securitylib? | Notes |
|----------|------|---------------------------|-------|
| `Severity` | Basic/Finding.lean | yes | 5-level severity enum, identical to Go `core/controldef` |
| `Evidence` | Basic/Finding.lean | yes | path + actual value pair |
| `Fix` | Basic/Finding.lean | yes | remediation suggestion |
| `Finding` | Basic/Finding.lean | yes | core finding structure |
| `AssetType`, `ControlId`, `ChainId`, `AssetId` | Basic/Finding.lean | yes | shared type aliases |
| `EvalOutcome` | Evaluate/Observation.lean | yes | clear/unsafe/unevaluable tri-state |
| `PropValue` | Evaluate/Observation.lean | yes | runtime property value ADT |
| `Observation` | Evaluate/Observation.lean | yes | generic asset observation |
| `GhostAssumption` | Ghost.lean | yes | ghost property assumption ADT |
| `RefStatus` | Ghost.lean | yes | absent/stale/present tri-state |
| `FindingSeverity` | Ghost.lean | no | duplicate of `Severity` — consolidate |
| `Tri` | Basic.lean | yes | three-valued logic type |
| `Effect` | Basic.lean | yes | monotonicity effect annotation |
| `Rule` | Basic/Rule.lean | yes | generic predicate rule |
| `ControlType` | Schema/Types.lean | yes | 5 evaluatable control types |
| `Classification` | Schema/Types.lean | yes | predicate shape taxonomy |
| `Operator` | Schema/Types.lean | yes | 17 comparison operators |
| `FieldPath` | Schema/Types.lean | yes | dot-separated property path |
| `ControlDef` | Schema/Control.lean | yes | full control definition |
| `UnsafePredicate` | Schema/Predicate.lean | yes | predicate tree type |
| `ContractField` | Schema/Contract.lean | yes | collector contract field |
| `CloudTrailObs` | Controls/Types.lean | no | domain-specific typed obs |
| `OrgSCPObs` | Controls/Types.lean | no | domain-specific typed obs |
| `IAMAccountObs` | Controls/Types.lean | no | domain-specific typed obs |
| `IAMUserObs` | Controls/Types.lean | no | domain-specific typed obs |
| `SecurityGroupObs` | Controls/Types.lean | no | domain-specific typed obs |
| `TypedObs` | Controls/Eval.lean | no | domain-specific dispatch |
| `ChainDef` | Compose/Basic.lean | maybe | generic enough, but tightly coupled to composition proofs |
| `IAMGraph` | IAM/Graph.lean | no | domain-specific |
| `NetGraph` | Network/Graph.lean | no | domain-specific |
| `Topology` | CrossAccount/Topology.lean | no | domain-specific |
| `DiffResult` | Harness/DiffTest.lean | no | test harness only |

## Summary

- **20 types** are candidates for securitylib extraction (vendor-neutral, reusable)
- **1 consolidation** needed: `FindingSeverity` in Ghost.lean duplicates `Severity`
- **0 TODO markers** found in the codebase
- Domain-specific types (IAM, network, cross-account, controls) stay in the kernel
