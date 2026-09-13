# LEAN-EXTRACT — Unified Extraction Program

Date: 2026-09-08

## Inventory

| Stream | Items | Controls | Proofs | Status |
|--------|:-----:|:--------:|:------:|--------|
| HN controls | 8 | 8 in `Stave/Controls/` | 24 in `Stave/Proofs/` | ✅ DONE |
| aws-bench B (type gap) | 13 | 7 evaluators in `AWSBench/Types.lean` | 13/13 proved | ✅ DONE (scattered) |
| aws-bench C (catalog gap) | 17 | 0 | 17/17 proved (trivial) | Theorems exist, controls don't |
| aws-bench A (scope mismatch) | 35 | N/A | 33/35 proved | ✅ DONE (not extraction targets) |

Total: 38 controls to extract (8 HN + 13 B + 17 C). 8 done, 30 remain.

## The merge

All three streams share:
- **Foundation**: CEL.lean (Value, Expr, eval) + Policy/Statement types
- **Proof pattern**: `List.any_eq_true.mp/mpr` for soundness/completeness, `inferInstance` for decidability
- **Type layer**: observation types (AWSBench stubs + Stave local types)

They diverge only at the control-authoring step:
- HN controls: logic came from a practitioner audit (done)
- B items: logic exists in Go/CEL, needs Lean form (evaluators done, not yet promoted to Stave/)
- C items: logic doesn't exist yet — author then formalize

## Phases

### Phase 0: Foundation ✅ COMPLETE

- `Stave/CEL.lean` — 14-constructor Expr, total eval, 10 #guard tests
- `IamExplainer/Policy.lean` — Statement, Policy, Effect
- `IamExplainer/Match.lean` — stmtGrantsAction, allows, matchActionPattern

### Phase 1: Type Unification

**Problem**: Two parallel type systems for the same domain.

| Type | AWSBench/Types.lean | Stave/Controls/ |
|------|-------------------|----------------|
| SG rule | `IngressRule` (5 fields) | `SGRule` (4 fields) |
| SG observation | `SecurityGroupObs` (3 fields) | `SGObs` (2 fields) |
| Trail observation | — | `TrailObs` (4 fields) |
| S3, EC2, VPC, ... | 22 stub types | — |

**Action**: Create `Stave/Obs.lean` — the canonical observation types.

- Merge `SGRule`/`IngressRule` → one type in `Stave/Obs.lean`
- Move `TrailObs` from `OrgTrail.lean` to `Stave/Obs.lean`
- Move the 22 AWSBench stubs into `Stave/Obs.lean`
- Update controls and proofs to import from `Stave/Obs.lean`
- AWSBench/Types.lean becomes thin: just imports `Stave/Obs` + keeps evaluator functions

**Gate**: `lake build` passes, zero sorry change.

### Phase 2: B-Item Control Promotion

Promote 7 evaluator functions from AWSBench/Types.lean into proper Stave controls.
Each gets: control file + soundness/completeness/decidability proofs.

| # | Evaluator | Control file | Obs types used |
|:-:|-----------|-------------|----------------|
| 1 | `sgAllowsInbound` | `Stave/Controls/SGInbound.lean` | SecurityGroupObs |
| 2 | `isPubliclyAccessible` | `Stave/Controls/S3Public.lean` | S3BucketObs |
| 3 | `isSshReachable` | `Stave/Controls/SSHReachable.lean` | EC2InstanceObs, SubnetObs, SecurityGroupObs |
| 4 | `scanInstance` | `Stave/Controls/VulnScan.lean` | EC2InstanceObs, SubnetObs |
| 5 | `vpcHasRouteToTarget` | `Stave/Controls/VPCRoute.lean` | RouteTableObs |
| 6 | `sparkDriverFitsInstance` | `Stave/Controls/EMRMemory.lean` | EMRClusterObs |
| 7 | `naclAllows` | `Stave/Controls/NACLEval.lean` | NACLRule |

The remaining 6 B items are simple field predicates (s3 encryption, website,
ownership, subnet IGW, default VPC, flow logs, aurora deletion, WAF rules).
These don't warrant separate control files — the theorem IS the control.

**Proof pattern**: Same as HN controls — `List.any_eq_true.mp/mpr` for
`sgAllowsInbound` and `vpcHasRouteToTarget`; `simp` for compound booleans.

**Yield**: 7 new control files, 21 new proofs (7×3), AWSBench theorems
re-proved against Stave controls instead of local evaluators.

**Gate**: `lake build` passes, sorry count unchanged.

### Phase 3: C-Item Control Authoring — Security Tier

5 controls. These don't exist in Go/CEL. Author the Lean control directly,
then back-port to Go/CEL for runtime parity.

| # | Control | Obs type | Logic shape |
|:-:|---------|----------|-------------|
| 1 | Cognito recovery feasibility | `CognitoPoolObs` | phone in recovery ∧ ¬smsConfigured → dead config |
| 2 | DynamoDB resource policy | `DynamoDBTableObs` | resourcePolicy.isSome |
| 3 | S3 metrics without alarms | `S3BucketObs` | metricsConfigs ≠ [] ∧ no alarm consumes them |
| 4 | Backup cross-region copy | `BackupPlanObs` | crossRegionCopy.isSome |
| 5 | Aurora scaling adequacy | `AuroraClusterObs` | maxACU > threshold ∨ readerCount > 0 |

**Pattern**: Same as HN controls. Define boolean predicate, prove three theorems.

Controls 2 and 4 are `Option.isSome` checks — one-liner definitions.
Control 1 is a conjunction with negation. Controls 3 and 5 are compound.

**Yield**: 5 new control files, 15 new proofs.

### Phase 4: C-Item Control Authoring — Operational Tier

12 controls. Lower priority — cost, operational, observability, networking.

| # | Control | Logic |
|:-:|---------|-------|
| 1 | S3 intelligent tiering | `intelligentTiering ≠ []` |
| 2 | S3 lifecycle presence | `lifecycleRules ≠ []` |
| 3 | S3 lifecycle tag filter | `rule ∈ lifecycleRules` |
| 4 | S3 inventory prefix | `cfg ∈ inventoryConfigs` |
| 5 | EC2 same-VPC connectivity | `a.vpcId = b.vpcId` |
| 6 | DynamoDB Kinesis stream | `kinesisStreamArn.isSome` |
| 7 | CFn ImportValue deps | `importValues ≠ []` |
| 8 | ECS non-default config | `desiredCount ≠ 1` |
| 9 | Lambda layer S3 code | `layerS3Code = true` |
| 10 | Lambda SNS trigger | `protocol = "lambda"` |
| 11 | Metric stream exclusions | `ns ∈ excludeFilters` |
| 12 | CFn Glue table provenance | `resourceType ∈ resources` |

Most are trivial field checks. These can be batched into
`Stave/Controls/ConfigPredicates.lean` — one file, 12 defs.

**Yield**: 1 control file (batched), 36 proofs (12×3). Or skip standalone
proofs for trivial field checks where the AWSBench theorem already serves.

### Phase 5: Dual Evaluator (CH4)

Parity gate: evaluate the same observation with both Go/CEL (via FFI or
test harness) and Lean, assert identical verdicts.

**Depends on**: Phases 1-4 (control set must stabilize first).

**Shape**: A `dualEval` function that runs both evaluators and returns
a `Parity` type (`match | mismatch of controlId × goVerdict × leanVerdict`).

### Phase 6: Spec Cleanup

- Strengthen `eventbridge_s3_wrong_bucket` hypothesis (add `req.action = "s3:GetObject"`)
- Strengthen `sg_blocks_health_check` hypothesis (add `cidrIp = none` for self-ref rules)
- Remove 2 remaining sorry

## Counts at each gate

| Phase | Controls | Proofs (Stave) | Proofs (AWSBench) | Sorry |
|-------|:--------:|:--------------:|:-----------------:|:-----:|
| Phase 0 (now) | 8 | 24 | 63/65 | 2 |
| Phase 1 | 8 | 24 | 63/65 | 2 |
| Phase 2 | 15 | 45 | 63/65 | 2 |
| Phase 3 | 20 | 60 | 63/65 | 2 |
| Phase 4 | 32 | 96 (or 60+batch) | 63/65 | 2 |
| Phase 6 | 32 | 96 | 65/65 | 0 |

## Decision: where to cut

Phase 2 (B-item promotion) is the highest-ROI next step:
- Known control logic, just needs Stave/ form
- 7 controls, 21 proofs — doubles the Stave proof count
- Unblocks Phase 5 (dual evaluator needs controls in Stave/, not AWSBench/)

Phase 3 (security C items) is the highest unique-value step:
- 5 controls Stave has never checked
- Externally validated by aws-bench (independent specification)
- Cognito recovery feasibility is the most novel

Phase 4 can be deferred or batched — trivial field checks don't justify
per-control ceremony.
