# AWSBENCH-LEAN — Requirements Table

Date: 2026-09-07
Source: github.com/aws-bench/aws-bench-datasets (cloned at HEAD)

## Summary

| Metric | Count |
|--------|:-----:|
| Total introspection tasks | 99 |
| CONFIG-PREDICATE | 35 |
| COMPOSITION | 39 |
| DATA-RETRIEVAL (out of scope) | 20 |
| RUNTIME-ONLY (out of scope) | 5 |
| REQUIRES-CONTEXT | 0 |
| **Formalizable** | **74** |
| Lean theorem stubs written | 65 |
| Type stubs created | 24 |
| Evaluation function stubs | 7 |
| IAM-relevant tasks | 13 |
| Tasks covered by existing iam-explainer types | 8 |

## Classification Counts

| Class | Count | % | Formalizable? |
|-------|:-----:|:-:|:------------:|
| CONFIG-PREDICATE | 35 | 35.4% | YES |
| COMPOSITION | 39 | 39.4% | YES |
| DATA-RETRIEVAL | 20 | 20.2% | NO — raw data listing, no evaluation verdict |
| RUNTIME-ONLY | 5 | 5.1% | NO — requires live behavior |
| REQUIRES-CONTEXT | 0 | 0% | N/A |

## Requirements Table — IAM Policy Evaluation (12 tasks)

These map to existing iam-explainer types (Policy, Statement, allows, Request).

| # | Task | Class | Theorem | Diagnosis |
|:-:|------|-------|---------|-----------|
| 1 | debug-api-gateway-iam-authorization | COMP | `aws_bench_apigw_iam_method_mismatch` | Resource ARN encodes POST, request uses GET |
| 2 | cloudfront-oac-s-forbidden-troubleshoot | COMP | `aws_bench_s3_deny_only_no_grant` | S3 bucket policy has no Allow for CloudFront OAC |
| 3 | check-s-bucket-access-profiles | COMP | `aws_bench_s3_no_identity_no_bucket_ref` | No identity policy + not in bucket policy = denied |
| 4 | ec-secrets-manager-exit-code-error | COMP | `aws_bench_missing_kms_decrypt` | Role missing kms:Decrypt for encrypted secret |
| 5 | asg-secondary-network-interface-attach-failure | COMP | `aws_bench_missing_ec2_eni_perms` | Role missing ec2:CreateNetworkInterface |
| 6 | ecs-services-ecr-access-check | COMP | `aws_bench_ecs_no_ecr_access` | Task role missing ecr:GetDownloadUrlForLayer |
| 7 | diagnose-auto-scaling-group-launch-failure | COMP | `aws_bench_kms_disabled_blocks_ebs` | KMS key disabled → can't create encrypted EBS |
| 8 | diagnose-auto-scaling-group-launch-failure | COMP | `aws_bench_asg_zero_desired_no_launch` | DesiredCapacity=0 → no launches |
| 9 | troubleshoot-glue-job-table-read-failure | COMP | `aws_bench_lakeformation_no_grants` | LF enforces, no grants → IAM alone insufficient |
| 10 | diagnose-glue-pipeline-not-running | COMP | `aws_bench_glue_role_missing_logs` | Role missing logs:CreateLogGroup |
| 11 | eventbridge-ecs-task-trigger-debugging | COMP | `aws_bench_eventbridge_s3_wrong_bucket` | S3 policy on bucket A, request targets bucket B |
| 12 | glue-job-wrong-deployment-region | COMP | `aws_bench_cfn_wrong_region` | Stack deployed to wrong region (IAM incidental) |

## Requirements Table — Security Group Analysis (7 tasks)

| # | Task | Class | Theorem | Diagnosis |
|:-:|------|-------|---------|-----------|
| 1 | asg-instance-health-check-failure | COMP | `aws_bench_sg_blocks_health_check` | SG self-ref only, NLB health check on port 4000 blocked |
| 2 | diagnose-asg-instance-issues | COMP | `aws_bench_sg_empty_blocks_all` | SG has no inbound rules → all blocked |
| 3 | trace-ec2-ssh-access-path | COMP | `aws_bench_ssh_vpc_cidr_only` | SSH restricted to VPC CIDR, not 0.0.0.0/0 |
| 4 | list-ec-instances-all-regions-1 | COMP | `aws_bench_ssh_reachable_requires_all_three` | SSH reachable iff public IP + public subnet + SG allows |
| 5 | list-unused-security-groups-all-regions | CP | `aws_bench_unused_sg` | SG not attached to any resource |
| 6 | troubleshoot-asg-ssh-connectivity | COMP | `aws_bench_ssh_blocked_three_layers` | No key + private subnet + NACL deny |
| 7 | ec-instance-security-vulnerability-scan | COMP | `aws_bench_ec2_vuln_scan_unencrypted_ebs` | Multi-property vuln scan |

## Requirements Table — S3 Configuration (8 tasks)

| # | Task | Class | Theorem | Diagnosis |
|:-:|------|-------|---------|-----------|
| 1 | check-s-buckets-public-access | CP | `aws_bench_s3_partial_block_still_safe` | BlockPublicAcls=false but IgnorePublicAcls=true compensates |
| 2 | report-unencrypted-s-buckets | CP | `aws_bench_s3_kms_not_default` | SSE-KMS ≠ AES256 |
| 3 | list-s-cross-account-analytics-exports | CP | `aws_bench_s3_cross_account_export` | Analytics export to different account |
| 4 | analyze-s-intelligent-tiering-configs | CP | `aws_bench_s3_no_intelligent_tiering` | Missing tiering config |
| 5 | list-buckets-with-lifecycle-policy | CP | `aws_bench_s3_has_lifecycle` | Lifecycle rules present |
| 6 | list-s-buckets-website-hosting | CP | `aws_bench_s3_website_enabled` | Website hosting enabled |
| 7 | check-s-lifecycle-tag-filter-rules | CP | `aws_bench_s3_lifecycle_tag_filter` | Tag-based lifecycle rule |
| 8 | s-bucket-metrics-tag-filter-check | CP | `aws_bench_s3_metrics_no_alarm` | Metrics exist but no CW alarms consume them |

## Requirements Table — EC2 / VPC / Networking (5 tasks)

| # | Task | Class | Theorem | Diagnosis |
|:-:|------|-------|---------|-----------|
| 1 | find-ec-instances-in-public-subnets | CP | `aws_bench_public_subnet_has_igw_route` | Subnet has IGW route = public |
| 2 | ec-instances-without-default-vpc | CP | `aws_bench_ec2_not_in_default_vpc` | Instance VPC ≠ default VPC |
| 3 | describe-ec-instances-cross-region-connectivity | CP | `aws_bench_ec2_same_vpc_connectivity` | Same VPC = private connectivity |
| 4 | check-vpc-flow-log-destinations | CP | `aws_bench_vpc_flow_log_to_s3` | Flow log destination is S3 |
| 5 | ecs-elasticache-transit-gateway-connectivity | COMP | `aws_bench_tgw_missing_routes` | Missing forward + return routes via TGW |

## Requirements Table — Infrastructure Services (14 tasks)

| # | Task | Class | Theorem | Diagnosis |
|:-:|------|-------|---------|-----------|
| 1 | audit-cognito-account-recovery | COMP | `aws_bench_cognito_dead_phone_recovery` | Phone recovery listed but SmsConfiguration null |
| 2 | review-aurora-production-readiness | COMP | `aws_bench_aurora_no_deletion_protection` | DeletionProtection=false |
| 3 | review-aurora-production-readiness | COMP | `aws_bench_aurora_scaling_too_low` | Max 1 ACU + no readers |
| 4 | diagnose-redshift-cluster-health-issues | CP | `aws_bench_alarm_inverted_comparison` | GT 0.5 on HealthStatus fires when healthy |
| 5 | diagnose-sftp-alarm-not-firing | COMP | `aws_bench_alarm_no_actions` | AlarmActions empty |
| 6 | diagnose-sftp-alarm-not-firing | COMP | `aws_bench_log_destination_mismatch` | Transfer logs to wrong group |
| 7 | diagnose-emr-cluster-performance-issues | CP | `aws_bench_emr_driver_memory_exceeds_instance` | Spark driver > instance memory |
| 8 | review-backup-plan-cross-region | CP | `aws_bench_backup_cross_region_copy` | Cross-region copy configured |
| 9 | list-waf-webacl-findings | CP | `aws_bench_waf_has_rules` | WebACL has rules |
| 10 | dynamodb-tables-resource-based-policy | CP | `aws_bench_dynamodb_has_resource_policy` | Resource policy present |
| 11 | list-dynamodb-kinesis-streams-all-regions | CP | `aws_bench_dynamodb_has_kinesis_stream` | Kinesis stream configured |
| 12 | cloudfront-distribution-origin-error-diagnosis | CP | `aws_bench_cloudfront_no_root_object` | No defaultRootObject + 0 cache behaviors |
| 13 | opensearch-cognito-alb-timeout-diagnosis | CP | `aws_bench_opensearch_no_custom_endpoint` | CustomEndpointEnabled=false with Cognito |
| 14 | bedrock-kb-embedding-model-cfn-deps | CP | `aws_bench_cfn_import_dependency` | CFn stack has ImportValue deps |

## Requirements Table — COMPOSITION Cross-Resource (12 tasks)

| # | Task | Class | Theorem | Diagnosis |
|:-:|------|-------|---------|-----------|
| 1 | diagnose-alb-opensearch-bad-gateway | COMP | `aws_bench_alb_target_ip_mismatch` | Target IPs ∉ active ENIs |
| 2 | find-missing-step-functions-state-machine | COMP | `aws_bench_cfn_resource_drift` | Stack COMPLETE but resource deleted |
| 3 | lambda-sqs-reconciliation-no-output | COMP | `aws_bench_lambda_cross_region_s3_gateway` | S3 gateway = same-region only |
| 4 | diagnose-ecs-cluster-no-traffic | COMP | `aws_bench_ecs_zero_desired_no_traffic` | desiredCount=0 |
| 5 | diagnose-ecs-service-no-running-tasks-1 | COMP | `aws_bench_ecs_ecr_tag_mismatch` | ECR tag doesn't exist |
| 6 | ecs-service-deployment-failure-diagnosis | COMP | `aws_bench_ecs_deployment_latent_blockers` | desiredCount=0 + ECR empty |
| 7 | verify-ec-traffic-routes-through-network-firewall | COMP | `aws_bench_dmz_vpc_no_igw_dead_end` | DMZ only local routes → dead end |
| 8 | lambda-appconfig-stale-value-troubleshoot | COMP | `aws_bench_lambda_env_var_mismatch` | Env var = CFn logical ID ≠ physical name |
| 9 | diagnose-batch-job-no-logs | COMP | `aws_bench_batch_ecr_empty` | ECR repo empty |
| 10 | diagnose-rabbitmq-consumer-failure | COMP | `aws_bench_esm_missing_queue` | ESM target queue doesn't exist |
| 11 | diagnose-glue-pipeline-not-running | COMP | `aws_bench_pipeline_no_source_branch` | CodeCommit has no branches |
| 12 | fix-cloudformation-update-failed-stack | CP | `aws_bench_cfn_dangling_version_ref` | Alias refs non-existent Lambda version |

## Out-of-Scope Tasks

### DATA-RETRIEVAL (20 tasks)

These tasks ask for raw data listing (instance IDs, bucket contents, table records, file contents). They don't evaluate correctness and produce no verdict a kernel theorem could constrain.

| Category | Tasks | Examples |
|----------|:-----:|---------|
| DynamoDB data queries | 6 | scan-dynamodb-table-by-status, dynamodb-scan-filter-by-attribute |
| S3 object retrieval | 4 | retrieve-s-csv-object-contents, s-download-csv-identify-columns |
| Resource enumeration | 6 | list-ec-instances-all-regions, list-ec-private-ips-all-regions |
| CloudFormation inspection | 2 | cloudformation-top-stacks-resource-breakdown, describe-cloudformation-stack-resources |
| Other | 2 | count-windows-server-managed-nodes, estimate-ec-running-instance-costs |

### RUNTIME-ONLY (5 tasks)

| Task | Why runtime-only |
|------|-----------------|
| bedrock-agentcore-runtime-missing-logs | Requires live IAM deny policy evaluation + CloudWatch logs |
| debug-websocket-api-backend-response | Lambda execution logs + agent script behavior |
| diagnose-alb-five-xx-errors | ALB access logs (runtime traffic patterns) |
| diagnose-cloudwatch-alarm-firing | Real-time CloudWatch metrics + X-Ray traces |
| diagnose-xray-service-latency-cause | X-Ray trace analysis |

### Tasks not formalized (9 remaining formalizable)

These formalizable tasks were not given theorem stubs because their diagnosis reduces to code-level logic analysis (Lambda handler source code, Step Functions ASL execution semantics) rather than config-snapshot evaluation:

| Task | Why deferred |
|------|-------------|
| diagnose-onyx-lambda-processing-failure | Lambda code logic (OldImage check) |
| analyze-stepfunctions-job-poller-loop | SFn ASL execution semantics + Lambda handler code |
| diagnose-rekognition-reupload-stale | DynamoDB conditional write logic in Lambda code |
| diagnose-s3-event-notification-break | Lambda merge logic bug (code analysis) |
| opensearch-check-document-request-status-logs | Audit log capability knowledge (meta-question) |
| list-s-buckets-with-metrics-tag-filters | Duplicate of s-bucket-metrics-tag-filter-check |
| list-s-inventory-configs-with-prefix | Same predicate as s3_inventory_no_prefix |
| get-s-bucket-ownership-controls | Same predicate as s3_ownership_enforced |
| list-ec-instances-by-vpc-across-regions | Same predicate as ec2_same_vpc_connectivity |

## Gap List — Externally Discovered

Tasks with NO-MATCH to existing Stave controls represent evaluation capabilities the kernel doesn't yet cover. Grouped by gap type:

| Gap Type | Count | Key Examples |
|----------|:-----:|-------------|
| Cross-service permission dependency | 4 | kms:Decrypt for encrypted secrets, LF overriding IAM |
| Security group port alignment | 3 | SG vs NLB/ALB health check port |
| VPC routing reachability | 3 | TGW missing routes, dead-end DMZ VPC |
| SSH multi-layer reachability | 2 | Public IP + subnet + SG + NACL + key pair |
| S3 public access nuance | 1 | BlockPublicAcls=false but IgnorePublicAcls compensates |
| CloudWatch alarm semantics | 1 | Inverted comparison operator on health metric |
| Resource drift detection | 1 | CFn stack OK but resource deleted |
| API Gateway ARN method matching | 1 | Resource ARN encodes HTTP method |

**All 65 theorem stubs have NO-MATCH** — aws-bench covers zero existing Stave controls. This is expected: aws-bench tests broad AWS operations, not IAM policy logic. The value is in *expanding* the kernel's evaluation scope, not validating what it already does.

## A/B/C Classification of 65 NO-MATCH Theorems

Date: 2026-09-08

The 65/65 NO-MATCH result needs explanation before it's actionable.
Three categories explain why each theorem doesn't match an existing Stave control:

- **A (Scope mismatch)**: aws-bench asks "why did X fail?" (operational diagnosis).
  Stave asks "is X configured safely?" (configuration verification).
  Same resources, different questions. No extraction work needed.
- **B (Observation-type gap)**: The security check exists or is a natural extension
  of the Go/CEL catalog. Lean types exist as stubs but need full definitions
  and evaluators. Work = expand types, wire evaluators.
- **C (Genuine catalog gap)**: Stave doesn't check this at all.
  Work = author new controls in Go/CEL, then formalize in Lean.

### Summary

| Class | Count | % | Pipeline action |
|-------|:-----:|:-:|-----------------|
| **A — Scope mismatch** | 35 | 54% | None — validates `allows` evaluator, not Stave |
| **B — Observation-type gap** | 13 | 20% | Expand Lean types, wire evaluators |
| **C — Genuine catalog gap** | 17 | 26% | Author new controls, then formalize |

### A — Scope Mismatch (35 theorems)

Over half the NO-MATCH results aren't gaps. aws-bench is a diagnostic benchmark;
Stave is a security posture tool. These theorems constrain the `allows` evaluator
(already built) or diagnose operational failures (not Stave's domain).

| # | Theorem | Diagnosis type |
|:-:|---------|---------------|
| 1 | `apigw_iam_method_mismatch` | Debugging API GW 403 (wrong method in resource ARN) |
| 2 | `s3_deny_only_no_grant` | Debugging CloudFront 403 (no Allow for OAC) |
| 3 | `s3_no_identity_no_bucket_ref` | Debugging S3 access (no identity + not in bucket policy) |
| 4 | `missing_kms_decrypt` | Debugging secrets access (missing kms:Decrypt) |
| 5 | `missing_ec2_eni_perms` | Debugging ENI attach (missing ec2 perms) |
| 6 | `ecs_no_ecr_access` | Debugging ECS pull (missing ecr perms) |
| 7 | `kms_disabled_blocks_ebs` | Debugging ASG launch (disabled KMS key) |
| 8 | `asg_zero_desired_no_launch` | Debugging ASG (DesiredCapacity=0) |
| 9 | `lakeformation_no_grants` | Debugging Glue (LF authorization layer) |
| 10 | `glue_role_missing_logs` | Debugging Glue worker (missing logs perms) |
| 11 | `eventbridge_s3_wrong_bucket` | Debugging task failure (wrong S3 ARN) |
| 12 | `cfn_wrong_region` | Debugging deployment (wrong region) |
| 13 | `sg_blocks_health_check` | Debugging NLB health check (SG blocks port 4000) |
| 14 | `sg_empty_blocks_all` | Debugging blocked traffic (empty SG) |
| 15 | `ssh_vpc_cidr_only` | Debugging SSH timeout (VPC CIDR only) |
| 16 | `ssh_blocked_three_layers` | Debugging SSH (no key + private + NACL deny) |
| 17 | `tgw_missing_routes` | Debugging TGW connectivity (missing routes) |
| 18 | `alarm_inverted_comparison` | Debugging alarm (fires when healthy) |
| 19 | `alarm_no_actions` | Debugging alarm (no actions configured) |
| 20 | `log_destination_mismatch` | Debugging logging (wrong log group) |
| 21 | `emr_driver_memory_exceeds_instance` | Debugging EMR (driver > instance memory) |
| 22 | `cloudfront_no_root_object` | Debugging origin error (no defaultRootObject) |
| 23 | `opensearch_no_custom_endpoint` | Debugging timeout (no custom endpoint + Cognito) |
| 24 | `alb_target_ip_mismatch` | Debugging bad gateway (IPs not in ENIs) |
| 25 | `cfn_resource_drift` | Debugging drift (resource deleted post-create) |
| 26 | `lambda_cross_region_s3_gateway` | Debugging Lambda (cross-region S3 gateway) |
| 27 | `ecs_zero_desired_no_traffic` | Debugging no traffic (desiredCount=0) |
| 28 | `ecs_ecr_tag_mismatch` | Debugging ECS (ECR tag doesn't exist) |
| 29 | `ecs_deployment_latent_blockers` | Debugging deployment (desiredCount=0 + ECR empty) |
| 30 | `dmz_vpc_no_igw_dead_end` | Debugging routing (DMZ local-only routes) |
| 31 | `lambda_env_var_mismatch` | Debugging stale config (CFn logical ID in env var) |
| 32 | `batch_ecr_empty` | Debugging batch job (ECR repo empty) |
| 33 | `esm_missing_queue` | Debugging consumer (queue doesn't exist) |
| 34 | `pipeline_no_source_branch` | Debugging pipeline (zero branches) |
| 35 | `cfn_dangling_version_ref` | Debugging stack (alias refs non-existent version) |

### B — Observation-Type Gap (13 theorems)

Security checks that exist or are natural extensions of Go/CEL controls.
Lean types exist as stubs. Work = expand type definitions, wire evaluators.

| # | Theorem | Existing coverage | Missing in Lean |
|:-:|---------|------------------|-----------------|
| 1 | `ssh_reachable_requires_all_three` | SGIngress + compound | `isSshReachable` evaluator |
| 2 | `unused_sg` | SG attachment audit | `attachedTo` evaluator |
| 3 | `ec2_vuln_scan_unencrypted_ebs` | Multi-property scan | `scanInstance` evaluator |
| 4 | `s3_partial_block_still_safe` | S3 public access block | `isPubliclyAccessible` evaluator |
| 5 | `s3_kms_not_default` | S3 encryption audit | Encryption type predicate |
| 6 | `s3_cross_account_export` | Cross-account data flow | Analytics export check |
| 7 | `s3_website_enabled` | S3 website hosting | Website-enabled predicate |
| 8 | `s3_ownership_enforced` | S3 ownership control | Ownership predicate |
| 9 | `public_subnet_has_igw_route` | Public subnet check | SubnetObs IGW predicate |
| 10 | `ec2_not_in_default_vpc` | Default VPC audit | VPC comparison predicate |
| 11 | `vpc_flow_log_to_s3` | VPC flow log compliance | Flow log destination check |
| 12 | `aurora_no_deletion_protection` | DB deletion protection | AuroraClusterObs predicate |
| 13 | `waf_has_rules` | WAF rule presence | WAFWebACLObs predicate |

### C — Genuine Catalog Gap (17 theorems)

Stave doesn't check these. New control-authoring targets, grouped by domain.

| # | Theorem | Domain | What's new |
|:-:|---------|--------|-----------|
| 1 | `cognito_dead_phone_recovery` | Security | Recovery mechanism feasibility |
| 2 | `dynamodb_has_resource_policy` | Security-adj | DynamoDB resource policy (newer API) |
| 3 | `s3_metrics_no_alarm` | Observability | Metrics without CW alarm consumers |
| 4 | `backup_cross_region_copy` | DR | Cross-region backup presence |
| 5 | `aurora_scaling_too_low` | Capacity | Max ACU + reader count sizing |
| 6 | `s3_no_intelligent_tiering` | Cost | Tiering config presence |
| 7 | `s3_has_lifecycle` | Operational | Lifecycle rules presence |
| 8 | `s3_lifecycle_tag_filter` | Operational | Tag-based lifecycle detail |
| 9 | `s3_inventory_no_prefix` | Operational | Inventory config detail |
| 10 | `ec2_same_vpc_connectivity` | Networking | Topology query |
| 11 | `dynamodb_has_kinesis_stream` | Operational | Stream config presence |
| 12 | `cfn_import_dependency` | Infra | CloudFormation ImportValue deps |
| 13 | `ecs_non_default_config` | Operational | Non-default ECS config listing |
| 14 | `lambda_layer_s3_code` | Operational | Lambda layer hosting |
| 15 | `lambda_sns_triggered` | Operational | Trigger listing |
| 16 | `metric_stream_excludes` | Observability | Metric stream exclusion filters |
| 17 | `cfn_glue_table_provenance` | Provenance | Resource origin tracking |

### Pipeline Priority

1. **B items first (13)** — Type expansion. Controls exist; work is expanding Lean
   stubs into full definitions. Each B item yields a provable theorem. Quick wins.
2. **C items, security-first (7 of 17)** — Items 1-5 above are security/DR/capacity.
   Author Go/CEL controls, then formalize. Highest unique value.
3. **C items, operational (10 of 17)** — Items 6-17 are cost/operational/observability.
   Lower priority; useful but not on the security critical path.
4. **A items need no extraction work** — They validate `allows` (already built).
   Many are already proved (`exact h_...`). Leave as spec anchors.

### Key Insight

The real extraction surface is **30 tasks** (13B + 17C), not 65.
The B:C ratio (13:17) is roughly balanced — the pipeline needs both
type expansion AND control authoring, with type expansion being faster
and higher-confidence (known control logic).

## Type Coverage Analysis

| Scope | Tasks covered | % of formalizable |
|-------|:------------:|:-----------------:|
| Existing iam-explainer types | 8 | 10.8% |
| + SecurityGroupObs + SubnetObs | 15 | 20.3% |
| + S3BucketObs | 23 | 31.1% |
| + All 24 type stubs | 65 | 87.8% |
| Code-analysis tasks (deferred) | 9 | 12.2% |

## Lean Artifacts

| File | Contents |
|------|----------|
| `AWSBench/Types.lean` | 24 observation type stubs, 7 evaluation function stubs |
| `AWSBench/Requirements.lean` | 65 theorem stubs (`aws_bench_*` prefix) |
| `AWSBench.lean` | Root module (imports Types + Requirements) |
| `lake build` | Passes — 381 jobs, 0 errors |
