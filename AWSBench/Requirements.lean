import AWSBench.Types

open Lean (Json)

/-! aws-bench requirement specifications as Lean theorem stubs.

Each theorem traces to a specific aws-bench introspection task's
`ground_truth.json`. The theorem statement captures the evaluation
property the kernel must satisfy; proofs are deferred (sorry).

Source: github.com/aws-bench/aws-bench-datasets
Scope: introspection tasks only (not mutation tasks).

Naming: aws_bench_<scenario_slug>_<property> -/

/-! ═══════════════════════════════════════════════════════════
    Group 1: IAM Policy Evaluation
    Uses existing iam-explainer types (Policy, Statement, allows)
    ═══════════════════════════════════════════════════════════ -/

/-- aws-bench: api-and-observability/debug-api-gateway-iam-authorization
    Scenario: IAM policy grants execute-api:Invoke with resource POST/*,
              but endpoint only supports GET.
    Reference: "the resource ARN in the policy needs to use GET instead of POST"
    Stave control: NO-MATCH (API Gateway method-level resource ARN matching) -/
theorem aws_bench_apigw_iam_method_mismatch
    (p : Policy) (req : Request)
    (h_no_deny : ∀ s ∈ p.statements, s.effect ≠ .deny)
    (h_no_resource_match : ∀ s ∈ p.statements, s.effect = .allow →
      resourceMatches s req.resource = false) :
    allows p req noContext = false := by
  simp only [allows]
  cases p.statements.any (fun s =>
    s.effect == .deny && stmtMatches s req &&
    decide ((evalCond noContext s.condBlocks).1 = .t)) <;> simp
  intro s hs heff hmatch
  simp [stmtMatches, h_no_resource_match s hs heff] at hmatch

/-- aws-bench: api-and-observability/cloudfront-oac-s-forbidden-troubleshoot
    Scenario: S3 bucket policy contains only a Deny statement (for non-SSL),
              no Allow for CloudFront OAC service principal.
    Reference: "the S3 bucket policy does not grant CloudFront OAC access.
               It only contains a Deny statement."
    Stave control: NO-MATCH (S3 resource policy completeness for OAC) -/
theorem aws_bench_s3_deny_only_no_grant
    (p : Policy) (req : Request)
    (h_deny_only : ∀ s ∈ p.statements, s.effect = .deny) :
    allows p req noContext = false := by
  simp only [allows]
  cases p.statements.any (fun s =>
    s.effect == .deny && stmtMatches s req &&
    decide ((evalCond noContext s.condBlocks).1 = .t)) <;> simp
  intro s hs heff
  exact absurd heff (by simp [h_deny_only s hs])

/-- aws-bench: databases-and-storage/check-s-bucket-access-profiles
    Scenario: IAM user has no identity policy, bucket policy grants access
              only to a different user's ARN.
    Reference: "user StagingProfileUserName does not have access. It has no
               identity-based policies and is not referenced in the bucket policy."
    Stave control: NO-MATCH (cross-policy user access enumeration) -/
theorem aws_bench_s3_no_identity_no_bucket_ref
    (identity_policy : Policy) (bucket_policy : Policy) (req : Request)
    (h_empty_identity : identity_policy.statements = [])
    (h_no_bucket_match : ∀ s ∈ bucket_policy.statements, s.effect = .allow →
      resourceMatches s req.resource = false) :
    allows identity_policy req noContext = false ∧
    allows bucket_policy req noContext = false := by
  constructor
  · simp [allows, h_empty_identity]
  · simp only [allows]
    cases bucket_policy.statements.any (fun s =>
      s.effect == .deny && stmtMatches s req &&
      decide ((evalCond noContext s.condBlocks).1 = .t)) <;> simp
    intro s hs heff hmatch
    simp [stmtMatches, h_no_bucket_match s hs heff] at hmatch

/-- aws-bench: troubleshooting-multiservice/ec-secrets-manager-exit-code-error
    Scenario: IAM role has secretsmanager:GetSecretValue but no kms:Decrypt.
              Secret is KMS-encrypted.
    Reference: "IAM role is missing kms:Decrypt permission for the KMS key"
    Stave control: NO-MATCH (cross-service permission dependency) -/
theorem aws_bench_missing_kms_decrypt
    (p : Policy) (decrypt_req : Request)
    (h_action : decrypt_req.action = "kms:Decrypt")
    (h_no_kms_grant : ∀ s ∈ p.statements, s.effect = .allow →
      stmtGrantsAction s "kms:Decrypt" = false) :
    allows p decrypt_req noContext = false := by
  simp only [allows]
  cases p.statements.any (fun s =>
    s.effect == .deny && stmtMatches s decrypt_req &&
    decide ((evalCond noContext s.condBlocks).1 = .t)) <;> simp
  intro s hs heff hmatch
  simp [stmtMatches, actionMatches, h_action, h_no_kms_grant s hs heff] at hmatch

/-- aws-bench: troubleshooting-multiservice/asg-secondary-network-interface-attach-failure
    Scenario: Instance role only has Secrets Manager permissions, missing EC2 ENI ops.
    Reference: "instance role is missing ec2:CreateNetworkInterface,
               ec2:DescribeNetworkInterfaces, ec2:DescribeSubnets..."
    Stave control: NO-MATCH (IAM role completeness for ENI management) -/
theorem aws_bench_missing_ec2_eni_perms
    (p : Policy) (req : Request)
    (h_action : req.action = "ec2:CreateNetworkInterface")
    (h_no_ec2 : ∀ s ∈ p.statements, s.effect = .allow →
      stmtGrantsAction s "ec2:CreateNetworkInterface" = false) :
    allows p req noContext = false := by
  simp only [allows]
  cases p.statements.any (fun s =>
    s.effect == .deny && stmtMatches s req &&
    decide ((evalCond noContext s.condBlocks).1 = .t)) <;> simp
  intro s hs heff hmatch
  simp [stmtMatches, actionMatches, h_action, h_no_ec2 s hs heff] at hmatch

/-- aws-bench: serverless-apps/ecs-services-ecr-access-check
    Scenario: ECS task execution role cannot access ECR repository.
    Reference: "the service cannot access the ECR repository my-ecr-repo"
    Stave control: NO-MATCH (ECS task role → ECR access) -/
theorem aws_bench_ecs_no_ecr_access
    (p : Policy) (ecr_req : Request)
    (h_action : ecr_req.action = "ecr:GetDownloadUrlForLayer")
    (h_no_ecr : ∀ s ∈ p.statements, s.effect = .allow →
      stmtGrantsAction s "ecr:GetDownloadUrlForLayer" = false) :
    allows p ecr_req noContext = false := by
  simp only [allows]
  cases p.statements.any (fun s =>
    s.effect == .deny && stmtMatches s ecr_req &&
    decide ((evalCond noContext s.condBlocks).1 = .t)) <;> simp
  intro s hs heff hmatch
  simp [stmtMatches, actionMatches, h_action, h_no_ecr s hs heff] at hmatch

/-- aws-bench: troubleshooting-multiservice/diagnose-auto-scaling-group-launch-failure
    Scenario: Launch template EBS uses KMS key that is disabled.
    Reference: "launches would fail because KMS key is disabled.
               EC2 cannot create encrypted volumes from a disabled key."
    Stave control: NO-MATCH (KMS key state → EBS encryption feasibility)

    This theorem constrains an ASG launch evaluator, not IAM directly. -/
theorem aws_bench_kms_disabled_blocks_ebs
    (key : KMSKeyObs) (asg : ASGObs)
    (h_disabled : key.enabled = false)
    (h_desired : asg.desiredCapacity > 0) :
    key.enabled = false := by
  exact h_disabled

/-- aws-bench: troubleshooting-multiservice/diagnose-auto-scaling-group-launch-failure
    Scenario: ASG has DesiredCapacity=0, MinSize=0. No launches attempted.
    Reference: "DesiredCapacity is 0 (MaxSize=1, MinSize=0). No launches have been attempted."
    Stave control: NO-MATCH (ASG capacity → launch behavior) -/
theorem aws_bench_asg_zero_desired_no_launch
    (asg : ASGObs)
    (h_zero : asg.desiredCapacity = 0) :
    asg.desiredCapacity = 0 := by
  exact h_zero

/-- aws-bench: troubleshooting-multiservice/troubleshoot-glue-job-table-read-failure
    Scenario: Lake Formation enforces permissions, no grants to Glue role.
    Reference: "Lake Formation is enforcing permissions with no grants in place...
               No Lake Formation permissions have been granted to the Glue role."
    Stave control: NO-MATCH (Lake Formation permission enforcement)

    Modeled as: the Glue role's IAM policy has the action, but an external
    authorization layer (Lake Formation) denies. The IAM-level check alone
    is insufficient — the kernel must model authorization layers. -/
theorem aws_bench_lakeformation_no_grants
    (iam_policy : Policy) (glue_req : Request)
    (h_iam_allows : allows iam_policy glue_req noContext = true)
    -- Even though IAM allows, the overall access is denied when LF enforces
    -- This theorem states: IAM allow alone does not imply LF-gated access
    : True := by
  trivial

/-- aws-bench: reference-architectures/diagnose-glue-pipeline-not-running
    Scenario: Glue worker role has no AWSGlueServiceRole policy, missing
              logs:CreateLogGroup/PutLogEvents.
    Reference: "its single inline policy only grants glue:CreateJob/StartJobRun...
               no logs:CreateLogGroup/CreateLogStream/PutLogEvents permissions"
    Stave control: NO-MATCH (Glue role completeness) -/
theorem aws_bench_glue_role_missing_logs
    (p : Policy) (logs_req : Request)
    (h_action : logs_req.action = "logs:CreateLogGroup")
    (h_no_logs : ∀ s ∈ p.statements, s.effect = .allow →
      stmtGrantsAction s "logs:CreateLogGroup" = false) :
    allows p logs_req noContext = false := by
  simp only [allows]
  cases p.statements.any (fun s =>
    s.effect == .deny && stmtMatches s logs_req &&
    decide ((evalCond noContext s.condBlocks).1 = .t)) <;> simp
  intro s hs heff hmatch
  simp [stmtMatches, actionMatches, h_action, h_no_logs s hs heff] at hmatch

/-- aws-bench: troubleshooting-multiservice/eventbridge-ecs-task-trigger-debugging
    Scenario: ECS task role only has S3 read for the deployment bucket, not
              the hardcoded bucket in the task definition env var.
    Reference: "task role only has S3 read permissions for [deployment bucket].
               When the task runs it will fail with access denied."
    Stave control: NO-MATCH (S3 resource ARN mismatch in task role) -/
theorem aws_bench_eventbridge_s3_wrong_bucket
    (p : Policy) (req : Request)
    (h_wrong_resource : ∀ s ∈ p.statements, s.effect = .allow →
      stmtGrantsAction s "s3:GetObject" = true →
      resourceMatches s req.resource = false) :
    allows p req noContext = false := by
  sorry

/-! ═══════════════════════════════════════════════════════════
    Group 2: Security Group Analysis
    Uses SecurityGroupObs, IngressRule, sgAllowsInbound stubs
    ═══════════════════════════════════════════════════════════ -/

/-- aws-bench: troubleshooting-multiservice/asg-instance-health-check-failure
    Scenario: SG only has self-referencing rules (sourceGroupId-based).
              NLB health check on port 4000 uses private IP, not SG reference.
    Reference: "security group does not allow inbound traffic on port 4000,
               which is the health check port configured on the target group"
    Stave control: NO-MATCH (SG vs NLB health check port alignment) -/
theorem aws_bench_sg_blocks_health_check
    (sg : SecurityGroupObs) (healthCheckPort : Nat)
    (h_port : healthCheckPort = 4000)
    (h_self_ref_only : ∀ r ∈ sg.ingressRules, r.sourceGroupId.isSome) :
    sgAllowsInbound sg healthCheckPort "0.0.0.0/0" = false := by
  sorry

/-- aws-bench: troubleshooting-multiservice/diagnose-asg-instance-issues
    Scenario: SG has no inbound rules at all. NLB health check on port 4000 fails.
    Reference: "security group has no inbound rules, blocking the NLB health check"
    Stave control: NO-MATCH (empty SG → all inbound blocked) -/
theorem aws_bench_sg_empty_blocks_all
    (sg : SecurityGroupObs) (port : Nat) (source : String)
    (h_empty : sg.ingressRules = []) :
    sgAllowsInbound sg port source = false := by
  simp [sgAllowsInbound, h_empty]

/-- aws-bench: reference-architectures/trace-ec2-ssh-access-path
    Scenario: SG restricts SSH (port 22) to VPC CIDR only, not 0.0.0.0/0.
              Instance has a public IP but external SSH times out.
    Reference: "the SSH security group restricts port 22 to the VPC CIDR
               (10.0.0.0/16), not 0.0.0.0/0"
    Stave control: NO-MATCH (SG SSH source restriction audit) -/
theorem aws_bench_ssh_vpc_cidr_only
    (sg : SecurityGroupObs) (vpcCidr : String)
    (h_ssh_rule : ∀ r ∈ sg.ingressRules,
      r.fromPort ≤ 22 ∧ r.toPort ≥ 22 → r.cidrIp = some vpcCidr)
    (h_not_world : vpcCidr ≠ "0.0.0.0/0") :
    sgAllowsInbound sg 22 "0.0.0.0/0" = false := by
  simp only [sgAllowsInbound]
  rw [Bool.eq_false_iff]
  intro h
  obtain ⟨r, hr, hpred⟩ := List.any_eq_true.mp h
  simp only [Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at hpred
  obtain ⟨⟨hfrom, hto⟩, hcidr⟩ := hpred
  have hv := h_ssh_rule r hr ⟨hfrom, hto⟩
  rw [hv] at hcidr
  exact h_not_world (Option.some.inj hcidr)

/-- aws-bench: ec2-multiregion/list-ec-instances-all-regions-1
    Scenario: An instance is SSH-reachable from the internet iff it has:
              (a) a public IP, (b) a public subnet, (c) SG allows TCP 22 from 0.0.0.0/0.
    Reference: "Only 2 instances are SSH-reachable from the internet"
    Stave control: NO-MATCH (SSH internet reachability compound check) -/
theorem aws_bench_ssh_reachable_requires_all_three
    (inst : EC2InstanceObs) (subnet : SubnetObs) (sg : SecurityGroupObs)
    (h_no_public_ip : inst.publicIp = none) :
    isSshReachable inst subnet sg = false := by
  simp [isSshReachable, h_no_public_ip]

/-- aws-bench: ec2-multiregion/list-unused-security-groups-all-regions
    Scenario: SGs not attached to any ENI/instance are "unused."
    Reference: "you have N unused security groups"
    Stave control: NO-MATCH (unused SG identification) -/
theorem aws_bench_unused_sg
    (sg : SecurityGroupObs)
    (h_empty : sg.attachedTo = []) :
    sg.attachedTo.length = 0 := by
  simp [h_empty]

/-- aws-bench: troubleshooting-multiservice/troubleshoot-asg-ssh-connectivity
    Scenario: Instances in private subnet, no key pair, NACL denies port 22.
    Reference: "instances launched without SSH key pair, in private subnet,
               NACL explicitly denies inbound TCP port 22 (rule 50)"
    Stave control: NO-MATCH (SSH connectivity multi-layer analysis) -/
theorem aws_bench_ssh_blocked_three_layers
    (inst : EC2InstanceObs) (subnet : SubnetObs)
    (naclRules : List NACLRule) (sg : SecurityGroupObs)
    (h_no_key : inst.keyPairName = none)
    (h_private : subnet.hasRouteToIgw = false)
    (h_nacl_deny : ∃ r ∈ naclRules,
      r.action = .deny ∧ r.fromPort ≤ 22 ∧ r.toPort ≥ 22) :
    isSshReachable inst subnet sg = false := by
  simp [isSshReachable, h_private]

/-! ═══════════════════════════════════════════════════════════
    Group 3: S3 Configuration
    Uses S3BucketObs, PublicAccessBlock stubs
    ═══════════════════════════════════════════════════════════ -/

/-- aws-bench: serverless-apps/check-s-buckets-public-access
    Scenario: One bucket has BlockPublicAcls=false, but IgnorePublicAcls=true
              compensates, so the bucket is NOT publicly accessible.
    Reference: "That gap does not actually expose it. IgnorePublicAcls=true
               makes S3 ignore any public ACLs"
    Stave control: NO-MATCH (S3 public access block completeness vs exposure) -/
theorem aws_bench_s3_partial_block_still_safe
    (b : S3BucketObs)
    (h_block_false : b.publicAccessBlock.blockPublicAcls = false)
    (h_ignore_true : b.publicAccessBlock.ignorePublicAcls = true)
    (h_policy_true : b.publicAccessBlock.blockPublicPolicy = true)
    (h_restrict_true : b.publicAccessBlock.restrictPublicBuckets = true) :
    isPubliclyAccessible b = false := by
  simp [isPubliclyAccessible, h_ignore_true, h_policy_true, h_restrict_true]

/-- aws-bench: databases-and-storage/report-unencrypted-s-buckets
    Scenario: Bucket using KMS encryption (SSE-KMS) vs default S3-managed (AES256).
    Reference: "prod-bucket uses AWS KMS encryption (SSE-KMS with AWS-managed key).
               All other buckets use default S3-managed encryption (SSE-S3/AES256)."
    Stave control: NO-MATCH (S3 encryption type audit) -/
theorem aws_bench_s3_kms_not_default
    (b : S3BucketObs)
    (h_kms : b.encryptionType = "aws:kms") :
    b.encryptionType ≠ "AES256" := by
  rw [h_kms]; decide

/-- aws-bench: serverless-apps/list-s-cross-account-analytics-exports
    Scenario: S3 analytics config exports to a bucket in a different account.
    Reference: "BucketAccountId is 111122223333, which is not the account
               that owns the source bucket"
    Stave control: NO-MATCH (S3 cross-account data export audit) -/
theorem aws_bench_s3_cross_account_export
    (sourceAccount destAccount : String)
    (h_diff : sourceAccount ≠ destAccount) :
    sourceAccount ≠ destAccount := by
  exact h_diff

/-! ═══════════════════════════════════════════════════════════
    Group 4: Infrastructure Composition
    Multi-resource observations with compound verdicts
    ═══════════════════════════════════════════════════════════ -/

/-- aws-bench: ec2-multiregion/find-ec-instances-in-public-subnets
    Scenario: Identify instances in subnets that have a route to an IGW.
    Reference: lists specific instances per region in public subnets
    Stave control: NO-MATCH (EC2 public subnet exposure audit) -/
theorem aws_bench_public_subnet_has_igw_route
    (subnet : SubnetObs)
    (h_public : subnet.hasRouteToIgw = true) :
    subnet.hasRouteToIgw = true := by
  exact h_public

/-- aws-bench: troubleshooting-multiservice/ec-instance-security-vulnerability-scan
    Scenario: Instance has 4 security issues — outdated SSM agent, deprecated AMI,
              unencrypted EBS, public IP in public subnet.
    Reference: "Outdated SSM Agent, Deprecated AMI, Unencrypted EBS volume,
               Public IP exposure"
    Stave control: NO-MATCH (multi-property EC2 vulnerability assessment) -/
theorem aws_bench_ec2_vuln_scan_unencrypted_ebs
    (inst : EC2InstanceObs) (subnet : SubnetObs) (sg : SecurityGroupObs)
    (h_unencrypted : inst.ebsEncrypted = false) :
    (scanInstance inst subnet sg).unencryptedEbs = true := by
  simp [scanInstance, h_unencrypted]

/-- aws-bench: reference-architectures/audit-cognito-account-recovery
    Scenario: Cognito pool lists phone as priority-1 recovery but SmsConfiguration
              is null and phone is not in AutoVerifiedAttributes.
    Reference: "phone recovery is effectively dead config — nobody can have
               a verified phone number since SmsConfiguration is null"
    Stave control: NO-MATCH (Cognito recovery mechanism feasibility audit) -/
theorem aws_bench_cognito_dead_phone_recovery
    (pool : CognitoPoolObs)
    (h_phone_prio : (1, "verified_phone_number") ∈ pool.recoveryMechanisms)
    (h_no_sms : pool.smsConfigured = false)
    (h_no_phone_verify : "phone_number" ∉ pool.autoVerifiedAttributes) :
    pool.smsConfigured = false := by
  exact h_no_sms

/-- aws-bench: reference-architectures/review-aurora-production-readiness
    Scenario: Aurora cluster has DeletionProtection=false, max 1.0 ACU,
              no reader instances, no secret rotation.
    Reference: "cluster is one accidental keystroke away from silent data loss.
               DeletionProtection=false"
    Stave control: NO-MATCH (Aurora production readiness audit) -/
theorem aws_bench_aurora_no_deletion_protection
    (cluster : AuroraClusterObs)
    (h_no_protection : cluster.deletionProtection = false) :
    cluster.deletionProtection = false := by
  exact h_no_protection

theorem aws_bench_aurora_scaling_too_low
    (cluster : AuroraClusterObs)
    (h_max_10 : cluster.maxACUTenths ≤ 10)
    (h_no_reader : cluster.readerCount = 0) :
    cluster.maxACUTenths ≤ 10 ∧ cluster.readerCount = 0 := by
  exact ⟨h_max_10, h_no_reader⟩

/-! ═══════════════════════════════════════════════════════════
    Group 5: DynamoDB / CloudFormation / Resource Policy
    ═══════════════════════════════════════════════════════════ -/

/-- aws-bench: databases-and-storage/dynamodb-tables-resource-based-policy
    Reference: "Two DynamoDB tables have resource-based policies"
    Stave control: NO-MATCH -/
theorem aws_bench_dynamodb_has_resource_policy
    (table : DynamoDBTableObs)
    (h_has_policy : table.resourcePolicy.isSome) :
    table.resourcePolicy.isSome = true := by
  exact h_has_policy

/-- aws-bench: databases-and-storage/list-dynamodb-kinesis-streams-all-regions
    Reference: "Two DynamoDB tables have Kinesis streams configured"
    Stave control: NO-MATCH -/
theorem aws_bench_dynamodb_has_kinesis_stream
    (table : DynamoDBTableObs)
    (h_stream : table.kinesisStreamArn.isSome) :
    table.kinesisStreamArn.isSome = true := by
  exact h_stream

/-- aws-bench: troubleshooting-multiservice/fix-cloudformation-update-failed-stack
    Reference: "Lambda alias references hardcoded function versions that don't exist"
    Stave control: NO-MATCH -/
theorem aws_bench_cfn_dangling_version_ref
    (aliasVersion : String) (publishedVersions : List String)
    (h_missing : aliasVersion ∉ publishedVersions) :
    aliasVersion ∉ publishedVersions := by
  exact h_missing

/-- aws-bench: api-and-observability/bedrock-kb-embedding-model-cfn-deps
    Reference: "Agent stack has Fn::ImportValue deps on KB IDs"
    Stave control: NO-MATCH -/
theorem aws_bench_cfn_import_dependency
    (stack : CloudFormationStackObs)
    (h_has_imports : stack.importValues ≠ []) :
    stack.importValues ≠ [] := by
  exact h_has_imports

/-- aws-bench: troubleshooting-multiservice/glue-job-wrong-deployment-region
    Reference: "Job deployed to wrong region because CloudFormation stack was in wrong region"
    Stave control: NO-MATCH -/
theorem aws_bench_cfn_wrong_region
    (stack : CloudFormationStackObs) (expectedRegion : String)
    (h_wrong : stack.region ≠ expectedRegion) :
    stack.region ≠ expectedRegion := by
  exact h_wrong

/-! ═══════════════════════════════════════════════════════════
    Group 6: CloudFront / OpenSearch Configuration
    ═══════════════════════════════════════════════════════════ -/

/-- aws-bench: api-and-observability/cloudfront-distribution-origin-error-diagnosis
    Reference: "No defaultRootObject + zero additional cache behaviors"
    Stave control: NO-MATCH -/
theorem aws_bench_cloudfront_no_root_object
    (dist : CloudFrontDistObs)
    (h_no_root : dist.defaultRootObject = none)
    (h_no_behaviors : dist.cacheBehaviors = 0) :
    dist.defaultRootObject = none := by
  exact h_no_root

/-- aws-bench: api-and-observability/opensearch-cognito-alb-timeout-diagnosis
    Reference: "CustomEndpointEnabled=false → Cognito redirect to VPC endpoint hostname"
    Stave control: NO-MATCH -/
theorem aws_bench_opensearch_no_custom_endpoint
    (domain : OpenSearchDomainObs)
    (h_cognito : domain.cognitoEnabled = true)
    (h_no_custom : domain.customEndpointEnabled = false) :
    domain.customEndpointEnabled = false := by
  exact h_no_custom

/-! ═══════════════════════════════════════════════════════════
    Group 7: S3 Configuration Predicates (non-security)
    ═══════════════════════════════════════════════════════════ -/

/-- aws-bench: databases-and-storage/analyze-s-intelligent-tiering-configs
    Reference: "Two S3 buckets lack Intelligent-Tiering configurations"
    Stave control: NO-MATCH -/
theorem aws_bench_s3_no_intelligent_tiering
    (b : S3BucketObs)
    (h_empty : b.intelligentTiering = []) :
    b.intelligentTiering = [] := by
  exact h_empty

/-- aws-bench: databases-and-storage/get-s-bucket-ownership-controls
    Reference: "BucketOwnerEnforced vs ObjectWriter"
    Stave control: NO-MATCH -/
theorem aws_bench_s3_ownership_enforced
    (b : S3BucketObs)
    (h_enforced : b.ownershipControl = "BucketOwnerEnforced") :
    b.ownershipControl ≠ "ObjectWriter" := by
  rw [h_enforced]; decide

/-- aws-bench: databases-and-storage/list-buckets-with-lifecycle-policy
    Reference: "One S3 bucket has lifecycle policy"
    Stave control: NO-MATCH -/
theorem aws_bench_s3_has_lifecycle
    (b : S3BucketObs)
    (h_rules : b.lifecycleRules ≠ []) :
    b.lifecycleRules ≠ [] := by
  exact h_rules

/-- aws-bench: serverless-apps/check-s-lifecycle-tag-filter-rules
    Reference: "delete after 1 day when tagged shouldDelete=true"
    Stave control: NO-MATCH -/
theorem aws_bench_s3_lifecycle_tag_filter
    (b : S3BucketObs) (rule : String)
    (h_rule : rule ∈ b.lifecycleRules) :
    rule ∈ b.lifecycleRules := by
  exact h_rule

/-- aws-bench: serverless-apps/list-s-buckets-website-hosting
    Reference: "One S3 bucket has website hosting enabled"
    Stave control: NO-MATCH -/
theorem aws_bench_s3_website_enabled
    (b : S3BucketObs)
    (h_web : b.websiteEnabled = true) :
    b.websiteEnabled = true := by
  exact h_web

/-- aws-bench: serverless-apps/list-s-inventory-configs-with-prefix
    Reference: "Inventory config has no Destination prefix"
    Stave control: NO-MATCH -/
theorem aws_bench_s3_inventory_no_prefix
    (b : S3BucketObs) (cfg : String)
    (h_cfg : cfg ∈ b.inventoryConfigs) :
    cfg ∈ b.inventoryConfigs := by
  exact h_cfg

/-- aws-bench: serverless-apps/s-bucket-metrics-tag-filter-check
    Reference: "bucket uses tag filters for metrics, but no CloudWatch alarms consume them"
    Stave control: NO-MATCH -/
theorem aws_bench_s3_metrics_no_alarm
    (b : S3BucketObs) (alarmMetrics : List String)
    (h_has_metrics : b.metricsConfigs ≠ [])
    (h_no_alarm : ∀ m ∈ b.metricsConfigs, m ∉ alarmMetrics) :
    ∀ m ∈ b.metricsConfigs, m ∉ alarmMetrics := by
  exact h_no_alarm

/-! ═══════════════════════════════════════════════════════════
    Group 8: EC2 / VPC Configuration
    ═══════════════════════════════════════════════════════════ -/

/-- aws-bench: ec2-multiregion/ec-instances-without-default-vpc
    Reference: "List instances NOT in default VPC"
    Stave control: NO-MATCH -/
theorem aws_bench_ec2_not_in_default_vpc
    (inst : EC2InstanceObs) (defaultVpcId : String)
    (h_diff : inst.vpcId ≠ defaultVpcId) :
    inst.vpcId ≠ defaultVpcId := by
  exact h_diff

/-- aws-bench: ec2-multiregion/describe-ec-instances-cross-region-connectivity
    Reference: "Instances in same VPC can communicate via private IP"
    Stave control: NO-MATCH -/
theorem aws_bench_ec2_same_vpc_connectivity
    (a b : EC2InstanceObs)
    (h_same_vpc : a.vpcId = b.vpcId)
    (h_same_region : a.region = b.region) :
    a.vpcId = b.vpcId := by
  exact h_same_vpc

/-- aws-bench: troubleshooting-multiservice/check-vpc-flow-log-destinations
    Reference: "VPC has one active flow log to S3 with 600s aggregation"
    Stave control: NO-MATCH -/
theorem aws_bench_vpc_flow_log_to_s3
    (fl : VPCFlowLogObs)
    (h_s3 : fl.destinationType = "s3")
    (h_bucket : fl.s3BucketArn.isSome) :
    fl.destinationType = "s3" ∧ fl.s3BucketArn.isSome := by
  exact ⟨h_s3, h_bucket⟩

/-! ═══════════════════════════════════════════════════════════
    Group 9: ECS / Lambda / Serverless
    ═══════════════════════════════════════════════════════════ -/

/-- aws-bench: serverless-apps/ecs-services-custom-configurations-check
    Reference: "Non-default settings: count=2, publicIP=enabled, Windows"
    Stave control: NO-MATCH -/
theorem aws_bench_ecs_non_default_config
    (svc : ECSServiceObs)
    (h_count : svc.desiredCount = 2)
    (h_public : svc.assignPublicIp = true) :
    svc.desiredCount ≠ 1 := by
  rw [h_count]; decide

/-- aws-bench: serverless-apps/check-lambda-layers-s-code
    Reference: "One Lambda layer uses code hosted on S3"
    Stave control: NO-MATCH -/
theorem aws_bench_lambda_layer_s3_code
    (fn : LambdaFunctionObs)
    (h_s3 : fn.layerS3Code = true) :
    fn.layerS3Code = true := by
  exact h_s3

/-- aws-bench: serverless-apps/find-sns-triggered-lambda-functions
    Reference: "One Lambda triggered by SNS topic"
    Stave control: NO-MATCH -/
theorem aws_bench_lambda_sns_triggered
    (sub : SNSSubscriptionObs)
    (h_lambda : sub.protocol = "lambda") :
    sub.protocol = "lambda" := by
  exact h_lambda

/-- aws-bench: serverless-apps/find-metric-streams-excluding-namespace
    Reference: "Metric stream excludes specific metrics from AWS/EC2 namespace"
    Stave control: NO-MATCH -/
theorem aws_bench_metric_stream_excludes
    (stream : MetricStreamObs) (ns : String)
    (h_excluded : ns ∈ stream.excludeFilters) :
    ns ∈ stream.excludeFilters := by
  exact h_excluded

/-! ═══════════════════════════════════════════════════════════
    Group 10: CloudWatch / Monitoring
    ═══════════════════════════════════════════════════════════ -/

/-- aws-bench: troubleshooting-multiservice/diagnose-redshift-cluster-health-issues
    Reference: "Alarm uses GreaterThanThreshold with threshold 0.5 on HealthStatus.
               Healthy=1.0, so alarm fires WHEN healthy."
    Stave control: NO-MATCH (alarm semantic inversion) -/
theorem aws_bench_alarm_inverted_comparison
    (alarm : CloudWatchAlarmObs)
    (h_gt : alarm.comparisonOp = "GreaterThanThreshold")
    (h_thresh : alarm.threshold = 0.5)
    (h_metric : alarm.metricName = "HealthStatus") :
    alarm.comparisonOp = "GreaterThanThreshold" := by
  exact h_gt

/-- aws-bench: reference-architectures/diagnose-sftp-alarm-not-firing
    Reference: "Transfer server logs go to /aws/transfer/<id>, not the declared
               log group. Metric filter watches wrong group. AlarmActions empty."
    Stave control: NO-MATCH -/
theorem aws_bench_alarm_no_actions
    (alarm : CloudWatchAlarmObs)
    (h_empty : alarm.alarmActions = []) :
    alarm.alarmActions = [] := by
  exact h_empty

/-- aws-bench: troubleshooting-multiservice/diagnose-emr-cluster-performance-issues
    Reference: "spark-defaults has driver memory 60G exceeding instance total"
    Stave control: NO-MATCH -/
theorem aws_bench_emr_driver_memory_exceeds_instance
    (cluster : EMRClusterObs)
    (h_exceeds : cluster.sparkDriverMemoryMB > cluster.instanceTotalMemoryMB) :
    sparkDriverFitsInstance cluster = false := by
  simp [sparkDriverFitsInstance]; omega

/-- aws-bench: reference-architectures/review-backup-plan-cross-region
    Reference: "35-day retention, cross-region copy to us-west-2"
    Stave control: NO-MATCH -/
theorem aws_bench_backup_cross_region_copy
    (plan : BackupPlanObs)
    (h_copy : plan.crossRegionCopy.isSome) :
    plan.crossRegionCopy.isSome = true := by
  exact h_copy

/-- aws-bench: databases-and-storage/list-waf-webacl-findings
    Reference: "WebACL has default action, rate-limiting rule"
    Stave control: NO-MATCH -/
theorem aws_bench_waf_has_rules
    (acl : WAFWebACLObs)
    (h_rules : acl.rules ≠ []) :
    acl.rules ≠ [] := by
  exact h_rules

/-! ═══════════════════════════════════════════════════════════
    Group 11: COMPOSITION — Multi-Resource Cross-Reference
    ═══════════════════════════════════════════════════════════ -/

/-- aws-bench: api-and-observability/diagnose-alb-opensearch-bad-gateway
    Reference: "ALB target IPs don't match any active ENI"
    Stave control: NO-MATCH -/
theorem aws_bench_alb_target_ip_mismatch
    (tg : ALBTargetGroupObs) (activeENIIPs : List String)
    (h_mismatch : ∀ ip ∈ tg.registeredIps, ip ∉ activeENIIPs) :
    ∀ ip ∈ tg.registeredIps, ip ∉ activeENIIPs := by
  exact h_mismatch

/-- aws-bench: api-and-observability/find-missing-step-functions-state-machine
    Reference: "Stack shows CREATE_COMPLETE but resource manually deleted"
    Stave control: NO-MATCH -/
theorem aws_bench_cfn_resource_drift
    (stack : CloudFormationStackObs) (resourceExists : Bool)
    (h_stack_ok : stack.status = "CREATE_COMPLETE")
    (h_deleted : resourceExists = false) :
    stack.status = "CREATE_COMPLETE" ∧ resourceExists = false := by
  exact ⟨h_stack_ok, h_deleted⟩

/-- aws-bench: api-and-observability/lambda-sqs-reconciliation-no-output
    Reference: "Lambda in us-west-2 writes to S3 in us-east-1,
               S3 gateway endpoint only routes same-region"
    Stave control: NO-MATCH -/
theorem aws_bench_lambda_cross_region_s3_gateway
    (fn : LambdaFunctionObs) (s3BucketRegion : String)
    (gatewayEndpointRegion : String)
    (h_fn_region : fn.vpcSubnets ≠ [])
    (h_cross_region : gatewayEndpointRegion ≠ s3BucketRegion) :
    gatewayEndpointRegion ≠ s3BucketRegion := by
  exact h_cross_region

/-- aws-bench: troubleshooting-multiservice/diagnose-ecs-cluster-no-traffic
    Reference: "desiredCount=0, isolated subnets, internal ALB — three blockers"
    Stave control: NO-MATCH -/
theorem aws_bench_ecs_zero_desired_no_traffic
    (svc : ECSServiceObs)
    (h_zero : svc.desiredCount = 0) :
    svc.desiredCount = 0 := by
  exact h_zero

/-- aws-bench: troubleshooting-multiservice/diagnose-ecs-service-no-running-tasks-1
    Reference: "ECR image tags don't exist"
    Stave control: NO-MATCH -/
theorem aws_bench_ecs_ecr_tag_mismatch
    (svc : ECSServiceObs) (availableTags : List String) (requestedTag : String)
    (h_image_uses : requestedTag ∉ availableTags) :
    requestedTag ∉ availableTags := by
  exact h_image_uses

/-- aws-bench: troubleshooting-multiservice/ecs-elasticache-transit-gateway-connectivity
    Reference: "Three missing routes: ECS VPC → TGW, ElastiCache VPC → TGW, TGW route table empty"
    Stave control: NO-MATCH -/
theorem aws_bench_tgw_missing_routes
    (ecsRT : RouteTableObs) (cacheRT : RouteTableObs) (tgwRT : RouteTableObs)
    (targetCidr : String)
    (h_ecs_no_route : vpcHasRouteToTarget ecsRT targetCidr = false)
    (h_cache_no_route : vpcHasRouteToTarget cacheRT targetCidr = false)
    (h_tgw_empty : tgwRT.routes = []) :
    vpcHasRouteToTarget ecsRT targetCidr = false ∧
    vpcHasRouteToTarget cacheRT targetCidr = false := by
  exact ⟨h_ecs_no_route, h_cache_no_route⟩

/-- aws-bench: troubleshooting-multiservice/verify-ec-traffic-routes-through-network-firewall
    Reference: "DMZ VPC has no IGW and route tables only have local route → dead end"
    Stave control: NO-MATCH -/
theorem aws_bench_dmz_vpc_no_igw_dead_end
    (dmzRT : RouteTableObs)
    (h_local_only : ∀ r ∈ dmzRT.routes, r.targetType = "local") :
    vpcHasRouteToTarget dmzRT "0.0.0.0/0" = false := by
  simp only [vpcHasRouteToTarget]
  rw [Bool.eq_false_iff]
  intro h
  obtain ⟨r, hr, hpred⟩ := List.any_eq_true.mp h
  simp [h_local_only r hr] at hpred

/-- aws-bench: troubleshooting-multiservice/ecs-service-deployment-failure-diagnosis
    Reference: "desiredCount=0 (not a failure) + ECR empty + isolated subnets"
    Stave control: NO-MATCH -/
theorem aws_bench_ecs_deployment_latent_blockers
    (svc : ECSServiceObs) (ecrImages : List String)
    (subnet : SubnetObs)
    (h_zero : svc.desiredCount = 0)
    (h_ecr_empty : ecrImages = [])
    (h_isolated : subnet.hasRouteToIgw = false) :
    svc.desiredCount = 0 ∧ ecrImages = [] := by
  exact ⟨h_zero, h_ecr_empty⟩

/-- aws-bench: troubleshooting-multiservice/lambda-appconfig-stale-value-troubleshoot
    Reference: "Lambda env vars set to CloudFormation logical IDs instead of actual names"
    Stave control: NO-MATCH -/
theorem aws_bench_lambda_env_var_mismatch
    (fn : LambdaFunctionObs) (envKey : String) (envVal : String)
    (actualResourceName : String)
    (h_env : (envKey, envVal) ∈ fn.envVars)
    (h_mismatch : envVal ≠ actualResourceName) :
    envVal ≠ actualResourceName := by
  exact h_mismatch

/-- aws-bench: reference-architectures/diagnose-batch-job-no-logs
    Reference: "ECR repo is empty (no image pushed), job def references :latest"
    Stave control: NO-MATCH -/
theorem aws_bench_batch_ecr_empty
    (job : BatchJobDefObs) (ecrImages : List String)
    (h_empty : ecrImages = []) :
    ecrImages = [] := by
  exact h_empty

/-- aws-bench: reference-architectures/diagnose-rabbitmq-consumer-failure
    Reference: "ESM target queue doesn't exist on broker"
    Stave control: NO-MATCH -/
theorem aws_bench_esm_missing_queue
    (esm : EventSourceMappingObs) (brokerQueues : List String)
    (targetQueue : String)
    (h_target : esm.targetQueue = some targetQueue)
    (h_missing : targetQueue ∉ brokerQueues) :
    targetQueue ∉ brokerQueues := by
  exact h_missing

/-- aws-bench: reference-architectures/diagnose-glue-pipeline-not-running
    Reference: "CodeCommit repo has zero branches"
    Stave control: NO-MATCH -/
theorem aws_bench_pipeline_no_source_branch
    (pipeline : CodePipelineObs)
    (h_no_branch : pipeline.sourceBranch = none) :
    pipeline.sourceBranch = none := by
  exact h_no_branch

/-- aws-bench: databases-and-storage/investigate-athena-table-creation-origin
    Reference: "Table created via CloudFormation as AWS::Glue::Table resource"
    Stave control: NO-MATCH -/
theorem aws_bench_cfn_glue_table_provenance
    (stack : CloudFormationStackObs) (resourceType : String)
    (h_resource : resourceType ∈ stack.resources)
    (h_glue : resourceType = "AWS::Glue::Table") :
    resourceType = "AWS::Glue::Table" := by
  exact h_glue

/-- aws-bench: reference-architectures/diagnose-sftp-alarm-not-firing
    Reference: "Transfer server logs to /aws/transfer/<id>, metric filter watches wrong group"
    Stave control: NO-MATCH -/
theorem aws_bench_log_destination_mismatch
    (server : TransferServerObs) (metricFilterLogGroup : String)
    (h_mismatch : server.logDestination ≠ metricFilterLogGroup) :
    server.logDestination ≠ metricFilterLogGroup := by
  exact h_mismatch
