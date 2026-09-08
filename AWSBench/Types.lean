import IamExplainer.Match

/-! Observation type stubs for aws-bench requirement formalization.

Each type represents the minimal config snapshot an evaluator needs
to reproduce an aws-bench introspection diagnosis. Full definitions
deferred to the broader security-kernel project.

Every stub is marked with the aws-bench task(s) that require it. -/

-- STUB: aws-bench requirement (SG-related tasks)
structure IngressRule where
  fromPort      : Nat
  toPort        : Nat
  protocol      : String
  cidrIp        : Option String
  sourceGroupId : Option String
deriving Repr, DecidableEq

-- STUB: aws-bench requirement (SG-related tasks)
structure SecurityGroupObs where
  groupId      : String
  ingressRules : List IngressRule
  attachedTo   : List String
deriving Repr

-- STUB: aws-bench requirement (check-s-buckets-public-access)
structure PublicAccessBlock where
  blockPublicAcls       : Bool
  ignorePublicAcls      : Bool
  blockPublicPolicy     : Bool
  restrictPublicBuckets : Bool
deriving Repr, DecidableEq

-- STUB: aws-bench requirement (S3 config tasks)
structure S3BucketObs where
  name              : String
  publicAccessBlock : PublicAccessBlock
  encryptionType    : String
  bucketPolicy      : Option Policy
  lifecycleRules    : List String
  websiteEnabled    : Bool
  intelligentTiering : List String
  ownershipControl  : String
  inventoryConfigs  : List String
  metricsConfigs    : List String
  analyticsExportAccount : Option String

-- STUB: aws-bench requirement (EC2 instance tasks)
structure EC2InstanceObs where
  instanceId   : String
  subnetId     : String
  vpcId        : String
  sgIds        : List String
  publicIp     : Option String
  amiId        : String
  keyPairName  : Option String
  ebsEncrypted : Bool
  region       : String
deriving Repr

-- STUB: aws-bench requirement (subnet/VPC tasks)
structure SubnetObs where
  subnetId      : String
  vpcId         : String
  cidr          : String
  hasRouteToIgw : Bool
  isDefault     : Bool := false
deriving Repr, DecidableEq

-- STUB: aws-bench requirement (VPC-level observation)
structure VPCObs where
  vpcId     : String
  isDefault : Bool
  region    : String
deriving Repr, DecidableEq

-- STUB: aws-bench requirement (troubleshoot-asg-ssh-connectivity)
inductive NACLAction where | allow | deny
deriving Repr, DecidableEq

-- STUB: aws-bench requirement (troubleshoot-asg-ssh-connectivity)
structure NACLRule where
  ruleNumber : Nat
  protocol   : String
  action     : NACLAction
  fromPort   : Nat
  toPort     : Nat
  cidr       : String
deriving Repr

-- STUB: aws-bench requirement (diagnose-auto-scaling-group-launch-failure)
structure KMSKeyObs where
  keyId   : String
  enabled : Bool
deriving Repr, DecidableEq

-- STUB: aws-bench requirement (review-aurora-production-readiness)
structure AuroraClusterObs where
  clusterId          : String
  deletionProtection : Bool
  maxACUTenths       : Nat
  readerCount        : Nat
  secretRotation     : Bool
deriving Repr

-- STUB: aws-bench requirement (audit-cognito-account-recovery)
structure CognitoPoolObs where
  poolId                  : String
  recoveryMechanisms      : List (Nat × String)
  smsConfigured           : Bool
  autoVerifiedAttributes  : List String
  appClientCount          : Nat
deriving Repr

-- STUB: aws-bench requirement (asg tasks)
structure ASGObs where
  name            : String
  desiredCapacity : Nat
  minSize         : Nat
  maxSize         : Nat
deriving Repr

-- STUB: aws-bench requirement (cloudfront tasks)
structure CloudFrontDistObs where
  distributionId    : String
  defaultRootObject : Option String
  cacheBehaviors    : Nat
deriving Repr

-- STUB: aws-bench requirement (opensearch tasks)
structure OpenSearchDomainObs where
  domainName            : String
  customEndpointEnabled : Bool
  cognitoEnabled        : Bool
deriving Repr

-- STUB: aws-bench requirement (dynamodb tasks)
structure DynamoDBTableObs where
  tableName       : String
  region          : String
  resourcePolicy  : Option String
  kinesisStreamArn : Option String
deriving Repr

-- STUB: aws-bench requirement (lambda tasks)
structure LambdaFunctionObs where
  functionName : String
  envVars      : List (String × String)
  vpcSubnets   : List String
  layers       : List String
  layerS3Code  : Bool
  tags         : List (String × String)
deriving Repr

-- STUB: aws-bench requirement (ECS tasks)
structure ECSServiceObs where
  serviceName       : String
  desiredCount      : Nat
  containerImage    : String
  assignPublicIp    : Bool
  platformFamily    : String
  healthCheckGrace  : Nat
deriving Repr

-- STUB: aws-bench requirement (CloudWatch alarm tasks)
structure CloudWatchAlarmObs where
  alarmName      : String
  metricName     : String
  comparisonOp   : String
  threshold      : Float
  actionsEnabled : Bool
  alarmActions   : List String
deriving Repr

-- STUB: aws-bench requirement (VPC route table tasks)
structure RouteEntry where
  destinationCidr : String
  targetType      : String
  targetId        : String
deriving Repr, DecidableEq

-- STUB: aws-bench requirement (VPC route table tasks)
structure RouteTableObs where
  routeTableId : String
  vpcId        : String
  routes       : List RouteEntry
deriving Repr

-- STUB: aws-bench requirement (EMR cluster tasks)
structure EMRClusterObs where
  clusterId            : String
  sparkDriverMemoryMB  : Nat
  instanceTotalMemoryMB : Nat
  steps                : List String
deriving Repr

-- STUB: aws-bench requirement (backup plan tasks)
structure BackupPlanObs where
  planId             : String
  schedule           : String
  retentionDays      : Nat
  crossRegionCopy    : Option String
  selectionTagKey    : String
  selectionTagValue  : String
deriving Repr

-- STUB: aws-bench requirement (WAF tasks)
structure WAFWebACLObs where
  webAclId      : String
  defaultAction : String
  rules         : List String
deriving Repr

-- STUB: aws-bench requirement (ALB tasks)
structure ALBTargetGroupObs where
  targetGroupArn  : String
  healthCheckPort : Nat
  registeredIps   : List String
deriving Repr

-- STUB: aws-bench requirement (CloudFormation tasks)
structure CloudFormationStackObs where
  stackId    : String
  stackName  : String
  status     : String
  region     : String
  resources  : List String
  importValues : List String
deriving Repr

-- STUB: aws-bench requirement (VPC flow log tasks)
structure VPCFlowLogObs where
  flowLogId       : String
  destinationType : String
  logGroupName    : Option String
  s3BucketArn     : Option String
  aggregationSec  : Nat
deriving Repr

-- STUB: aws-bench requirement (SNS subscription tasks)
structure SNSSubscriptionObs where
  subscriptionArn : String
  topicArn        : String
  protocol        : String
  endpoint        : String
deriving Repr

-- STUB: aws-bench requirement (CloudWatch metric stream tasks)
structure MetricStreamObs where
  streamName       : String
  excludeFilters   : List String
  includeFilters   : List String
deriving Repr

-- STUB: aws-bench requirement (AWS Transfer Family tasks)
structure TransferServerObs where
  serverId       : String
  logDestination : String
deriving Repr

-- STUB: aws-bench requirement (Batch job tasks)
structure BatchJobDefObs where
  jobDefName     : String
  containerImage : String
  logConfig      : Option String
deriving Repr

-- STUB: aws-bench requirement (CodePipeline tasks)
structure CodePipelineObs where
  pipelineName : String
  sourceType   : String
  sourceBranch : Option String
deriving Repr

-- STUB: aws-bench requirement (SQS/ESM tasks)
structure EventSourceMappingObs where
  uuid        : String
  sourceArn   : String
  targetQueue : Option String
deriving Repr

/-! Evaluation function stubs.

These are the functions aws-bench theorems constrain. Any correct
kernel implementation must satisfy the theorem specifications below.
Bodies are sorry — implementation comes when the kernel is built. -/

-- STUB: aws-bench requirement (SG evaluation)
def sgAllowsInbound (sg : SecurityGroupObs) (port : Nat) (source : String) : Bool := sorry

-- STUB: aws-bench requirement (S3 public access)
def isPubliclyAccessible (b : S3BucketObs) : Bool := sorry

-- STUB: aws-bench requirement (SSH reachability)
def isSshReachable (inst : EC2InstanceObs) (subnet : SubnetObs)
    (sg : SecurityGroupObs) : Bool := sorry

-- STUB: aws-bench requirement (NACL evaluation)
def naclAllows (rules : List NACLRule) (port : Nat) (source : String) : Bool := sorry

-- STUB: aws-bench requirement (EC2 vulnerability scan)
structure VulnerabilityScan where
  outdatedAgent    : Bool
  deprecatedAmi    : Bool
  unencryptedEbs   : Bool
  publiclyExposed  : Bool

def scanInstance (inst : EC2InstanceObs) (subnet : SubnetObs)
    (sg : SecurityGroupObs) : VulnerabilityScan := sorry

-- STUB: aws-bench requirement (VPC routing reachability)
def vpcHasRouteToTarget (rt : RouteTableObs) (targetCidr : String) : Bool := sorry

-- STUB: aws-bench requirement (EMR memory check)
def sparkDriverFitsInstance (cluster : EMRClusterObs) : Bool := sorry
