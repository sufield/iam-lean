import Stave.Controls.Types
import Stave.KMS.Eval

/-! Concrete Lean evaluators for 8 HN practitioner controls.
Each function mirrors the CEL unsafe_predicate from its control YAML.
Fail-closed: any missing field (none) fires the finding. -/

-- Control 1: CTL.CLOUDTRAIL.ORG.001
-- all: [kind=trail, is_organization_trail=false]
def evalCloudTrailOrg (obs : CloudTrailObs) : EvalOutcome :=
  match obs.kind, obs.is_organization_trail with
  | some "trail", some false => .«unsafe»
  | some "trail", some true  => .clear
  | some "trail", none       => .unevaluable
  | _, _                     => .clear

-- Control 2: CTL.ORG.REGION.SCP.001
-- all: [kind=scp_policy_set, region_restriction.has_scp=false]
def evalOrgRegionSCP (obs : OrgSCPObs) : EvalOutcome :=
  match obs.kind, obs.region_restriction_has_scp with
  | some "scp_policy_set", some false => .«unsafe»
  | some "scp_policy_set", some true  => .clear
  | some "scp_policy_set", none       => .unevaluable
  | _, _                              => .clear

-- Control 3: CTL.IAM.ROOT.MFA.001
-- all: [kind=account, root.mfa_enabled != true]
def evalRootMFA (obs : IAMAccountObs) : EvalOutcome :=
  match obs.kind, obs.root_mfa_enabled with
  | some "account", some true  => .clear
  | some "account", some false => .«unsafe»
  | some "account", none       => .unevaluable
  | _, _                       => .clear

-- Control 4: CTL.IAM.ROOT.ACCESSKEY.001
-- all: [kind=account, root.has_access_keys=present, root.has_access_keys=true]
def evalRootAccessKey (obs : IAMAccountObs) : EvalOutcome :=
  match obs.kind, obs.root_has_access_keys with
  | some "account", some true  => .«unsafe»
  | some "account", some false => .clear
  | some "account", none       => .clear  -- not present = pass (present op fails)
  | _, _                       => .clear

-- Control 5: CTL.CLOUDTRAIL.LOG.VALIDATION.001
-- all: [trail.log_file_validation_enabled=false]
def evalCloudTrailLogValidation (obs : CloudTrailObs) : EvalOutcome :=
  match obs.log_file_validation_enabled with
  | some false => .«unsafe»
  | some true  => .clear
  | none       => .unevaluable

-- Control 6: CTL.IAM.CONSOLE.MFA.001
-- all: [kind=user, console_access.enabled=present,
--       console_access.enabled=true, console_access.mfa_enabled != true]
def evalConsoleMFA (obs : IAMUserObs) : EvalOutcome :=
  match obs.kind, obs.console_access_enabled, obs.console_access_mfa_enabled with
  | some "user", some true, some true  => .clear
  | some "user", some true, some false => .«unsafe»
  | some "user", some true, none       => .unevaluable
  | some "user", some false, _         => .clear
  | some "user", none, _               => .clear  -- enabled not present = pass
  | _, _, _                            => .clear

-- Control 7: CTL.VPC.SG.UNRESTRICTED.001
-- all: [kind=security_group, has_unrestricted_ingress=true]
def evalSGUnrestricted (obs : SecurityGroupObs) : EvalOutcome :=
  match obs.kind, obs.has_unrestricted_ingress with
  | some "security_group", some true  => .«unsafe»
  | some "security_group", some false => .clear
  | some "security_group", none       => .unevaluable
  | _, _                              => .clear

-- Control 8: CTL.CLOUDTRAIL.REGIONAL.COVERAGE.001
-- all: [kind=trail, is_multi_region != true]
def evalCloudTrailRegional (obs : CloudTrailObs) : EvalOutcome :=
  match obs.kind, obs.is_multi_region with
  | some "trail", some true  => .clear
  | some "trail", some false => .«unsafe»
  | some "trail", none       => .unevaluable
  | _, _                     => .clear

-- CH2 Control 1: CTL.CLOUDFRONT.ACCESS.SIGNED.LONG.EXPIRY.001
-- all: [kind=distribution, signed_url_default_expiry_seconds > 86400]
def evalSignedLongExpiry (obs : CDNObs) : EvalOutcome :=
  match obs.kind, obs.signed_url_default_expiry_seconds with
  | some "distribution", some n => if n > 86400 then .«unsafe» else .clear
  | some "distribution", none   => .unevaluable
  | _, _                        => .clear

-- CH2 Control 2: CTL.CLOUDFRONT.VIEWER.CERT.EXPIRY.WARN.001
-- all: [kind=distribution, viewer_cert_days_until_expiry < 30]
def evalCertExpiryWarn (obs : CDNObs) : EvalOutcome :=
  match obs.kind, obs.viewer_cert_days_until_expiry with
  | some "distribution", some n => if n < 30 then .«unsafe» else .clear
  | some "distribution", none   => .unevaluable
  | _, _                        => .clear

-- CH2 Control 3: CTL.CLOUDFRONT.WAF.001
-- all: [kind=distribution, waf_web_acl_id missing true]
def evalCloudFrontWAF (obs : CDNObs) : EvalOutcome :=
  match obs.kind, obs.waf_web_acl_id with
  | some "distribution", none   => .«unsafe»
  | some "distribution", some _ => .clear
  | _, _                        => .clear

-- CH2 Control 4: CTL.CLOUDFRONT.LIFECYCLE.ORPHAN.POLICY.001
-- all: [kind in [cache_policy, response_headers_policy], policy_referenced=false]
def evalOrphanPolicy (obs : CDNObs) : EvalOutcome :=
  let kindMatch := match obs.kind with
    | some "cache_policy" | some "response_headers_policy" => true
    | _ => false
  if !kindMatch then .clear
  else match obs.policy_referenced with
    | some false => .«unsafe»
    | some true  => .clear
    | none       => .unevaluable

-- CH2 Control 5: CTL.VPC.ENDPOINT.KMS.EGRESS.001
-- all: [kind=vpc_endpoint, service_name contains ".kms", restricts_to_org=false]
def evalVPCEndpointKMS (obs : VPCEndpointObs) : EvalOutcome :=
  match obs.kind with
  | some "vpc_endpoint" =>
    match obs.service_name with
    | some name =>
      if (name.splitOn ".kms").length > 1 then
        match obs.restricts_to_org_resources with
        | some false => .«unsafe»
        | some true  => .clear
        | none       => .unevaluable
      else .clear
    | none => .unevaluable
  | _ => .clear

-- CH2 Control 6: CTL.IAM.CRED.UNUSED45.001
-- all: [kind=user, credentials.unused_days > 45]
def evalCredUnused45 (obs : IAMUserObs) : EvalOutcome :=
  match obs.kind, obs.credentials_unused_days with
  | some "user", some n => if n > 45 then .«unsafe» else .clear
  | some "user", none   => .unevaluable
  | _, _                => .clear

-- CH2 Control 7: CTL.IAM.ADMIN.COUNT.001
-- all: [kind=account_summary, admin_user_count > 2]
def evalAdminCount (obs : IAMSummaryObs) : EvalOutcome :=
  match obs.kind, obs.admin_user_count with
  | some "account_summary", some n => if n > 2 then .«unsafe» else .clear
  | some "account_summary", none   => .unevaluable
  | _, _                           => .clear

-- CH2 Control 8: CTL.S3.GOVERNANCE.001
-- all: [kind=bucket, tags.data-classification missing true]
def evalS3Governance (obs : StorageObs) : EvalOutcome :=
  match obs.kind, obs.data_classification with
  | some "bucket", none   => .«unsafe»
  | some "bucket", some _ => .clear
  | _, _                  => .clear

/-- Dispatch by control ID. Unknown control -> unevaluable (fail-closed). -/
inductive TypedObs where
  | cloudtrail (obs : CloudTrailObs)
  | orgSCP (obs : OrgSCPObs)
  | iamAccount (obs : IAMAccountObs)
  | iamUser (obs : IAMUserObs)
  | iamSummary (obs : IAMSummaryObs)
  | securityGroup (obs : SecurityGroupObs)
  | cdn (obs : CDNObs)
  | vpcEndpoint (obs : VPCEndpointObs)
  | storage (obs : StorageObs)
  | kmsKey (obs : KMSKeyObs)
  | kmsGrant (obs : KMSGrantObs)
  deriving Repr

def evalTypedControl (ctrlId : ControlId) (obs : TypedObs) : ControlResult :=
  let outcome := match ctrlId, obs with
    | "CTL.CLOUDTRAIL.ORG.001", .cloudtrail o => evalCloudTrailOrg o
    | "CTL.ORG.REGION.SCP.001", .orgSCP o => evalOrgRegionSCP o
    | "CTL.IAM.ROOT.MFA.001", .iamAccount o => evalRootMFA o
    | "CTL.IAM.ROOT.ACCESSKEY.001", .iamAccount o => evalRootAccessKey o
    | "CTL.CLOUDTRAIL.LOG.VALIDATION.001", .cloudtrail o => evalCloudTrailLogValidation o
    | "CTL.IAM.CONSOLE.MFA.001", .iamUser o => evalConsoleMFA o
    | "CTL.VPC.SG.UNRESTRICTED.001", .securityGroup o => evalSGUnrestricted o
    | "CTL.CLOUDTRAIL.REGIONAL.COVERAGE.001", .cloudtrail o => evalCloudTrailRegional o
    | "CTL.CLOUDFRONT.ACCESS.SIGNED.LONG.EXPIRY.001", .cdn o => evalSignedLongExpiry o
    | "CTL.CLOUDFRONT.VIEWER.CERT.EXPIRY.WARN.001", .cdn o => evalCertExpiryWarn o
    | "CTL.CLOUDFRONT.WAF.001", .cdn o => evalCloudFrontWAF o
    | "CTL.CLOUDFRONT.LIFECYCLE.ORPHAN.POLICY.001", .cdn o => evalOrphanPolicy o
    | "CTL.VPC.ENDPOINT.KMS.EGRESS.001", .vpcEndpoint o => evalVPCEndpointKMS o
    | "CTL.IAM.CRED.UNUSED45.001", .iamUser o => evalCredUnused45 o
    | "CTL.IAM.ADMIN.COUNT.001", .iamSummary o => evalAdminCount o
    | "CTL.S3.GOVERNANCE.001", .storage o => evalS3Governance o
    | "CTL.KMS.ROTATION.001", .kmsKey o => evalKMSRotation o
    | "CTL.KMS.STATE.DISABLED.001", .kmsKey o => evalKMSStateDisabled o
    | "CTL.KMS.DELETION.NOPROTECTION.001", .kmsKey o => evalKMSDeletionNoProtection o
    | "CTL.KMS.PENDING.DELETION.001", .kmsKey o => evalKMSPendingDeletion o
    | "CTL.KMS.LIFECYCLE.DORMANT.001", .kmsKey o => evalKMSDormant o
    | "CTL.KMS.LIFECYCLE.NOALIAS.001", .kmsKey o => evalKMSNoAlias o
    | "CTL.KMS.LIFECYCLE.CROSSENV.001", .kmsKey o => evalKMSCrossEnv o
    | "CTL.KMS.LIFECYCLE.ROTATION.PERIOD.001", .kmsKey o => evalKMSRotationPeriod o
    | "CTL.KMS.ENTROPY.EXTERNAL.ORIGIN.001", .kmsKey o => evalKMSEntropyExternal o
    | "CTL.KMS.FIPS.001", .kmsKey o => evalKMSFips o
    | "CTL.KMS.INCOMPLETE.001", .kmsKey o => evalKMSIncomplete o
    | "CTL.KMS.SEPARATION.001", .kmsKey o => evalKMSSeparation o
    | "CTL.KMS.POLICY.001", .kmsKey o => evalKMSPolicyWildcard o
    | "CTL.KMS.POLICY.ADMIN.BROAD.001", .kmsKey o => evalKMSPolicyAdminBroad o
    | "CTL.KMS.POLICY.CONDITION.001", .kmsKey o => evalKMSPolicyCondition o
    | "CTL.KMS.POLICY.CROSSACCOUNT.001", .kmsKey o => evalKMSPolicyCrossAccount o
    | "CTL.KMS.POLICY.DECRYPT.BROAD.001", .kmsKey o => evalKMSPolicyDecryptBroad o
    | "CTL.KMS.POLICY.ENCLAVE.NOPCR.001", .kmsKey o => evalKMSPolicyEnclaveNoPcr o
    | "CTL.KMS.POLICY.GHOSTREF.001", .kmsKey o => evalKMSPolicyGhostRef o
    | "CTL.KMS.POLICY.GRANTWITHGRANT.001", .kmsKey o => evalKMSPolicyGrantWithGrant o
    | "CTL.KMS.POLICY.NOCONTEXT.001", .kmsKey o => evalKMSPolicyNoContext o
    | "CTL.KMS.POLICY.NOVIASERVICE.001", .kmsKey o => evalKMSPolicyNoViaService o
    | "CTL.KMS.POLICY.ROOT.PRINCIPAL.001", .kmsKey o => evalKMSPolicyRootPrincipal o
    | "CTL.KMS.ALARM.CREATEGRANT.001", .kmsKey o => evalKMSAlarmCreateGrant o
    | "CTL.KMS.ALARM.CROSSACCOUNT.001", .kmsKey o => evalKMSAlarmCrossAccount o
    | "CTL.KMS.ALARM.DECRYPT.FAILURE.001", .kmsKey o => evalKMSAlarmDecryptFailure o
    | "CTL.KMS.ALARM.DECRYPT.VOLUME.001", .kmsKey o => evalKMSAlarmDecryptVolume o
    | "CTL.KMS.ALARM.DELETION.001", .kmsKey o => evalKMSAlarmDeletion o
    | "CTL.KMS.ALARM.DISABLE.001", .kmsKey o => evalKMSAlarmDisable o
    | "CTL.KMS.ALARM.POLICYCHANGE.001", .kmsKey o => evalKMSAlarmPolicyChange o
    | "CTL.KMS.ALARM.ROTATION.FAILURE.001", .kmsKey o => evalKMSAlarmRotationFailure o
    | _, _ => EvalOutcome.unevaluable
  { controlId := ctrlId, outcome := outcome }
