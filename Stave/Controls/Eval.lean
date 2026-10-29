import Stave.Controls.Types

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

/-- Dispatch by control ID. Unknown control -> unevaluable (fail-closed). -/
inductive TypedObs where
  | cloudtrail (obs : CloudTrailObs)
  | orgSCP (obs : OrgSCPObs)
  | iamAccount (obs : IAMAccountObs)
  | iamUser (obs : IAMUserObs)
  | securityGroup (obs : SecurityGroupObs)
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
    | _, _ => EvalOutcome.unevaluable
  { controlId := ctrlId, outcome := outcome }
