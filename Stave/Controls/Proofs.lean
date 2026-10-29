import Stave.Controls.Eval

/-! Per-control fail-closed proofs and known-answer tests.
Each control proves: missing required field -> finding fires. -/

-- Control 1: CloudTrail org-wide
-- Missing is_organization_trail on a trail -> unevaluable -> fires
theorem cloudtrail_org_failclosed :
    (evalCloudTrailOrg { kind := some "trail" }).fires = true := by native_decide

theorem cloudtrail_org_unsafe :
    (evalCloudTrailOrg { kind := some "trail", is_organization_trail := some false }).fires = true := by
  native_decide

theorem cloudtrail_org_safe :
    (evalCloudTrailOrg { kind := some "trail", is_organization_trail := some true }).fires = false := by
  native_decide

-- Control 2: Region-pinning SCP
theorem org_region_scp_failclosed :
    (evalOrgRegionSCP { kind := some "scp_policy_set" }).fires = true := by native_decide

theorem org_region_scp_unsafe :
    (evalOrgRegionSCP { kind := some "scp_policy_set",
                        region_restriction_has_scp := some false }).fires = true := by
  native_decide

theorem org_region_scp_safe :
    (evalOrgRegionSCP { kind := some "scp_policy_set",
                        region_restriction_has_scp := some true }).fires = false := by
  native_decide

-- Control 3: Root MFA
theorem root_mfa_failclosed :
    (evalRootMFA { kind := some "account" }).fires = true := by native_decide

theorem root_mfa_unsafe :
    (evalRootMFA { kind := some "account", root_mfa_enabled := some false }).fires = true := by
  native_decide

theorem root_mfa_safe :
    (evalRootMFA { kind := some "account", root_mfa_enabled := some true }).fires = false := by
  native_decide

-- Control 4: Root access keys
theorem root_accesskey_unsafe :
    (evalRootAccessKey { kind := some "account",
                         root_has_access_keys := some true }).fires = true := by
  native_decide

theorem root_accesskey_safe :
    (evalRootAccessKey { kind := some "account",
                         root_has_access_keys := some false }).fires = false := by
  native_decide

-- Access keys not present = pass (the `present` op in the predicate fails first)
theorem root_accesskey_absent_passes :
    (evalRootAccessKey { kind := some "account" }).fires = false := by native_decide

-- Control 5: CloudTrail log validation
theorem cloudtrail_logval_failclosed :
    (evalCloudTrailLogValidation {}).fires = true := by native_decide

theorem cloudtrail_logval_unsafe :
    (evalCloudTrailLogValidation { log_file_validation_enabled := some false }).fires = true := by
  native_decide

theorem cloudtrail_logval_safe :
    (evalCloudTrailLogValidation { log_file_validation_enabled := some true }).fires = false := by
  native_decide

-- Control 6: Console MFA
-- User with console access but no MFA -> unsafe
theorem console_mfa_unsafe :
    (evalConsoleMFA { kind := some "user",
                      console_access_enabled := some true,
                      console_access_mfa_enabled := some false }).fires = true := by
  native_decide

-- User with console access and MFA -> safe
theorem console_mfa_safe :
    (evalConsoleMFA { kind := some "user",
                      console_access_enabled := some true,
                      console_access_mfa_enabled := some true }).fires = false := by
  native_decide

-- User with console access but MFA field missing -> unevaluable -> fires
theorem console_mfa_failclosed :
    (evalConsoleMFA { kind := some "user",
                      console_access_enabled := some true }).fires = true := by
  native_decide

-- User without console access -> safe regardless of MFA
theorem console_mfa_no_console :
    (evalConsoleMFA { kind := some "user",
                      console_access_enabled := some false }).fires = false := by
  native_decide

-- Control 7: SG unrestricted ingress
theorem sg_unrestricted_failclosed :
    (evalSGUnrestricted { kind := some "security_group" }).fires = true := by native_decide

theorem sg_unrestricted_unsafe :
    (evalSGUnrestricted { kind := some "security_group",
                          has_unrestricted_ingress := some true }).fires = true := by
  native_decide

theorem sg_unrestricted_safe :
    (evalSGUnrestricted { kind := some "security_group",
                          has_unrestricted_ingress := some false }).fires = false := by
  native_decide

-- Control 8: CloudTrail regional coverage
theorem cloudtrail_regional_failclosed :
    (evalCloudTrailRegional { kind := some "trail" }).fires = true := by native_decide

theorem cloudtrail_regional_unsafe :
    (evalCloudTrailRegional { kind := some "trail",
                              is_multi_region := some false }).fires = true := by
  native_decide

theorem cloudtrail_regional_safe :
    (evalCloudTrailRegional { kind := some "trail",
                              is_multi_region := some true }).fires = false := by
  native_decide

-- Cross-control: wrong asset type always passes (non-applicable)
theorem wrong_kind_cloudtrail :
    (evalCloudTrailOrg { kind := some "not_a_trail" }).fires = false := by native_decide

theorem wrong_kind_sg :
    (evalSGUnrestricted { kind := some "not_sg" }).fires = false := by native_decide

-- Dispatch: unknown control ID -> unevaluable -> fires
theorem unknown_control_failclosed :
    (evalTypedControl "CTL.UNKNOWN.999" (.cloudtrail {})).outcome.fires = true := by native_decide
