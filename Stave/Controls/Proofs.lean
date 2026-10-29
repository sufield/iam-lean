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

-- CH2 Control 1: CloudFront signed URL long expiry (gt)
theorem signed_long_expiry_unsafe :
    (evalSignedLongExpiry { kind := some "distribution",
                            signed_url_default_expiry_seconds := some 172800 }).fires = true := by native_decide

theorem signed_long_expiry_safe :
    (evalSignedLongExpiry { kind := some "distribution",
                            signed_url_default_expiry_seconds := some 3600 }).fires = false := by native_decide

theorem signed_long_expiry_failclosed :
    (evalSignedLongExpiry { kind := some "distribution" }).fires = true := by native_decide

-- CH2 Control 2: CloudFront cert expiry warn (lt)
theorem cert_expiry_warn_unsafe :
    (evalCertExpiryWarn { kind := some "distribution",
                          viewer_cert_days_until_expiry := some 15 }).fires = true := by native_decide

theorem cert_expiry_warn_safe :
    (evalCertExpiryWarn { kind := some "distribution",
                          viewer_cert_days_until_expiry := some 90 }).fires = false := by native_decide

theorem cert_expiry_warn_failclosed :
    (evalCertExpiryWarn { kind := some "distribution" }).fires = true := by native_decide

-- CH2 Control 3: CloudFront WAF (missing)
theorem cloudfront_waf_unsafe :
    (evalCloudFrontWAF { kind := some "distribution" }).fires = true := by native_decide

theorem cloudfront_waf_safe :
    (evalCloudFrontWAF { kind := some "distribution",
                          waf_web_acl_id := some "arn:aws:wafv2:..." }).fires = false := by native_decide

-- CH2 Control 4: CloudFront orphan policy (in)
theorem orphan_policy_unsafe :
    (evalOrphanPolicy { kind := some "cache_policy",
                         policy_referenced := some false }).fires = true := by native_decide

theorem orphan_policy_safe :
    (evalOrphanPolicy { kind := some "response_headers_policy",
                         policy_referenced := some true }).fires = false := by native_decide

theorem orphan_policy_failclosed :
    (evalOrphanPolicy { kind := some "cache_policy" }).fires = true := by native_decide

theorem orphan_policy_wrong_kind :
    (evalOrphanPolicy { kind := some "distribution" }).fires = false := by native_decide

-- CH2 Control 5: VPC endpoint KMS (contains)
theorem vpc_endpoint_kms_unsafe :
    (evalVPCEndpointKMS { kind := some "vpc_endpoint",
                           service_name := some "com.amazonaws.us-east-1.kms",
                           restricts_to_org_resources := some false }).fires = true := by native_decide

theorem vpc_endpoint_kms_safe :
    (evalVPCEndpointKMS { kind := some "vpc_endpoint",
                           service_name := some "com.amazonaws.us-east-1.kms",
                           restricts_to_org_resources := some true }).fires = false := by native_decide

theorem vpc_endpoint_kms_failclosed :
    (evalVPCEndpointKMS { kind := some "vpc_endpoint",
                           service_name := some "com.amazonaws.us-east-1.kms" }).fires = true := by native_decide

theorem vpc_endpoint_kms_wrong_service :
    (evalVPCEndpointKMS { kind := some "vpc_endpoint",
                           service_name := some "com.amazonaws.us-east-1.s3" }).fires = false := by native_decide

-- CH2 Control 6: IAM credential unused 45 days (gt)
theorem cred_unused45_unsafe :
    (evalCredUnused45 { kind := some "user",
                         credentials_unused_days := some 90 }).fires = true := by native_decide

theorem cred_unused45_safe :
    (evalCredUnused45 { kind := some "user",
                         credentials_unused_days := some 30 }).fires = false := by native_decide

theorem cred_unused45_failclosed :
    (evalCredUnused45 { kind := some "user" }).fires = true := by native_decide

-- CH2 Control 7: IAM admin count (gt)
theorem admin_count_unsafe :
    (evalAdminCount { kind := some "account_summary",
                       admin_user_count := some 5 }).fires = true := by native_decide

theorem admin_count_safe :
    (evalAdminCount { kind := some "account_summary",
                       admin_user_count := some 1 }).fires = false := by native_decide

theorem admin_count_failclosed :
    (evalAdminCount { kind := some "account_summary" }).fires = true := by native_decide

-- CH2 Control 8: S3 governance tag (missing)
theorem s3_governance_unsafe :
    (evalS3Governance { kind := some "bucket" }).fires = true := by native_decide

theorem s3_governance_safe :
    (evalS3Governance { kind := some "bucket",
                         data_classification := some "internal" }).fires = false := by native_decide

-- Dispatch: unknown control ID -> unevaluable -> fires
theorem unknown_control_failclosed :
    (evalTypedControl "CTL.UNKNOWN.999" (.cloudtrail {})).outcome.fires = true := by native_decide
