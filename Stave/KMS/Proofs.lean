import Stave.KMS.Eval

/-! Per-control fail-closed proofs and known-answer tests for KMS-P1.
Each control proves: missing required field on a matching kind → fires. -/

-- CTL.KMS.ROTATION.001
theorem kms_rotation_failclosed :
    (evalKMSRotation { kind := some "key" }).fires = true := by native_decide

theorem kms_rotation_unsafe :
    (evalKMSRotation { kind := some "key",
                       key_rotation_enabled := some false }).fires = true := by native_decide

theorem kms_rotation_safe :
    (evalKMSRotation { kind := some "key",
                       key_rotation_enabled := some true }).fires = false := by native_decide

-- CTL.KMS.STATE.DISABLED.001
theorem kms_state_disabled_failclosed :
    (evalKMSStateDisabled { kind := some "key",
                            is_disabled := some true }).fires = true := by native_decide

theorem kms_state_disabled_unsafe :
    (evalKMSStateDisabled { kind := some "key",
                            is_disabled := some true,
                            dependent_resource_count := some 3 }).fires = true := by native_decide

theorem kms_state_disabled_safe_not_disabled :
    (evalKMSStateDisabled { kind := some "key",
                            is_disabled := some false }).fires = false := by native_decide

theorem kms_state_disabled_safe_zero_deps :
    (evalKMSStateDisabled { kind := some "key",
                            is_disabled := some true,
                            dependent_resource_count := some 0 }).fires = false := by native_decide

-- CTL.KMS.DELETION.NOPROTECTION.001
theorem kms_deletion_noprotection_failclosed :
    (evalKMSDeletionNoProtection { kind := some "key" }).fires = true := by native_decide

theorem kms_deletion_noprotection_unsafe :
    (evalKMSDeletionNoProtection { kind := some "key",
                                   alarms := { has_schedule_deletion_alarm := some false },
                                   deletion_protection := { has_scp_deny := some false } }).fires = true := by
  native_decide

theorem kms_deletion_noprotection_safe_alarm :
    (evalKMSDeletionNoProtection { kind := some "key",
                                   alarms := { has_schedule_deletion_alarm := some true },
                                   deletion_protection := { has_scp_deny := some false } }).fires = false := by
  native_decide

theorem kms_deletion_noprotection_safe_scp :
    (evalKMSDeletionNoProtection { kind := some "key",
                                   alarms := { has_schedule_deletion_alarm := some false },
                                   deletion_protection := { has_scp_deny := some true } }).fires = false := by
  native_decide

-- CTL.KMS.PENDING.DELETION.001
theorem kms_pending_deletion_failclosed :
    (evalKMSPendingDeletion { kind := some "key" }).fires = true := by native_decide

theorem kms_pending_deletion_unsafe :
    (evalKMSPendingDeletion { kind := some "key",
                              lifecycle := { pending_deletion := some true } }).fires = true := by native_decide

theorem kms_pending_deletion_safe :
    (evalKMSPendingDeletion { kind := some "key",
                              lifecycle := { pending_deletion := some false } }).fires = false := by native_decide

-- CTL.KMS.LIFECYCLE.DORMANT.001
theorem kms_dormant_failclosed :
    (evalKMSDormant { kind := some "key" }).fires = true := by native_decide

theorem kms_dormant_unsafe :
    (evalKMSDormant { kind := some "key",
                      is_dormant := some true }).fires = true := by native_decide

theorem kms_dormant_safe :
    (evalKMSDormant { kind := some "key",
                      is_dormant := some false }).fires = false := by native_decide

-- CTL.KMS.LIFECYCLE.NOALIAS.001
theorem kms_noalias_failclosed :
    (evalKMSNoAlias { kind := some "key" }).fires = true := by native_decide

theorem kms_noalias_unsafe :
    (evalKMSNoAlias { kind := some "key",
                      lifecycle := { has_alias := some false } }).fires = true := by native_decide

theorem kms_noalias_safe :
    (evalKMSNoAlias { kind := some "key",
                      lifecycle := { has_alias := some true } }).fires = false := by native_decide

-- CTL.KMS.LIFECYCLE.CROSSENV.001
theorem kms_crossenv_failclosed :
    (evalKMSCrossEnv { kind := some "key" }).fires = true := by native_decide

theorem kms_crossenv_unsafe :
    (evalKMSCrossEnv { kind := some "key",
                       lifecycle := { cross_env := some true } }).fires = true := by native_decide

theorem kms_crossenv_safe :
    (evalKMSCrossEnv { kind := some "key",
                       lifecycle := { cross_env := some false } }).fires = false := by native_decide

-- CTL.KMS.LIFECYCLE.ROTATION.PERIOD.001
theorem kms_rotation_period_failclosed :
    (evalKMSRotationPeriod { kind := some "key",
                             lifecycle := { rotation_enabled := some true } }).fires = true := by native_decide

theorem kms_rotation_period_unsafe :
    (evalKMSRotationPeriod { kind := some "key",
                             lifecycle := { rotation_enabled := some true,
                                            rotation_period_compliant := some false } }).fires = true := by
  native_decide

theorem kms_rotation_period_safe :
    (evalKMSRotationPeriod { kind := some "key",
                             lifecycle := { rotation_enabled := some true,
                                            rotation_period_compliant := some true } }).fires = false := by
  native_decide

theorem kms_rotation_period_rotation_off :
    (evalKMSRotationPeriod { kind := some "key",
                             lifecycle := { rotation_enabled := some false } }).fires = false := by native_decide

-- CTL.KMS.ENTROPY.EXTERNAL.ORIGIN.001
theorem kms_entropy_external_failclosed :
    (evalKMSEntropyExternal { kind := some "key",
                              is_aws_managed := some false }).fires = true := by native_decide

theorem kms_entropy_external_unsafe :
    (evalKMSEntropyExternal { kind := some "key",
                              is_aws_managed := some false,
                              origin := some "EXTERNAL" }).fires = true := by native_decide

theorem kms_entropy_external_safe_aws_origin :
    (evalKMSEntropyExternal { kind := some "key",
                              is_aws_managed := some false,
                              origin := some "AWS_KMS" }).fires = false := by native_decide

theorem kms_entropy_external_safe_aws_managed :
    (evalKMSEntropyExternal { kind := some "key",
                              is_aws_managed := some true,
                              origin := some "EXTERNAL" }).fires = false := by native_decide

-- CTL.KMS.FIPS.001
theorem kms_fips_failclosed :
    (evalKMSFips { kind := some "key" }).fires = true := by native_decide

theorem kms_fips_unsafe :
    (evalKMSFips { kind := some "key",
                   origin := some "EXTERNAL" }).fires = true := by native_decide

theorem kms_fips_safe :
    (evalKMSFips { kind := some "key",
                   origin := some "AWS_KMS" }).fires = false := by native_decide

-- CTL.KMS.INCOMPLETE.001
theorem kms_incomplete_unsafe :
    (evalKMSIncomplete { kind := some "key" }).fires = true := by native_decide

theorem kms_incomplete_safe :
    (evalKMSIncomplete { kind := some "key",
                         policy := { has_wildcard_principal := some false } }).fires = false := by native_decide

theorem kms_incomplete_safe_true :
    (evalKMSIncomplete { kind := some "key",
                         policy := { has_wildcard_principal := some true } }).fires = false := by native_decide

-- CTL.KMS.SEPARATION.001
theorem kms_separation_failclosed :
    (evalKMSSeparation { kind := some "key" }).fires = true := by native_decide

theorem kms_separation_unsafe :
    (evalKMSSeparation { kind := some "key",
                         principal_has_admin_and_usage := some true }).fires = true := by native_decide

theorem kms_separation_safe :
    (evalKMSSeparation { kind := some "key",
                         principal_has_admin_and_usage := some false }).fires = false := by native_decide

-- Cross-control: wrong kind always passes
theorem kms_wrong_kind_rotation :
    (evalKMSRotation { kind := some "alias" }).fires = false := by native_decide

theorem kms_wrong_kind_disabled :
    (evalKMSStateDisabled { kind := some "grant" }).fires = false := by native_decide

-- ===== KMS-P2: Policy controls =====

-- CTL.KMS.POLICY.001
theorem kms_policy_wildcard_failclosed :
    (evalKMSPolicyWildcard { kind := some "key" }).fires = true := by native_decide
theorem kms_policy_wildcard_unsafe :
    (evalKMSPolicyWildcard { kind := some "key",
                             policy := { has_wildcard_principal := some true } }).fires = true := by native_decide
theorem kms_policy_wildcard_safe :
    (evalKMSPolicyWildcard { kind := some "key",
                             policy := { has_wildcard_principal := some false } }).fires = false := by native_decide

-- CTL.KMS.POLICY.ADMIN.BROAD.001
theorem kms_policy_admin_broad_failclosed :
    (evalKMSPolicyAdminBroad { kind := some "key" }).fires = true := by native_decide
theorem kms_policy_admin_broad_unsafe :
    (evalKMSPolicyAdminBroad { kind := some "key",
                               policy := { admin_actions_broadly_granted := some true } }).fires = true := by
  native_decide
theorem kms_policy_admin_broad_safe :
    (evalKMSPolicyAdminBroad { kind := some "key",
                               policy := { admin_actions_broadly_granted := some false } }).fires = false := by
  native_decide

-- CTL.KMS.POLICY.CONDITION.001
theorem kms_policy_condition_failclosed :
    (evalKMSPolicyCondition { kind := some "key" }).fires = true := by native_decide
theorem kms_policy_condition_unsafe :
    (evalKMSPolicyCondition { kind := some "key",
                              policy := { has_usage_conditions := some false } }).fires = true := by native_decide
theorem kms_policy_condition_safe :
    (evalKMSPolicyCondition { kind := some "key",
                              policy := { has_usage_conditions := some true } }).fires = false := by native_decide

-- CTL.KMS.POLICY.CROSSACCOUNT.001
theorem kms_policy_crossaccount_failclosed :
    (evalKMSPolicyCrossAccount { kind := some "key" }).fires = true := by native_decide
theorem kms_policy_crossaccount_unsafe :
    (evalKMSPolicyCrossAccount { kind := some "key",
                                 policy := { has_broad_cross_account := some true } }).fires = true := by
  native_decide
theorem kms_policy_crossaccount_safe :
    (evalKMSPolicyCrossAccount { kind := some "key",
                                 policy := { has_broad_cross_account := some false } }).fires = false := by
  native_decide

-- CTL.KMS.POLICY.DECRYPT.BROAD.001
theorem kms_policy_decrypt_broad_failclosed :
    (evalKMSPolicyDecryptBroad { kind := some "key",
                                 is_aws_managed := some false }).fires = true := by native_decide
theorem kms_policy_decrypt_broad_unsafe :
    (evalKMSPolicyDecryptBroad { kind := some "key",
                                 is_aws_managed := some false,
                                 policy := { decrypt_broadly_granted := some true } }).fires = true := by
  native_decide
theorem kms_policy_decrypt_broad_safe :
    (evalKMSPolicyDecryptBroad { kind := some "key",
                                 is_aws_managed := some false,
                                 policy := { decrypt_broadly_granted := some false } }).fires = false := by
  native_decide
theorem kms_policy_decrypt_broad_aws_managed :
    (evalKMSPolicyDecryptBroad { kind := some "key",
                                 is_aws_managed := some true }).fires = false := by native_decide

-- CTL.KMS.POLICY.ENCLAVE.NOPCR.001
theorem kms_policy_enclave_nopcr_failclosed :
    (evalKMSPolicyEnclaveNoPcr { kind := some "key",
                                 tags := { enclave_protected := some true } }).fires = true := by native_decide
theorem kms_policy_enclave_nopcr_unsafe :
    (evalKMSPolicyEnclaveNoPcr { kind := some "key",
                                 tags := { enclave_protected := some true },
                                 enclave_attestation := { has_pcr_condition := some false } }).fires = true := by
  native_decide
theorem kms_policy_enclave_nopcr_safe :
    (evalKMSPolicyEnclaveNoPcr { kind := some "key",
                                 tags := { enclave_protected := some true },
                                 enclave_attestation := { has_pcr_condition := some true } }).fires = false := by
  native_decide
theorem kms_policy_enclave_nopcr_not_enclave :
    (evalKMSPolicyEnclaveNoPcr { kind := some "key",
                                 tags := { enclave_protected := some false } }).fires = false := by native_decide

-- CTL.KMS.POLICY.GHOSTREF.001
theorem kms_policy_ghostref_failclosed :
    (evalKMSPolicyGhostRef { kind := some "key" }).fires = true := by native_decide
theorem kms_policy_ghostref_unsafe :
    (evalKMSPolicyGhostRef { kind := some "key",
                             policy := { has_ghost_principal := some true } }).fires = true := by native_decide
theorem kms_policy_ghostref_safe :
    (evalKMSPolicyGhostRef { kind := some "key",
                             policy := { has_ghost_principal := some false } }).fires = false := by native_decide

-- CTL.KMS.POLICY.GRANTWITHGRANT.001
theorem kms_policy_grantwithgrant_failclosed :
    (evalKMSPolicyGrantWithGrant { kind := some "key" }).fires = true := by native_decide
theorem kms_policy_grantwithgrant_unsafe :
    (evalKMSPolicyGrantWithGrant { kind := some "key",
                                   policy := { allows_grant_with_grant := some true } }).fires = true := by
  native_decide
theorem kms_policy_grantwithgrant_safe :
    (evalKMSPolicyGrantWithGrant { kind := some "key",
                                   policy := { allows_grant_with_grant := some false } }).fires = false := by
  native_decide

-- CTL.KMS.POLICY.NOCONTEXT.001
theorem kms_policy_nocontext_failclosed :
    (evalKMSPolicyNoContext { kind := some "key" }).fires = true := by native_decide
theorem kms_policy_nocontext_unsafe :
    (evalKMSPolicyNoContext { kind := some "key",
                              policy := { requires_encryption_context := some false } }).fires = true := by
  native_decide
theorem kms_policy_nocontext_safe :
    (evalKMSPolicyNoContext { kind := some "key",
                              policy := { requires_encryption_context := some true } }).fires = false := by
  native_decide

-- CTL.KMS.POLICY.NOVIASERVICE.001
theorem kms_policy_noviaservice_failclosed :
    (evalKMSPolicyNoViaService { kind := some "key",
                                 key_usage := some "ENCRYPT_DECRYPT" }).fires = true := by native_decide
theorem kms_policy_noviaservice_unsafe :
    (evalKMSPolicyNoViaService { kind := some "key",
                                 key_usage := some "ENCRYPT_DECRYPT",
                                 policy := { has_via_service := some false } }).fires = true := by native_decide
theorem kms_policy_noviaservice_safe :
    (evalKMSPolicyNoViaService { kind := some "key",
                                 key_usage := some "ENCRYPT_DECRYPT",
                                 policy := { has_via_service := some true } }).fires = false := by native_decide
theorem kms_policy_noviaservice_other_usage :
    (evalKMSPolicyNoViaService { kind := some "key",
                                 key_usage := some "SIGN_VERIFY" }).fires = false := by native_decide

-- CTL.KMS.POLICY.ROOT.PRINCIPAL.001
theorem kms_policy_root_principal_failclosed :
    (evalKMSPolicyRootPrincipal { kind := some "key" }).fires = true := by native_decide
theorem kms_policy_root_principal_unsafe :
    (evalKMSPolicyRootPrincipal { kind := some "key",
                                  policy := { has_root_principal_full_access := some true } }).fires = true := by
  native_decide
theorem kms_policy_root_principal_safe :
    (evalKMSPolicyRootPrincipal { kind := some "key",
                                  policy := { has_root_principal_full_access := some false } }).fires = false := by
  native_decide

-- Dispatcher: unknown control → unevaluable → fires
theorem kms_unknown_control_failclosed :
    (evalKMSControl "CTL.KMS.UNKNOWN.999" {}).outcome.fires = true := by native_decide
