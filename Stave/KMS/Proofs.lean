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

-- ===== KMS-P3: Monitoring controls =====

-- CTL.KMS.ALARM.CREATEGRANT.001
theorem kms_alarm_creategrant_failclosed :
    (evalKMSAlarmCreateGrant { kind := some "key" }).fires = true := by native_decide
theorem kms_alarm_creategrant_unsafe :
    (evalKMSAlarmCreateGrant { kind := some "key",
                               alarms := { has_create_grant_alarm := some false } }).fires = true := by native_decide
theorem kms_alarm_creategrant_safe :
    (evalKMSAlarmCreateGrant { kind := some "key",
                               alarms := { has_create_grant_alarm := some true } }).fires = false := by native_decide

-- CTL.KMS.ALARM.CROSSACCOUNT.001
theorem kms_alarm_crossaccount_failclosed :
    (evalKMSAlarmCrossAccount { kind := some "key",
                                policy := { has_cross_account_principal := some true } }).fires = true := by
  native_decide
theorem kms_alarm_crossaccount_unsafe :
    (evalKMSAlarmCrossAccount { kind := some "key",
                                policy := { has_cross_account_principal := some true },
                                alarms := { has_cross_account_alarm := some false } }).fires = true := by
  native_decide
theorem kms_alarm_crossaccount_safe :
    (evalKMSAlarmCrossAccount { kind := some "key",
                                policy := { has_cross_account_principal := some true },
                                alarms := { has_cross_account_alarm := some true } }).fires = false := by
  native_decide
theorem kms_alarm_crossaccount_no_xacct :
    (evalKMSAlarmCrossAccount { kind := some "key",
                                policy := { has_cross_account_principal := some false } }).fires = false := by
  native_decide

-- CTL.KMS.ALARM.DECRYPT.FAILURE.001
theorem kms_alarm_decrypt_failure_failclosed :
    (evalKMSAlarmDecryptFailure { kind := some "key" }).fires = true := by native_decide
theorem kms_alarm_decrypt_failure_unsafe :
    (evalKMSAlarmDecryptFailure { kind := some "key",
                                  alarms := { has_decrypt_failure_alarm := some false } }).fires = true := by
  native_decide
theorem kms_alarm_decrypt_failure_safe :
    (evalKMSAlarmDecryptFailure { kind := some "key",
                                  alarms := { has_decrypt_failure_alarm := some true } }).fires = false := by
  native_decide

-- CTL.KMS.ALARM.DECRYPT.VOLUME.001
theorem kms_alarm_decrypt_volume_failclosed :
    (evalKMSAlarmDecryptVolume { kind := some "key" }).fires = true := by native_decide
theorem kms_alarm_decrypt_volume_unsafe :
    (evalKMSAlarmDecryptVolume { kind := some "key",
                                 alarms := { has_decrypt_volume_alarm := some false } }).fires = true := by
  native_decide
theorem kms_alarm_decrypt_volume_safe :
    (evalKMSAlarmDecryptVolume { kind := some "key",
                                 alarms := { has_decrypt_volume_alarm := some true } }).fires = false := by
  native_decide

-- CTL.KMS.ALARM.DELETION.001
theorem kms_alarm_deletion_failclosed :
    (evalKMSAlarmDeletion { kind := some "key" }).fires = true := by native_decide
theorem kms_alarm_deletion_unsafe :
    (evalKMSAlarmDeletion { kind := some "key",
                            alarms := { has_schedule_deletion_alarm := some false } }).fires = true := by
  native_decide
theorem kms_alarm_deletion_safe :
    (evalKMSAlarmDeletion { kind := some "key",
                            alarms := { has_schedule_deletion_alarm := some true } }).fires = false := by
  native_decide

-- CTL.KMS.ALARM.DISABLE.001
theorem kms_alarm_disable_failclosed :
    (evalKMSAlarmDisable { kind := some "key" }).fires = true := by native_decide
theorem kms_alarm_disable_unsafe :
    (evalKMSAlarmDisable { kind := some "key",
                           alarms := { has_disable_key_alarm := some false } }).fires = true := by native_decide
theorem kms_alarm_disable_safe :
    (evalKMSAlarmDisable { kind := some "key",
                           alarms := { has_disable_key_alarm := some true } }).fires = false := by native_decide

-- CTL.KMS.ALARM.POLICYCHANGE.001
theorem kms_alarm_policychange_failclosed :
    (evalKMSAlarmPolicyChange { kind := some "key" }).fires = true := by native_decide
theorem kms_alarm_policychange_unsafe :
    (evalKMSAlarmPolicyChange { kind := some "key",
                                alarms := { has_put_key_policy_alarm := some false } }).fires = true := by
  native_decide
theorem kms_alarm_policychange_safe :
    (evalKMSAlarmPolicyChange { kind := some "key",
                                alarms := { has_put_key_policy_alarm := some true } }).fires = false := by
  native_decide

-- CTL.KMS.ALARM.ROTATION.FAILURE.001
theorem kms_alarm_rotation_failure_failclosed :
    (evalKMSAlarmRotationFailure { kind := some "key" }).fires = true := by native_decide
theorem kms_alarm_rotation_failure_unsafe :
    (evalKMSAlarmRotationFailure { kind := some "key",
                                   alarms := { has_rotation_alarm := some false } }).fires = true := by native_decide
theorem kms_alarm_rotation_failure_safe :
    (evalKMSAlarmRotationFailure { kind := some "key",
                                   alarms := { has_rotation_alarm := some true } }).fires = false := by native_decide

-- ===== KMS-P4: Grant, Alias, and Remaining =====

-- CTL.KMS.ALIAS.GHOST.001
theorem kms_alias_ghost_failclosed :
    (evalKMSAliasGhost { kind := some "alias" }).fires = true := by native_decide
theorem kms_alias_ghost_unsafe :
    (evalKMSAliasGhost { kind := some "alias",
                         alias_is_ghost := some true }).fires = true := by native_decide
theorem kms_alias_ghost_safe :
    (evalKMSAliasGhost { kind := some "alias",
                         alias_is_ghost := some false }).fires = false := by native_decide
theorem kms_alias_ghost_wrong_kind :
    (evalKMSAliasGhost { kind := some "key" }).fires = false := by native_decide

-- CTL.KMS.ALIAS.ORPHAN.001
theorem kms_alias_orphan_failclosed :
    (evalKMSAliasOrphan { kind := some "alias" }).fires = true := by native_decide
theorem kms_alias_orphan_unsafe :
    (evalKMSAliasOrphan { kind := some "alias",
                          alias_is_orphan := some true }).fires = true := by native_decide
theorem kms_alias_orphan_safe :
    (evalKMSAliasOrphan { kind := some "alias",
                          alias_is_orphan := some false }).fires = false := by native_decide

-- CTL.KMS.CONCENTRATION.001
theorem kms_concentration_001_failclosed :
    (evalKMSConcentration001 { kind := some "key" }).fires = true := by native_decide
theorem kms_concentration_001_unsafe :
    (evalKMSConcentration001 { kind := some "key",
                               key_concentration := { resource_count := some 100 } }).fires = true := by native_decide
theorem kms_concentration_001_safe :
    (evalKMSConcentration001 { kind := some "key",
                               key_concentration := { resource_count := some 10 } }).fires = false := by native_decide

-- CTL.KMS.CONCENTRATION.002
theorem kms_concentration_002_failclosed :
    (evalKMSConcentration002 { kind := some "key",
                               key_concentration := { resource_count := some 100 } }).fires = true := by native_decide
theorem kms_concentration_002_unsafe :
    (evalKMSConcentration002 { kind := some "key",
                               key_concentration := { resource_count := some 100,
                                                      has_deletion_protection := some false } }).fires = true := by
  native_decide
theorem kms_concentration_002_safe_protected :
    (evalKMSConcentration002 { kind := some "key",
                               key_concentration := { resource_count := some 100,
                                                      has_deletion_protection := some true } }).fires = false := by
  native_decide
theorem kms_concentration_002_safe_low_count :
    (evalKMSConcentration002 { kind := some "key",
                               key_concentration := { resource_count := some 10 } }).fires = false := by native_decide

-- CTL.KMS.CROSSACCOUNT.BLASTRADIUS.001
theorem kms_crossaccount_blastradius_failclosed :
    (evalKMSCrossAccountBlastRadius { kind := some "key" }).fires = true := by native_decide
theorem kms_crossaccount_blastradius_unsafe :
    (evalKMSCrossAccountBlastRadius { kind := some "key",
                                      cross_account := { excessive := some true } }).fires = true := by native_decide
theorem kms_crossaccount_blastradius_safe :
    (evalKMSCrossAccountBlastRadius { kind := some "key",
                                      cross_account := { excessive := some false } }).fires = false := by native_decide

-- CTL.KMS.CROSSACCOUNT.DECOMMISSIONED.001
theorem kms_crossaccount_decommissioned_failclosed :
    (evalKMSCrossAccountDecommissioned { kind := some "key" }).fires = true := by native_decide
theorem kms_crossaccount_decommissioned_unsafe :
    (evalKMSCrossAccountDecommissioned { kind := some "key",
                                         cross_account := { has_decommissioned_account := some true } }).fires = true := by
  native_decide
theorem kms_crossaccount_decommissioned_safe :
    (evalKMSCrossAccountDecommissioned { kind := some "key",
                                         cross_account := { has_decommissioned_account := some false } }).fires = false := by
  native_decide

-- CTL.KMS.DELETION.MINWAIT.001
theorem kms_deletion_minwait_failclosed :
    (evalKMSDeletionMinWait { kind := some "key",
                              lifecycle := { pending_deletion := some true } }).fires = true := by native_decide
theorem kms_deletion_minwait_unsafe :
    (evalKMSDeletionMinWait { kind := some "key",
                              lifecycle := { pending_deletion := some true,
                                             deletion_wait_minimum := some true } }).fires = true := by native_decide
theorem kms_deletion_minwait_safe :
    (evalKMSDeletionMinWait { kind := some "key",
                              lifecycle := { pending_deletion := some true,
                                             deletion_wait_minimum := some false } }).fires = false := by native_decide
theorem kms_deletion_minwait_not_pending :
    (evalKMSDeletionMinWait { kind := some "key",
                              lifecycle := { pending_deletion := some false } }).fires = false := by native_decide

-- CTL.KMS.GRANT.BROAD.001
theorem kms_grant_broad_failclosed :
    (evalKMSGrantBroad { kind := some "key" }).fires = true := by native_decide
theorem kms_grant_broad_unsafe :
    (evalKMSGrantBroad { kind := some "key",
                         grant_operations_excessive := some true }).fires = true := by native_decide
theorem kms_grant_broad_safe :
    (evalKMSGrantBroad { kind := some "key",
                         grant_operations_excessive := some false }).fires = false := by native_decide

-- CTL.KMS.GRANT.EXCESSIVE.001
theorem kms_grant_excessive_failclosed :
    (evalKMSGrantExcessive { kind := some "key" }).fires = true := by native_decide
theorem kms_grant_excessive_unsafe :
    (evalKMSGrantExcessive { kind := some "key",
                             has_excessive_grants := some true }).fires = true := by native_decide
theorem kms_grant_excessive_safe :
    (evalKMSGrantExcessive { kind := some "key",
                             has_excessive_grants := some false }).fires = false := by native_decide

-- CTL.KMS.GRANT.EXTERNAL.001
theorem kms_grant_external_unsafe :
    (evalKMSGrantExternal { grantee_is_service_principal := some false,
                            grantee_is_external_account := some true }).fires = true := by native_decide
theorem kms_grant_external_safe_service :
    (evalKMSGrantExternal { grantee_is_service_principal := some true,
                            grantee_is_external_account := some true }).fires = false := by native_decide
theorem kms_grant_external_safe_internal :
    (evalKMSGrantExternal { grantee_is_service_principal := some false,
                            grantee_is_external_account := some false }).fires = false := by native_decide
theorem kms_grant_external_failclosed :
    (evalKMSGrantExternal { grantee_is_service_principal := some false }).fires = true := by native_decide

-- CTL.KMS.GRANT.ORPHAN.001
theorem kms_grant_orphan_failclosed :
    (evalKMSGrantOrphan { kind := some "grant" }).fires = true := by native_decide
theorem kms_grant_orphan_unsafe :
    (evalKMSGrantOrphan { kind := some "grant",
                          grant_is_orphan := some true }).fires = true := by native_decide
theorem kms_grant_orphan_safe :
    (evalKMSGrantOrphan { kind := some "grant",
                          grant_is_orphan := some false }).fires = false := by native_decide
theorem kms_grant_orphan_wrong_kind :
    (evalKMSGrantOrphan { kind := some "key" }).fires = false := by native_decide

-- CTL.KMS.GRANT.STALE.001
theorem kms_grant_stale_failclosed :
    (evalKMSGrantStale { kind := some "kms_key",
                         rotation_enabled := some true }).fires = true := by native_decide
theorem kms_grant_stale_unsafe :
    (evalKMSGrantStale { kind := some "kms_key",
                         rotation_enabled := some true,
                         grants := { has_pre_rotation_grants := some true } }).fires = true := by native_decide
theorem kms_grant_stale_safe :
    (evalKMSGrantStale { kind := some "kms_key",
                         rotation_enabled := some true,
                         grants := { has_pre_rotation_grants := some false } }).fires = false := by native_decide
theorem kms_grant_stale_wrong_kind :
    (evalKMSGrantStale { kind := some "key" }).fires = false := by native_decide

-- CTL.KMS.IMPORTED.EXPIRY.001
theorem kms_imported_expiry_failclosed :
    (evalKMSImportedExpiry { kind := some "key" }).fires = true := by native_decide
theorem kms_imported_expiry_unsafe :
    (evalKMSImportedExpiry { kind := some "key",
                             imported_material_no_expiry := some true }).fires = true := by native_decide
theorem kms_imported_expiry_safe :
    (evalKMSImportedExpiry { kind := some "key",
                             imported_material_no_expiry := some false }).fires = false := by native_decide

-- CTL.KMS.MATERIAL.EXPIRED.001
theorem kms_material_expired_failclosed :
    (evalKMSMaterialExpired { kind := some "key" }).fires = true := by native_decide
theorem kms_material_expired_unsafe :
    (evalKMSMaterialExpired { kind := some "key",
                              imported_material_expired := some true }).fires = true := by native_decide
theorem kms_material_expired_safe :
    (evalKMSMaterialExpired { kind := some "key",
                              imported_material_expired := some false }).fires = false := by native_decide

-- CTL.KMS.ISOLATION.001
theorem kms_isolation_unsafe :
    (evalKMSIsolation { kms_key_id := some "key-123",
                        key_isolation_is_exclusive := some false }).fires = true := by native_decide
theorem kms_isolation_safe :
    (evalKMSIsolation { kms_key_id := some "key-123",
                        key_isolation_is_exclusive := some true }).fires = false := by native_decide
theorem kms_isolation_failclosed :
    (evalKMSIsolation { kms_key_id := some "key-123" }).fires = true := by native_decide
theorem kms_isolation_no_key_id :
    (evalKMSIsolation {}).fires = false := by native_decide

-- CTL.KMS.MULTIREGION.NONCOMPLIANT.REGION.001
theorem kms_multiregion_noncompliant_failclosed :
    (evalKMSMultiRegionNoncompliant { kind := some "key",
                                      multi_region := { is_multi_region := some true } }).fires = true := by
  native_decide
theorem kms_multiregion_noncompliant_unsafe :
    (evalKMSMultiRegionNoncompliant { kind := some "key",
                                      multi_region := { is_multi_region := some true,
                                                        has_noncompliant_replica := some true } }).fires = true := by
  native_decide
theorem kms_multiregion_noncompliant_safe :
    (evalKMSMultiRegionNoncompliant { kind := some "key",
                                      multi_region := { is_multi_region := some true,
                                                        has_noncompliant_replica := some false } }).fires = false := by
  native_decide

-- CTL.KMS.MULTIREGION.NOREPLICA.001
theorem kms_multiregion_noreplica_failclosed :
    (evalKMSMultiRegionNoReplica { kind := some "key",
                                   multi_region := { is_multi_region := some true } }).fires = true := by native_decide
theorem kms_multiregion_noreplica_unsafe :
    (evalKMSMultiRegionNoReplica { kind := some "key",
                                   multi_region := { is_multi_region := some true,
                                                     replica_count := some 0 } }).fires = true := by native_decide
theorem kms_multiregion_noreplica_safe :
    (evalKMSMultiRegionNoReplica { kind := some "key",
                                   multi_region := { is_multi_region := some true,
                                                     replica_count := some 3 } }).fires = false := by native_decide

-- CTL.KMS.MULTIREGION.POLICY.MISMATCH.001
theorem kms_multiregion_policy_mismatch_failclosed :
    (evalKMSMultiRegionPolicyMismatch { kind := some "key",
                                        multi_region := { is_multi_region := some true } }).fires = true := by
  native_decide
theorem kms_multiregion_policy_mismatch_unsafe :
    (evalKMSMultiRegionPolicyMismatch { kind := some "key",
                                        multi_region := { is_multi_region := some true,
                                                          replica_policies_consistent := some false } }).fires = true := by
  native_decide
theorem kms_multiregion_policy_mismatch_safe :
    (evalKMSMultiRegionPolicyMismatch { kind := some "key",
                                        multi_region := { is_multi_region := some true,
                                                          replica_policies_consistent := some true } }).fires = false := by
  native_decide

-- CTL.KMS.STATE.PENDINGDELETION.001
theorem kms_state_pending_deletion_failclosed :
    (evalKMSStatePendingDeletion { kind := some "key",
                                   lifecycle := { pending_deletion := some true } }).fires = true := by native_decide
theorem kms_state_pending_deletion_unsafe :
    (evalKMSStatePendingDeletion { kind := some "key",
                                   lifecycle := { pending_deletion := some true },
                                   dependent_resource_count := some 5 }).fires = true := by native_decide
theorem kms_state_pending_deletion_safe_no_deps :
    (evalKMSStatePendingDeletion { kind := some "key",
                                   lifecycle := { pending_deletion := some true },
                                   dependent_resource_count := some 0 }).fires = false := by native_decide
theorem kms_state_pending_deletion_safe_not_pending :
    (evalKMSStatePendingDeletion { kind := some "key",
                                   lifecycle := { pending_deletion := some false } }).fires = false := by native_decide

-- CTL.KMS.STATE.PENDINGIMPORT.001
theorem kms_state_pending_import_failclosed :
    (evalKMSStatePendingImport { kind := some "key" }).fires = true := by native_decide
theorem kms_state_pending_import_unsafe :
    (evalKMSStatePendingImport { kind := some "key",
                                 is_pending_import := some true }).fires = true := by native_decide
theorem kms_state_pending_import_safe :
    (evalKMSStatePendingImport { kind := some "key",
                                 is_pending_import := some false }).fires = false := by native_decide

-- Dispatcher: unknown control → unevaluable → fires
theorem kms_unknown_control_failclosed :
    (evalKMSControl "CTL.KMS.UNKNOWN.999" {}).outcome.fires = true := by native_decide
