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

-- Dispatcher: unknown control → unevaluable → fires
theorem kms_unknown_control_failclosed :
    (evalKMSControl "CTL.KMS.UNKNOWN.999" {}).outcome.fires = true := by native_decide
