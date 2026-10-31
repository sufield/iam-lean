import Stave.KMS.Types
import Stave.Controls.Types

/-! Concrete Lean evaluators for KMS-P1 controls (12 controls).
Each function mirrors the unsafe_predicate from its control YAML.
Fail-closed: any missing field (none) → unevaluable → fires. -/

-- CTL.KMS.ROTATION.001
-- all: [kind=key, key_rotation_enabled=false]
def evalKMSRotation (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.key_rotation_enabled with
    | some false => .«unsafe»
    | some true  => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.STATE.DISABLED.001
-- all: [kind=key, is_disabled=true, dependent_resource_count > 0]
def evalKMSStateDisabled (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.is_disabled with
    | some true =>
      match obs.dependent_resource_count with
      | some n => if n > 0 then .«unsafe» else .clear
      | none   => .unevaluable
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.DELETION.NOPROTECTION.001
-- all: [kind=key, alarms.has_schedule_deletion_alarm=false, deletion_protection.has_scp_deny=false]
def evalKMSDeletionNoProtection (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.alarms.has_schedule_deletion_alarm, obs.deletion_protection.has_scp_deny with
    | some false, some false => .«unsafe»
    | some true, _           => .clear
    | _, some true           => .clear
    | none, _                => .unevaluable
    | _, none                => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.PENDING.DELETION.001
-- all: [kind=key, lifecycle.pending_deletion=true]
def evalKMSPendingDeletion (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.lifecycle.pending_deletion with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.LIFECYCLE.DORMANT.001
-- all: [kind=key, is_dormant=true]
def evalKMSDormant (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.is_dormant with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.LIFECYCLE.NOALIAS.001
-- all: [kind=key, lifecycle.has_alias=false]
def evalKMSNoAlias (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.lifecycle.has_alias with
    | some false => .«unsafe»
    | some true  => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.LIFECYCLE.CROSSENV.001
-- all: [kind=key, lifecycle.cross_env=true]
def evalKMSCrossEnv (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.lifecycle.cross_env with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.LIFECYCLE.ROTATION.PERIOD.001
-- all: [kind=key, lifecycle.rotation_enabled=true, lifecycle.rotation_period_compliant=false]
def evalKMSRotationPeriod (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.lifecycle.rotation_enabled with
    | some true =>
      match obs.lifecycle.rotation_period_compliant with
      | some false => .«unsafe»
      | some true  => .clear
      | none       => .unevaluable
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.ENTROPY.EXTERNAL.ORIGIN.001
-- all: [kind=key, is_aws_managed=false, origin=EXTERNAL]
def evalKMSEntropyExternal (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.is_aws_managed with
    | some false =>
      match obs.origin with
      | some "EXTERNAL" => .«unsafe»
      | some _          => .clear
      | none            => .unevaluable
    | some true => .clear
    | none      => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.FIPS.001
-- all: [kind=key, origin ne AWS_KMS]
def evalKMSFips (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.origin with
    | some "AWS_KMS" => .clear
    | some _         => .«unsafe»
    | none           => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.INCOMPLETE.001
-- all: [kind=key, policy.has_wildcard_principal missing true]
def evalKMSIncomplete (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.policy.has_wildcard_principal with
    | none   => .«unsafe»
    | some _ => .clear
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.SEPARATION.001
-- all: [kind=key, principal_has_admin_and_usage=true]
def evalKMSSeparation (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.principal_has_admin_and_usage with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- ===== KMS-P2: Policy controls (11 new) =====

-- CTL.KMS.POLICY.001
-- all: [kind=key, policy.has_wildcard_principal=true]
def evalKMSPolicyWildcard (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.policy.has_wildcard_principal with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.POLICY.ADMIN.BROAD.001
-- all: [kind=key, policy.admin_actions_broadly_granted=true]
def evalKMSPolicyAdminBroad (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.policy.admin_actions_broadly_granted with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.POLICY.CONDITION.001
-- all: [kind=key, policy.has_usage_conditions=false]
def evalKMSPolicyCondition (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.policy.has_usage_conditions with
    | some false => .«unsafe»
    | some true  => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.POLICY.CROSSACCOUNT.001
-- all: [kind=key, policy.has_broad_cross_account=true]
def evalKMSPolicyCrossAccount (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.policy.has_broad_cross_account with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.POLICY.DECRYPT.BROAD.001
-- all: [kind=key, is_aws_managed=false, policy.decrypt_broadly_granted=true]
def evalKMSPolicyDecryptBroad (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.is_aws_managed with
    | some false =>
      match obs.policy.decrypt_broadly_granted with
      | some true  => .«unsafe»
      | some false => .clear
      | none       => .unevaluable
    | some true => .clear
    | none      => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.POLICY.ENCLAVE.NOPCR.001
-- all: [kind=key, tags.enclave_protected=true, policy.enclave_attestation.has_pcr_condition=false]
def evalKMSPolicyEnclaveNoPcr (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.tags.enclave_protected with
    | some true =>
      match obs.enclave_attestation.has_pcr_condition with
      | some false => .«unsafe»
      | some true  => .clear
      | none       => .unevaluable
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.POLICY.GHOSTREF.001
-- all: [kind=key, policy.has_ghost_principal=true]
def evalKMSPolicyGhostRef (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.policy.has_ghost_principal with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.POLICY.GRANTWITHGRANT.001
-- all: [kind=key, policy.allows_grant_with_grant=true]
def evalKMSPolicyGrantWithGrant (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.policy.allows_grant_with_grant with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.POLICY.NOCONTEXT.001
-- all: [kind=key, policy.requires_encryption_context=false]
def evalKMSPolicyNoContext (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.policy.requires_encryption_context with
    | some false => .«unsafe»
    | some true  => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.POLICY.NOVIASERVICE.001
-- all: [kind=key, key_usage=ENCRYPT_DECRYPT, policy.has_via_service=false]
def evalKMSPolicyNoViaService (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.key_usage with
    | some "ENCRYPT_DECRYPT" =>
      match obs.policy.has_via_service with
      | some false => .«unsafe»
      | some true  => .clear
      | none       => .unevaluable
    | some _ => .clear
    | none   => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.POLICY.ROOT.PRINCIPAL.001
-- all: [kind=key, policy.has_root_principal_full_access=true]
def evalKMSPolicyRootPrincipal (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.policy.has_root_principal_full_access with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- ===== KMS-P3: Monitoring controls (8) =====

private def evalAlarmPresent (obs : KMSKeyObs) (alarmField : KMSAlarms → Option Bool) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match alarmField obs.alarms with
    | some false => .«unsafe»
    | some true  => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.ALARM.CREATEGRANT.001
def evalKMSAlarmCreateGrant (obs : KMSKeyObs) : EvalOutcome :=
  evalAlarmPresent obs (·.has_create_grant_alarm)

-- CTL.KMS.ALARM.CROSSACCOUNT.001
-- Compound: policy.has_cross_account_principal=true AND alarms.has_cross_account_alarm=false
def evalKMSAlarmCrossAccount (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.policy.has_cross_account_principal with
    | some true =>
      match obs.alarms.has_cross_account_alarm with
      | some false => .«unsafe»
      | some true  => .clear
      | none       => .unevaluable
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.ALARM.DECRYPT.FAILURE.001
def evalKMSAlarmDecryptFailure (obs : KMSKeyObs) : EvalOutcome :=
  evalAlarmPresent obs (·.has_decrypt_failure_alarm)

-- CTL.KMS.ALARM.DECRYPT.VOLUME.001
def evalKMSAlarmDecryptVolume (obs : KMSKeyObs) : EvalOutcome :=
  evalAlarmPresent obs (·.has_decrypt_volume_alarm)

-- CTL.KMS.ALARM.DELETION.001
def evalKMSAlarmDeletion (obs : KMSKeyObs) : EvalOutcome :=
  evalAlarmPresent obs (·.has_schedule_deletion_alarm)

-- CTL.KMS.ALARM.DISABLE.001
def evalKMSAlarmDisable (obs : KMSKeyObs) : EvalOutcome :=
  evalAlarmPresent obs (·.has_disable_key_alarm)

-- CTL.KMS.ALARM.POLICYCHANGE.001
def evalKMSAlarmPolicyChange (obs : KMSKeyObs) : EvalOutcome :=
  evalAlarmPresent obs (·.has_put_key_policy_alarm)

-- CTL.KMS.ALARM.ROTATION.FAILURE.001
def evalKMSAlarmRotationFailure (obs : KMSKeyObs) : EvalOutcome :=
  evalAlarmPresent obs (·.has_rotation_alarm)

-- ===== KMS-P4: Grant, Alias, and Remaining (20) =====

-- CTL.KMS.ALIAS.GHOST.001
-- all: [kind=alias, alias_is_ghost=true]
def evalKMSAliasGhost (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "alias" =>
    match obs.alias_is_ghost with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.ALIAS.ORPHAN.001
-- all: [kind=alias, alias_is_orphan=true]
def evalKMSAliasOrphan (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "alias" =>
    match obs.alias_is_orphan with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.CONCENTRATION.001
-- all: [kind=key, key_concentration.resource_count > 50]
def evalKMSConcentration001 (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.key_concentration.resource_count with
    | some n => if n > 50 then .«unsafe» else .clear
    | none   => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.CONCENTRATION.002
-- all: [kind=key, key_concentration.resource_count > 50, key_concentration.has_deletion_protection=false]
def evalKMSConcentration002 (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.key_concentration.resource_count with
    | some n =>
      if n > 50 then
        match obs.key_concentration.has_deletion_protection with
        | some false => .«unsafe»
        | some true  => .clear
        | none       => .unevaluable
      else .clear
    | none => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.CROSSACCOUNT.BLASTRADIUS.001
-- all: [kind=key, cross_account.excessive=true]
def evalKMSCrossAccountBlastRadius (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.cross_account.excessive with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.CROSSACCOUNT.DECOMMISSIONED.001
-- all: [kind=key, cross_account.has_decommissioned_account=true]
def evalKMSCrossAccountDecommissioned (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.cross_account.has_decommissioned_account with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.DELETION.MINWAIT.001
-- all: [kind=key, lifecycle.pending_deletion=true, lifecycle.deletion_wait_minimum=true]
def evalKMSDeletionMinWait (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.lifecycle.pending_deletion with
    | some true =>
      match obs.lifecycle.deletion_wait_minimum with
      | some true  => .«unsafe»
      | some false => .clear
      | none       => .unevaluable
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.GRANT.BROAD.001
-- all: [kind=key, grant_operations_excessive=true]
def evalKMSGrantBroad (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.grant_operations_excessive with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.GRANT.EXCESSIVE.001
-- all: [kind=key, has_excessive_grants=true]
def evalKMSGrantExcessive (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.has_excessive_grants with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.GRANT.EXTERNAL.001 (reads from properties.encryption.kms.grant.*)
-- all: [grantee_is_service_principal ne true, grantee_is_external_account=true]
def evalKMSGrantExternal (obs : KMSGrantObs) : EvalOutcome :=
  match obs.grantee_is_service_principal with
  | some true => .clear
  | some false =>
    match obs.grantee_is_external_account with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable
  | none =>
    match obs.grantee_is_external_account with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable

-- CTL.KMS.GRANT.ORPHAN.001
-- all: [kind=grant, grant_is_orphan=true]
def evalKMSGrantOrphan (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "grant" =>
    match obs.grant_is_orphan with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.GRANT.STALE.001
-- all: [kind=kms_key, rotation.enabled=true, grants.has_pre_rotation_grants=true]
def evalKMSGrantStale (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "kms_key" =>
    match obs.rotation_enabled with
    | some true =>
      match obs.grants.has_pre_rotation_grants with
      | some true  => .«unsafe»
      | some false => .clear
      | none       => .unevaluable
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.IMPORTED.EXPIRY.001
-- all: [kind=key, imported_material_no_expiry=true]
def evalKMSImportedExpiry (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.imported_material_no_expiry with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.MATERIAL.EXPIRED.001
-- all: [kind=key, imported_material_expired=true]
def evalKMSMaterialExpired (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.imported_material_expired with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.ISOLATION.001
-- all: [kms_key_id present, key_isolation.is_exclusive_to_domain=false]
def evalKMSIsolation (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kms_key_id with
  | some _ =>
    match obs.key_isolation_is_exclusive with
    | some false => .«unsafe»
    | some true  => .clear
    | none       => .unevaluable
  | none => .clear

-- CTL.KMS.MULTIREGION.NONCOMPLIANT.REGION.001
-- all: [kind=key, multi_region.is_multi_region=true, multi_region.has_noncompliant_replica=true]
def evalKMSMultiRegionNoncompliant (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.multi_region.is_multi_region with
    | some true =>
      match obs.multi_region.has_noncompliant_replica with
      | some true  => .«unsafe»
      | some false => .clear
      | none       => .unevaluable
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.MULTIREGION.NOREPLICA.001
-- all: [kind=key, multi_region.is_multi_region=true, multi_region.replica_count=0]
def evalKMSMultiRegionNoReplica (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.multi_region.is_multi_region with
    | some true =>
      match obs.multi_region.replica_count with
      | some 0 => .«unsafe»
      | some _ => .clear
      | none   => .unevaluable
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.MULTIREGION.POLICY.MISMATCH.001
-- all: [kind=key, multi_region.is_multi_region=true, multi_region.replica_policies_consistent=false]
def evalKMSMultiRegionPolicyMismatch (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.multi_region.is_multi_region with
    | some true =>
      match obs.multi_region.replica_policies_consistent with
      | some false => .«unsafe»
      | some true  => .clear
      | none       => .unevaluable
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.STATE.PENDINGDELETION.001
-- all: [kind=key, lifecycle.pending_deletion=true, dependent_resource_count > 0]
def evalKMSStatePendingDeletion (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.lifecycle.pending_deletion with
    | some true =>
      match obs.dependent_resource_count with
      | some n => if n > 0 then .«unsafe» else .clear
      | none   => .unevaluable
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

-- CTL.KMS.STATE.PENDINGIMPORT.001
-- all: [kind=key, is_pending_import=true]
def evalKMSStatePendingImport (obs : KMSKeyObs) : EvalOutcome :=
  match obs.kind with
  | some "key" =>
    match obs.is_pending_import with
    | some true  => .«unsafe»
    | some false => .clear
    | none       => .unevaluable
  | some _ => .clear
  | none   => .unevaluable

/-- Dispatch KMS control ID to evaluator. Unknown → unevaluable (fail-closed). -/
def evalKMSControl (ctrlId : ControlId) (obs : KMSKeyObs) : ControlResult :=
  let outcome := match ctrlId with
    | "CTL.KMS.ROTATION.001"                  => evalKMSRotation obs
    | "CTL.KMS.STATE.DISABLED.001"            => evalKMSStateDisabled obs
    | "CTL.KMS.DELETION.NOPROTECTION.001"     => evalKMSDeletionNoProtection obs
    | "CTL.KMS.PENDING.DELETION.001"          => evalKMSPendingDeletion obs
    | "CTL.KMS.LIFECYCLE.DORMANT.001"         => evalKMSDormant obs
    | "CTL.KMS.LIFECYCLE.NOALIAS.001"         => evalKMSNoAlias obs
    | "CTL.KMS.LIFECYCLE.CROSSENV.001"        => evalKMSCrossEnv obs
    | "CTL.KMS.LIFECYCLE.ROTATION.PERIOD.001" => evalKMSRotationPeriod obs
    | "CTL.KMS.ENTROPY.EXTERNAL.ORIGIN.001"   => evalKMSEntropyExternal obs
    | "CTL.KMS.FIPS.001"                      => evalKMSFips obs
    | "CTL.KMS.INCOMPLETE.001"                => evalKMSIncomplete obs
    | "CTL.KMS.SEPARATION.001"                => evalKMSSeparation obs
    | "CTL.KMS.POLICY.001"                    => evalKMSPolicyWildcard obs
    | "CTL.KMS.POLICY.ADMIN.BROAD.001"        => evalKMSPolicyAdminBroad obs
    | "CTL.KMS.POLICY.CONDITION.001"          => evalKMSPolicyCondition obs
    | "CTL.KMS.POLICY.CROSSACCOUNT.001"       => evalKMSPolicyCrossAccount obs
    | "CTL.KMS.POLICY.DECRYPT.BROAD.001"      => evalKMSPolicyDecryptBroad obs
    | "CTL.KMS.POLICY.ENCLAVE.NOPCR.001"      => evalKMSPolicyEnclaveNoPcr obs
    | "CTL.KMS.POLICY.GHOSTREF.001"           => evalKMSPolicyGhostRef obs
    | "CTL.KMS.POLICY.GRANTWITHGRANT.001"     => evalKMSPolicyGrantWithGrant obs
    | "CTL.KMS.POLICY.NOCONTEXT.001"          => evalKMSPolicyNoContext obs
    | "CTL.KMS.POLICY.NOVIASERVICE.001"       => evalKMSPolicyNoViaService obs
    | "CTL.KMS.POLICY.ROOT.PRINCIPAL.001"     => evalKMSPolicyRootPrincipal obs
    | "CTL.KMS.ALARM.CREATEGRANT.001"         => evalKMSAlarmCreateGrant obs
    | "CTL.KMS.ALARM.CROSSACCOUNT.001"        => evalKMSAlarmCrossAccount obs
    | "CTL.KMS.ALARM.DECRYPT.FAILURE.001"     => evalKMSAlarmDecryptFailure obs
    | "CTL.KMS.ALARM.DECRYPT.VOLUME.001"      => evalKMSAlarmDecryptVolume obs
    | "CTL.KMS.ALARM.DELETION.001"            => evalKMSAlarmDeletion obs
    | "CTL.KMS.ALARM.DISABLE.001"             => evalKMSAlarmDisable obs
    | "CTL.KMS.ALARM.POLICYCHANGE.001"        => evalKMSAlarmPolicyChange obs
    | "CTL.KMS.ALARM.ROTATION.FAILURE.001"    => evalKMSAlarmRotationFailure obs
    | "CTL.KMS.ALIAS.GHOST.001"              => evalKMSAliasGhost obs
    | "CTL.KMS.ALIAS.ORPHAN.001"             => evalKMSAliasOrphan obs
    | "CTL.KMS.CONCENTRATION.001"            => evalKMSConcentration001 obs
    | "CTL.KMS.CONCENTRATION.002"            => evalKMSConcentration002 obs
    | "CTL.KMS.CROSSACCOUNT.BLASTRADIUS.001" => evalKMSCrossAccountBlastRadius obs
    | "CTL.KMS.CROSSACCOUNT.DECOMMISSIONED.001" => evalKMSCrossAccountDecommissioned obs
    | "CTL.KMS.DELETION.MINWAIT.001"         => evalKMSDeletionMinWait obs
    | "CTL.KMS.GRANT.BROAD.001"              => evalKMSGrantBroad obs
    | "CTL.KMS.GRANT.EXCESSIVE.001"          => evalKMSGrantExcessive obs
    | "CTL.KMS.GRANT.ORPHAN.001"             => evalKMSGrantOrphan obs
    | "CTL.KMS.GRANT.STALE.001"              => evalKMSGrantStale obs
    | "CTL.KMS.IMPORTED.EXPIRY.001"          => evalKMSImportedExpiry obs
    | "CTL.KMS.MATERIAL.EXPIRED.001"         => evalKMSMaterialExpired obs
    | "CTL.KMS.ISOLATION.001"                => evalKMSIsolation obs
    | "CTL.KMS.MULTIREGION.NONCOMPLIANT.REGION.001" => evalKMSMultiRegionNoncompliant obs
    | "CTL.KMS.MULTIREGION.NOREPLICA.001"    => evalKMSMultiRegionNoReplica obs
    | "CTL.KMS.MULTIREGION.POLICY.MISMATCH.001" => evalKMSMultiRegionPolicyMismatch obs
    | "CTL.KMS.STATE.PENDINGDELETION.001"    => evalKMSStatePendingDeletion obs
    | "CTL.KMS.STATE.PENDINGIMPORT.001"      => evalKMSStatePendingImport obs
    | _ => EvalOutcome.unevaluable
  (ControlResult.mk ctrlId outcome : ControlResult)

/-- Dispatch KMS grant control ID. Only CTL.KMS.GRANT.EXTERNAL.001 uses KMSGrantObs. -/
def evalKMSGrantControl (ctrlId : ControlId) (obs : KMSGrantObs) : ControlResult :=
  let outcome := match ctrlId with
    | "CTL.KMS.GRANT.EXTERNAL.001" => evalKMSGrantExternal obs
    | _ => EvalOutcome.unevaluable
  (ControlResult.mk ctrlId outcome : ControlResult)
