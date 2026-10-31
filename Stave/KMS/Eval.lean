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
    | _ => EvalOutcome.unevaluable
  (ControlResult.mk ctrlId outcome : ControlResult)
