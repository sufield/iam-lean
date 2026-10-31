import Stave.Evaluate.Observation
import Stave.Basic.Finding

/-! Typed observation structures for all 51 KMS controls.
All controls read from `properties.cryptography.*` except
CTL.KMS.GRANT.EXTERNAL.001 which reads `properties.encryption.kms.grant.*`.
Every leaf field is Option — fail-closed by construction. -/

structure KMSAlarms where
  has_schedule_deletion_alarm : Option Bool := none
  has_create_grant_alarm      : Option Bool := none
  has_cross_account_alarm     : Option Bool := none
  has_decrypt_failure_alarm   : Option Bool := none
  has_decrypt_volume_alarm    : Option Bool := none
  has_disable_key_alarm       : Option Bool := none
  has_put_key_policy_alarm    : Option Bool := none
  has_rotation_alarm          : Option Bool := none
  deriving Repr, BEq

structure KMSDeletionProtection where
  has_scp_deny : Option Bool := none
  deriving Repr, BEq

structure KMSPolicy where
  has_wildcard_principal        : Option Bool := none
  has_broad_cross_account       : Option Bool := none
  has_cross_account_principal   : Option Bool := none
  admin_actions_broadly_granted : Option Bool := none
  has_usage_conditions          : Option Bool := none
  decrypt_broadly_granted       : Option Bool := none
  has_ghost_principal           : Option Bool := none
  allows_grant_with_grant       : Option Bool := none
  requires_encryption_context   : Option Bool := none
  has_via_service               : Option Bool := none
  has_root_principal_full_access : Option Bool := none
  deriving Repr, BEq

structure KMSEnclaveAttestation where
  has_pcr_condition : Option Bool := none
  deriving Repr, BEq

structure KMSKeyConcentration where
  resource_count          : Option Nat := none
  has_deletion_protection : Option Bool := none
  deriving Repr, BEq

structure KMSCrossAccount where
  excessive                  : Option Bool := none
  has_decommissioned_account : Option Bool := none
  deriving Repr, BEq

structure KMSLifecycle where
  cross_env                 : Option Bool := none
  has_alias                 : Option Bool := none
  rotation_enabled          : Option Bool := none
  rotation_period_compliant : Option Bool := none
  pending_deletion          : Option Bool := none
  deletion_wait_minimum     : Option Bool := none
  deriving Repr, BEq

structure KMSMultiRegion where
  is_multi_region             : Option Bool := none
  has_noncompliant_replica    : Option Bool := none
  replica_count               : Option Nat := none
  replica_policies_consistent : Option Bool := none
  deriving Repr, BEq

structure KMSGrants where
  has_pre_rotation_grants : Option Bool := none
  deriving Repr, BEq

structure KMSTags where
  enclave_protected : Option Bool := none
  deriving Repr, BEq

/-- KMS key observation — full `properties.cryptography.*` surface for all 51 controls. -/
structure KMSKeyObs where
  kind                          : Option String := none
  key_rotation_enabled          : Option Bool   := none
  is_disabled                   : Option Bool   := none
  dependent_resource_count      : Option Nat    := none
  is_aws_managed                : Option Bool   := none
  origin                        : Option String := none
  is_dormant                    : Option Bool   := none
  is_pending_import             : Option Bool   := none
  key_usage                     : Option String := none
  principal_has_admin_and_usage : Option Bool   := none
  grant_operations_excessive    : Option Bool   := none
  has_excessive_grants          : Option Bool   := none
  grant_is_orphan               : Option Bool   := none
  imported_material_no_expiry   : Option Bool   := none
  imported_material_expired     : Option Bool   := none
  alias_is_ghost                : Option Bool   := none
  alias_is_orphan               : Option Bool   := none
  kms_key_id                    : Option String := none
  key_isolation_is_exclusive    : Option Bool   := none
  rotation_enabled              : Option Bool   := none
  alarms                        : KMSAlarms              := {}
  deletion_protection           : KMSDeletionProtection   := {}
  policy                        : KMSPolicy               := {}
  enclave_attestation           : KMSEnclaveAttestation   := {}
  key_concentration             : KMSKeyConcentration     := {}
  cross_account                 : KMSCrossAccount         := {}
  lifecycle                     : KMSLifecycle            := {}
  multi_region                  : KMSMultiRegion          := {}
  grants                        : KMSGrants               := {}
  tags                          : KMSTags                 := {}
  deriving Repr, BEq

/-- Grant observation for CTL.KMS.GRANT.EXTERNAL.001 (reads `properties.encryption.kms.grant.*`). -/
structure KMSGrantObs where
  kind                         : Option String := none
  grantee_is_service_principal : Option Bool   := none
  grantee_is_external_account  : Option Bool   := none
  deriving Repr, BEq

/-- Dispatch envelope for KMS observations. -/
inductive KMSTypedObs where
  | key (obs : KMSKeyObs)
  | grant (obs : KMSGrantObs)
  deriving Repr
