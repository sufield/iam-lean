import Lean.Data.Json
import Stave.KMS.Eval

/-! FromJson instances for KMS observation types.
Parses obs.v0.1 asset JSON — navigates `properties.cryptography.*`. -/

open Lean (Json FromJson)

private def getOptBool (j : Json) (key : String) : Option Bool :=
  match j.getObjValAs? Bool key with
  | .ok v => some v
  | .error _ => none

private def getOptStr (j : Json) (key : String) : Option String :=
  match j.getObjValAs? String key with
  | .ok v => some v
  | .error _ => none

private def getOptNat (j : Json) (key : String) : Option Nat :=
  match j.getObjValAs? Nat key with
  | .ok v => some v
  | .error _ => none

private def getObj (j : Json) (key : String) : Json :=
  match j.getObjValAs? Json key with
  | .ok v => v
  | .error _ => .null

instance : FromJson KMSKeyObs where
  fromJson? j := do
    let props := getObj j "properties"
    let crypto := getObj props "cryptography"
    let alarms := getObj crypto "alarms"
    let delProt := getObj crypto "deletion_protection"
    let policy := getObj crypto "policy"
    let enclave := getObj policy "enclave_attestation"
    let conc := getObj crypto "key_concentration"
    let xacct := getObj crypto "cross_account"
    let lc := getObj crypto "lifecycle"
    let mr := getObj crypto "multi_region"
    let grnts := getObj crypto "grants"
    let tgs := getObj crypto "tags"
    let iso := getObj crypto "key_isolation"
    pure {
      kind                          := getOptStr  crypto "kind"
      key_rotation_enabled          := getOptBool crypto "key_rotation_enabled"
      is_disabled                   := getOptBool crypto "is_disabled"
      dependent_resource_count      := getOptNat  crypto "dependent_resource_count"
      is_aws_managed                := getOptBool crypto "is_aws_managed"
      origin                        := getOptStr  crypto "origin"
      is_dormant                    := getOptBool crypto "is_dormant"
      is_pending_import             := getOptBool crypto "is_pending_import"
      key_usage                     := getOptStr  crypto "key_usage"
      principal_has_admin_and_usage := getOptBool crypto "principal_has_admin_and_usage"
      grant_operations_excessive    := getOptBool crypto "grant_operations_excessive"
      has_excessive_grants          := getOptBool crypto "has_excessive_grants"
      grant_is_orphan               := getOptBool crypto "grant_is_orphan"
      imported_material_no_expiry   := getOptBool crypto "imported_material_no_expiry"
      imported_material_expired     := getOptBool crypto "imported_material_expired"
      alias_is_ghost                := getOptBool crypto "alias_is_ghost"
      alias_is_orphan               := getOptBool crypto "alias_is_orphan"
      kms_key_id                    := getOptStr  crypto "kms_key_id"
      key_isolation_is_exclusive    := getOptBool iso    "is_exclusive_to_domain"
      rotation_enabled              := getOptBool (getObj crypto "rotation") "enabled"
      alarms := {
        has_schedule_deletion_alarm := getOptBool alarms "has_schedule_deletion_alarm"
        has_create_grant_alarm      := getOptBool alarms "has_create_grant_alarm"
        has_cross_account_alarm     := getOptBool alarms "has_cross_account_alarm"
        has_decrypt_failure_alarm   := getOptBool alarms "has_decrypt_failure_alarm"
        has_decrypt_volume_alarm    := getOptBool alarms "has_decrypt_volume_alarm"
        has_disable_key_alarm       := getOptBool alarms "has_disable_key_alarm"
        has_put_key_policy_alarm    := getOptBool alarms "has_put_key_policy_alarm"
        has_rotation_alarm          := getOptBool alarms "has_rotation_alarm"
      }
      deletion_protection := {
        has_scp_deny := getOptBool delProt "has_scp_deny"
      }
      policy := {
        has_wildcard_principal        := getOptBool policy  "has_wildcard_principal"
        has_broad_cross_account       := getOptBool policy  "has_broad_cross_account"
        has_cross_account_principal   := getOptBool policy  "has_cross_account_principal"
        admin_actions_broadly_granted := getOptBool policy  "admin_actions_broadly_granted"
        has_usage_conditions          := getOptBool policy  "has_usage_conditions"
        decrypt_broadly_granted       := getOptBool policy  "decrypt_broadly_granted"
        has_ghost_principal           := getOptBool policy  "has_ghost_principal"
        allows_grant_with_grant       := getOptBool policy  "allows_grant_with_grant"
        requires_encryption_context   := getOptBool policy  "requires_encryption_context"
        has_via_service               := getOptBool policy  "has_via_service"
        has_root_principal_full_access := getOptBool policy "has_root_principal_full_access"
      }
      enclave_attestation := {
        has_pcr_condition := getOptBool enclave "has_pcr_condition"
      }
      key_concentration := {
        resource_count          := getOptNat  conc "resource_count"
        has_deletion_protection := getOptBool conc "has_deletion_protection"
      }
      cross_account := {
        excessive                  := getOptBool xacct "excessive"
        has_decommissioned_account := getOptBool xacct "has_decommissioned_account"
      }
      lifecycle := {
        cross_env                 := getOptBool lc "cross_env"
        has_alias                 := getOptBool lc "has_alias"
        rotation_enabled          := getOptBool lc "rotation_enabled"
        rotation_period_compliant := getOptBool lc "rotation_period_compliant"
        pending_deletion          := getOptBool lc "pending_deletion"
        deletion_wait_minimum     := getOptBool lc "deletion_wait_minimum"
      }
      multi_region := {
        is_multi_region             := getOptBool mr "is_multi_region"
        has_noncompliant_replica    := getOptBool mr "has_noncompliant_replica"
        replica_count               := getOptNat  mr "replica_count"
        replica_policies_consistent := getOptBool mr "replica_policies_consistent"
      }
      grants := {
        has_pre_rotation_grants := getOptBool grnts "has_pre_rotation_grants"
      }
      tags := {
        enclave_protected := getOptBool tgs "enclave-protected"
      }
    }

instance : FromJson KMSGrantObs where
  fromJson? j := do
    let props := getObj j "properties"
    let enc := getObj props "encryption"
    let kms := getObj enc "kms"
    let grant := getObj kms "grant"
    pure {
      kind                         := getOptStr  grant "kind"
      grantee_is_service_principal := getOptBool grant "grantee_is_service_principal"
      grantee_is_external_account  := getOptBool grant "grantee_is_external_account"
    }

instance : FromJson KMSTypedObs where
  fromJson? j := do
    let props := getObj j "properties"
    if (getObj props "cryptography") != .null then
      let obs ← @FromJson.fromJson? KMSKeyObs _ j
      pure (.key obs)
    else if (getObj (getObj (getObj props "encryption") "kms") "grant") != .null then
      let obs ← @FromJson.fromJson? KMSGrantObs _ j
      pure (.grant obs)
    else
      .error "no recognized KMS property bag in asset JSON"

-- Self-test: parse a minimal KMS key JSON
#guard
  let j := Json.mkObj [
    ("properties", Json.mkObj [
      ("cryptography", Json.mkObj [
        ("kind", "key"),
        ("key_rotation_enabled", false)
      ])
    ])
  ]
  match @FromJson.fromJson? KMSKeyObs _ j with
  | .ok obs => obs.kind == some "key" && obs.key_rotation_enabled == some false
  | .error _ => false
