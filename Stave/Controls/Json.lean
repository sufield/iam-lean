import Lean.Data.Json
import Stave.Controls.Eval
import Stave.KMS.Json

/-! FromJson instances for the 5 CH1 observation types.
Parses obs.v0.1 asset JSON — navigates nested properties to
populate the flat typed observation structures.

JSON field paths (from control YAML):
  CloudTrailObs:    properties.audit_trail.{kind,is_organization_trail,is_multi_region}
                    properties.trail.{log_file_validation_enabled}
  OrgSCPObs:        properties.organization.{kind,region_restriction.has_scp}
  IAMAccountObs:    properties.identity.{kind,root.mfa_enabled,root.has_access_keys}
  IAMUserObs:       properties.identity.{kind,console_access.enabled,console_access.mfa_enabled}
  SecurityGroupObs: properties.network.{kind,security_group.has_unrestricted_ingress}
-/

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

instance : FromJson CloudTrailObs where
  fromJson? j := do
    let props := getObj j "properties"
    let auditTrail := getObj props "audit_trail"
    let trail := getObj props "trail"
    pure {
      kind := getOptStr auditTrail "kind"
      is_organization_trail := getOptBool auditTrail "is_organization_trail"
      is_multi_region := getOptBool auditTrail "is_multi_region"
      log_file_validation_enabled := getOptBool trail "log_file_validation_enabled"
    }

instance : FromJson OrgSCPObs where
  fromJson? j := do
    let props := getObj j "properties"
    let org := getObj props "organization"
    let regionRestriction := getObj org "region_restriction"
    pure {
      kind := getOptStr org "kind"
      region_restriction_has_scp := getOptBool regionRestriction "has_scp"
    }

instance : FromJson IAMAccountObs where
  fromJson? j := do
    let props := getObj j "properties"
    let identity := getObj props "identity"
    let root := getObj identity "root"
    pure {
      kind := getOptStr identity "kind"
      root_mfa_enabled := getOptBool root "mfa_enabled"
      root_has_access_keys := getOptBool root "has_access_keys"
    }

instance : FromJson IAMUserObs where
  fromJson? j := do
    let props := getObj j "properties"
    let identity := getObj props "identity"
    let consoleAccess := getObj identity "console_access"
    let credentials := getObj identity "credentials"
    pure {
      kind := getOptStr identity "kind"
      console_access_enabled := getOptBool consoleAccess "enabled"
      console_access_mfa_enabled := getOptBool consoleAccess "mfa_enabled"
      credentials_unused_days := getOptNat credentials "unused_days"
    }

instance : FromJson SecurityGroupObs where
  fromJson? j := do
    let props := getObj j "properties"
    let network := getObj props "network"
    let sg := getObj network "security_group"
    pure {
      kind := getOptStr network "kind"
      has_unrestricted_ingress := getOptBool sg "has_unrestricted_ingress"
    }

instance : FromJson IAMSummaryObs where
  fromJson? j := do
    let props := getObj j "properties"
    let identity := getObj props "identity"
    pure {
      kind := getOptStr identity "kind"
      admin_user_count := getOptNat identity "admin_user_count"
    }

instance : FromJson CDNObs where
  fromJson? j := do
    let props := getObj j "properties"
    let cdn := getObj props "cdn"
    let cf := getObj cdn "cloudfront"
    pure {
      kind := getOptStr cdn "kind"
      signed_url_default_expiry_seconds := getOptNat cf "signed_url_default_expiry_seconds"
      viewer_cert_days_until_expiry := getOptNat cf "viewer_cert_days_until_expiry"
      waf_web_acl_id := getOptStr cdn "waf_web_acl_id"
      policy_referenced := getOptBool cf "policy_referenced"
    }

instance : FromJson VPCEndpointObs where
  fromJson? j := do
    let props := getObj j "properties"
    let network := getObj props "network"
    let endpoint := getObj network "vpc_endpoint"
    let policy := getObj network "endpoint_policy"
    pure {
      kind := getOptStr network "kind"
      service_name := getOptStr endpoint "service_name"
      restricts_to_org_resources := getOptBool policy "restricts_to_org_resources"
    }

instance : FromJson StorageObs where
  fromJson? j := do
    let props := getObj j "properties"
    let storage := getObj props "storage"
    let tags := getObj storage "tags"
    pure {
      kind := getOptStr storage "kind"
      data_classification := getOptStr tags "data-classification"
    }

-- ponytail: TypedObs FromJson dispatches by which property bag exists in the asset.
-- Upgrade to explicit asset_type matching if ambiguity arises.
instance : FromJson TypedObs where
  fromJson? j := do
    let props := getObj j "properties"
    if (getObj props "audit_trail") != .null || (getObj props "trail") != .null then
      let obs ← @FromJson.fromJson? CloudTrailObs _ j
      pure (.cloudtrail obs)
    else if (getObj props "organization") != .null then
      let obs ← @FromJson.fromJson? OrgSCPObs _ j
      pure (.orgSCP obs)
    else if (getObj props "cdn") != .null then
      let obs ← @FromJson.fromJson? CDNObs _ j
      pure (.cdn obs)
    else if (getObj props "storage") != .null then
      let obs ← @FromJson.fromJson? StorageObs _ j
      pure (.storage obs)
    else if (getObj props "network") != .null then
      let network := getObj props "network"
      let kind := getOptStr network "kind"
      match kind with
      | some "vpc_endpoint" =>
        let obs ← @FromJson.fromJson? VPCEndpointObs _ j
        pure (.vpcEndpoint obs)
      | _ =>
        let obs ← @FromJson.fromJson? SecurityGroupObs _ j
        pure (.securityGroup obs)
    else if (getObj props "identity") != .null then
      let identity := getObj props "identity"
      let kind := getOptStr identity "kind"
      match kind with
      | some "account" =>
        let obs ← @FromJson.fromJson? IAMAccountObs _ j
        pure (.iamAccount obs)
      | some "user" =>
        let obs ← @FromJson.fromJson? IAMUserObs _ j
        pure (.iamUser obs)
      | some "account_summary" =>
        let obs ← @FromJson.fromJson? IAMSummaryObs _ j
        pure (.iamSummary obs)
      | _ => .error s!"unknown identity kind: {kind}"
    else if (getObj props "cryptography") != .null then
      let obs ← @FromJson.fromJson? KMSKeyObs _ j
      pure (.kmsKey obs)
    else if (getObj (getObj (getObj props "encryption") "kms") "grant") != .null then
      let obs ← @FromJson.fromJson? KMSGrantObs _ j
      pure (.kmsGrant obs)
    else
      .error "no recognized property bag in asset JSON"

-- Self-test: parse a minimal asset JSON and check a field.
#guard
  let j := Json.mkObj [
    ("properties", Json.mkObj [
      ("audit_trail", Json.mkObj [
        ("kind", "trail"),
        ("is_organization_trail", false)
      ]),
      ("trail", Json.mkObj [
        ("log_file_validation_enabled", true)
      ])
    ])
  ]
  match @FromJson.fromJson? CloudTrailObs _ j with
  | .ok obs => obs.kind == some "trail" && obs.is_organization_trail == some false
  | .error _ => false

#guard
  let j := Json.mkObj [
    ("properties", Json.mkObj [
      ("network", Json.mkObj [
        ("kind", "security_group"),
        ("security_group", Json.mkObj [
          ("has_unrestricted_ingress", true)
        ])
      ])
    ])
  ]
  match @FromJson.fromJson? SecurityGroupObs _ j with
  | .ok obs => obs.has_unrestricted_ingress == some true
  | .error _ => false
