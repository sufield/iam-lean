import Stave.CEL.TypedAST

/-! Typed CEL expressions for existing CH1/CH2 controls.

Each control's CEL predicate is encoded as a `CelExpr` over a typed
environment. The type indices guarantee that the predicate is well-typed
— e.g., `> 86400` can only be applied to an int field.

These are parallel to the hand-written evaluators in Controls/Eval.lean.
The `erase` function recovers the untyped PredicateRule for comparison. -/

def mkFieldPath (parts : List String) (h : parts.length > 0 := by decide) : FieldPath :=
  ⟨parts, h⟩

/-! ### Typed environments for each observation domain -/

def cloudTrailEnv : CelEnv := CelEnv.empty
  |>.bind (mkFieldPath ["kind"]) .string
  |>.bind (mkFieldPath ["is_organization_trail"]) .bool
  |>.bind (mkFieldPath ["is_multi_region"]) .bool
  |>.bind (mkFieldPath ["log_file_validation_enabled"]) .bool

def iamAccountEnv : CelEnv := CelEnv.empty
  |>.bind (mkFieldPath ["kind"]) .string
  |>.bind (mkFieldPath ["root_mfa_enabled"]) .bool
  |>.bind (mkFieldPath ["root_has_access_keys"]) .bool

def iamUserEnv : CelEnv := CelEnv.empty
  |>.bind (mkFieldPath ["kind"]) .string
  |>.bind (mkFieldPath ["console_access_enabled"]) .bool
  |>.bind (mkFieldPath ["console_access_mfa_enabled"]) .bool
  |>.bind (mkFieldPath ["credentials_unused_days"]) .int

def orgSCPEnv : CelEnv := CelEnv.empty
  |>.bind (mkFieldPath ["kind"]) .string
  |>.bind (mkFieldPath ["region_restriction_has_scp"]) .bool

def sgEnv : CelEnv := CelEnv.empty
  |>.bind (mkFieldPath ["kind"]) .string
  |>.bind (mkFieldPath ["has_unrestricted_ingress"]) .bool

def cdnEnv : CelEnv := CelEnv.empty
  |>.bind (mkFieldPath ["kind"]) .string
  |>.bind (mkFieldPath ["signed_url_default_expiry_seconds"]) .int
  |>.bind (mkFieldPath ["viewer_cert_days_until_expiry"]) .int
  |>.bind (mkFieldPath ["waf_web_acl_id"]) .string
  |>.bind (mkFieldPath ["policy_referenced"]) .bool

def vpcEndpointEnv : CelEnv := CelEnv.empty
  |>.bind (mkFieldPath ["kind"]) .string
  |>.bind (mkFieldPath ["service_name"]) .string
  |>.bind (mkFieldPath ["restricts_to_org_resources"]) .bool

def iamSummaryEnv : CelEnv := CelEnv.empty
  |>.bind (mkFieldPath ["kind"]) .string
  |>.bind (mkFieldPath ["admin_user_count"]) .int

def storageEnv : CelEnv := CelEnv.empty
  |>.bind (mkFieldPath ["kind"]) .string
  |>.bind (mkFieldPath ["data_classification"]) .string

/-! ### Typed control expressions

Each expression is a `CelExpr env .bool` — a boolean-valued predicate
over the typed environment. The constructors enforce type safety:
`gtInt` only accepts int fields, `eqStr` only accepts string fields. -/

private def kindField : FieldPath := mkFieldPath ["kind"]
private def isOrgTrailField : FieldPath := mkFieldPath ["is_organization_trail"]
private def isMultiRegionField : FieldPath := mkFieldPath ["is_multi_region"]
private def logValField : FieldPath := mkFieldPath ["log_file_validation_enabled"]
private def rootMfaField : FieldPath := mkFieldPath ["root_mfa_enabled"]
private def rootKeysField : FieldPath := mkFieldPath ["root_has_access_keys"]
private def consoleMfaField : FieldPath := mkFieldPath ["console_access_mfa_enabled"]
private def consoleEnabledField : FieldPath := mkFieldPath ["console_access_enabled"]
private def credUnusedField : FieldPath := mkFieldPath ["credentials_unused_days"]
private def regionSCPField : FieldPath := mkFieldPath ["region_restriction_has_scp"]
private def sgUnrestrictedField : FieldPath := mkFieldPath ["has_unrestricted_ingress"]
private def expirySecsField : FieldPath := mkFieldPath ["signed_url_default_expiry_seconds"]
private def certDaysField : FieldPath := mkFieldPath ["viewer_cert_days_until_expiry"]
private def wafAclField : FieldPath := mkFieldPath ["waf_web_acl_id"]
private def policyRefField : FieldPath := mkFieldPath ["policy_referenced"]
private def serviceNameField : FieldPath := mkFieldPath ["service_name"]
private def restrictsOrgField : FieldPath := mkFieldPath ["restricts_to_org_resources"]
private def adminCountField : FieldPath := mkFieldPath ["admin_user_count"]
private def dataClassField : FieldPath := mkFieldPath ["data_classification"]

-- CTL.CLOUDTRAIL.LOG.VALIDATION.001: log_file_validation_enabled == false
def ctlLogValidation : CelExpr cloudTrailEnv .bool :=
  .binop .eqBool
    (.field logValField (by native_decide))
    (.lit (.bool false))

-- CTL.CLOUDFRONT.ACCESS.SIGNED.LONG.EXPIRY.001: signed_url_default_expiry_seconds > 86400
def ctlSignedLongExpiry : CelExpr cdnEnv .bool :=
  .binop .gtInt
    (.field expirySecsField (by native_decide))
    (.lit (.int 86400))

-- CTL.CLOUDFRONT.VIEWER.CERT.EXPIRY.WARN.001: viewer_cert_days_until_expiry < 30
def ctlCertExpiryWarn : CelExpr cdnEnv .bool :=
  .binop .ltInt
    (.field certDaysField (by native_decide))
    (.lit (.int 30))

-- CTL.CLOUDFRONT.WAF.001: waf_web_acl_id missing
def ctlCloudFrontWAF : CelExpr cdnEnv .bool :=
  .missing wafAclField

-- CTL.IAM.CRED.UNUSED45.001: credentials.unused_days > 45
def ctlCredUnused45 : CelExpr iamUserEnv .bool :=
  .binop .gtInt
    (.field credUnusedField (by native_decide))
    (.lit (.int 45))

-- CTL.IAM.ADMIN.COUNT.001: admin_user_count > 2
def ctlAdminCount : CelExpr iamSummaryEnv .bool :=
  .binop .gtInt
    (.field adminCountField (by native_decide))
    (.lit (.int 2))

-- CTL.S3.GOVERNANCE.001: data_classification missing
def ctlS3Governance : CelExpr storageEnv .bool :=
  .missing dataClassField

-- CTL.VPC.SG.UNRESTRICTED.001: has_unrestricted_ingress == true
def ctlSGUnrestricted : CelExpr sgEnv .bool :=
  .binop .eqBool
    (.field sgUnrestrictedField (by native_decide))
    (.lit (.bool true))

/-! ### Type safety proofs: ill-typed predicates are rejected

These non-examples would fail to compile if uncommented,
demonstrating that the AST rejects type errors statically:

-- ERROR: gtInt requires int fields, not bool
-- def bad1 : CelExpr cloudTrailEnv .bool :=
--   .binop .gtInt
--     (.field isOrgTrailField (by native_decide))  -- bool field
--     (.lit (.int 5))                                -- int literal

-- ERROR: containsStr requires string fields, not int
-- def bad2 : CelExpr cdnEnv .bool :=
--   .binop .containsStr
--     (.field expirySecsField (by native_decide))   -- int field
--     (.lit (.string "kms"))                          -- string literal
-/

/-! ### Proofs: typed controls on conforming observations never unevaluable -/

-- Proving: if an observation conforms to cdnEnv, ctlSignedLongExpiry
-- always evaluates to either unsafe or clear, never unevaluable.
theorem signedLongExpiry_no_unevaluable (obs : Observation)
    (hConf : ObservationConforms obs cdnEnv) :
    ctlSignedLongExpiry.toOutcome obs ≠ .unevaluable :=
  no_unevaluable_on_conforming obs cdnEnv hConf ctlSignedLongExpiry

theorem certExpiryWarn_no_unevaluable (obs : Observation)
    (hConf : ObservationConforms obs cdnEnv) :
    ctlCertExpiryWarn.toOutcome obs ≠ .unevaluable :=
  no_unevaluable_on_conforming obs cdnEnv hConf ctlCertExpiryWarn

theorem logValidation_no_unevaluable (obs : Observation)
    (hConf : ObservationConforms obs cloudTrailEnv) :
    ctlLogValidation.toOutcome obs ≠ .unevaluable :=
  no_unevaluable_on_conforming obs cloudTrailEnv hConf ctlLogValidation

theorem credUnused45_no_unevaluable (obs : Observation)
    (hConf : ObservationConforms obs iamUserEnv) :
    ctlCredUnused45.toOutcome obs ≠ .unevaluable :=
  no_unevaluable_on_conforming obs iamUserEnv hConf ctlCredUnused45

theorem adminCount_no_unevaluable (obs : Observation)
    (hConf : ObservationConforms obs iamSummaryEnv) :
    ctlAdminCount.toOutcome obs ≠ .unevaluable :=
  no_unevaluable_on_conforming obs iamSummaryEnv hConf ctlAdminCount

-- Missing-field controls are ALWAYS definite (don't even need conformance).
theorem cloudFrontWAF_always_definite (obs : Observation) :
    ctlCloudFrontWAF.toOutcome obs ≠ .unevaluable :=
  missing_never_unevaluable obs wafAclField

theorem s3Governance_always_definite (obs : Observation) :
    ctlS3Governance.toOutcome obs ≠ .unevaluable :=
  missing_never_unevaluable obs dataClassField

theorem sgUnrestricted_no_unevaluable (obs : Observation)
    (hConf : ObservationConforms obs sgEnv) :
    ctlSGUnrestricted.toOutcome obs ≠ .unevaluable :=
  no_unevaluable_on_conforming obs sgEnv hConf ctlSGUnrestricted
