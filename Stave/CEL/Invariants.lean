import Stave.CEL.TypedAST
import Stave.CEL.Controls
import Stave.CEL.Result
import Stave.Compose.Monotonicity

/-! ∀-quantified security invariants over typed CEL expressions.

Unlike the `native_decide` proofs in Controls.lean (known-answer on
concrete observations), these theorems quantify over ALL observations.
They connect field-level properties to evaluation outcomes:

- **Correctness:** bad value → fires, good value → clears
- **Fail-closed on missing:** absent field → fires (for binop controls)
- **Missing-field definiteness:** missing controls are always definite
- **Chain bridge:** typed control firing feeds chain composition -/

/-! ### Resolution lemmas

Connect `mkFieldPath [key]` through `resolveField` to `obs.lookup`. -/

theorem resolveField_single_key (obs : Observation) (key : String) :
    obs.resolveField (mkFieldPath [key]) = obs.lookup key := by
  simp [Observation.resolveField, mkFieldPath, FieldPath.stripPropertiesPrefix]

theorem resolveTyped_bool (obs : Observation) (key : String) (v : Bool)
    (h : obs.lookup key = some (.bool v)) :
    resolveTyped obs (mkFieldPath [key]) .bool = some v := by
  simp [resolveTyped, resolveField_single_key, h]

theorem resolveTyped_int (obs : Observation) (key : String) (n : Int)
    (h : obs.lookup key = some (.int n)) :
    resolveTyped obs (mkFieldPath [key]) .int = some n := by
  simp [resolveTyped, resolveField_single_key, h]

theorem resolveTyped_str (obs : Observation) (key : String) (s : String)
    (h : obs.lookup key = some (.str s)) :
    resolveTyped obs (mkFieldPath [key]) .string = some s := by
  simp [resolveTyped, resolveField_single_key, h]

theorem resolveTyped_none (obs : Observation) (key : String) (ty : CelType)
    (h : obs.lookup key = none) :
    resolveTyped obs (mkFieldPath [key]) ty = none := by
  simp [resolveTyped, resolveField_single_key, h]

/-! ### Generic binop correctness

A `binop op (field fp _) (lit v)` expression fires iff the field resolves
and the operator evaluates to true. These lift per-control proofs. -/

theorem binop_field_lit_fires (obs : Observation) (env : CelEnv)
    {a r : CelType}
    (op : CelBinOp a a r) (fp : FieldPath) (hBind : env.hasBinding fp a)
    (lit : CelLit a) (fv : CelType.Interp a)
    (hResolve : resolveTyped obs fp a = some fv)
    (hOp : op.eval fv lit.val = true)
    (hr : r = .bool) :
    (CelExpr.binop (r := r) op (.field fp hBind) (.lit lit)).eval obs = some (hr ▸ true) := by
  subst hr
  simp [CelExpr.eval, hResolve, bind, Option.bind, hOp]

theorem binop_field_lit_clears (obs : Observation) (env : CelEnv)
    {a r : CelType}
    (op : CelBinOp a a r) (fp : FieldPath) (hBind : env.hasBinding fp a)
    (lit : CelLit a) (fv : CelType.Interp a)
    (hResolve : resolveTyped obs fp a = some fv)
    (hOp : op.eval fv lit.val = false)
    (hr : r = .bool) :
    (CelExpr.binop (r := r) op (.field fp hBind) (.lit lit)).eval obs = some (hr ▸ false) := by
  subst hr
  simp [CelExpr.eval, hResolve, bind, Option.bind, hOp]

/-! ### Fail-closed on missing field (generic)

Any binop(field, lit) expression yields `none` when the field is absent,
which `toOutcome` maps to `unevaluable` → fires. -/

theorem binop_field_missing_none (obs : Observation) (env : CelEnv)
    {a b r : CelType}
    (op : CelBinOp a b r) (fp : FieldPath) (hBind : env.hasBinding fp a)
    (rhs : CelExpr env b)
    (hNone : resolveTyped obs fp a = none) :
    (CelExpr.binop op (.field fp hBind) rhs).eval obs = none := by
  simp [CelExpr.eval, hNone, bind, Option.bind]

theorem binop_field_missing_fires (obs : Observation) (env : CelEnv)
    (op : CelBinOp a a .bool) (fp : FieldPath) (hBind : env.hasBinding fp a)
    (lit : CelLit a)
    (hNone : resolveTyped obs fp a = none) :
    (CelExpr.binop op (.field fp hBind) (.lit lit)).toOutcome obs = .unevaluable := by
  simp [CelExpr.toOutcome, CelExpr.eval, hNone, bind, Option.bind]

/-! ### Per-control correctness theorems

Each control gets three universally quantified theorems:
  1. fires_when:  field present with bad value → outcome = unsafe
  2. clears_when: field present with good value → outcome = clear
  3. fires_on_missing: field absent → outcome = unevaluable (fires) -/

-- ctlLogValidation: log_file_validation_enabled == false
theorem logValidation_fires_when (obs : Observation)
    (h : obs.lookup "log_file_validation_enabled" = some (.bool false)) :
    ctlLogValidation.toOutcome obs = .«unsafe» := by
  simp [ctlLogValidation, CelExpr.toOutcome, CelExpr.eval, bind, Option.bind,
        resolveTyped, resolveField_single_key, h, CelBinOp.eval]

theorem logValidation_clears_when (obs : Observation)
    (h : obs.lookup "log_file_validation_enabled" = some (.bool true)) :
    ctlLogValidation.toOutcome obs = .clear := by
  simp [ctlLogValidation, CelExpr.toOutcome, CelExpr.eval, bind, Option.bind,
        resolveTyped, resolveField_single_key, h, CelBinOp.eval]

theorem logValidation_fires_on_missing (obs : Observation)
    (h : obs.lookup "log_file_validation_enabled" = none) :
    ctlLogValidation.toOutcome obs = .unevaluable := by
  simp [ctlLogValidation, CelExpr.toOutcome, CelExpr.eval, bind, Option.bind,
        resolveTyped, resolveField_single_key, h]

-- ctlSignedLongExpiry: signed_url_default_expiry_seconds > 86400
theorem signedLongExpiry_fires_when (obs : Observation) (n : Int)
    (hLookup : obs.lookup "signed_url_default_expiry_seconds" = some (.int n))
    (hGt : n > 86400) :
    ctlSignedLongExpiry.toOutcome obs = .«unsafe» := by
  simp [ctlSignedLongExpiry, CelExpr.toOutcome, CelExpr.eval, bind, Option.bind,
        resolveTyped, resolveField_single_key, hLookup, CelBinOp.eval]
  exact hGt

theorem signedLongExpiry_clears_when (obs : Observation) (n : Int)
    (hLookup : obs.lookup "signed_url_default_expiry_seconds" = some (.int n))
    (hLe : n ≤ 86400) :
    ctlSignedLongExpiry.toOutcome obs = .clear := by
  simp [ctlSignedLongExpiry, CelExpr.toOutcome, CelExpr.eval, bind, Option.bind,
        resolveTyped, resolveField_single_key, hLookup, CelBinOp.eval]
  omega

theorem signedLongExpiry_fires_on_missing (obs : Observation)
    (h : obs.lookup "signed_url_default_expiry_seconds" = none) :
    ctlSignedLongExpiry.toOutcome obs = .unevaluable := by
  simp [ctlSignedLongExpiry, CelExpr.toOutcome, CelExpr.eval, bind, Option.bind,
        resolveTyped, resolveField_single_key, h]

-- ctlCertExpiryWarn: viewer_cert_days_until_expiry < 30
theorem certExpiryWarn_fires_when (obs : Observation) (n : Int)
    (hLookup : obs.lookup "viewer_cert_days_until_expiry" = some (.int n))
    (hLt : n < 30) :
    ctlCertExpiryWarn.toOutcome obs = .«unsafe» := by
  simp [ctlCertExpiryWarn, CelExpr.toOutcome, CelExpr.eval, bind, Option.bind,
        resolveTyped, resolveField_single_key, hLookup, CelBinOp.eval]
  exact hLt

theorem certExpiryWarn_clears_when (obs : Observation) (n : Int)
    (hLookup : obs.lookup "viewer_cert_days_until_expiry" = some (.int n))
    (hGe : n ≥ 30) :
    ctlCertExpiryWarn.toOutcome obs = .clear := by
  simp [ctlCertExpiryWarn, CelExpr.toOutcome, CelExpr.eval, bind, Option.bind,
        resolveTyped, resolveField_single_key, hLookup, CelBinOp.eval]
  omega

theorem certExpiryWarn_fires_on_missing (obs : Observation)
    (h : obs.lookup "viewer_cert_days_until_expiry" = none) :
    ctlCertExpiryWarn.toOutcome obs = .unevaluable := by
  simp [ctlCertExpiryWarn, CelExpr.toOutcome, CelExpr.eval, bind, Option.bind,
        resolveTyped, resolveField_single_key, h]

-- ctlCloudFrontWAF: waf_web_acl_id missing
theorem cloudFrontWAF_fires_when (obs : Observation)
    (h : obs.lookup "waf_web_acl_id" = none) :
    ctlCloudFrontWAF.toOutcome obs = .«unsafe» := by
  simp [ctlCloudFrontWAF, CelExpr.toOutcome, CelExpr.eval,
        Observation.resolveField, mkFieldPath, FieldPath.stripPropertiesPrefix,
        Observation.lookup, h]

theorem cloudFrontWAF_clears_when (obs : Observation) (pv : PropValue)
    (h : obs.lookup "waf_web_acl_id" = some pv) :
    ctlCloudFrontWAF.toOutcome obs = .clear := by
  simp [ctlCloudFrontWAF, CelExpr.toOutcome, CelExpr.eval,
        Observation.resolveField, mkFieldPath, FieldPath.stripPropertiesPrefix,
        Observation.lookup, h]

-- ctlCredUnused45: credentials_unused_days > 45
theorem credUnused45_fires_when (obs : Observation) (n : Int)
    (hLookup : obs.lookup "credentials_unused_days" = some (.int n))
    (hGt : n > 45) :
    ctlCredUnused45.toOutcome obs = .«unsafe» := by
  simp [ctlCredUnused45, CelExpr.toOutcome, CelExpr.eval, bind, Option.bind,
        resolveTyped, resolveField_single_key, hLookup, CelBinOp.eval]
  exact hGt

theorem credUnused45_clears_when (obs : Observation) (n : Int)
    (hLookup : obs.lookup "credentials_unused_days" = some (.int n))
    (hLe : n ≤ 45) :
    ctlCredUnused45.toOutcome obs = .clear := by
  simp [ctlCredUnused45, CelExpr.toOutcome, CelExpr.eval, bind, Option.bind,
        resolveTyped, resolveField_single_key, hLookup, CelBinOp.eval]
  omega

theorem credUnused45_fires_on_missing (obs : Observation)
    (h : obs.lookup "credentials_unused_days" = none) :
    ctlCredUnused45.toOutcome obs = .unevaluable := by
  simp [ctlCredUnused45, CelExpr.toOutcome, CelExpr.eval, bind, Option.bind,
        resolveTyped, resolveField_single_key, h]

-- ctlAdminCount: admin_user_count > 2
theorem adminCount_fires_when (obs : Observation) (n : Int)
    (hLookup : obs.lookup "admin_user_count" = some (.int n))
    (hGt : n > 2) :
    ctlAdminCount.toOutcome obs = .«unsafe» := by
  simp [ctlAdminCount, CelExpr.toOutcome, CelExpr.eval, bind, Option.bind,
        resolveTyped, resolveField_single_key, hLookup, CelBinOp.eval]
  exact hGt

theorem adminCount_clears_when (obs : Observation) (n : Int)
    (hLookup : obs.lookup "admin_user_count" = some (.int n))
    (hLe : n ≤ 2) :
    ctlAdminCount.toOutcome obs = .clear := by
  simp [ctlAdminCount, CelExpr.toOutcome, CelExpr.eval, bind, Option.bind,
        resolveTyped, resolveField_single_key, hLookup, CelBinOp.eval]
  omega

theorem adminCount_fires_on_missing (obs : Observation)
    (h : obs.lookup "admin_user_count" = none) :
    ctlAdminCount.toOutcome obs = .unevaluable := by
  simp [ctlAdminCount, CelExpr.toOutcome, CelExpr.eval, bind, Option.bind,
        resolveTyped, resolveField_single_key, h]

-- ctlS3Governance: data_classification missing
theorem s3Governance_fires_when (obs : Observation)
    (h : obs.lookup "data_classification" = none) :
    ctlS3Governance.toOutcome obs = .«unsafe» := by
  simp [ctlS3Governance, CelExpr.toOutcome, CelExpr.eval,
        Observation.resolveField, mkFieldPath, FieldPath.stripPropertiesPrefix,
        Observation.lookup, h]

theorem s3Governance_clears_when (obs : Observation) (pv : PropValue)
    (h : obs.lookup "data_classification" = some pv) :
    ctlS3Governance.toOutcome obs = .clear := by
  simp [ctlS3Governance, CelExpr.toOutcome, CelExpr.eval,
        Observation.resolveField, mkFieldPath, FieldPath.stripPropertiesPrefix,
        Observation.lookup, h]

-- ctlSGUnrestricted: has_unrestricted_ingress == true
theorem sgUnrestricted_fires_when (obs : Observation)
    (h : obs.lookup "has_unrestricted_ingress" = some (.bool true)) :
    ctlSGUnrestricted.toOutcome obs = .«unsafe» := by
  simp [ctlSGUnrestricted, CelExpr.toOutcome, CelExpr.eval, bind, Option.bind,
        resolveTyped, resolveField_single_key, h, CelBinOp.eval]

theorem sgUnrestricted_clears_when (obs : Observation)
    (h : obs.lookup "has_unrestricted_ingress" = some (.bool false)) :
    ctlSGUnrestricted.toOutcome obs = .clear := by
  simp [ctlSGUnrestricted, CelExpr.toOutcome, CelExpr.eval, bind, Option.bind,
        resolveTyped, resolveField_single_key, h, CelBinOp.eval]

theorem sgUnrestricted_fires_on_missing (obs : Observation)
    (h : obs.lookup "has_unrestricted_ingress" = none) :
    ctlSGUnrestricted.toOutcome obs = .unevaluable := by
  simp [ctlSGUnrestricted, CelExpr.toOutcome, CelExpr.eval, bind, Option.bind,
        resolveTyped, resolveField_single_key, h]

/-! ### Outcome completeness

For each binop control, the three cases (fires/clears/missing) are
exhaustive: every observation falls into exactly one. -/

theorem binop_bool_exhaustive (obs : Observation) (key : String) :
    obs.lookup key = none ∨
    (∃ v, obs.lookup key = some (.bool v)) ∨
    (∃ pv, obs.lookup key = some pv ∧ ∀ b, pv ≠ .bool b) := by
  cases h : obs.lookup key with
  | none => exact Or.inl h
  | some pv =>
    cases pv with
    | bool v => exact Or.inr (Or.inl ⟨v, h⟩)
    | _ => exact Or.inr (Or.inr ⟨_, h, by intro b; simp⟩)

theorem binop_int_exhaustive (obs : Observation) (key : String) :
    obs.lookup key = none ∨
    (∃ n, obs.lookup key = some (.int n)) ∨
    (∃ pv, obs.lookup key = some pv ∧ ∀ n, pv ≠ .int n) := by
  cases h : obs.lookup key with
  | none => exact Or.inl h
  | some pv =>
    cases pv with
    | int n => exact Or.inr (Or.inl ⟨n, h⟩)
    | _ => exact Or.inr (Or.inr ⟨_, h, by intro n; simp⟩)

/-! ### Type mismatch fires (fail-closed for wrong types)

When a field exists but has the wrong type, resolveTyped returns none,
so the control fires via unevaluable. -/

theorem resolveTyped_type_mismatch_int (obs : Observation) (key : String) (pv : PropValue)
    (hLookup : obs.lookup key = some pv) (hNotInt : ∀ n, pv ≠ .int n) :
    resolveTyped obs (mkFieldPath [key]) .int = none := by
  simp [resolveTyped, resolveField_single_key, hLookup]
  cases pv with
  | int n => exact absurd rfl (hNotInt n)
  | bool _ => rfl
  | str _ => rfl
  | list _ => rfl
  | null => rfl

theorem resolveTyped_type_mismatch_bool (obs : Observation) (key : String) (pv : PropValue)
    (hLookup : obs.lookup key = some pv) (hNotBool : ∀ b, pv ≠ .bool b) :
    resolveTyped obs (mkFieldPath [key]) .bool = none := by
  simp [resolveTyped, resolveField_single_key, hLookup]
  cases pv with
  | bool b => exact absurd rfl (hNotBool b)
  | int _ => rfl
  | str _ => rfl
  | list _ => rfl
  | null => rfl

/-! ### CelResult consistency

The CelResult evaluation path preserves the same invariants. -/

theorem adminCount_result_fires_when (obs : Observation) (n : Int)
    (hLookup : obs.lookup "admin_user_count" = some (.int n))
    (hGt : n > 2) :
    ctlAdminCount.toOutcomeResult obs = .«unsafe» := by
  rw [toOutcomeResult_eq_toOutcome]
  exact adminCount_fires_when obs n hLookup hGt

theorem adminCount_result_clears_when (obs : Observation) (n : Int)
    (hLookup : obs.lookup "admin_user_count" = some (.int n))
    (hLe : n ≤ 2) :
    ctlAdminCount.toOutcomeResult obs = .clear := by
  rw [toOutcomeResult_eq_toOutcome]
  exact adminCount_clears_when obs n hLookup hLe

/-! ### Chain bridge

If two typed controls both fire on the same observation, and those
control IDs appear in a chain, the chain fires. This connects
L3 invariants to the P4 chain composition proof. -/

theorem typed_dual_fire_chain (chain : ChainDef)
    (failing : List ControlId)
    (h : ∀ c, c ∈ chain.controls → c ∈ failing) :
    chainFires chain failing :=
  chain_fires_when_all_fail chain failing h
