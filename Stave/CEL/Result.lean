import Stave.CEL.TypedAST

/-! CelResult — tri-state evaluation with error provenance.

Enriches `EvalOutcome` by tracking WHY evaluation failed: which field
was missing, what type mismatch occurred. `CelResult.fires` preserves
the existing fail-closed semantics: any error fires. -/

/-! ### Error provenance -/

inductive CelError where
  | missingField (fp : FieldPath)
  | typeMismatch (fp : FieldPath) (expected : CelType) (actual : String)
  | divisionByZero
  deriving Repr

/-! ### CelResult — typed evaluation outcome -/

inductive CelResult (α : Type) where
  | ok (val : α)
  | error (reason : CelError)
  deriving Repr

def CelResult.map (f : α → β) : CelResult α → CelResult β
  | .ok v      => .ok (f v)
  | .error e   => .error e

def CelResult.bind (f : α → CelResult β) : CelResult α → CelResult β
  | .ok v    => f v
  | .error e => .error e

instance : Monad CelResult where
  pure := .ok
  bind x f := x.bind f


/-! ### Fail-closed semantics -/

def CelResult.fires : CelResult Bool → Bool
  | .ok true  => true
  | .ok false => false
  | .error _  => true

/-! ### Bridge to EvalOutcome -/

def CelResult.toEvalOutcome : CelResult Bool → EvalOutcome
  | .ok true  => .«unsafe»
  | .ok false => .clear
  | .error _  => .unevaluable

/-! ### Compatibility proof: fires semantics preserved -/

theorem celResult_fires_iff_outcome_fires (r : CelResult Bool) :
    r.fires = r.toEvalOutcome.fires := by
  cases r with
  | ok v => cases v <;> rfl
  | error _ => rfl

/-! ### CelResult-based expression evaluation

Mirrors `CelExpr.eval` but returns `CelResult` with error provenance
instead of bare `Option`. -/

def resolveTypedResult (obs : Observation) (fp : FieldPath) (ty : CelType) : CelResult (CelType.Interp ty) :=
  match obs.resolveField fp with
  | none => .error (.missingField fp)
  | some pv =>
    match ty, pv with
    | .bool,   .bool v   => .ok v
    | .string, .str v    => .ok v
    | .int,    .int v    => .ok v
    | _, _ => .error (.typeMismatch fp ty (reprStr pv))

def CelExpr.evalResult (obs : Observation) : CelExpr env ty → CelResult (CelType.Interp ty)
  | .lit l          => .ok l.val
  | .field fp _     => resolveTypedResult obs fp ty
  | .binop op l r   => do
      let lv ← l.evalResult obs
      let rv ← r.evalResult obs
      pure (op.eval lv rv)
  | .and l r        => do
      let lv ← l.evalResult obs
      let rv ← r.evalResult obs
      pure (lv && rv)
  | .or l r         => do
      let lv ← l.evalResult obs
      let rv ← r.evalResult obs
      pure (lv || rv)
  | .not e          => do
      let v ← e.evalResult obs
      pure (!v)
  | .missing fp     => .ok (obs.resolveField fp).isNone

/-! ### CelResult-based outcome bridge -/

def CelExpr.toOutcomeResult (obs : Observation) (expr : CelExpr env .bool) : EvalOutcome :=
  match expr.evalResult obs with
  | .ok true  => .«unsafe»
  | .ok false => .clear
  | .error _  => .unevaluable

/-! ### Bridge lemma: resolveTypedResult and resolveTyped agree -/

private theorem resolveTyped_bridge (obs : Observation) (fp : FieldPath) (ty : CelType) :
    (match resolveTypedResult obs fp ty with
     | .ok v    => some v
     | .error _ => none) = resolveTyped obs fp ty := by
  unfold resolveTypedResult resolveTyped
  cases obs.resolveField fp with
  | none => rfl
  | some pv => cases ty <;> cases pv <;> rfl

/-! ### Consistency: CelResult evaluation agrees with Option evaluation -/

theorem evalResult_to_option (obs : Observation) (expr : CelExpr env ty) :
    (match expr.evalResult obs with
     | .ok v    => some v
     | .error _ => none) = expr.eval obs := by
  induction expr with
  | lit _ => rfl
  | field fp _ => exact resolveTyped_bridge obs fp _
  | binop op l r ihl ihr =>
    simp only [CelExpr.evalResult, CelExpr.eval, bind, CelResult.bind, Option.bind]
    conv => rhs; rw [← ihl, ← ihr]
    cases l.evalResult obs <;> cases r.evalResult obs <;> rfl
  | and l r ihl ihr =>
    simp only [CelExpr.evalResult, CelExpr.eval, bind, CelResult.bind, Option.bind]
    conv => rhs; rw [← ihl, ← ihr]
    cases l.evalResult obs <;> cases r.evalResult obs <;> rfl
  | or l r ihl ihr =>
    simp only [CelExpr.evalResult, CelExpr.eval, bind, CelResult.bind, Option.bind]
    conv => rhs; rw [← ihl, ← ihr]
    cases l.evalResult obs <;> cases r.evalResult obs <;> rfl
  | not e ih =>
    simp only [CelExpr.evalResult, CelExpr.eval, bind, CelResult.bind, Option.bind]
    conv => rhs; rw [← ih]
    cases e.evalResult obs <;> rfl
  | missing _ => rfl

/-! ### Corollary: toOutcomeResult agrees with toOutcome -/

theorem toOutcomeResult_eq_toOutcome (obs : Observation) (expr : CelExpr env .bool) :
    expr.toOutcomeResult obs = expr.toOutcome obs := by
  simp only [CelExpr.toOutcomeResult, CelExpr.toOutcome]
  have h := evalResult_to_option obs expr
  match hr : expr.evalResult obs with
  | .ok true  => simp [hr] at h; rw [← h]
  | .ok false => simp [hr] at h; rw [← h]
  | .error _  => simp [hr] at h; rw [← h]
