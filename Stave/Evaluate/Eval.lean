import Stave.Evaluate.Observation
import Stave.Schema.Predicate
import Stave.Schema.Control

/-! Executable predicate evaluator -- fail-closed by construction.
Formalizes the CEL evaluation semantics from
internal/core/evaluation/engine/assessor.go (evaluateControl).
The evaluator produces a three-valued outcome: the predicate matched
(unsafe), did not match (clear), or could not be evaluated (fires,
because fail-closed). -/

/-- Compare a resolved property value against an operand.
    Returns none on type mismatch (triggers unevaluable). -/
def compareValues (op : Operator) (pv : PropValue) (operand : Operand) : Option Bool :=
  match op, pv, operand with
  | .eq, .bool a, .bool b => some (a == b)
  | .eq, .str a, .str b => some (a == b)
  | .eq, .int a, .int b => some (a == b)
  | .ne, .bool a, .bool b => some (a != b)
  | .ne, .str a, .str b => some (a != b)
  | .ne, .int a, .int b => some (a != b)
  | .gt, .int a, .int b => some (a > b)
  | .lt, .int a, .int b => some (a < b)
  | .gte, .int a, .int b => some (a >= b)
  | .lte, .int a, .int b => some (a <= b)
  | .contains, .str a, .str b => some (a.contains b)
  | _, _, _ => none

/-- Evaluate a leaf operator against an observation field.
    Missing field + non-presence operator -> unevaluable. -/
def evalLeaf (obs : Observation) (field : FieldPath) (op : Operator)
    (value : Operand) : EvalOutcome :=
  match op with
  | .missing =>
    if (obs.resolveField field).isNone then .«unsafe» else .clear
  | .present =>
    if (obs.resolveField field).isSome then .«unsafe» else .clear
  | .listEmpty =>
    match obs.resolveField field with
    | some (.list vs) => if vs.isEmpty then .«unsafe» else .clear
    | some _ => .unevaluable
    | none => .unevaluable
  | _ =>
    match obs.resolveField field with
    | none => .unevaluable
    | some pv =>
      match compareValues op pv value with
      | some true => .«unsafe»
      | some false => .clear
      | none => .unevaluable

/-- Evaluate a predicate rule tree against an observation. -/
partial def evalRule (obs : Observation) : PredicateRule -> EvalOutcome
  | .leaf field op value _ => evalLeaf obs field op value
  | .anyBlock rules => evalAnyBlock obs rules
  | .allBlock rules => evalAllBlock obs rules
where
  evalAnyBlock (obs : Observation) : List PredicateRule -> EvalOutcome
    | [] => EvalOutcome.clear
    | r :: rs =>
      match evalRule obs r with
      | .«unsafe» => EvalOutcome.«unsafe»
      | other =>
        match evalAnyBlock obs rs with
        | .«unsafe» => EvalOutcome.«unsafe»
        | .unevaluable => EvalOutcome.unevaluable
        | .clear => other
  evalAllBlock (obs : Observation) : List PredicateRule -> EvalOutcome
    | [] => EvalOutcome.«unsafe»
    | r :: rs =>
      match evalRule obs r with
      | .clear => EvalOutcome.clear
      | other =>
        match evalAllBlock obs rs with
        | .clear => EvalOutcome.clear
        | .unevaluable => EvalOutcome.unevaluable
        | .«unsafe» => other

/-- Evaluate a full UnsafePredicate against an observation.
    Empty predicate -> unevaluable (fail-closed: no predicate = no
    evidence of safety). The Go evaluator treats this as an error. -/
def evalPredicate (obs : Observation) (pred : UnsafePredicate) : EvalOutcome :=
  if pred.isEmpty then EvalOutcome.unevaluable
  else
    let anyResult := evalRule.evalAnyBlock obs pred.any
    let allResult := evalRule.evalAllBlock obs pred.all
    match anyResult, allResult with
    | .«unsafe», _ => EvalOutcome.«unsafe»
    | _, .«unsafe» => EvalOutcome.«unsafe»
    | .unevaluable, _ => EvalOutcome.unevaluable
    | _, .unevaluable => EvalOutcome.unevaluable
    | .clear, .clear => EvalOutcome.clear

/-- Evaluate a control against an observation.
    Checks asset type applicability first. -/
def evalControl (obs : Observation) (ctrl : ControlDef) : EvalOutcome :=
  if !ctrl.appliesToAssetType obs.assetType then EvalOutcome.clear
  else evalPredicate obs ctrl.predicate

/-- Evaluate a full catalog against one observation, collecting findings. -/
def evalCatalog (obs : Observation) (cat : Catalog) : List (ControlId × EvalOutcome) :=
  cat.map fun ctrl => (ctrl.id, evalControl obs ctrl)

/-- The findings (controls that fire) from evaluating a catalog. -/
def findings (obs : Observation) (cat : Catalog) : List ControlId :=
  (evalCatalog obs cat).filter (fun p => EvalOutcome.fires p.2) |>.map (fun p => p.1)

/-- Evaluate a catalog across an observation set, collecting all findings. -/
def evalObservationSet (obss : ObservationSet) (cat : Catalog) : List (AssetId × ControlId) :=
  obss.flatMap fun obs =>
    (findings obs cat).map fun cid => (obs.assetId, cid)
