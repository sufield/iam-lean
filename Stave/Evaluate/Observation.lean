import Stave.Basic.Finding
import Stave.Schema.Types

/-! Observation model and evaluation outcome types.
Formalizes obs.v0.1: an asset with a typed property bag.
The evaluator resolves FieldPaths against this bag.
Vendor-neutral -- no cloud provider noun appears in this module. -/

/-- Evaluation outcome for a single predicate rule or full control. -/
inductive EvalOutcome where
  | clear
  | «unsafe»
  | unevaluable
  deriving Repr, DecidableEq, BEq, Inhabited

/-- A finding fires on unsafe OR unevaluable (fail-closed). -/
def EvalOutcome.fires : EvalOutcome -> Bool
  | .«unsafe» => true
  | .unevaluable => true
  | .clear => false

/-- Runtime property value -- the CEL evaluation target.
    Go source: the JSON values that CEL predicates compare against. -/
inductive PropValue where
  | bool (v : Bool)
  | str (v : String)
  | int (v : Int)
  | list (vs : List PropValue)
  | null
  deriving Repr, BEq, Inhabited

/-- A single observation: one asset's configuration at one point in time.
    Go source: internal/types/observation.go (Observation struct). -/
structure Observation where
  assetId : AssetId
  assetType : AssetType
  properties : List (String × PropValue)
  deriving Repr

/-- An observation set -- multiple snapshots of possibly many assets. -/
abbrev ObservationSet := List Observation

/-- Look up a top-level property by key. -/
def Observation.lookup (obs : Observation) (key : String) : Option PropValue :=
  obs.properties.find? (fun p => p.1 == key) |>.map (fun p => p.2)

/-- Resolve a FieldPath against an observation's properties.
    Supports one level of nesting (properties.X -> lookup X).
    Missing path -> none (triggers fail-closed). -/
def Observation.resolveField (obs : Observation) (fp : FieldPath) : Option PropValue :=
  match fp.stripPropertiesPrefix with
  | [key] => obs.lookup key
  | _ => none
