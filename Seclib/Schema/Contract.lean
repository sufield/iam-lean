import Seclib.Schema.Control

/-! Collector contract schema types.
Formalizes: data/collector-contract.yaml (3913 fields).
The contract defines the boundary between the collector (Physical Domain)
and the evaluation engine (Functional Domain). -/

/-! ### FieldType — JSON types a contract field can carry
    Go source: data/collector-contract.yaml type column -/

inductive FieldType where
  | boolean
  | string
  | integer
  | number
  | list
  | object
deriving DecidableEq, Repr, Inhabited

/-! ### ContractField — one entry in the collector contract -/

structure ContractField where
  path : String
  fieldType : FieldType
  consumers : List ControlId
deriving Repr

abbrev Contract := List ContractField

/-! ### Contract queries -/

def Contract.fieldPaths (c : Contract) : List String :=
  c.map (·.path)

def Contract.consumersOf (c : Contract) (path : String) : List ControlId :=
  match c.find? (·.path == path) with
  | some f => f.consumers
  | none => []

def Contract.fieldsForControl (c : Contract) (id : ControlId) : List ContractField :=
  c.filter (·.consumers.contains id)

def Contract.hasField (c : Contract) (path : String) : Bool :=
  c.any (·.path == path)

/-! ### Schema-predicate consistency check
    A predicate is contract-consistent when every field path it references
    (after stripping the "properties." prefix) appears in the contract. -/

def predicateConsistentWithContract (pred : UnsafePredicate) (contract : Contract) : Bool :=
  pred.fieldPaths.all fun fp =>
    let stripped := ".".intercalate fp.stripPropertiesPrefix
    contract.hasField stripped
