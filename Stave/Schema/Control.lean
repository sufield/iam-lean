import Stave.Schema.Predicate

/-! Control definition and catalog types.
Formalizes: internal/core/controldef/definition.go (ControlDefinition),
internal/core/controldef/definition.go:19 (ControlDefinitions).
Projects the ~40-field Go struct down to the type-system-relevant fields. -/

/-! ### ControlDef — projected control definition
    Go source: internal/core/controldef/definition.go:32-133 -/

structure ControlDef where
  id : ControlId
  severity : Severity
  controlType : ControlType
  classification : Classification
  applicableAssetTypes : List AssetType
  predicate : UnsafePredicate
  observationFields : List String
deriving Repr

def ControlDef.requiresCELValidation (c : ControlDef) : Bool :=
  c.controlType.requiresCELValidation

def ControlDef.isEvaluatable (c : ControlDef) : Bool :=
  c.controlType.isEvaluatable

/-- Go source: definition.go:281-286.
    Empty applicable list = applies to all asset types. -/
def ControlDef.appliesToAssetType (c : ControlDef) (at_ : AssetType) : Bool :=
  c.applicableAssetTypes.isEmpty || c.applicableAssetTypes.contains at_

def ControlDef.predicateFieldPaths (c : ControlDef) : List FieldPath :=
  c.predicate.fieldPaths

/-! ### Catalog — collection of controls -/

abbrev Catalog := List ControlDef

def Catalog.controlIds (cat : Catalog) : List ControlId :=
  cat.map (·.id)

def Catalog.assetTypes (cat : Catalog) : List AssetType :=
  (cat.flatMap (·.applicableAssetTypes)).eraseDups

def Catalog.findById (cat : Catalog) (id : ControlId) : Option ControlDef :=
  cat.find? (·.id == id)

def Catalog.controlsForAssetType (cat : Catalog) (at_ : AssetType) : List ControlDef :=
  cat.filter (·.appliesToAssetType at_)
