/-! Core type vocabulary for the CEL predicate type system.
Formalizes: internal/core/kernel/ (AssetType, ControlID),
internal/core/controldef/ (Severity, ControlType, Classification),
internal/core/predicate/ (Operator, FieldPath).
Vendor-neutral — no cloud provider noun appears in this module. -/

/-! ### Scalar identifiers -/

abbrev AssetType := String
abbrev ControlId := String
abbrev ChainId := String
abbrev ParamRef := String

/-- Validation predicate for asset type strings.
    Go source: internal/core/kernel/asset_type.go regex `^[a-z0-9][a-z0-9_.-]*$` -/
def validAssetType (s : String) : Bool :=
  s.length > 0 &&
  let c0 := s.toList.head!
  (c0.isAlpha && c0.isLower || c0.isDigit) &&
  s.all fun c => c.isAlpha && c.isLower || c.isDigit || c == '_' || c == '.' || c == '-'

/-! ### Severity (ordered enum, 5 levels)
    Go source: internal/core/controldef/severity.go:13-17 -/

inductive Severity where
  | info
  | low
  | medium
  | high
  | critical
deriving DecidableEq, Repr, Inhabited

def Severity.toNat : Severity → Nat
  | .info => 1
  | .low => 2
  | .medium => 3
  | .high => 4
  | .critical => 5

instance : Ord Severity where
  compare a b := compare a.toNat b.toNat

instance : LE Severity where
  le a b := a.toNat ≤ b.toNat

instance (a b : Severity) : Decidable (a ≤ b) :=
  inferInstanceAs (Decidable (a.toNat ≤ b.toNat))

def Severity.max (a b : Severity) : Severity :=
  if a.toNat ≥ b.toNat then a else b

/-! ### ControlType (5 evaluatable types + unknown)
    Go source: internal/core/controldef/control_type.go:13-37 -/

inductive ControlType where
  | unsafeState
  | unsafeDuration
  | unsafeRecurrence
  | prefixExposure
  | marker
deriving DecidableEq, Repr, Inhabited

def ControlType.requiresCELValidation : ControlType → Bool
  | .unsafeState => true
  | .marker => true
  | _ => false

def ControlType.isEvaluatable : ControlType → Bool
  | .unsafeState | .unsafeDuration | .unsafeRecurrence
  | .prefixExposure | .marker => true

/-! ### Classification (predicate shape taxonomy)
    Go source: internal/core/controldef/classification.go:19-49 -/

inductive Classification where
  | stateAssertion
  | parameterizedCheck
  | absenceCheck
  | aggregateCheck
deriving DecidableEq, Repr, Inhabited

/-! ### Operator (17 predicate comparison operators)
    Go source: internal/core/predicate/operators.go:12-62
    Closed set — IsSupported is a closed switch -/

inductive Operator where
  | eq | ne | gt | lt | gte | lte
  | missing | present
  | «in» | listEmpty
  | notSubsetOfField | neqField | notInField
  | contains
  | anyMatch | anyIdentityMatch | anyInField
deriving DecidableEq, Repr, Inhabited

def Operator.requiresValue : Operator → Bool
  | .missing => false
  | .present => false
  | .listEmpty => false
  | _ => true

/-! ### FieldPath
    Go source: internal/core/predicate/field_path.go:14
    Dot-separated property path, eagerly split into segments -/

structure FieldPath where
  parts : List String
  hNonempty : parts.length > 0 := by omega
deriving Repr

instance : BEq FieldPath where
  beq a b := a.parts == b.parts

instance : DecidableEq FieldPath := fun a b =>
  if h : a.parts = b.parts then
    isTrue (by cases a; cases b; simp_all)
  else
    isFalse (by intro heq; cases heq; exact h rfl)

def FieldPath.raw (fp : FieldPath) : String :=
  ".".intercalate fp.parts

def FieldPath.hasPathPrefix (fp : FieldPath) (pfx : String) : Bool :=
  match fp.parts with
  | p :: _ => p == pfx
  | [] => false

def FieldPath.stripPropertiesPrefix (fp : FieldPath) : List String :=
  match fp.parts with
  | "properties" :: rest => rest
  | ps => ps
