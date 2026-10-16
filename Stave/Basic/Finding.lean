/-! Vendor-neutral security finding types and shared identifiers.
No cloud provider noun appears in this module. -/

abbrev AssetType := String
abbrev ControlId := String
abbrev ChainId := String
abbrev AssetId := String
abbrev ParamRef := String

inductive Severity where
  | info
  | low
  | medium
  | high
  | critical
deriving BEq, DecidableEq, Repr, Inhabited

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

def Severity.toString : Severity → String
  | .info     => "info"
  | .critical => "critical"
  | .high     => "high"
  | .medium   => "medium"
  | .low      => "low"

instance : ToString Severity := ⟨Severity.toString⟩

structure Evidence where
  path   : String
  actual : String

structure Fix where
  kind       : String
  suggestion : String

structure Finding where
  controlId   : String
  severity    : Severity
  location    : String
  evidence    : Evidence
  explanation : String
  fix         : Fix
