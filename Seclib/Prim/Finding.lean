/-! Vendor-neutral security finding types.
No cloud provider noun appears in this module. -/

inductive Severity where
  | critical | high | medium | low
deriving BEq

def Severity.toString : Severity → String
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
