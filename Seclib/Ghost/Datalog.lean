import Seclib.Ghost
import Seclib.Ghost.SMT

/-! Soufflé Datalog encoding of ghost assumptions.
Produces ground facts only — rules interpreting these facts
(e.g. wildcard grant expansion for overPermissive) belong in
the Soufflé program, not the encoder. Vendor-agnostic. -/

private def hasSubstr (s sub : String) : Bool :=
  (s.splitOn sub).length > 1

def ghostPropertyToDatalog (id : String) (p : GhostProperty) : String :=
  match p.value with
  | .bool b =>
    s!"ghost_prop(\"{id}\", \"{p.name}\", \"{b}\")."
  | .string s =>
    s!"ghost_prop(\"{id}\", \"{p.name}\", \"{s}\")."
  | .stringList ss =>
    "\n".intercalate <| ss.map fun s =>
      s!"ghost_prop(\"{id}\", \"{p.name}\", \"{s}\")."

def ghostAssumptionToDatalog (id : String) (assume : GhostAssumption) : String :=
  match assume with
  | .overPermissive =>
    s!"ghost_assumes(\"{id}\", \"over_permissive\")."
  | .leastPrivilege =>
    s!"ghost_assumes(\"{id}\", \"least_privilege\")."
  | .explicit props =>
    s!"ghost_assumes(\"{id}\", \"explicit\")." ++
    (if props.isEmpty then "" else
      "\n" ++ ("\n".intercalate <| props.map (ghostPropertyToDatalog id)))

def refStatusToDatalog [ToString α] (id : String) (ref : RefStatus α) : String :=
  match ref with
  | .resolved payload =>
    s!"resolved(\"{id}\", \"{toString payload}\")."
  | .ghost gid assume =>
    ghostAssumptionToDatalog gid assume

/-! ### #guard tests -/

#guard ghostAssumptionToDatalog "arn:role/X" .overPermissive
  == "ghost_assumes(\"arn:role/X\", \"over_permissive\")."

#guard ghostAssumptionToDatalog "arn:role/X" .leastPrivilege
  == "ghost_assumes(\"arn:role/X\", \"least_privilege\")."

#guard hasSubstr (ghostAssumptionToDatalog "arn:role/X"
  (.explicit [⟨"managed", .bool true⟩])) "ghost_prop"

#guard ghostAssumptionToDatalog "arn:role/X" (.explicit [])
  == "ghost_assumes(\"arn:role/X\", \"explicit\")."

#guard (ghostAssumptionToDatalog "ref1" .overPermissive).endsWith "."

-- Semantic consistency: overPermissive
#guard hasSubstr (ghostAssumptionToSMT "ref1" .overPermissive) "grants" &&
  hasSubstr (ghostAssumptionToDatalog "ref1" .overPermissive) "over_permissive"

-- Semantic consistency: leastPrivilege
#guard hasSubstr (ghostAssumptionToSMT "ref1" .leastPrivilege) "not" &&
  hasSubstr (ghostAssumptionToDatalog "ref1" .leastPrivilege) "least_privilege"
