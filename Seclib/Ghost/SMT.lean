import Seclib.Ghost

/-! SMT-LIB 2.6 encoding of ghost assumptions for Z3.
Vendor-agnostic — `id` is an opaque string, not an ARN. -/

private def hasSubstr (s sub : String) : Bool :=
  (s.splitOn sub).length > 1

def ghostPropertyToSMT (id : String) (p : GhostProperty) : String :=
  match p.value with
  | .bool b =>
    s!"(assert (= (ghost_prop \"{id}\" \"{p.name}\") {b}))"
  | .string s =>
    s!"(assert (= (ghost_prop \"{id}\" \"{p.name}\") \"{s}\"))"
  | .stringList ss =>
    "\n".intercalate <| ss.map fun s =>
      s!"(assert (ghost_prop_member \"{id}\" \"{p.name}\" \"{s}\"))"

def ghostAssumptionToSMT (id : String) (assume : GhostAssumption) : String :=
  match assume with
  | .overPermissive =>
    s!"(assert (forall ((action String)) (grants \"{id}\" action)))"
  | .leastPrivilege =>
    s!"(assert (forall ((action String)) (not (grants \"{id}\" action))))"
  | .explicit props =>
    "\n".intercalate <| props.map (ghostPropertyToSMT id)

def refStatusToSMT [ToString α] (id : String) (ref : RefStatus α) : String :=
  match ref with
  | .resolved payload =>
    s!"(assert (resolved \"{id}\" \"{toString payload}\"))"
  | .ghost gid assume =>
    ghostAssumptionToSMT gid assume

/-! ### #guard tests -/

#guard hasSubstr (ghostAssumptionToSMT "arn:role/X" .overPermissive) "forall"
#guard hasSubstr (ghostAssumptionToSMT "arn:role/X" .overPermissive) "grants"
#guard hasSubstr (ghostAssumptionToSMT "arn:role/X" .leastPrivilege) "not"
#guard hasSubstr (ghostAssumptionToSMT "arn:role/X" .leastPrivilege) "grants"
#guard hasSubstr (ghostAssumptionToSMT "arn:role/X"
  (.explicit [⟨"managed", .bool true⟩])) "ghost_prop"
#guard (ghostAssumptionToSMT "ref1" .overPermissive).startsWith "(assert"
#guard hasSubstr (ghostPropertyToSMT "ref1"
  ⟨"tags", .stringList ["prod", "staging"]⟩) "ghost_prop_member"
