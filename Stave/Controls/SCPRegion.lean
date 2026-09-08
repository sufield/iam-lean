import IamExplainer.Match
/-! Control 2: Region-pinning SCP — deny all outside allowed regions. -/
open Lean (Json)

def scpHasRegionDeny (p : Policy) : Bool :=
  p.statements.any fun s =>
    s.effect == .deny && stmtGrantsAction s "*" && s.condition.isSome

section Tests

private def goodSCP : Policy := ⟨some "2012-10-17", [
  { effect := .deny
    actions := some ["*"]
    resources := some ["*"]
    condition := some (Json.str "region-gate") }
]⟩

private def noConditionSCP : Policy := ⟨some "2012-10-17", [
  { effect := .deny, actions := some ["*"], resources := some ["*"] }
]⟩

private def allowOnlySCP : Policy := ⟨some "2012-10-17", [
  { effect := .allow, actions := some ["*"], resources := some ["*"] }
]⟩

private def emptySCP : Policy := ⟨none, []⟩

-- Green: deny * with condition present
#guard scpHasRegionDeny goodSCP == true
-- Red: deny * but no condition — blanket deny, not region-scoped
#guard scpHasRegionDeny noConditionSCP == false
-- Red: allow only
#guard scpHasRegionDeny allowOnlySCP == false
-- Red: empty policy
#guard scpHasRegionDeny emptySCP == false

end Tests
