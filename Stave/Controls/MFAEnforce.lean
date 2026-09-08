import IamExplainer.Match
/-! Control 6: Console login without MFA — deny when MFA absent. -/
open Lean (Json)

def mfaEnforced (p : Policy) : Bool :=
  p.statements.any fun s =>
    s.effect == .deny && stmtGrantsAction s "*" && s.condition.isSome

section Tests

private def goodSCP : Policy := ⟨some "2012-10-17", [
  { effect := .deny
    actions := some ["*"]
    resources := some ["*"]
    condition := some (Json.str "mfa-check") }
]⟩

private def noCondition : Policy := ⟨some "2012-10-17", [
  { effect := .deny, actions := some ["*"], resources := some ["*"] }
]⟩

private def empty : Policy := ⟨none, []⟩

-- Green: deny-all with MFA condition
#guard mfaEnforced goodSCP == true
-- Red: deny-all but no condition (unconditional blanket deny)
#guard mfaEnforced noCondition == false
-- Red: empty
#guard mfaEnforced empty == false

end Tests
