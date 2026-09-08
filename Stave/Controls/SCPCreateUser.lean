import IamExplainer.Match
/-! Control 4: IAM user creation blocked by SCP. -/

def scpDeniesCreateUser (p : Policy) : Bool :=
  p.statements.any fun s =>
    s.effect == .deny && stmtGrantsAction s "iam:CreateUser"

section Tests

private def goodSCP : Policy := ⟨some "2012-10-17", [
  { effect := .deny
    actions := some ["iam:CreateUser"]
    resources := some ["*"] }
]⟩

private def wildDeny : Policy := ⟨some "2012-10-17", [
  { effect := .deny, actions := some ["iam:*"], resources := some ["*"] }
]⟩

private def missingSCP : Policy := ⟨none, []⟩

private def wrongAction : Policy := ⟨some "2012-10-17", [
  { effect := .deny, actions := some ["iam:CreateRole"], resources := some ["*"] }
]⟩

-- Green: exact action deny
#guard scpDeniesCreateUser goodSCP == true
-- Green: wildcard covers it
#guard scpDeniesCreateUser wildDeny == true
-- Red: empty
#guard scpDeniesCreateUser missingSCP == false
-- Red: wrong action
#guard scpDeniesCreateUser wrongAction == false

end Tests
