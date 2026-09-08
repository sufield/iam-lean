import IamExplainer.Match
/-! Control 5: CloudTrail tamper protection SCP — deny StopLogging,
    DeleteTrail, UpdateTrail. -/

def scpProtectsTrail (p : Policy) : Bool :=
  ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail"].all fun a =>
    p.statements.any fun s =>
      s.effect == .deny && stmtGrantsAction s a

section Tests

private def goodSCP : Policy := ⟨some "2012-10-17", [
  { effect := .deny
    actions := some ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail",
                      "cloudtrail:UpdateTrail"]
    resources := some ["*"] }
]⟩

private def wildSCP : Policy := ⟨some "2012-10-17", [
  { effect := .deny, actions := some ["cloudtrail:*"], resources := some ["*"] }
]⟩

private def partialSCP : Policy := ⟨some "2012-10-17", [
  { effect := .deny
    actions := some ["cloudtrail:StopLogging"]
    resources := some ["*"] }
]⟩

private def missingSCP : Policy := ⟨none, []⟩

-- Green: all three denied
#guard scpProtectsTrail goodSCP == true
-- Green: wildcard covers all
#guard scpProtectsTrail wildSCP == true
-- Red: only one of three
#guard scpProtectsTrail partialSCP == false
-- Red: empty
#guard scpProtectsTrail missingSCP == false

end Tests
