import IamExplainer.Match
/-! Control 7: Expensive instance types blocked by SCP. -/
open Lean (Json)

def scpDeniesLargeInstances (p : Policy) : Bool :=
  p.statements.any fun s =>
    s.effect == .deny && stmtGrantsAction s "ec2:RunInstances" && s.condition.isSome

section Tests

private def goodSCP : Policy := ⟨some "2012-10-17", [
  { effect := .deny
    actions := some ["ec2:RunInstances"]
    resources := some ["*"]
    condition := some (Json.str "instance-type-gate") }
]⟩

private def noCondition : Policy := ⟨some "2012-10-17", [
  { effect := .deny
    actions := some ["ec2:RunInstances"]
    resources := some ["*"] }
]⟩

private def wrongAction : Policy := ⟨some "2012-10-17", [
  { effect := .deny
    actions := some ["ec2:TerminateInstances"]
    resources := some ["*"]
    condition := some (Json.str "gate") }
]⟩

private def empty : Policy := ⟨none, []⟩

-- Green: deny RunInstances with instance-type condition
#guard scpDeniesLargeInstances goodSCP == true
-- Red: deny RunInstances but no condition
#guard scpDeniesLargeInstances noCondition == false
-- Red: wrong action
#guard scpDeniesLargeInstances wrongAction == false
-- Red: empty
#guard scpDeniesLargeInstances empty == false

end Tests
