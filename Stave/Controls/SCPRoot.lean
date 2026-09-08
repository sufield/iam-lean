import IamExplainer.Match
/-! Control 3: Root actions blocked by SCP. -/
open Lean (Json)

def scpDeniesRoot (p : Policy) : Bool :=
  p.statements.any fun s =>
    s.effect == .deny && stmtGrantsAction s "*" && s.condition.isSome

section Tests

private def goodSCP : Policy := ⟨some "2012-10-17", [
  { effect := .deny
    actions := some ["*"]
    resources := some ["*"]
    condition := some (Json.str "principal-is-root") }
]⟩

private def missingSCP : Policy := ⟨none, []⟩

private def allowSCP : Policy := ⟨some "2012-10-17", [
  { effect := .allow, actions := some ["s3:*"], resources := some ["*"] }
]⟩

-- Green: root-deny SCP present
#guard scpDeniesRoot goodSCP == true
-- Red: empty
#guard scpDeniesRoot missingSCP == false
-- Red: allow only
#guard scpDeniesRoot allowSCP == false

end Tests
