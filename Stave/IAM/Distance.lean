import Stave.IAM.Barrier
import Stave.Compose.Basic

/-! Distance metric specialized to IAM escalation scenarios.
Imports chain distance from Compose; maps the 10 catalog scenarios
to named constructors.
Go source: finding_risk.go:11-24 (Exploitability classification).
Soufflé source: fixture escalation semantics. -/

/-- The 10 named privilege escalation scenarios from the fixture catalog.
    Go source: internal/fixtures/labs/iam-* directories. -/
inductive EscalationScenario where
  | addUserToGroup
  | attachRolePolicy
  | attachGroupPolicy
  | attachUserPolicy
  | putGroupPolicy
  | putRolePolicy
  | putUserPolicy
  | createLoginProfile
  | updateLoginProfile
  | createPolicyVersion
deriving DecidableEq, Repr

/-- The primary IAM action for each escalation scenario.
    Go source: escalation control YAML (unsafe_predicate fields). -/
def EscalationScenario.primaryAction : EscalationScenario → String
  | .addUserToGroup => "iam:AddUserToGroup"
  | .attachRolePolicy => "iam:AttachRolePolicy"
  | .attachGroupPolicy => "iam:AttachGroupPolicy"
  | .attachUserPolicy => "iam:AttachUserPolicy"
  | .putGroupPolicy => "iam:PutGroupPolicy"
  | .putRolePolicy => "iam:PutRolePolicy"
  | .putUserPolicy => "iam:PutUserPolicy"
  | .createLoginProfile => "iam:CreateLoginProfile"
  | .updateLoginProfile => "iam:UpdateLoginProfile"
  | .createPolicyVersion => "iam:CreatePolicyVersion"

/-- Escalation distance: 0 = exploitable, ≥ 1 = one or more barriers.
    Reuses Compose's chainDistance concept.
    Go source: finding_risk.go:11-24. -/
def escalationDistance (g : IAMGraph) (principalId : String) (scenario : EscalationScenario) : Nat :=
  let action := scenario.primaryAction
  if !g.escalationPath principalId action then 2
  else if barrierBlocks g principalId action .mfa then 1
  else if barrierBlocks g principalId action .scp then 1
  else if barrierBlocks g principalId action .permBoundary then 1
  else 0

/-- Classify escalation exploitability using Compose's Exploitability type.
    Go source: finding_risk.go:11-24. -/
def classifyEscalation (g : IAMGraph) (principalId : String) (scenario : EscalationScenario) : Exploitability :=
  match escalationDistance g principalId scenario with
  | 0 => .exploitable
  | 1 => .oneAway
  | _ + 2 => .reachable
