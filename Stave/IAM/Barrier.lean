import Stave.IAM.Reachability

/-! Barriers: what blocks an escalation path from being exploitable.
Go source: fixture semantics (partial scenarios in internal/fixtures/labs/).
Soufflé source: rules.dl:78-82 (unconditional_assume excludes conditioned edges). -/

/-- A barrier that blocks an escalation path.
    Go source: fixture partial semantics (MFA, self-scope, missing action, SCP, perm boundary). -/
inductive Barrier where
  | mfa              -- Trust policy requires MFA
  | selfScope        -- Condition restricts action to own resources
  | missingAction    -- Required co-action not held (e.g., SetDefaultPolicyVersion)
  | scp              -- SCP explicitly denies the action
  | permBoundary     -- Permission boundary excludes the action
deriving DecidableEq, Repr

/-- Whether a barrier blocks the escalation path from principal to target action.
    Go source: fixture partial semantics. -/
def barrierBlocks (g : IAMGraph) (principalId targetAction : String) : Barrier → Bool
  | .mfa =>
    let assumable := g.transitiveAssume principalId
    let unconditional := g.unconditionalAssume principalId
    let conditionalOnly := assumable.filter fun r => !unconditional.any (· == r)
    conditionalOnly.any fun r => (g.directActions r).any (· == targetAction)
  | .scp => g.scpDenies principalId targetAction
  | .permBoundary =>
    g.hasPermBoundary principalId &&
    !(g.permBoundary principalId |>.any (· == targetAction))
  | .selfScope => false
  | .missingAction => false

/-- An escalation path is blocked if any barrier applies.
    Go source: partial fixture semantics — partial fires atomic but not chain. -/
def pathBlocked (g : IAMGraph) (principalId targetAction : String) (barrier : Barrier) : Prop :=
  barrierBlocks g principalId targetAction barrier = true

/-- A partial finding: the escalation path exists but a barrier blocks it.
    Distance is ≥ 1 (one-away, not exploitable).
    Go source: fixture partial scenarios. -/
def partialFinding (g : IAMGraph) (principalId targetAction : String) (barrier : Barrier) : Prop :=
  EscalationPath g principalId targetAction ∧ pathBlocked g principalId targetAction barrier
