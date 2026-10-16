import Stave.IAM.Graph

/-! Privilege reachability: transitive closure of can_assume edges.
Soufflé source: rules.dl:61-65 (transitive_assume), :78-82 (unconditional_assume).
Go source: reasoning/souffle/iam/rules.dl. -/

/-- Bounded transitive assumption closure. Computes the fixpoint of
    can_assume up to `fuel` steps (prevents nontermination in Lean).
    Soufflé source: rules.dl:61-65. -/
def IAMGraph.transitiveAssume (g : IAMGraph) (principalId : String) (fuel : Nat := 20) : List String :=
  go [principalId] [] fuel
where
  go (frontier visited : List String) : Nat → List String
    | 0 => visited
    | fuel + 1 =>
      let newEdges := frontier.flatMap fun p =>
        (g.canAssume.filter fun (f, _) => f == p).map (·.2)
      let novel := newEdges.filter fun r => !visited.any (· == r)
      if novel.isEmpty then visited
      else go novel (visited ++ novel) fuel

/-- Bounded unconditional assumption closure: only edges where the
    target role has no trust condition gate (MFA, ExternalId, etc.).
    Soufflé source: rules.dl:78-82. -/
def IAMGraph.unconditionalAssume (g : IAMGraph) (principalId : String) (fuel : Nat := 20) : List String :=
  go [principalId] [] fuel
where
  go (frontier visited : List String) : Nat → List String
    | 0 => visited
    | fuel + 1 =>
      let newEdges := frontier.flatMap fun p =>
        (g.canAssume.filter fun (f, t) => f == p && !g.hasCondition t).map (·.2)
      let novel := newEdges.filter fun r => !visited.any (· == r)
      if novel.isEmpty then visited
      else go novel (visited ++ novel) fuel

/-- Privilege reachability as a Prop: principal P can transitively
    assume role R via some chain of can_assume edges.
    Soufflé source: rules.dl:61-65 (transitive_assume). -/
inductive PrivReachable (g : IAMGraph) : String → String → Prop where
  | base {src dst : String}
    (h : g.canAssume.any fun (f, t) => f == src && t == dst) :
    PrivReachable g src dst
  | step {src dst : String} (mid : String)
    (h1 : PrivReachable g src mid)
    (h2 : g.canAssume.any fun (f, t) => f == mid && t == dst) :
    PrivReachable g src dst

/-- Actions reachable by a principal (direct + via assumption chains).
    Soufflé source: rules.dl:93-97 (reachable_action). -/
def IAMGraph.reachableActions (g : IAMGraph) (principalId : String) : List String :=
  let direct := g.directActions principalId
  let viaAssume := (g.transitiveAssume principalId).flatMap (g.directActions ·)
  direct ++ viaAssume

/-- Resources reachable by a principal.
    Soufflé source: rules.dl:99-103 (reachable_resource). -/
def IAMGraph.reachableResources (g : IAMGraph) (principalId : String) : List String :=
  let direct := g.directResources principalId
  let viaAssume := (g.transitiveAssume principalId).flatMap (g.directResources ·)
  direct ++ viaAssume

/-- Deny actions reachable by a principal.
    Soufflé source: rules.dl:109-113 (reachable_deny_action). -/
def IAMGraph.reachableDenyActions (g : IAMGraph) (principalId : String) : List String :=
  let direct := g.directDenyActions principalId
  let viaAssume := (g.transitiveAssume principalId).flatMap (g.directDenyActions ·)
  direct ++ viaAssume

/-- Effective permission: allow minus deny.
    Soufflé source: rules.dl:190-192 (effective_permission).
    Simplified: omits scope-aware joins (those eliminate cross-account
    Cartesian false positives but don't affect the formal properties). -/
def IAMGraph.effectivePermission (g : IAMGraph) (principalId : String) (action resource : String) : Bool :=
  let hasAllow := (g.reachableActions principalId).any (· == action) &&
                  (g.reachableResources principalId).any (· == resource)
  let hasDeny := (g.reachableDenyActions principalId).any (· == action)
  hasAllow && !hasDeny

/-- Whether principal can perform action on resource (abstract ARN matching).
    Soufflé source: rules.dl:245-250 (effective_access).
    Uses exact string match — real Soufflé uses arn_matches with wildcards. -/
def IAMGraph.effectiveAccess (g : IAMGraph) (principalId resource action : String) : Bool :=
  g.effectivePermission principalId action resource

/-- Escalation path: principal can reach actions it doesn't directly hold,
    via assumption chains. This is the core IAM privilege escalation concept.
    Soufflé source: transitive_assume + reachable_action composition. -/
def IAMGraph.escalationPath (g : IAMGraph) (principalId : String) (targetAction : String) : Bool :=
  let directlyHeld := g.directActions principalId |>.any (· == targetAction)
  let reachable := g.reachableActions principalId |>.any (· == targetAction)
  !directlyHeld && reachable

/-- Escalation path as a Prop.
    "Principal can reach an action it doesn't directly hold." -/
def EscalationPath (g : IAMGraph) (principalId targetAction : String) : Prop :=
  g.escalationPath principalId targetAction = true
