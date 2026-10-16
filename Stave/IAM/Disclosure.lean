import Stave.IAM.TrustBoundary

/-! Disclosure: what the IAM privilege formalization does NOT claim.
Go source: reasoning/souffle/iam/schema.dl header (Coverage Limitations).

When the Lean model proves an escalation path does not exist, the
following layers are NOT evaluated:

1. Group membership — no aws_iam_group in the observation contract;
   group-inherited permissions are a real but minority gap.
2. Policy statement granularity — sirfacts pre-evaluates policy logic;
   the Lean/Soufflé model reasons over has_action/has_resource directly,
   not per-statement Allow/Deny decomposition.
3. Trust condition detail — has_trust_condition is partially populated;
   condition-aware queries degrade to unconditional assumption closure.
4. SCP document parsing — Stave has boolean-only SCP handling
   (has/doesn't have SCP), not parsed SCP document evaluation.
   A parsed model would add: specific action × resource deny evaluation,
   NotAction/NotResource handling, condition key evaluation.
5. Resource policy evaluation — resource policies are partially modeled
   (resource_policy_principal/action); the Lean model does not evaluate
   the full resource-policy evaluation algorithm.
6. Service control policies interaction — SCPs interact with identity
   policies and permission boundaries; the boolean model over-approximates.

The Lean formalization models the ABSTRACT reachability structure —
whether privilege paths exist — not the concrete AWS policy evaluation
algorithm (5-step: Organization SCP → Resource-based → Permission boundary →
Identity-based → Session policies). -/

/-- Layers NOT modeled by the IAM privilege formalization.
    Go source: schema.dl header (Coverage Limitations 1-3). -/
inductive ExcludedIAMLayer where
  | groupMembership
  | policyStatementGranularity
  | trustConditionDetail
  | scpDocumentParsing
  | resourcePolicyEvaluation
  | serviceControlPolicyInteraction
deriving DecidableEq, Repr

/-- All excluded layers. -/
def allExcludedIAMLayers : List ExcludedIAMLayer :=
  [.groupMembership, .policyStatementGranularity, .trustConditionDetail,
   .scpDocumentParsing, .resourcePolicyEvaluation, .serviceControlPolicyInteraction]

/-- The formalization is sound over the abstract reachability model.
    Type-level marker — proofs about IAM reachability carry these assumptions. -/
structure AbstractReachabilityOnly where
  excludedLayers : List ExcludedIAMLayer := allExcludedIAMLayers
