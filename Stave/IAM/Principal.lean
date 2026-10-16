import Stave.Basic

/-! IAM principal model: types for IAM principals, policies, and actions.
Soufflé source: schema.dl (is_principal_type, has_action, has_resource, etc.).
Go source: internal/core/iam/sensitive_actions.go (ActionRiskCategory, EdgeType). -/

/-- IAM principal kind.
    Soufflé source: schema.dl:226-231 (is_principal_type). -/
inductive PrincipalKind where
  | user
  | role
  | service
  | federated
  | account
deriving DecidableEq, Repr

/-- An IAM principal.
    Soufflé source: schema.dl:57 (has_type → principal_type). -/
structure Principal where
  id : String
  kind : PrincipalKind
  accountId : String
deriving DecidableEq, Repr

/-- Policy type classification.
    Go source: sirfacts/facts.go (projector categories). -/
inductive PolicyType where
  | managed
  | inline
  | trust
  | resource
  | scp
  | permissionBoundary
deriving DecidableEq, Repr

/-- Action risk category.
    Go source: internal/core/iam/sensitive_actions.go:8-17. -/
inductive ActionRisk where
  | credentialExposure
  | dataAccess
  | privEsc
  | resourceExposure
  | discovery
deriving DecidableEq, Repr

/-- Reachability edge type.
    Go source: internal/core/iam/sensitive_actions.go:224-233. -/
inductive EdgeType where
  | metadata
  | dataAccess
  | credential
  | privEsc
  | resExposure
  | discovery
deriving DecidableEq, Repr

/-- Abstract action — identified by service:operation string.
    Soufflé source: schema.dl:67 (has_action predicate). -/
abbrev Action := String

/-- Abstract resource — identified by ARN string.
    Soufflé source: schema.dl:69 (has_resource predicate). -/
abbrev Resource := String

/-- Federation mechanism for external trust edges.
    Soufflé source: federation.dl:59-77 (external_reach mechanism). -/
inductive FederationMechanism where
  | oidc
  | saml
  | crossAccount
deriving DecidableEq, Repr
