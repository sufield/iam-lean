import Seclib.IAM.Principal

/-! Privilege graph: nodes = principals, edges = privilege grants.
Faithful to the Soufflé relation structure in schema.dl + rules.dl.
Go source: reasoning/souffle/iam/ (schema.dl, rules.dl, federation.dl). -/

/-- A trust condition on a role's trust policy that gates assumption.
    Soufflé source: schema.dl:138 (has_trust_condition). -/
structure TrustCondition where
  roleId : String
  conditionKey : String
deriving DecidableEq, Repr

/-- An external trust edge from a federation source to an IAM role.
    Soufflé source: federation.dl:59-65 (external_reach). -/
structure ExternalTrust where
  source : String
  roleArn : String
  mechanism : FederationMechanism
  restricted : Bool
deriving DecidableEq, Repr

/-- The IAM privilege graph. Fields correspond to Soufflé input relations.
    Soufflé source: schema.dl (input relations), rules.dl (join structure). -/
structure IAMGraph where
  principals : List Principal
  /-- Direct role-assumption edges. Soufflé: can_assume(P, R). schema.dl:96 -/
  canAssume : List (String × String)
  /-- Action grants per principal. Soufflé: has_action(P, A). schema.dl:67 -/
  actions : List (String × String)
  /-- Resource grants per principal. Soufflé: has_resource(P, R). schema.dl:69 -/
  resources : List (String × String)
  /-- Deny action grants. Soufflé: has_deny_action(P, A). schema.dl:72 -/
  denyActions : List (String × String)
  /-- Deny resource grants. Soufflé: has_deny_resource(P, R). schema.dl:75 -/
  denyResources : List (String × String)
  /-- Trust conditions on roles. Soufflé: has_trust_condition(R, K). schema.dl:138 -/
  trustConditions : List TrustCondition
  /-- Permission boundary action grants. Soufflé: has_permission_action(P, A). schema.dl:78 -/
  permBoundaryActions : List (String × String)
  /-- SCP deny effects (boolean model). -/
  scpDenyStatements : List (String × String)
  /-- External federation edges. Soufflé: federation.dl inputs. -/
  externalTrusts : List ExternalTrust
deriving Repr

/-- Whether a direct assumption edge exists.
    Soufflé source: rules.dl:64 (base case of transitive_assume). -/
def IAMGraph.hasEdge (g : IAMGraph) (src dst : String) : Bool :=
  g.canAssume.any fun (f, t) => f == src && t == dst

/-- Whether a role has a trust condition gate.
    Soufflé source: schema.dl:138 / rules.dl:81. -/
def IAMGraph.hasCondition (g : IAMGraph) (roleId : String) : Bool :=
  g.trustConditions.any fun tc => tc.roleId == roleId

/-- Actions directly held by a principal.
    Soufflé source: schema.dl:67 (has_action). -/
def IAMGraph.directActions (g : IAMGraph) (principalId : String) : List String :=
  (g.actions.filter fun (p, _) => p == principalId).map (·.2)

/-- Resources directly held by a principal.
    Soufflé source: schema.dl:69 (has_resource). -/
def IAMGraph.directResources (g : IAMGraph) (principalId : String) : List String :=
  (g.resources.filter fun (p, _) => p == principalId).map (·.2)

/-- Deny actions directly held by a principal.
    Soufflé source: schema.dl:72 (has_deny_action). -/
def IAMGraph.directDenyActions (g : IAMGraph) (principalId : String) : List String :=
  (g.denyActions.filter fun (p, _) => p == principalId).map (·.2)

/-- Permission boundary actions for a principal.
    Soufflé source: schema.dl:78 (has_permission_action). -/
def IAMGraph.permBoundary (g : IAMGraph) (principalId : String) : List String :=
  (g.permBoundaryActions.filter fun (p, _) => p == principalId).map (·.2)

/-- Whether a principal has any permission boundary.
    Go source: CTL.IAM.BOUNDARY.MISSING.001 semantics. -/
def IAMGraph.hasPermBoundary (g : IAMGraph) (principalId : String) : Bool :=
  g.permBoundaryActions.any fun (p, _) => p == principalId

/-- Whether a principal has an SCP deny for an action.
    Boolean SCP model — known limitation (see Disclosure). -/
def IAMGraph.scpDenies (g : IAMGraph) (principalId : String) (action : String) : Bool :=
  g.scpDenyStatements.any fun (p, a) => p == principalId && a == action
