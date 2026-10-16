/-! Cross-account trust topology: accounts as nodes, trust grants as edges.
Go source: data/frameworks/cross-account-v1.yaml (64-pair taxonomy).
Stave source: 136 cross-account controls across internal/controls/. -/

/-- AWS account identifier. Abstract — not an API model. -/
abbrev AccountId := String

/-- Direction of a cross-account trust grant.
    Go source: cross-account-v1.yaml direction annotations. -/
inductive Direction where
  | inboundGrant
  | outboundFlow
  | both
deriving DecidableEq, Repr

/-- Mechanism by which cross-account access is established.
    Go source: cross-account-v1.yaml mechanism column. -/
inductive Mechanism where
  | resourcePolicy
  | trustPolicy
  | grant
  | accessPoint
  | sharingAPI
  | replicationConfig
  | accessEntry
  | podIdentity
  | oidcFederation
  | invitationDelegation
  | attributeShare
  | association
  | ramShare
deriving DecidableEq, Repr

/-- Abstract service identifier. 55 known services in the taxonomy.
    Go source: cross-account-v1.yaml service column. -/
abbrev Service := String

/-- A service × mechanism × direction triple — one row in the taxonomy.
    Go source: cross-account-v1.yaml check id. -/
structure TrustPair where
  service : Service
  mechanism : Mechanism
  direction : Direction
deriving DecidableEq, Repr

/-- A directed trust edge between two accounts for a specific service.
    Go source: individual control YAML predicates. -/
structure TrustEdge where
  source : AccountId
  target : AccountId
  service : Service
  mechanism : Mechanism
  direction : Direction
deriving Repr

/-- Cross-account trust topology: the graph of inter-account trust grants. -/
structure Topology where
  accounts : List AccountId
  edges : List TrustEdge
deriving Repr

/-- Whether a direct trust edge exists between accounts for a service. -/
def Topology.hasEdge (t : Topology) (src dst : AccountId) (svc : Service) : Bool :=
  t.edges.any fun e => e.source == src && e.target == dst && e.service == svc

/-- All services with edges from a given account. -/
def Topology.servicesFrom (t : Topology) (acct : AccountId) : List Service :=
  (t.edges.filter fun e => e.source == acct).map (·.service)

/-- All accounts a service grants access to from a given account. -/
def Topology.targetsFor (t : Topology) (acct : AccountId) (svc : Service) : List AccountId :=
  (t.edges.filter fun e => e.source == acct && e.service == svc).map (·.target)
