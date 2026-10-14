/-! Network graph model — nodes, edges, route classification.
Go source: internal/core/network/graph.go, proof.go:428-456 -/

/-- Host classification tags.
    Go source: graph.go:10-24 -/
structure Host where
  id : String
  vpcId : String
  subnetId : String
  sgIds : List String
  tags : List (String × String)
deriving DecidableEq, Repr

/-- Go source: graph.go:20 -/
def Host.isProduction (h : Host) : Bool :=
  h.tags.any (fun p => p.1 == "stave:environment" && p.2 == "production")

/-- Go source: graph.go:21 -/
def Host.isBastion (h : Host) : Bool :=
  h.tags.any (fun p => p.1 == "stave:role" && p.2 == "bastion")

/-- Go source: graph.go:22 -/
def Host.isDevelopment (h : Host) : Bool :=
  h.tags.any (fun p => p.1 == "stave:environment" && p.2 == "development")

/-- Go source: graph.go:23 -/
def Host.isDatabaseTier (h : Host) : Bool :=
  h.tags.any (fun p => p.1 == "stave:tier" && p.2 == "database")

/-- Go source: graph.go:24 -/
def Host.isIsolated (h : Host) : Bool :=
  h.tags.any (fun p => p.1 == "stave:network-zone" && p.2 == "isolated")

/-- Go source: graph.go:27-33 -/
structure SGRule where
  direction : String
  protocol : String
  port : Nat
  sourceType : String
  sourceValue : String
deriving DecidableEq, Repr

/-- Go source: graph.go:36-40 -/
structure VPCPeering where
  peeringId : String
  requesterVpc : String
  accepterVpc : String
deriving DecidableEq, Repr

/-- Go source: graph.go:43-48 -/
structure Subnet where
  id : String
  vpcId : String
  routeTableId : String
  tags : List (String × String)
deriving DecidableEq, Repr

/-- Go source: graph.go:51 -/
def Subnet.isPrivate (s : Subnet) : Bool :=
  s.tags.any (fun p => p.1 == "stave:subnet-type" && p.2 == "private")

/-- Go source: graph.go:54-58 -/
structure Route where
  destination : String
  targetType : String
  targetId : String
deriving DecidableEq, Repr

/-- Route target classification for transitive-egress.
    Go source: proof.go:428-434 -/
inductive RouteClass where
  | sink     -- definite internet egress (nat, igw, eigw)
  | gated    -- cannot determine without additional observation
  | nonSink  -- no internet egress (local)
deriving DecidableEq, Repr

/-- Go source: proof.go:439-456 -/
def classifyRoute (targetType : String) : RouteClass :=
  if targetType == "nat" || targetType == "igw" || targetType == "eigw" then .sink
  else if targetType == "local" then .nonSink
  else .gated

/-- RFC1918 + internet CIDRs treated as broad.
    Go source: reachability.go:17-23 -/
def broadCIDRs : List String :=
  ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "0.0.0.0/0", "::/0"]

/-- Go source: graph.go:68-76 -/
structure NetGraph where
  hosts : List Host
  sgRules : List (String × List SGRule)  -- sg_id → rules
  peerings : List VPCPeering
  subnets : List Subnet
  routes : List (String × List Route)    -- route_table_id → routes
  firewallEndpoints : List String
deriving Repr

/-- Go source: graph.go:198-206 -/
def NetGraph.productionHosts (g : NetGraph) : List Host :=
  g.hosts.filter Host.isProduction

/-- Go source: graph.go:209-217 -/
def NetGraph.bastionHosts (g : NetGraph) : List Host :=
  g.hosts.filter Host.isBastion

/-- Go source: graph.go:220-228 -/
def NetGraph.developmentHosts (g : NetGraph) : List Host :=
  g.hosts.filter Host.isDevelopment

/-- Go source: graph.go:231-239 -/
def NetGraph.databaseHosts (g : NetGraph) : List Host :=
  g.hosts.filter Host.isDatabaseTier

/-- Go source: graph.go:242-250 -/
def NetGraph.isolatedHosts (g : NetGraph) : List Host :=
  g.hosts.filter Host.isIsolated

/-- Go source: graph.go:253-261 -/
def NetGraph.privateSubnets (g : NetGraph) : List Subnet :=
  g.subnets.filter Subnet.isPrivate

/-- Look up SG rules by SG ID. -/
def NetGraph.rulesFor (g : NetGraph) (sgId : String) : List SGRule :=
  match g.sgRules.find? (fun p => p.1 == sgId) with
  | some (_, rules) => rules
  | none => []

/-- Look up routes by route table ID. -/
def NetGraph.routesFor (g : NetGraph) (rtId : String) : List Route :=
  match g.routes.find? (fun p => p.1 == rtId) with
  | some (_, rs) => rs
  | none => []

/-- Find subnet by ID. -/
def NetGraph.findSubnet (g : NetGraph) (subnetId : String) : Option Subnet :=
  g.subnets.find? (fun s => s.id == subnetId)
