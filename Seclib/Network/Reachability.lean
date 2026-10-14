import Seclib.Network.Graph

/-! SG-ingress-only reachability predicate.
Go source: reachability.go:26-71 (CanReach), 138-182 (canReachAnyPort).
Scoped to security-group ingress rules — NACLs and SG egress are NOT
evaluated. -/

/-- Whether two VPCs are connected via peering or transit gateway.
    Go source: reachability.go:80-88, graph.go:323-343 -/
def NetGraph.vpcsConnected (g : NetGraph) (vpc1 vpc2 : String) : Bool :=
  g.peerings.any fun p =>
    (p.requesterVpc == vpc1 && p.accepterVpc == vpc2) ||
    (p.requesterVpc == vpc2 && p.accepterVpc == vpc1)

/-- Whether a CIDR covers a host (same-VPC + broad CIDR).
    Go source: reachability.go:73-78 -/
def cidrCovers (cidr : String) (src dst : Host) : Bool :=
  src.vpcId == dst.vpcId && cidr ∈ broadCIDRs

/-- Check if a single ingress rule allows src to reach dst on a given port.
    Go source: reachability.go:37-50 (inner loop) -/
def ruleAllows (rule : SGRule) (src dst : Host) (port : Nat) : Bool :=
  rule.direction == "ingress" && rule.port == port &&
  match rule.sourceType with
  | "sg" => src.sgIds.any (· == rule.sourceValue)
  | "cidr" => cidrCovers rule.sourceValue src dst
  | _ => false

/-- Same-VPC reachability via SG ingress rules on a specific port.
    Go source: reachability.go:36-51 -/
def NetGraph.canReachSameVpc (g : NetGraph) (src dst : Host) (port : Nat) : Bool :=
  dst.sgIds.any fun sgId =>
    (g.rulesFor sgId).any fun rule =>
      ruleAllows rule src dst port

/-- Cross-VPC reachability: peered/TGW-connected VPCs with broad CIDR ingress.
    Go source: reachability.go:54-68 -/
def NetGraph.canReachCrossVpc (g : NetGraph) (src dst : Host) (port : Nat) : Bool :=
  src.vpcId != "" && dst.vpcId != "" && src.vpcId != dst.vpcId &&
  g.vpcsConnected src.vpcId dst.vpcId &&
  dst.sgIds.any fun sgId =>
    (g.rulesFor sgId).any fun rule =>
      rule.direction == "ingress" && rule.port == port &&
      rule.sourceType == "cidr" && rule.sourceValue ∈ broadCIDRs

/-- Full reachability: same-VPC or cross-VPC.
    Go source: reachability.go:26-71 -/
def NetGraph.canReach (g : NetGraph) (src dst : Host) (port : Nat) : Bool :=
  g.canReachSameVpc src dst port || g.canReachCrossVpc src dst port

/-- Any-port reachability: returns whether src can reach dst on any port.
    Go source: reachability.go:138-182 -/
def NetGraph.canReachAny (g : NetGraph) (src dst : Host) : Bool :=
  dst.sgIds.any fun sgId =>
    (g.rulesFor sgId).any fun rule =>
      rule.direction == "ingress" &&
      (match rule.sourceType with
       | "sg" => src.sgIds.any (· == rule.sourceValue)
       | "cidr" => cidrCovers rule.sourceValue src dst ||
                   (src.vpcId != dst.vpcId && g.vpcsConnected src.vpcId dst.vpcId &&
                    rule.sourceValue ∈ broadCIDRs)
       | _ => false)

/-- Whether dst has external SSH ingress (0.0.0.0/0 or ::/0).
    Go source: proof.go:120-142 -/
def NetGraph.hasExternalIngress (g : NetGraph) (dst : Host) (port : Nat) : Bool :=
  dst.sgIds.any fun sgId =>
    (g.rulesFor sgId).any fun rule =>
      rule.direction == "ingress" && rule.port == port &&
      rule.sourceType == "cidr" &&
      (rule.sourceValue == "0.0.0.0/0" || rule.sourceValue == "::/0")

/-- Reachability as a Prop (for proofs).
    Go source: reachability.go:26-71 (CanReach, lifted to Prop) -/
def Reachable (g : NetGraph) (src dst : Host) (port : Nat) : Prop :=
  g.canReach src dst port = true

instance (g : NetGraph) (src dst : Host) (port : Nat) :
    Decidable (Reachable g src dst port) :=
  inferInstanceAs (Decidable (_ = true))

/-- Any-port reachability as a Prop.
    Go source: reachability.go:138-182 (canReachAnyPort, lifted to Prop) -/
def ReachableAny (g : NetGraph) (src dst : Host) : Prop :=
  g.canReachAny src dst = true
