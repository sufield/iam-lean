/-! Canonical observation types for Stave controls.
    Types live here; controls import them. -/

structure IngressRule where
  fromPort      : Nat
  toPort        : Nat
  protocol      : String
  cidrIp        : Option String
  sourceGroupId : Option String
deriving Repr, DecidableEq

structure SecurityGroupObs where
  groupId      : String
  ingressRules : List IngressRule
  attachedTo   : List String
deriving Repr

structure EC2InstanceObs where
  instanceId   : String
  subnetId     : String
  vpcId        : String
  sgIds        : List String
  publicIp     : Option String
  amiId        : String
  keyPairName  : Option String
  ebsEncrypted : Bool
  region       : String
deriving Repr

structure SubnetObs where
  subnetId      : String
  vpcId         : String
  cidr          : String
  hasRouteToIgw : Bool
  isDefault     : Bool := false
deriving Repr, DecidableEq
