import Stave.Controls.SGInbound
/-! Control: SSH internet reachability compound check.
    Reachable iff public IP + public subnet + SG allows TCP 22 from 0.0.0.0/0. -/

def isSshReachable (inst : EC2InstanceObs) (subnet : SubnetObs)
    (sg : SecurityGroupObs) : Bool :=
  inst.publicIp.isSome && subnet.hasRouteToIgw && sgAllowsInbound sg 22 "0.0.0.0/0"

section Tests

#guard isSshReachable
  ⟨"i-1", "sub-1", "vpc-1", ["sg-1"], some "1.2.3.4", "ami-1", none, true, "us-east-1"⟩
  ⟨"sub-1", "vpc-1", "10.0.0.0/24", true, false⟩
  ⟨"sg-1", [⟨22, 22, "tcp", some "0.0.0.0/0", none⟩], []⟩
  == true

#guard isSshReachable
  ⟨"i-1", "sub-1", "vpc-1", ["sg-1"], none, "ami-1", none, true, "us-east-1"⟩
  ⟨"sub-1", "vpc-1", "10.0.0.0/24", true, false⟩
  ⟨"sg-1", [⟨22, 22, "tcp", some "0.0.0.0/0", none⟩], []⟩
  == false

#guard isSshReachable
  ⟨"i-1", "sub-1", "vpc-1", ["sg-1"], some "1.2.3.4", "ami-1", none, true, "us-east-1"⟩
  ⟨"sub-1", "vpc-1", "10.0.0.0/24", false, false⟩
  ⟨"sg-1", [⟨22, 22, "tcp", some "0.0.0.0/0", none⟩], []⟩
  == false

end Tests
