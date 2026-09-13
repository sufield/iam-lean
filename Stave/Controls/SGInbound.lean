import Stave.Obs
/-! Control: Security Group inbound port/source check. -/

def sgAllowsInbound (sg : SecurityGroupObs) (port : Nat) (source : String) : Bool :=
  sg.ingressRules.any fun r =>
    r.fromPort ≤ port && port ≤ r.toPort && r.cidrIp == some source

section Tests

#guard sgAllowsInbound ⟨"sg-1", [⟨22, 22, "tcp", some "0.0.0.0/0", none⟩], []⟩ 22 "0.0.0.0/0" == true
#guard sgAllowsInbound ⟨"sg-1", [⟨22, 22, "tcp", some "0.0.0.0/0", none⟩], []⟩ 80 "0.0.0.0/0" == false
#guard sgAllowsInbound ⟨"sg-1", [⟨22, 22, "tcp", some "10.0.0.0/8", none⟩], []⟩ 22 "0.0.0.0/0" == false
#guard sgAllowsInbound ⟨"sg-1", [], []⟩ 22 "0.0.0.0/0" == false

end Tests
