import Stave.Obs
/-! Control 8: Security Group ingress world-open (0.0.0.0/0 or ::/0). -/

def ruleIsWorldOpen (r : IngressRule) : Bool :=
  r.cidrIp == some "0.0.0.0/0" || r.cidrIp == some "::/0"

def sgWorldOpen (sg : SecurityGroupObs) : Bool :=
  sg.ingressRules.any ruleIsWorldOpen

section Tests

#guard sgWorldOpen ⟨"sg-1", [⟨22, 22, "tcp", some "0.0.0.0/0", none⟩], []⟩ == true
#guard sgWorldOpen ⟨"sg-2", [⟨443, 443, "tcp", some "::/0", none⟩], []⟩ == true
#guard sgWorldOpen ⟨"sg-3", [⟨22, 22, "tcp", some "10.0.0.0/8", none⟩], []⟩ == false
#guard sgWorldOpen ⟨"sg-4", [], []⟩ == false
#guard sgWorldOpen ⟨"sg-5", [
  ⟨443, 443, "tcp", some "10.0.0.0/8", none⟩,
  ⟨80, 80, "tcp", some "0.0.0.0/0", none⟩], []⟩ == true

end Tests
