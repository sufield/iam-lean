/-! Control 8: Security Group ingress world-open (0.0.0.0/0 or ::/0). -/

structure SGRule where
  fromPort : Nat
  toPort   : Nat
  protocol : String
  cidrIp   : Option String
deriving Repr, DecidableEq, BEq

structure SGObs where
  groupId : String
  rules   : List SGRule
deriving Repr

def ruleIsWorldOpen (r : SGRule) : Bool :=
  r.cidrIp == some "0.0.0.0/0" || r.cidrIp == some "::/0"

def sgWorldOpen (sg : SGObs) : Bool :=
  sg.rules.any ruleIsWorldOpen

section Tests

-- Red: SSH open to the world
#guard sgWorldOpen ⟨"sg-1", [⟨22, 22, "tcp", some "0.0.0.0/0"⟩]⟩ == true
-- Red: HTTPS open to IPv6 world
#guard sgWorldOpen ⟨"sg-2", [⟨443, 443, "tcp", some "::/0"⟩]⟩ == true
-- Green: private CIDR only
#guard sgWorldOpen ⟨"sg-3", [⟨22, 22, "tcp", some "10.0.0.0/8"⟩]⟩ == false
-- Green: no rules at all
#guard sgWorldOpen ⟨"sg-4", []⟩ == false
-- Red: one safe + one world-open
#guard sgWorldOpen ⟨"sg-5", [
  ⟨443, 443, "tcp", some "10.0.0.0/8"⟩,
  ⟨80, 80, "tcp", some "0.0.0.0/0"⟩]⟩ == true

end Tests
