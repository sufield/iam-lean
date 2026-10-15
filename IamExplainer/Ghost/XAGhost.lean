import Seclib.Ghost
import IamExplainer.Ghost.Aws
import IamExplainer.Principal

/-! Ghost-aware cross-account trust check.
Retrofits XA.TRUST severity to operate on RefStatus Principal.
Resolved: run severity classification. Ghost: emit critical
(overPermissive = worst case). Proves ghostConservative. -/

def xaTrustSeverity (p : Principal) : FindingSeverity :=
  if p.typ == .wildcard then .critical
  else if p.isRoot then .high
  else .medium

def xaTrustGhostCheck (ref : RefStatus Principal) : FindingSeverity :=
  match ref with
  | .resolved p => xaTrustSeverity p
  | .ghost _ _ => .critical

theorem critical_is_top (s : FindingSeverity) : s ≤ .critical := by
  show s.toNat ≤ FindingSeverity.critical.toNat
  cases s <;> simp [FindingSeverity.toNat]

theorem xaTrust_ghost_conservative (ga : GhostAssumption) :
    ghostConservative xaTrustSeverity ga .critical := by
  intro concrete
  exact critical_is_top (xaTrustSeverity concrete)

/-! ### #guard tests -/

-- Resolved wildcard → critical
#guard xaTrustGhostCheck (.resolved ⟨.wildcard, "*"⟩) == .critical

-- Resolved root → high
#guard xaTrustGhostCheck (.resolved ⟨.aws, "arn:aws:iam::999:root"⟩) == .high

-- Resolved specific role → medium
#guard xaTrustGhostCheck (.resolved ⟨.aws, "arn:aws:iam::999:role/Audit"⟩) == .medium

-- Ghost → critical regardless of assumption
#guard xaTrustGhostCheck (.ghost "arn:aws:iam::999:role/X" .overPermissive) == .critical
#guard xaTrustGhostCheck (.ghost "arn:aws:iam::999:role/X" .leastPrivilege) == .critical
#guard xaTrustGhostCheck (.ghost "arn:aws:iam::999:role/X"
  (.explicit [⟨"awsManaged", .bool true⟩])) == .critical
