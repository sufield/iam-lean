import Stave.Controls.SCPTrailProtect

theorem scpProtectsTrail_sound (p : Policy) (h : scpProtectsTrail p = true) :
    ∀ a ∈ ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail"],
      (p.statements.any fun s => s.effect == .deny && stmtGrantsAction s a) = true :=
  List.all_eq_true.mp h

theorem scpProtectsTrail_complete (p : Policy)
    (h : ∀ a ∈ ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail"],
      (p.statements.any fun s => s.effect == .deny && stmtGrantsAction s a) = true) :
    scpProtectsTrail p = true :=
  List.all_eq_true.mpr h

instance scpProtectsTrail_decidable (p : Policy) :
    Decidable (scpProtectsTrail p = true) := inferInstance
