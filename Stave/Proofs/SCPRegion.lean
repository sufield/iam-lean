import Stave.Controls.SCPRegion

theorem scpHasRegionDeny_sound (p : Policy) (h : scpHasRegionDeny p = true) :
    ∃ s, s ∈ p.statements ∧
      (s.effect == .deny && stmtGrantsAction s "*" && s.condition.isSome) = true :=
  List.any_eq_true.mp h

theorem scpHasRegionDeny_complete (p : Policy) (s : Statement)
    (hmem : s ∈ p.statements)
    (hpred : (s.effect == .deny && stmtGrantsAction s "*" && s.condition.isSome) = true) :
    scpHasRegionDeny p = true :=
  List.any_eq_true.mpr ⟨s, hmem, hpred⟩

instance scpHasRegionDeny_decidable (p : Policy) :
    Decidable (scpHasRegionDeny p = true) := inferInstance
