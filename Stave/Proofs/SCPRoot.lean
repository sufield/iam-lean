import Stave.Controls.SCPRoot

theorem scpDeniesRoot_sound (p : Policy) (h : scpDeniesRoot p = true) :
    ∃ s, s ∈ p.statements ∧
      (s.effect == .deny && stmtGrantsAction s "*" && s.condition.isSome) = true :=
  List.any_eq_true.mp h

theorem scpDeniesRoot_complete (p : Policy) (s : Statement)
    (hmem : s ∈ p.statements)
    (hpred : (s.effect == .deny && stmtGrantsAction s "*" && s.condition.isSome) = true) :
    scpDeniesRoot p = true :=
  List.any_eq_true.mpr ⟨s, hmem, hpred⟩

instance scpDeniesRoot_decidable (p : Policy) :
    Decidable (scpDeniesRoot p = true) := inferInstance
