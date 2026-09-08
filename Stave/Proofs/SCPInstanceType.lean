import Stave.Controls.SCPInstanceType

theorem scpDeniesLargeInstances_sound (p : Policy) (h : scpDeniesLargeInstances p = true) :
    ∃ s, s ∈ p.statements ∧
      (s.effect == .deny && stmtGrantsAction s "ec2:RunInstances" && s.condition.isSome) = true :=
  List.any_eq_true.mp h

theorem scpDeniesLargeInstances_complete (p : Policy) (s : Statement)
    (hmem : s ∈ p.statements)
    (hpred : (s.effect == .deny && stmtGrantsAction s "ec2:RunInstances" && s.condition.isSome) = true) :
    scpDeniesLargeInstances p = true :=
  List.any_eq_true.mpr ⟨s, hmem, hpred⟩

instance scpDeniesLargeInstances_decidable (p : Policy) :
    Decidable (scpDeniesLargeInstances p = true) := inferInstance
