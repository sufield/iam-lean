import Stave.Controls.SCPCreateUser

theorem scpDeniesCreateUser_sound (p : Policy) (h : scpDeniesCreateUser p = true) :
    ∃ s, s ∈ p.statements ∧
      (s.effect == .deny && stmtGrantsAction s "iam:CreateUser") = true :=
  List.any_eq_true.mp h

theorem scpDeniesCreateUser_complete (p : Policy) (s : Statement)
    (hmem : s ∈ p.statements)
    (hpred : (s.effect == .deny && stmtGrantsAction s "iam:CreateUser") = true) :
    scpDeniesCreateUser p = true :=
  List.any_eq_true.mpr ⟨s, hmem, hpred⟩

instance scpDeniesCreateUser_decidable (p : Policy) :
    Decidable (scpDeniesCreateUser p = true) := inferInstance
