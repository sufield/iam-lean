import Stave.Controls.MFAEnforce

theorem mfaEnforced_sound (p : Policy) (h : mfaEnforced p = true) :
    ∃ s, s ∈ p.statements ∧
      (s.effect == .deny && stmtGrantsAction s "*" && s.condition.isSome) = true :=
  List.any_eq_true.mp h

theorem mfaEnforced_complete (p : Policy) (s : Statement)
    (hmem : s ∈ p.statements)
    (hpred : (s.effect == .deny && stmtGrantsAction s "*" && s.condition.isSome) = true) :
    mfaEnforced p = true :=
  List.any_eq_true.mpr ⟨s, hmem, hpred⟩

instance mfaEnforced_decidable (p : Policy) :
    Decidable (mfaEnforced p = true) := inferInstance
