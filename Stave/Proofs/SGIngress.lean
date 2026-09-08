import Stave.Controls.SGIngress

theorem sgWorldOpen_sound (sg : SGObs) (h : sgWorldOpen sg = true) :
    ∃ r, r ∈ sg.rules ∧ ruleIsWorldOpen r = true :=
  List.any_eq_true.mp h

theorem sgWorldOpen_complete (sg : SGObs) (r : SGRule)
    (hmem : r ∈ sg.rules) (hopen : ruleIsWorldOpen r = true) :
    sgWorldOpen sg = true :=
  List.any_eq_true.mpr ⟨r, hmem, hopen⟩

instance sgWorldOpen_decidable (sg : SGObs) : Decidable (sgWorldOpen sg = true) :=
  inferInstance
