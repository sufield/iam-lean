import Stave.Controls.SGIngress

theorem sgWorldOpen_sound (sg : SecurityGroupObs) (h : sgWorldOpen sg = true) :
    ∃ r, r ∈ sg.ingressRules ∧ ruleIsWorldOpen r = true :=
  List.any_eq_true.mp h

theorem sgWorldOpen_complete (sg : SecurityGroupObs) (r : IngressRule)
    (hmem : r ∈ sg.ingressRules) (hopen : ruleIsWorldOpen r = true) :
    sgWorldOpen sg = true :=
  List.any_eq_true.mpr ⟨r, hmem, hopen⟩

instance sgWorldOpen_decidable (sg : SecurityGroupObs) : Decidable (sgWorldOpen sg = true) :=
  inferInstance
