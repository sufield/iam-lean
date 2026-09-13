import Stave.Controls.SGInbound

theorem sgAllowsInbound_sound (sg : SecurityGroupObs) (port : Nat) (source : String)
    (h : sgAllowsInbound sg port source = true) :
    ∃ r ∈ sg.ingressRules, r.fromPort ≤ port ∧ port ≤ r.toPort ∧ r.cidrIp = some source := by
  simp only [sgAllowsInbound] at h
  obtain ⟨r, hr, hpred⟩ := List.any_eq_true.mp h
  simp only [Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at hpred
  exact ⟨r, hr, hpred.1.1, hpred.1.2, hpred.2⟩

theorem sgAllowsInbound_complete (sg : SecurityGroupObs) (port : Nat) (source : String)
    (r : IngressRule) (hr : r ∈ sg.ingressRules)
    (hfrom : r.fromPort ≤ port) (hto : port ≤ r.toPort) (hcidr : r.cidrIp = some source) :
    sgAllowsInbound sg port source = true := by
  simp only [sgAllowsInbound]
  exact List.any_eq_true.mpr ⟨r, hr, by simp [hfrom, hto, hcidr]⟩

instance sgAllowsInbound_decidable (sg : SecurityGroupObs) (port : Nat) (source : String) :
    Decidable (sgAllowsInbound sg port source = true) := inferInstance
