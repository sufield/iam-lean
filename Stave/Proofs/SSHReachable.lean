import Stave.Controls.SSHReachable

theorem isSshReachable_sound (inst : EC2InstanceObs) (subnet : SubnetObs)
    (sg : SecurityGroupObs) (h : isSshReachable inst subnet sg = true) :
    inst.publicIp.isSome = true ∧ subnet.hasRouteToIgw = true ∧
    sgAllowsInbound sg 22 "0.0.0.0/0" = true := by
  simp only [isSshReachable, Bool.and_eq_true] at h
  exact ⟨h.1.1, h.1.2, h.2⟩

theorem isSshReachable_complete (inst : EC2InstanceObs) (subnet : SubnetObs)
    (sg : SecurityGroupObs)
    (h1 : inst.publicIp.isSome = true) (h2 : subnet.hasRouteToIgw = true)
    (h3 : sgAllowsInbound sg 22 "0.0.0.0/0" = true) :
    isSshReachable inst subnet sg = true := by
  simp [isSshReachable, h1, h2, h3]

instance isSshReachable_decidable (inst : EC2InstanceObs) (subnet : SubnetObs)
    (sg : SecurityGroupObs) : Decidable (isSshReachable inst subnet sg = true) := inferInstance
