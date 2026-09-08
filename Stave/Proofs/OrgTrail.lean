import Stave.Controls.OrgTrail

theorem trailOrgWide_sound (t : TrailObs) (h : trailOrgWide t = true) :
    t.isOrganizationTrail = true ∧ t.isMultiRegion = true ∧ t.isLogging = true := by
  simp [trailOrgWide, and_assoc] at h; exact h

theorem trailOrgWide_complete (t : TrailObs)
    (h1 : t.isOrganizationTrail = true) (h2 : t.isMultiRegion = true)
    (h3 : t.isLogging = true) : trailOrgWide t = true := by
  simp [trailOrgWide, h1, h2, h3]

instance trailOrgWide_decidable (t : TrailObs) : Decidable (trailOrgWide t = true) :=
  inferInstance
