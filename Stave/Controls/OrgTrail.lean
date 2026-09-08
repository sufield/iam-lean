/-! Control 1: CloudTrail org-wide — detection blind-spot if missing. -/

structure TrailObs where
  trailArn            : String
  isOrganizationTrail : Bool
  isMultiRegion       : Bool
  isLogging           : Bool
deriving Repr, DecidableEq

def trailOrgWide (t : TrailObs) : Bool :=
  t.isOrganizationTrail && t.isMultiRegion && t.isLogging

section Tests

-- Green: fully configured org trail
#guard trailOrgWide ⟨"arn:trail/org", true, true, true⟩ == true
-- Red: not org-wide
#guard trailOrgWide ⟨"arn:trail/local", false, true, true⟩ == false
-- Red: single-region
#guard trailOrgWide ⟨"arn:trail/org", true, false, true⟩ == false
-- Red: logging off
#guard trailOrgWide ⟨"arn:trail/org", true, true, false⟩ == false
-- Red: all false
#guard trailOrgWide ⟨"arn:trail/none", false, false, false⟩ == false

end Tests
