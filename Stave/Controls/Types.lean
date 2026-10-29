import Stave.Evaluate.Observation
import Stave.Basic.Finding

/-! Typed observation structures for the 8 HN practitioner controls.
Each structure projects exactly the fields its controls read --
no more, no less. These are the Lean-side obs.v0.1 types. -/

-- CloudTrail trail observations (controls 1, 5, 8)
structure CloudTrailObs where
  kind : Option String := none
  is_organization_trail : Option Bool := none
  is_multi_region : Option Bool := none
  log_file_validation_enabled : Option Bool := none
  deriving Repr, BEq

-- Organization SCP observations (control 2)
structure OrgSCPObs where
  kind : Option String := none
  region_restriction_has_scp : Option Bool := none
  deriving Repr, BEq

-- IAM account root observations (controls 3, 4)
structure IAMAccountObs where
  kind : Option String := none
  root_mfa_enabled : Option Bool := none
  root_has_access_keys : Option Bool := none
  deriving Repr, BEq

-- IAM user console observations (control 6)
structure IAMUserObs where
  kind : Option String := none
  console_access_enabled : Option Bool := none
  console_access_mfa_enabled : Option Bool := none
  deriving Repr, BEq

-- Security group observations (control 7)
structure SecurityGroupObs where
  kind : Option String := none
  has_unrestricted_ingress : Option Bool := none
  deriving Repr, BEq

/-- A typed control evaluation result with control ID. -/
structure ControlResult where
  controlId : ControlId
  outcome : EvalOutcome
  deriving Repr, BEq
