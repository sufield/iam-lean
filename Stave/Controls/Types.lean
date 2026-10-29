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

-- IAM user observations (controls 6, CH2:6)
structure IAMUserObs where
  kind : Option String := none
  console_access_enabled : Option Bool := none
  console_access_mfa_enabled : Option Bool := none
  credentials_unused_days : Option Nat := none
  deriving Repr, BEq

-- Security group observations (control 7)
structure SecurityGroupObs where
  kind : Option String := none
  has_unrestricted_ingress : Option Bool := none
  deriving Repr, BEq

-- IAM account summary observations (CH2:7)
structure IAMSummaryObs where
  kind : Option String := none
  admin_user_count : Option Nat := none
  deriving Repr, BEq

-- CDN / CloudFront observations (CH2:1-4)
structure CDNObs where
  kind : Option String := none
  signed_url_default_expiry_seconds : Option Nat := none
  viewer_cert_days_until_expiry : Option Nat := none
  waf_web_acl_id : Option String := none
  policy_referenced : Option Bool := none
  deriving Repr, BEq

-- VPC endpoint observations (CH2:5)
structure VPCEndpointObs where
  kind : Option String := none
  service_name : Option String := none
  restricts_to_org_resources : Option Bool := none
  deriving Repr, BEq

-- S3 / storage observations (CH2:8)
structure StorageObs where
  kind : Option String := none
  data_classification : Option String := none
  deriving Repr, BEq

/-- A typed control evaluation result with control ID. -/
structure ControlResult where
  controlId : ControlId
  outcome : EvalOutcome
  deriving Repr, BEq
