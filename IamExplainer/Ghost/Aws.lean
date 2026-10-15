import Seclib.Ghost

/-! AWS-specific ghost reference kinds.
Maps each unresolvable reference type Stave encounters to its
default GhostAssumption. Imports from Seclib.Ghost (vendor-neutral);
every AWS-specific noun is in THIS module. -/

inductive AwsGhostKind where
  | managedPolicyArn (arn : String)
  | crossAccountRole (arn : String) (accountId : String)
  | serviceLinkedRole (servicePrincipal : String)
  | crossAccountResource (arn : String)
  | unmodeledService (arn : String)
deriving Repr, BEq, DecidableEq

def AwsGhostKind.defaultAssumption : AwsGhostKind → GhostAssumption
  | .managedPolicyArn _ => .overPermissive
  | .crossAccountRole _ _ => .overPermissive
  | .serviceLinkedRole _ =>
      .explicit [⟨"awsManaged", .bool true⟩]
  | .crossAccountResource _ => .overPermissive
  | .unmodeledService _ => .overPermissive

def AwsGhostKind.id : AwsGhostKind → String
  | .managedPolicyArn arn => arn
  | .crossAccountRole arn _ => arn
  | .serviceLinkedRole sp => s!"aws-service-role/{sp}"
  | .crossAccountResource arn => arn
  | .unmodeledService arn => arn

def AwsGhostKind.toRefStatus (kind : AwsGhostKind) : RefStatus α :=
  .ghost kind.id kind.defaultAssumption

/-! ### #guard tests -/

#guard (AwsGhostKind.managedPolicyArn "arn:aws:iam::aws:policy/ReadOnlyAccess").defaultAssumption
  == .overPermissive

#guard (AwsGhostKind.serviceLinkedRole "elasticmapreduce.amazonaws.com").defaultAssumption
  == .explicit [⟨"awsManaged", .bool true⟩]

#guard (AwsGhostKind.crossAccountRole "arn:aws:iam::999888777666:role/Audit" "999888777666").defaultAssumption
  == .overPermissive

#guard (AwsGhostKind.crossAccountResource "arn:aws:s3:::other-bucket").id
  == "arn:aws:s3:::other-bucket"
