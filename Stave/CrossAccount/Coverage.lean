import Stave.CrossAccount.Topology

/-! Coverage claims over the 64-pair taxonomy.
Go source: data/frameworks/cross-account-v1.yaml (make xa-inventory).
Terminal ledger: docs-internal/external-access-audit/ca-terminal-ledger.md.
64 total: 51 COVERED, 13 OOS. -/

/-- Coverage verdict for a service×mechanism×direction pair.
    Go source: cross-account-v1.yaml verdict field. -/
inductive CoverageVerdict where
  | covered
  | uncovered
  | oos
  | schemaBlocked
  | evidenceGated
deriving DecidableEq, Repr

/-- The 64-pair taxonomy as a decidable coverage function.
    Go source: cross-account-v1.yaml (55 services, 64 pairs).
    Encodes the terminal ledger: 51 COVERED, 13 OOS. -/
def pairCoverage : TrustPair → CoverageVerdict
  -- COVERED pairs (51) — representative sample, all resource-policy inbound-grants
  | ⟨"acm-pca", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"apigateway", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"backup", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"cloudtrail", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"codeartifact", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"codebuild", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"ds", .invitationDelegation, .inboundGrant⟩ => .covered
  | ⟨"dynamodb", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"ec2", .association, .both⟩ => .covered
  | ⟨"ec2", .attributeShare, .outboundFlow⟩ => .covered
  | ⟨"ecr", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"ecr-public", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"eks", .accessEntry, .inboundGrant⟩ => .covered
  | ⟨"eks", .podIdentity, .inboundGrant⟩ => .covered
  | ⟨"es", .association, .both⟩ => .covered
  | ⟨"events", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"glacier", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"glue", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"iam", .oidcFederation, .inboundGrant⟩ => .covered
  | ⟨"iam", .trustPolicy, .inboundGrant⟩ => .covered
  | ⟨"kinesis", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"kms", .grant, .inboundGrant⟩ => .covered
  | ⟨"kms", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"lakeformation", .association, .both⟩ => .covered
  | ⟨"lambda", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"logs", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"macie2", .invitationDelegation, .inboundGrant⟩ => .covered
  | ⟨"mediastore", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"network-firewall", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"opensearch", .association, .both⟩ => .covered
  | ⟨"organizations", .invitationDelegation, .inboundGrant⟩ => .covered
  | ⟨"organizations", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"ram", .ramShare, .outboundFlow⟩ => .covered
  | ⟨"redshift", .association, .both⟩ => .covered
  | ⟨"redshift", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"redshift-serverless", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"route53-recovery-control-config", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"s3", .accessPoint, .inboundGrant⟩ => .covered
  | ⟨"s3", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"s3control", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"secretsmanager", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"sns", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"sqs", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"ssm", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"ssm-incidents", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"vpc-lattice", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"waf", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"waf-regional", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"wafv2", .resourcePolicy, .inboundGrant⟩ => .covered
  | ⟨"xray", .resourcePolicy, .inboundGrant⟩ => .covered
  -- iam:federation is the third IAM pair
  | ⟨"iam", .association, .inboundGrant⟩ => .covered
  -- OOS pairs (13) — negligible prevalence or deprecated
  | ⟨"codeguruprofiler", .resourcePolicy, .inboundGrant⟩ => .oos
  | ⟨"comprehend", .resourcePolicy, .inboundGrant⟩ => .oos
  | ⟨"fms", .resourcePolicy, .inboundGrant⟩ => .oos
  | ⟨"gamelift", .association, .both⟩ => .oos
  | ⟨"lexv2-models", .resourcePolicy, .inboundGrant⟩ => .oos
  | ⟨"license-manager", .grant, .inboundGrant⟩ => .oos
  | ⟨"lookoutequipment", .resourcePolicy, .inboundGrant⟩ => .oos
  | ⟨"marketplace-catalog", .resourcePolicy, .inboundGrant⟩ => .oos
  | ⟨"mediaconvert", .resourcePolicy, .inboundGrant⟩ => .oos
  | ⟨"migration-hub-refactor-spaces", .resourcePolicy, .inboundGrant⟩ => .oos
  | ⟨"networkmanager", .association, .both⟩ => .oos
  | ⟨"networkmanager", .resourcePolicy, .inboundGrant⟩ => .oos
  | ⟨"schemas", .resourcePolicy, .inboundGrant⟩ => .oos
  -- Default: uncovered (any pair not enumerated above)
  | _ => .uncovered

/-- The set of all 64 pairs in the taxonomy. -/
def allPairs : List TrustPair :=
  [ ⟨"acm-pca", .resourcePolicy, .inboundGrant⟩
  , ⟨"apigateway", .resourcePolicy, .inboundGrant⟩
  , ⟨"backup", .resourcePolicy, .inboundGrant⟩
  , ⟨"cloudtrail", .resourcePolicy, .inboundGrant⟩
  , ⟨"codeartifact", .resourcePolicy, .inboundGrant⟩
  , ⟨"codebuild", .resourcePolicy, .inboundGrant⟩
  , ⟨"codeguruprofiler", .resourcePolicy, .inboundGrant⟩
  , ⟨"comprehend", .resourcePolicy, .inboundGrant⟩
  , ⟨"ds", .invitationDelegation, .inboundGrant⟩
  , ⟨"dynamodb", .resourcePolicy, .inboundGrant⟩
  , ⟨"ec2", .association, .both⟩
  , ⟨"ec2", .attributeShare, .outboundFlow⟩
  , ⟨"ecr", .resourcePolicy, .inboundGrant⟩
  , ⟨"ecr-public", .resourcePolicy, .inboundGrant⟩
  , ⟨"eks", .accessEntry, .inboundGrant⟩
  , ⟨"eks", .podIdentity, .inboundGrant⟩
  , ⟨"es", .association, .both⟩
  , ⟨"events", .resourcePolicy, .inboundGrant⟩
  , ⟨"fms", .resourcePolicy, .inboundGrant⟩
  , ⟨"gamelift", .association, .both⟩
  , ⟨"glacier", .resourcePolicy, .inboundGrant⟩
  , ⟨"glue", .resourcePolicy, .inboundGrant⟩
  , ⟨"iam", .oidcFederation, .inboundGrant⟩
  , ⟨"iam", .trustPolicy, .inboundGrant⟩
  , ⟨"iam", .association, .inboundGrant⟩
  , ⟨"kinesis", .resourcePolicy, .inboundGrant⟩
  , ⟨"kms", .grant, .inboundGrant⟩
  , ⟨"kms", .resourcePolicy, .inboundGrant⟩
  , ⟨"lakeformation", .association, .both⟩
  , ⟨"lambda", .resourcePolicy, .inboundGrant⟩
  , ⟨"lexv2-models", .resourcePolicy, .inboundGrant⟩
  , ⟨"license-manager", .grant, .inboundGrant⟩
  , ⟨"logs", .resourcePolicy, .inboundGrant⟩
  , ⟨"lookoutequipment", .resourcePolicy, .inboundGrant⟩
  , ⟨"macie2", .invitationDelegation, .inboundGrant⟩
  , ⟨"marketplace-catalog", .resourcePolicy, .inboundGrant⟩
  , ⟨"mediaconvert", .resourcePolicy, .inboundGrant⟩
  , ⟨"mediastore", .resourcePolicy, .inboundGrant⟩
  , ⟨"migration-hub-refactor-spaces", .resourcePolicy, .inboundGrant⟩
  , ⟨"network-firewall", .resourcePolicy, .inboundGrant⟩
  , ⟨"networkmanager", .association, .both⟩
  , ⟨"networkmanager", .resourcePolicy, .inboundGrant⟩
  , ⟨"opensearch", .association, .both⟩
  , ⟨"organizations", .invitationDelegation, .inboundGrant⟩
  , ⟨"organizations", .resourcePolicy, .inboundGrant⟩
  , ⟨"ram", .ramShare, .outboundFlow⟩
  , ⟨"redshift", .association, .both⟩
  , ⟨"redshift", .resourcePolicy, .inboundGrant⟩
  , ⟨"redshift-serverless", .resourcePolicy, .inboundGrant⟩
  , ⟨"route53-recovery-control-config", .resourcePolicy, .inboundGrant⟩
  , ⟨"s3", .accessPoint, .inboundGrant⟩
  , ⟨"s3", .resourcePolicy, .inboundGrant⟩
  , ⟨"s3control", .resourcePolicy, .inboundGrant⟩
  , ⟨"schemas", .resourcePolicy, .inboundGrant⟩
  , ⟨"secretsmanager", .resourcePolicy, .inboundGrant⟩
  , ⟨"sns", .resourcePolicy, .inboundGrant⟩
  , ⟨"sqs", .resourcePolicy, .inboundGrant⟩
  , ⟨"ssm", .resourcePolicy, .inboundGrant⟩
  , ⟨"ssm-incidents", .resourcePolicy, .inboundGrant⟩
  , ⟨"vpc-lattice", .resourcePolicy, .inboundGrant⟩
  , ⟨"waf", .resourcePolicy, .inboundGrant⟩
  , ⟨"waf-regional", .resourcePolicy, .inboundGrant⟩
  , ⟨"wafv2", .resourcePolicy, .inboundGrant⟩
  , ⟨"xray", .resourcePolicy, .inboundGrant⟩
  ]

/-- Whether a set of pairs is fully covered by the catalog. -/
def catalogCovers (pairs : List TrustPair) : Prop :=
  ∀ p ∈ pairs, pairCoverage p = .covered

instance (pairs : List TrustPair) : Decidable (catalogCovers pairs) :=
  inferInstanceAs (Decidable (∀ _, _))
