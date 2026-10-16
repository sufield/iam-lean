import Stave.CrossAccount.Coverage

/-! What is NOT covered: explicit boundary of the cross-account model.
Go source: docs-internal/external-access-audit/ca-triage-table.md.
When Stave says "no cross-account finding," it means "no finding in
the covered pairs" — this module formalizes the complement. -/

/-- The 13 OOS pairs — services with negligible enterprise prevalence.
    Go source: ca-triage-table.md (13 OOS). -/
def oosPairs : List TrustPair :=
  [ ⟨"codeguruprofiler", .resourcePolicy, .inboundGrant⟩
  , ⟨"comprehend", .resourcePolicy, .inboundGrant⟩
  , ⟨"fms", .resourcePolicy, .inboundGrant⟩
  , ⟨"gamelift", .association, .both⟩
  , ⟨"lexv2-models", .resourcePolicy, .inboundGrant⟩
  , ⟨"license-manager", .grant, .inboundGrant⟩
  , ⟨"lookoutequipment", .resourcePolicy, .inboundGrant⟩
  , ⟨"marketplace-catalog", .resourcePolicy, .inboundGrant⟩
  , ⟨"mediaconvert", .resourcePolicy, .inboundGrant⟩
  , ⟨"migration-hub-refactor-spaces", .resourcePolicy, .inboundGrant⟩
  , ⟨"networkmanager", .association, .both⟩
  , ⟨"networkmanager", .resourcePolicy, .inboundGrant⟩
  , ⟨"schemas", .resourcePolicy, .inboundGrant⟩
  ]

/-- The 51 covered pairs — services with active controls. -/
def coveredPairs : List TrustPair :=
  allPairs.filter fun p => pairCoverage p == .covered

/-- Disclosure: when Stave reports no cross-account findings, it means
    "no finding in the covered 51 pairs." The 13 OOS pairs are not evaluated. -/
structure CrossAccountDisclosure where
  coveredCount : Nat := 51
  oosCount : Nat := 13
  totalPairs : Nat := 64
