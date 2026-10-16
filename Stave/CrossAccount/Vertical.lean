import Stave.Compose.Compose
import Stave.CrossAccount.Grant

/-! The 4 shipped vertical chain models.
Each chain decomposes into individually-necessary steps.
Go source: internal/chains/ + internal/fixtures/labs/xa-*. -/

/-- KMS grant chain: external-account grantee + no constraint = exploitable.
    Go source: CTL.KMS.GRANT.EXTERNAL.001.
    Fixture: internal/fixtures/labs/xa-kms-grants/. -/
def kmsGrantChain : ChainDef where
  id := "kms_grant_external"
  controls := ["CTL.KMS.GRANT.EXTERNAL.001", "CTL.KMS.CROSSACCOUNT.BLASTRADIUS.001"]
  threshold := 2
  severity := .critical
  hMin := by native_decide
  hThreshBound := by native_decide

/-- S3 access point chain: AP policy grants external + bucket allows AP.
    Go source: CTL.S3.AP.POLICY.EXTERNAL.001, CTL.S3.AP.CROSSACCOUNT.BUCKET.001.
    Fixture: internal/fixtures/labs/xa-s3-access-points/. -/
def s3APChain : ChainDef where
  id := "s3_ap_external"
  controls := ["CTL.S3.AP.POLICY.EXTERNAL.001", "CTL.S3.AP.CROSSACCOUNT.BUCKET.001"]
  threshold := 2
  severity := .high
  hMin := by native_decide
  hThreshBound := by native_decide

/-- EKS access entry chain: external admin + pod identity external.
    Go source: CTL.EKS.ACCESSENTRY.EXTERNAL.ADMIN.001, CTL.EKS.PODIDENTITY.EXTERNAL.001.
    Fixture: internal/fixtures/labs/xa-eks-access-entries/. -/
def eksAccessChain : ChainDef where
  id := "eks_access_external"
  controls := ["CTL.EKS.ACCESSENTRY.EXTERNAL.ADMIN.001", "CTL.EKS.ACCESSENTRY.EXTERNAL.001", "CTL.EKS.PODIDENTITY.EXTERNAL.001"]
  threshold := 2
  severity := .critical
  hMin := by native_decide
  hThreshBound := by native_decide

/-- OIDC claim scoping chain: unscoped or org-wildcard claim.
    Go source: CTL.IAM.TRUST.OIDC.001 + CTL.IAM.TRUST.OIDC.ORGWILDCARD.001.
    Fixture: internal/fixtures/labs/xa-oidc-claim-scoping/.
    Uses supply_chain_ingress chain shape. -/
def oidcClaimChain : ChainDef where
  id := "oidc_claim_scoping"
  controls := ["CTL.IAM.TRUST.OIDC.001", "CTL.IAM.TRUST.OIDC.002", "CTL.IAM.TRUST.OIDC.003", "CTL.IAM.TRUST.EXTERNALID.001"]
  threshold := 2
  severity := .critical
  hMin := by native_decide
  hThreshBound := by native_decide

/-- Step-level decomposition: fixing any one step of a chain breaks it.
    This is the abstract property — proved in Monotonicity. -/
def stepNecessary (chain : ChainDef) (failing : List ControlId) (step : ControlId) : Prop :=
  step ∈ chain.controls ∧
  step ∈ failing ∧
  failingCount chain failing = chain.threshold →
  ¬ chainFires chain (failing.filter (· ≠ step))
