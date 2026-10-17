import Bridge.Schema
import Bridge.Parser
import Stave.Compose.Bridge
import Stave.Network.Bridge
import Stave.IAM.Bridge
import Stave.CrossAccount.Bridge
import Stave.Schema.Bridge

/-! Verdict re-derivation. Delegates to each per-domain bridge's
existing checkAll/checkRecord logic, then aggregates results into
a unified report. -/

open Lean (Json FromJson)

namespace Bridge.Verify

inductive VerifyResult where
  | agree
  | disagree (lean go : String)
  | skip     (reason : String)
  deriving Repr

structure DomainReport where
  domain      : Schema.Domain
  total       : Nat
  agreed      : Nat
  disagreed   : Nat
  skipped     : Nat
  failures    : List String
  deriving Repr

structure VerificationReport where
  domains     : List DomainReport
  deriving Repr

def VerificationReport.total (r : VerificationReport) : Nat :=
  r.domains.foldl (· + ·.total) 0

def VerificationReport.agreed (r : VerificationReport) : Nat :=
  r.domains.foldl (· + ·.agreed) 0

def VerificationReport.disagreed (r : VerificationReport) : Nat :=
  r.domains.foldl (· + ·.disagreed) 0

def VerificationReport.skipped (r : VerificationReport) : Nat :=
  r.domains.foldl (· + ·.skipped) 0

def VerificationReport.allFailures (r : VerificationReport) : List String :=
  r.domains.flatMap (·.failures)

def VerificationReport.exitCode (r : VerificationReport) : UInt32 :=
  if r.disagreed > 0 then 1 else 0

/-- Verify compose records using Compose.Bridge logic. -/
def verifyCompose (jsons : List Json) : DomainReport := Id.run do
  let records := jsons.filterMap fun j =>
    match @FromJson.fromJson? Compose.Bridge.BridgeRecord _ j with
    | .ok r => some r
    | .error _ => none
  let result := Compose.Bridge.checkAll records
  { domain := .compose
    total := result.total
    agreed := result.passed
    disagreed := result.failed
    skipped := result.skipped
    failures := result.failures }

/-- Verify network records using Network.Bridge logic. -/
def verifyNetwork (jsons : List Json) : IO DomainReport := do
  let records := jsons.filterMap fun j =>
    match @FromJson.fromJson? Network.Bridge.BridgeRecord _ j with
    | .ok r => some r
    | .error _ => none
  let mut total := 0
  let mut passed := 0
  let mut failed := 0
  let mut skipped := 0
  let mut failures : List String := []
  for r in records do
    total := total + 1
    if r.verdict == "VACUOUS" then
      skipped := skipped + 1
    else
      match Network.Bridge.checkRecord r with
      | none => passed := passed + 1
      | some msg =>
        failed := failed + 1
        failures := failures ++ [msg]
  return { domain := .network
           total, agreed := passed, disagreed := failed, skipped
           failures }

/-- Verify IAM records using IAM.Bridge logic. -/
def verifyIAM (jsons : List Json) : DomainReport := Id.run do
  let records := jsons.filterMap fun j =>
    match @FromJson.fromJson? IAM.Bridge.BridgeRecord _ j with
    | .ok r => some r
    | .error _ => none
  let mut total := 0
  let mut passed := 0
  let mut failed := 0
  let mut failures : List String := []
  for r in records do
    total := total + 1
    let (ok, msg) := IAM.Bridge.checkRecord r
    if ok then passed := passed + 1
    else
      failed := failed + 1
      failures := failures ++ [msg]
  { domain := .iam, total, agreed := passed, disagreed := failed
    skipped := 0, failures }

/-- Verify cross-account records using XAccount.Bridge logic. -/
def verifyXAccount (jsons : List Json) : DomainReport := Id.run do
  let mut total := 0
  let mut passed := 0
  let mut failed := 0
  let mut failures : List String := []
  for j in jsons do
    match XAccount.Bridge.parseAndCheckLine (toString j) with
    | none => pure ()
    | some (ok, msg) =>
      total := total + 1
      if ok then passed := passed + 1
      else
        failed := failed + 1
        failures := failures ++ [msg]
  { domain := .xaccount, total, agreed := passed, disagreed := failed
    skipped := 0, failures }

/-- Verify CEL type records using CelType.Bridge logic. -/
def verifyCeltype (jsons : List Json) : DomainReport := Id.run do
  let mut total := 0
  let mut passed := 0
  let mut failed := 0
  let mut failures : List String := []
  for j in jsons do
    match j.getObjValAs? String "kind" with
    | .error _ => pure ()
    | .ok kind =>
      let result := match kind with
        | "catalog_summary" =>
          match CelType.Bridge.parseCatalogSummary j with
          | .ok r => some (CelType.Bridge.checkCatalogSummary r)
          | .error _ => none
        | "control" =>
          match CelType.Bridge.parseControlRecord j with
          | .ok r => some (CelType.Bridge.checkControlRecord r)
          | .error _ => none
        | "contract_field" =>
          match CelType.Bridge.parseContractFieldRecord j with
          | .ok r => some (CelType.Bridge.checkContractField r)
          | .error _ => none
        | "capability" =>
          match CelType.Bridge.parseCapabilityRec j with
          | .ok r => some (CelType.Bridge.checkCapability r)
          | .error _ => none
        | _ => none
      match result with
      | none => pure ()
      | some (ok, msg) =>
        total := total + 1
        if ok then passed := passed + 1
        else
          failed := failed + 1
          failures := failures ++ [msg]
  { domain := .celtype, total, agreed := passed, disagreed := failed
    skipped := 0, failures }

/-- Verify all records in a JSONL file. -/
def verifyFile (content : String) : IO VerificationReport := do
  let (compose, network, iam, xaccount, celtype, _errors) :=
    Parser.partitionByDomain content
  let mut domains : List DomainReport := []
  if !compose.isEmpty then
    domains := domains ++ [verifyCompose compose]
  if !network.isEmpty then
    let nr ← verifyNetwork network
    domains := domains ++ [nr]
  if !iam.isEmpty then
    domains := domains ++ [verifyIAM iam]
  if !xaccount.isEmpty then
    domains := domains ++ [verifyXAccount xaccount]
  if !celtype.isEmpty then
    domains := domains ++ [verifyCeltype celtype]
  return { domains }

end Bridge.Verify
