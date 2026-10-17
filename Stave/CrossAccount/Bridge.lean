import Lean.Data.Json
import Stave.CrossAccount.Grant
import Stave.CrossAccount.Coverage

/-! Contract test bridge for cross-account trust model.
Parses JSONL records, evaluates Lean predicates, compares results.

Two record types:
  Grant record: tests wildcardGrant, conditionedGrant, scopedGrant
  Coverage record: tests pairCoverage verdict
-/

open Lean (Json toJson FromJson)

namespace XAccount.Bridge

structure GrantRecord where
  scenario : String
  target : String
  service : String
  mechanism : String
  hasExternalId : Bool
  hasOrgCondition : Bool
  hasIpCondition : Bool
  hasMfaRequired : Bool
  hasSourceArn : Bool
  hasSourceAccount : Bool
  expectedWildcard : Bool
  expectedConditioned : Bool
  expectedScoped : Bool
deriving Repr

structure CoverageRecord where
  scenario : String
  service : String
  mechanism : String
  direction : String
  expectedVerdict : String
deriving Repr

def parseMechanism : String → Option Mechanism
  | "resourcePolicy" => some .resourcePolicy
  | "trustPolicy" => some .trustPolicy
  | "grant" => some .grant
  | "accessPoint" => some .accessPoint
  | "sharingAPI" => some .sharingAPI
  | "replicationConfig" => some .replicationConfig
  | "accessEntry" => some .accessEntry
  | "podIdentity" => some .podIdentity
  | "oidcFederation" => some .oidcFederation
  | "invitationDelegation" => some .invitationDelegation
  | "attributeShare" => some .attributeShare
  | "association" => some .association
  | "ramShare" => some .ramShare
  | _ => none

def parseDirection : String → Option Direction
  | "inboundGrant" => some .inboundGrant
  | "outboundFlow" => some .outboundFlow
  | "both" => some .both
  | _ => none

def verdictToString : CoverageVerdict → String
  | .covered => "covered"
  | .uncovered => "uncovered"
  | .oos => "oos"
  | .schemaBlocked => "schemaBlocked"
  | .evidenceGated => "evidenceGated"

def parseGrantRecord (j : Json) : Except String GrantRecord := do
  let scenario ← j.getObjValAs? String "scenario"
  let target ← j.getObjValAs? String "target"
  let service ← j.getObjValAs? String "service"
  let mechanism ← j.getObjValAs? String "mechanism"
  let hasExternalId ← j.getObjValAs? Bool "has_external_id"
  let hasOrgCondition ← j.getObjValAs? Bool "has_org_condition"
  let hasIpCondition ← j.getObjValAs? Bool "has_ip_condition"
  let hasMfaRequired ← j.getObjValAs? Bool "has_mfa_required"
  let hasSourceArn ← j.getObjValAs? Bool "has_source_arn"
  let hasSourceAccount ← j.getObjValAs? Bool "has_source_account"
  let expectedWildcard ← j.getObjValAs? Bool "expected_wildcard"
  let expectedConditioned ← j.getObjValAs? Bool "expected_conditioned"
  let expectedScoped ← j.getObjValAs? Bool "expected_scoped"
  pure { scenario, target, service, mechanism, hasExternalId, hasOrgCondition,
         hasIpCondition, hasMfaRequired, hasSourceArn, hasSourceAccount,
         expectedWildcard, expectedConditioned, expectedScoped }

def parseCoverageRecord (j : Json) : Except String CoverageRecord := do
  let scenario ← j.getObjValAs? String "scenario"
  let service ← j.getObjValAs? String "service"
  let mechanism ← j.getObjValAs? String "mechanism"
  let direction ← j.getObjValAs? String "direction"
  let expectedVerdict ← j.getObjValAs? String "expected_verdict"
  pure { scenario, service, mechanism, direction, expectedVerdict }

def checkGrantRecord (r : GrantRecord) : Bool × String :=
  match parseMechanism r.mechanism with
  | none => (false, s!"unknown mechanism: {r.mechanism}")
  | some mech =>
    let g : TrustGrant := {
      source := "src-account"
      target := r.target
      service := r.service
      mechanism := mech
      conditions := {
        hasExternalId := r.hasExternalId
        hasOrgCondition := r.hasOrgCondition
        hasIpCondition := r.hasIpCondition
        hasMfaRequired := r.hasMfaRequired
        hasSourceArn := r.hasSourceArn
        hasSourceAccount := r.hasSourceAccount
      }
    }
    let wc := wildcardGrant g
    let cd := conditionedGrant g
    let sc := scopedGrant g
    if wc == r.expectedWildcard && cd == r.expectedConditioned && sc == r.expectedScoped then
      (true, s!"PASS: {r.scenario} wildcard={wc} conditioned={cd} scoped={sc}")
    else
      (false, s!"FAIL: {r.scenario} wildcard={wc}(exp={r.expectedWildcard}) conditioned={cd}(exp={r.expectedConditioned}) scoped={sc}(exp={r.expectedScoped})")

def checkCoverageRecord (r : CoverageRecord) : Bool × String :=
  match parseMechanism r.mechanism, parseDirection r.direction with
  | some mech, some dir =>
    let pair : TrustPair := ⟨r.service, mech, dir⟩
    let actual := verdictToString (pairCoverage pair)
    if actual == r.expectedVerdict then
      (true, s!"PASS: {r.scenario} verdict={actual}")
    else
      (false, s!"FAIL: {r.scenario} actual={actual} expected={r.expectedVerdict}")
  | none, _ => (false, s!"unknown mechanism: {r.mechanism}")
  | _, none => (false, s!"unknown direction: {r.direction}")

def parseAndCheckLine (line : String) : Option (Bool × String) :=
  match Json.parse line with
  | .error _ => none
  | .ok j =>
    if (j.getObjValAs? String "expected_verdict").toOption.isSome then
      match parseCoverageRecord j with
      | .ok r => some (checkCoverageRecord r)
      | .error _ => none
    else
      match parseGrantRecord j with
      | .ok r => some (checkGrantRecord r)
      | .error _ => none

def bridgeCheck (path : System.FilePath) : IO UInt32 := do
  let content ← IO.FS.readFile path
  let lines := content.splitOn "\n" |>.filter (· != "")
  let mut total := 0
  let mut passed := 0
  let mut failed := 0
  let mut failures : List String := []

  for line in lines do
    match parseAndCheckLine line with
    | none => pure ()
    | some (ok, msg) =>
      total := total + 1
      if ok then
        passed := passed + 1
      else
        failed := failed + 1
        failures := failures ++ [msg]

  IO.println s!"CrossAccount bridge check: {total} total, {passed} passed, {failed} failed"
  for msg in failures do
    IO.println s!"  {msg}"

  if failed > 0 then
    IO.println "FAIL: disagreements found"
    return 1
  else
    IO.println "PASS: Lean cross-account model agrees on all records"
    return 0

end XAccount.Bridge
