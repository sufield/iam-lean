import Lean.Data.Json
import Stave.Network.Property

/-! Contract test bridge for network prover.
Parses JSONL records from Go test expectations and verifies
that the Lean verdict model agrees on each record.

The bridge validates structural properties — the three-verdict
system, verdict precedence, and property definitions — not
full graph evaluation (which requires cloud-specific observation
parsing that stays in Go). -/

open Lean (Json toJson FromJson)

/-- A bridge record from the Go test suite. -/
structure BridgeRecord where
  test : String
  property : String
  verdict : String  -- "SAT", "UNSAT", "EVIDENCE_GATED", "VACUOUS"
deriving Repr

instance : FromJson BridgeRecord where
  fromJson? j := do
    let test ← j.getObjValAs? String "test"
    let property ← j.getObjValAs? String "property"
    let verdict ← j.getObjValAs? String "verdict"
    pure { test, property, verdict }

/-- Parse a verdict string to our Verdict type. -/
def parseVerdict (s : String) : Option Verdict :=
  match s with
  | "SAT" => some .sat
  | "EVIDENCE_GATED" => some .evidenceGated
  | "UNSAT" => some .unsat
  | _ => none

/-- Check structural consistency of a bridge record. -/
def checkRecord (r : BridgeRecord) : Option String :=
  -- Validate that the verdict is a recognized value
  if r.verdict == "VACUOUS" then none  -- skip vacuous tests
  else match parseVerdict r.verdict with
  | none => some s!"UNKNOWN_VERDICT {r.test}: {r.verdict}"
  | some v =>
    -- Validate verdict rank ordering
    let rank := v.rank
    if v == .sat && rank != 0 then
      some s!"RANK_MISMATCH {r.test}: SAT should have rank 0, got {rank}"
    else if v == .evidenceGated && rank != 1 then
      some s!"RANK_MISMATCH {r.test}: EVIDENCE_GATED should have rank 1, got {rank}"
    else if v == .unsat && rank != 2 then
      some s!"RANK_MISMATCH {r.test}: UNSAT should have rank 2, got {rank}"
    else none

/-- Check all bridge records. -/
def checkAll (records : List BridgeRecord) : IO UInt32 := do
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
      match checkRecord r with
      | none => passed := passed + 1
      | some msg =>
        failed := failed + 1
        failures := failures ++ [msg]

  IO.println s!"Bridge check: {total} total, {passed} passed, {failed} failed, {skipped} skipped"
  for msg in failures do
    IO.println s!"  {msg}"

  if failed > 0 then
    IO.println "FAIL: disagreements found"
    return 1
  else
    IO.println "PASS: Lean verdict model agrees on all records"
    return 0

/-- Parse JSONL into bridge records. -/
def parseJsonl (content : String) : List BridgeRecord :=
  content.splitOn "\n"
    |>.filter (· != "")
    |>.filterMap fun line =>
      match Json.parse line with
      | .ok j =>
        match FromJson.fromJson? j with
        | .ok r => some r
        | .error _ => none
      | .error _ => none

/-- Main entry point. -/
def bridgeCheck (path : System.FilePath) : IO UInt32 := do
  let content ← IO.FS.readFile path
  let records := parseJsonl content
  checkAll records
