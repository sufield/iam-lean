import Lean.Data.Json
import Seclib.Compose.Distance

/-! Contract test bridge: parse JSONL from the Go engine export,
run chainFires / chainDistance on the same inputs, compare verdicts.
Go source: bridge_gen.py produces the JSONL; this module consumes it. -/

open Lean (Json toJson FromJson)

structure BridgeRecord where
  chainId : String
  controls : List String
  threshold : Nat
  failing : List String
  verdict : String  -- "fires" or "near_miss"
  distance : Nat
deriving Repr

instance : FromJson BridgeRecord where
  fromJson? j := do
    let chainId ← j.getObjValAs? String "chain_id"
    let controls ← j.getObjValAs? (List String) "controls"
    let threshold ← j.getObjValAs? Nat "threshold"
    let failing ← j.getObjValAs? (List String) "failing"
    let verdict ← j.getObjValAs? String "verdict"
    let distance ← j.getObjValAs? Nat "distance"
    pure { chainId, controls, threshold, failing, verdict, distance }

/-- Build a ChainDef from a bridge record. Returns none if structural
    invariants don't hold (< 2 controls or threshold out of range). -/
def mkChainDef (r : BridgeRecord) : Option ChainDef :=
  if h1 : r.controls.length ≥ 2 then
    if h2 : r.threshold ≥ 1 then
      if h3 : r.threshold ≤ r.controls.length then
        some {
          id := r.chainId
          controls := r.controls
          threshold := r.threshold
          severity := .high
          hMin := h1
          hThreshPos := h2
          hThreshBound := h3
        }
      else none
    else none
  else none

structure CheckResult where
  total : Nat
  passed : Nat
  failed : Nat
  skipped : Nat
  failures : List String
deriving Repr

/-- Check one bridge record against the Lean composition model. -/
def checkRecord (r : BridgeRecord) : Option String :=
  match mkChainDef r with
  | none => none  -- skip records with < 2 controls (threshold-1 chains)
  | some chain =>
    let fires := chainFiresB chain r.failing
    let dist := chainDistance chain r.failing
    let goFires := r.verdict == "fires"
    let goDist := r.distance
    if fires != goFires then
      some s!"MISMATCH {r.chainId}: Lean fires={fires}, Go verdict={r.verdict}"
    else if dist != goDist then
      some s!"DISTANCE {r.chainId}: Lean dist={dist}, Go dist={goDist}"
    else
      none

/-- Run the bridge checker on parsed records. -/
def checkAll (records : List BridgeRecord) : CheckResult := Id.run do
  let mut total := 0
  let mut passed := 0
  let mut failed := 0
  let mut skipped := 0
  let mut failures : List String := []
  for r in records do
    total := total + 1
    match mkChainDef r with
    | none => skipped := skipped + 1
    | some _ =>
      match checkRecord r with
      | none => passed := passed + 1
      | some msg =>
        failed := failed + 1
        failures := failures ++ [msg]
  { total, passed, failed, skipped, failures }

/-- Parse a JSONL string into bridge records. -/
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

/-- Main bridge checker entry point. -/
def bridgeCheck (path : System.FilePath) : IO UInt32 := do
  let content ← IO.FS.readFile path
  let records := parseJsonl content
  let result := checkAll records
  IO.println s!"Bridge check: {result.total} total, {result.passed} passed, {result.failed} failed, {result.skipped} skipped"
  for msg in result.failures do
    IO.println s!"  {msg}"
  if result.failed > 0 then
    IO.println "FAIL: disagreements found"
    return 1
  else
    IO.println "PASS: Lean and Go agree on all records"
    return 0
