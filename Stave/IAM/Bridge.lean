import Lean.Data.Json
import Stave.IAM.Distance

/-! Contract test bridge for IAM privilege reachability.
Parses JSONL records with privilege graph + expected verdicts,
evaluates the Lean model, and compares results.

Record format (one JSON per line):
  { "principal": "<id>", "scenario": "<name>",
    "edges": [["from", "to"], ...],
    "actions": [["principal", "action"], ...],
    "conditions": [["role", "key"], ...],
    "expected_distance": <0|1|2> }
-/

open Lean (Json toJson FromJson)

namespace IAM.Bridge

/-- A bridge test record. -/
structure BridgeRecord where
  principal : String
  scenario : String
  edges : List (String × String)
  actions : List (String × String)
  conditions : List (String × String)
  expectedDistance : Nat
deriving Repr

instance : FromJson BridgeRecord where
  fromJson? j := do
    let principal ← j.getObjValAs? String "principal"
    let scenario ← j.getObjValAs? String "scenario"
    let edgesArr ← j.getObjValAs? (Array Json) "edges"
    let actionsArr ← j.getObjValAs? (Array Json) "actions"
    let conditionsArr ← j.getObjValAs? (Array Json) "conditions"
    let expectedDistance ← j.getObjValAs? Nat "expected_distance"
    let parsePair (j : Json) : Except String (String × String) := do
      let arr ← j.getArr?
      if arr.size != 2 then throw "expected pair"
      let a ← arr[0]!.getStr?
      let b ← arr[1]!.getStr?
      pure (a, b)
    let edges ← edgesArr.toList.mapM parsePair
    let actions ← actionsArr.toList.mapM parsePair
    let conditions ← conditionsArr.toList.mapM parsePair
    pure { principal, scenario, edges, actions, conditions, expectedDistance }

/-- Parse an escalation scenario name to the enum. -/
def parseScenario : String → Option EscalationScenario
  | "addUserToGroup" => some .addUserToGroup
  | "attachRolePolicy" => some .attachRolePolicy
  | "attachGroupPolicy" => some .attachGroupPolicy
  | "attachUserPolicy" => some .attachUserPolicy
  | "putGroupPolicy" => some .putGroupPolicy
  | "putRolePolicy" => some .putRolePolicy
  | "putUserPolicy" => some .putUserPolicy
  | "createLoginProfile" => some .createLoginProfile
  | "updateLoginProfile" => some .updateLoginProfile
  | "createPolicyVersion" => some .createPolicyVersion
  | _ => none

/-- Build an IAMGraph from a bridge record's edges, actions, and conditions. -/
def BridgeRecord.toGraph (r : BridgeRecord) : IAMGraph where
  principals := []
  canAssume := r.edges
  actions := r.actions
  resources := []
  denyActions := []
  denyResources := []
  trustConditions := r.conditions.map fun (role, key) =>
    { roleId := role, conditionKey := key }
  permBoundaryActions := []
  scpDenyStatements := []
  externalTrusts := []

/-- Check one bridge record: compare actual vs expected distance. -/
def checkRecord (r : BridgeRecord) : Bool × String :=
  match parseScenario r.scenario with
  | none => (false, s!"unknown scenario: {r.scenario}")
  | some scenario =>
    let g := r.toGraph
    let actual := escalationDistance g r.principal scenario
    if actual == r.expectedDistance then
      (true, s!"PASS: {r.principal}/{r.scenario} distance={actual}")
    else
      (false, s!"FAIL: {r.principal}/{r.scenario} expected={r.expectedDistance} actual={actual}")

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

/-- Check all records via IO, printing results. -/
def bridgeCheck (path : System.FilePath) : IO UInt32 := do
  let content ← IO.FS.readFile path
  let records := parseJsonl content
  let mut total := 0
  let mut passed := 0
  let mut failed := 0
  let mut failures : List String := []

  for r in records do
    total := total + 1
    let (ok, msg) := checkRecord r
    if ok then
      passed := passed + 1
    else
      failed := failed + 1
      failures := failures ++ [msg]

  IO.println s!"IAM bridge check: {total} total, {passed} passed, {failed} failed"
  for msg in failures do
    IO.println s!"  {msg}"

  if failed > 0 then
    IO.println "FAIL: disagreements found"
    return 1
  else
    IO.println "PASS: Lean IAM model agrees on all records"
    return 0

end IAM.Bridge
