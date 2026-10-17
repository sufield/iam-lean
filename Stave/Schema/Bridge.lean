import Lean.Data.Json
import Stave.Schema.Contract

/-! Contract test bridge for the CEL predicate type system.
Parses JSONL records exported by lean-celtype-bridge,
validates structural properties of the catalog, contract,
and capability vocabulary.

Four record kinds:
  catalog_summary: aggregate counts
  control: per-control identity + field paths
  contract_field: per-field from collector-contract.yaml
  capability: per-capability with chain reference count
-/

open Lean (Json toJson FromJson)

namespace CelType.Bridge

structure CatalogSummaryRecord where
  controlCount : Nat
  assetTypeCount : Nat
  operatorCount : Nat
deriving Repr

structure ControlRecord where
  id : String
  severity : String
  controlType : String
  classification : String
  assetTypes : List String
  fieldPaths : List String
  observationFields : List String
deriving Repr

structure ContractFieldRecord where
  path : String
  fieldType : String
  consumerCount : Nat
  consumers : List String
deriving Repr

structure CapabilityRec where
  name : String
  chainCount : Nat
deriving Repr

def parseSeverity : String → Option Severity
  | "info" => some .info
  | "low" => some .low
  | "medium" => some .medium
  | "high" => some .high
  | "critical" => some .critical
  | _ => none

def parseControlType : String → Option ControlType
  | "unsafe_state" => some .unsafeState
  | "unsafe_duration" => some .unsafeDuration
  | "unsafe_recurrence" => some .unsafeRecurrence
  | "prefix_exposure" => some .prefixExposure
  | "marker" => some .marker
  | _ => none

def parseClassification : String → Option Classification
  | "state_assertion" => some .stateAssertion
  | "parameterized_check" => some .parameterizedCheck
  | "absence_check" => some .absenceCheck
  | "aggregate_check" => some .aggregateCheck
  | _ => none

def parseFieldType : String → Option FieldType
  | "boolean" => some .boolean
  | "string" => some .string
  | "integer" => some .integer
  | "number" => some .number
  | "list" => some .list
  | "object" => some .object
  | _ => none

def parseOperator : String → Option Operator
  | "eq" => some .eq
  | "ne" => some .ne
  | "gt" => some .gt
  | "lt" => some .lt
  | "gte" => some .gte
  | "lte" => some .lte
  | "missing" => some .missing
  | "present" => some .present
  | "in" => some .in
  | "list_empty" => some .listEmpty
  | "not_subset_of_field" => some .notSubsetOfField
  | "neq_field" => some .neqField
  | "not_in_field" => some .notInField
  | "contains" => some .contains
  | "any_match" => some .anyMatch
  | "any_identity_match" => some .anyIdentityMatch
  | "any_in_field" => some .anyInField
  | _ => none

def getJsonStringArray (j : Json) (key : String) : List String :=
  match j.getObjValAs? (List String) key with
  | .ok arr => arr
  | .error _ =>
    match j.getObjValAs? Json key with
    | .ok .null => []
    | _ => []

def parseCatalogSummary (j : Json) : Except String CatalogSummaryRecord := do
  let controlCount ← j.getObjValAs? Nat "control_count"
  let assetTypeCount ← j.getObjValAs? Nat "asset_type_count"
  let operatorCount ← j.getObjValAs? Nat "operator_count"
  pure { controlCount, assetTypeCount, operatorCount }

def parseControlRecord (j : Json) : Except String ControlRecord := do
  let id ← j.getObjValAs? String "id"
  let severity ← j.getObjValAs? String "severity"
  let controlType ← j.getObjValAs? String "type"
  let classification ← j.getObjValAs? String "classification"
  let assetTypes := getJsonStringArray j "asset_types"
  let fieldPaths := getJsonStringArray j "field_paths"
  let observationFields := getJsonStringArray j "observation_fields"
  pure { id, severity, controlType, classification, assetTypes, fieldPaths, observationFields }

def parseContractFieldRecord (j : Json) : Except String ContractFieldRecord := do
  let path ← j.getObjValAs? String "path"
  let fieldType ← j.getObjValAs? String "type"
  let consumerCount ← j.getObjValAs? Nat "consumer_count"
  let consumers := getJsonStringArray j "consumers"
  pure { path, fieldType, consumerCount, consumers }

def parseCapabilityRec (j : Json) : Except String CapabilityRec := do
  let name ← j.getObjValAs? String "name"
  let chainCount ← j.getObjValAs? Nat "chain_count"
  pure { name, chainCount }

/-! ### Checks -/

def checkCatalogSummary (r : CatalogSummaryRecord) : Bool × String :=
  if r.controlCount == 0 then
    (false, s!"FAIL: catalog_summary control_count is 0")
  else if r.assetTypeCount == 0 then
    (false, s!"FAIL: catalog_summary asset_type_count is 0")
  else if r.operatorCount > 17 then
    (false, s!"FAIL: catalog_summary operator_count {r.operatorCount} exceeds 17 known operators")
  else
    (true, s!"PASS: catalog_summary controls={r.controlCount} assets={r.assetTypeCount} ops={r.operatorCount}")

def checkControlRecord (r : ControlRecord) : Bool × String :=
  let sevOk := (parseSeverity r.severity).isSome
  let typeOk := (parseControlType r.controlType).isSome
  let classOk := (parseClassification r.classification).isSome
  let assetOk := r.assetTypes.all validAssetType
  if !sevOk then
    (false, s!"FAIL: {r.id} unknown severity '{r.severity}'")
  else if !typeOk then
    (false, s!"FAIL: {r.id} unknown type '{r.controlType}'")
  else if !classOk then
    (false, s!"FAIL: {r.id} unknown classification '{r.classification}'")
  else if !assetOk then
    (false, s!"FAIL: {r.id} invalid asset type in {r.assetTypes}")
  else
    (true, s!"PASS: {r.id}")

def checkContractField (r : ContractFieldRecord) : Bool × String :=
  let typeOk := (parseFieldType r.fieldType).isSome
  let countOk := r.consumerCount == r.consumers.length
  if !typeOk then
    (false, s!"FAIL: contract field '{r.path}' unknown type '{r.fieldType}'")
  else if !countOk then
    (false, s!"FAIL: contract field '{r.path}' consumer_count={r.consumerCount} but list has {r.consumers.length}")
  else
    (true, s!"PASS: {r.path}")

def checkCapability (r : CapabilityRec) : Bool × String :=
  if r.chainCount == 0 then
    (false, s!"FAIL: capability '{r.name}' has zero chain references")
  else
    (true, s!"PASS: capability {r.name} chains={r.chainCount}")

/-! ### Main bridge check -/

def bridgeCheck (path : System.FilePath) : IO UInt32 := do
  let content ← IO.FS.readFile path
  let lines := content.splitOn "\n" |>.filter (· != "")
  let mut total := 0
  let mut passed := 0
  let mut failed := 0
  let mut failures : List String := []

  for line in lines do
    match Json.parse line with
    | .error _ => pure ()
    | .ok j =>
      match j.getObjValAs? String "kind" with
      | .error _ => pure ()
      | .ok kind =>
        let result ← match kind with
          | "catalog_summary" =>
            match parseCatalogSummary j with
            | .ok r => pure (some (checkCatalogSummary r))
            | .error _ => pure none
          | "control" =>
            match parseControlRecord j with
            | .ok r => pure (some (checkControlRecord r))
            | .error _ => pure none
          | "contract_field" =>
            match parseContractFieldRecord j with
            | .ok r => pure (some (checkContractField r))
            | .error _ => pure none
          | "capability" =>
            match parseCapabilityRec j with
            | .ok r => pure (some (checkCapability r))
            | .error _ => pure none
          | _ => pure none
        match result with
        | none => pure ()
        | some (ok, msg) =>
          total := total + 1
          if ok then
            passed := passed + 1
          else
            failed := failed + 1
            failures := failures ++ [msg]

  IO.println s!"CEL type bridge check: {total} total, {passed} passed, {failed} failed"
  for msg in failures do
    IO.println s!"  {msg}"

  if failed > 0 then
    IO.println "FAIL: disagreements found"
    return 1
  else
    IO.println "PASS: Lean CEL type model agrees on all records"
    return 0

end CelType.Bridge
