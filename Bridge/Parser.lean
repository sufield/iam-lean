import Lean.Data.Json
import Bridge.Schema

/-! Unified JSONL parser. Reads lines, detects domain from content,
delegates to per-domain parsers, collects errors with line numbers. -/

namespace Bridge.Parser

open Lean (Json)

structure ParseError where
  line   : Nat
  reason : String
  deriving Repr

inductive ParsedLine where
  | compose  (json : Json)
  | network  (json : Json)
  | iam      (json : Json)
  | xaccount (json : Json)
  | celtype  (json : Json)

/-- Detect domain from a parsed JSON line.
Per-domain bridges use different record shapes; we probe for
distinguishing keys. -/
def detectDomain (j : Json) : Option Schema.Domain :=
  -- celtype records have a "kind" field
  if (j.getObjValAs? String "kind").toOption.isSome then
    some .celtype
  -- compose records have "chain_id" + "controls"
  else if (j.getObjValAs? String "chain_id").toOption.isSome then
    some .compose
  -- iam records have "principal" + "scenario" + "edges"
  else if (j.getObjValAs? String "scenario").toOption.isSome &&
          (j.getObjValAs? String "principal").toOption.isSome then
    some .iam
  -- xaccount records have "mechanism" + ("target" or "expected_verdict")
  else if (j.getObjValAs? String "mechanism").toOption.isSome then
    some .xaccount
  -- network records have "test" + "property" + "verdict"
  else if (j.getObjValAs? String "test").toOption.isSome &&
          (j.getObjValAs? String "property").toOption.isSome then
    some .network
  else
    none

/-- Parse a JSONL file into categorized lines with error collection. -/
def parseFile (content : String) : List ParsedLine × List ParseError := Id.run do
  let lines := content.splitOn "\n" |>.filter (· != "")
  let mut parsed : List ParsedLine := []
  let mut errors : List ParseError := []
  let mut lineNum := 0
  for line in lines do
    lineNum := lineNum + 1
    match Json.parse line with
    | .error e =>
      errors := errors ++ [⟨lineNum, s!"JSON parse error: {e}"⟩]
    | .ok j =>
      match detectDomain j with
      | some .compose  => parsed := parsed ++ [.compose j]
      | some .network  => parsed := parsed ++ [.network j]
      | some .iam      => parsed := parsed ++ [.iam j]
      | some .xaccount => parsed := parsed ++ [.xaccount j]
      | some .celtype  => parsed := parsed ++ [.celtype j]
      | none =>
        errors := errors ++ [⟨lineNum, "unrecognized record shape"⟩]
  (parsed, errors)

/-- Parse and partition a JSONL file by domain. -/
def partitionByDomain (content : String) :
    List Json × List Json × List Json × List Json × List Json × List ParseError := Id.run do
  let (lines, errors) := parseFile content
  let mut compose : List Json := []
  let mut network : List Json := []
  let mut iam : List Json := []
  let mut xaccount : List Json := []
  let mut celtype : List Json := []
  for line in lines do
    match line with
    | .compose j  => compose := compose ++ [j]
    | .network j  => network := network ++ [j]
    | .iam j      => iam := iam ++ [j]
    | .xaccount j => xaccount := xaccount ++ [j]
    | .celtype j  => celtype := celtype ++ [j]
  (compose, network, iam, xaccount, celtype, errors)

end Bridge.Parser
