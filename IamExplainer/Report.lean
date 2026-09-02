import IamExplainer.Checks
import Lean.Data.Json

open Lean (Json ToJson)

structure Counts where
  critical : Nat := 0
  high     : Nat := 0
  medium   : Nat := 0
  low      : Nat := 0

def countFindings (fs : List Finding) : Counts :=
  fs.foldl (fun c f => match f.severity with
    | .critical => { c with critical := c.critical + 1 }
    | .high     => { c with high := c.high + 1 }
    | .medium   => { c with medium := c.medium + 1 }
    | .low      => { c with low := c.low + 1 }) {}

structure Report where
  verdict  : String
  findings : List Finding
  warnings : List ParseWarning
  counts   : Counts

def buildReport (findings : List Finding) (warnings : List ParseWarning) : Report :=
  let verdict := if findings.isEmpty then "pass" else "fail"
  { verdict, findings, warnings, counts := countFindings findings }

private def findingToJson (f : Finding) : Json :=
  .mkObj [
    ("control_id", .str f.controlId),
    ("severity", .str f.severity.toString),
    ("statement", .str f.location),
    ("evidence", .mkObj [("path", .str f.evidence.path), ("actual", .str f.evidence.actual)]),
    ("explanation", .str f.explanation),
    ("fix", .mkObj [("kind", .str f.fix.kind), ("suggestion", .str f.fix.suggestion)])
  ]

def reportToJson (r : Report) : Json :=
  .mkObj [
    ("verdict", .str r.verdict),
    ("findings", .arr (r.findings.map findingToJson).toArray),
    ("warnings", .arr (r.warnings.map ToJson.toJson).toArray),
    ("counts", .mkObj [
      ("critical", .num r.counts.critical),
      ("high", .num r.counts.high),
      ("medium", .num r.counts.medium),
      ("low", .num r.counts.low)
    ])
  ]

def renderText (r : Report) : String :=
  let header := s!"Verdict: {r.verdict} ({r.findings.length} finding(s))\n"
  let warns := r.warnings.foldl (fun acc w => acc ++ s!"  WARNING: {w.message}\n") ""
  let body := r.findings.foldl (fun acc f =>
    acc ++ s!"\n  [{f.severity}] {f.controlId}\n" ++
    s!"    Statement: {f.location}\n" ++
    s!"    Evidence:  {f.evidence.path} = {f.evidence.actual}\n" ++
    s!"    Explanation: {f.explanation}\n" ++
    s!"    Fix ({f.fix.kind}): {f.fix.suggestion}\n") ""
  header ++ warns ++ body
