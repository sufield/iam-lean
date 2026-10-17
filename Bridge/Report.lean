import Lean.Data.Json
import Bridge.Verify

/-! Structured report output. JSON to stdout, human summary to stderr. -/

open Lean (Json toJson ToJson)

namespace Bridge.Report

instance : ToJson Verify.DomainReport where
  toJson r := Json.mkObj [
    ("domain", toJson r.domain.toString),
    ("total", toJson r.total),
    ("agreed", toJson r.agreed),
    ("disagreed", toJson r.disagreed),
    ("skipped", toJson r.skipped),
    ("failures", toJson r.failures)
  ]

instance : ToJson Verify.VerificationReport where
  toJson r := Json.mkObj [
    ("total", toJson r.total),
    ("agreed", toJson r.agreed),
    ("disagreed", toJson r.disagreed),
    ("skipped", toJson r.skipped),
    ("domains", toJson r.domains),
    ("exit_code", toJson r.exitCode.toNat)
  ]

def writeJsonReport (r : Verify.VerificationReport) : IO Unit :=
  IO.println (toString (toJson r))

def writeSummary (r : Verify.VerificationReport) : IO Unit := do
  for d in r.domains do
    IO.eprintln s!"  {d.domain}: {d.total} total, {d.agreed} agreed, {d.disagreed} disagreed, {d.skipped} skipped"
    for f in d.failures do
      IO.eprintln s!"    {f}"
  IO.eprintln s!"Bridge: {r.total} total, {r.agreed} agreed, {r.disagreed} disagreed, {r.skipped} skipped"
  if r.disagreed > 0 then
    IO.eprintln "FAIL: disagreements found"
  else
    IO.eprintln "PASS: all domains agree"

end Bridge.Report
