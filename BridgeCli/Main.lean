import Bridge.Bridge

/-! Unified bridge CLI.

Subcommands:
  verify compose <file.jsonl>  — verify compose records
  verify network <file.jsonl>  — verify network records
  verify iam <file.jsonl>      — verify IAM records
  verify xaccount <file.jsonl> — verify cross-account records
  verify celtype <file.jsonl>  — verify CEL type records
  verify all <dir>             — verify all JSONL files in directory
  verify <file.jsonl>          — auto-detect domains and verify
  check-version <file.jsonl>   — check schema version compatibility
  version                      — print supported schema versions

Exit codes: 0 = all agree or skip, 1 = any disagree, 2 = usage error -/

open Bridge

/-- Verify a single file, auto-detecting domains. -/
def verifyOneFile (path : System.FilePath) : IO UInt32 := do
  let content ← IO.FS.readFile path
  let report ← Verify.verifyFile content
  Report.writeJsonReport report
  Report.writeSummary report
  return report.exitCode

/-- Verify a single file, filtering to one domain. -/
def verifyDomain (domain : Schema.Domain) (path : System.FilePath) : IO UInt32 := do
  let content ← IO.FS.readFile path
  let (compose, network, iam, xaccount, celtype, _) :=
    Parser.partitionByDomain content
  let jsons := match domain with
    | .compose  => compose
    | .network  => network
    | .iam      => iam
    | .xaccount => xaccount
    | .celtype  => celtype
  if jsons.isEmpty then
    IO.eprintln s!"No {domain} records found in {path}"
    return 2
  let domainReport ← match domain with
    | .compose  => pure (Verify.verifyCompose jsons)
    | .network  => Verify.verifyNetwork jsons
    | .iam      => pure (Verify.verifyIAM jsons)
    | .xaccount => pure (Verify.verifyXAccount jsons)
    | .celtype  => pure (Verify.verifyCeltype jsons)
  let report : Verify.VerificationReport := { domains := [domainReport] }
  Report.writeJsonReport report
  Report.writeSummary report
  return report.exitCode

/-- Verify all JSONL files in a directory. -/
def verifyAll (dir : System.FilePath) : IO UInt32 := do
  let entries ← dir.readDir
  let jsonlFiles := entries.filter fun e =>
    e.fileName.endsWith ".jsonl"
  if jsonlFiles.isEmpty then
    IO.eprintln s!"No .jsonl files found in {dir}"
    return 2
  let mut allDomains : List Verify.DomainReport := []
  let mut anyFailed := false
  for entry in jsonlFiles do
    let content ← IO.FS.readFile entry.path
    let report ← Verify.verifyFile content
    allDomains := allDomains ++ report.domains
    if report.disagreed > 0 then anyFailed := true
  let combined : Verify.VerificationReport := { domains := allDomains }
  Report.writeJsonReport combined
  Report.writeSummary combined
  if anyFailed then return 1 else return 0

/-- Check schema version compatibility of a file. -/
def checkVersion (path : System.FilePath) : IO UInt32 := do
  let content ← IO.FS.readFile path
  let (parsed, errors) := Parser.parseFile content
  IO.println s!"Records: {parsed.length}, Parse errors: {errors.length}"
  for e in errors do
    IO.eprintln s!"  line {e.line}: {e.reason}"
  if errors.isEmpty then
    IO.println "OK: all records parsed successfully"
    return 0
  else
    IO.println s!"WARN: {errors.length} records could not be parsed"
    return (if parsed.isEmpty then 2 else 0)

/-- Print supported schema versions. -/
def printVersions : IO UInt32 := do
  IO.println "Supported bridge schema versions:"
  for v in Schema.supportedVersions do
    IO.println s!"  {v}"
  IO.println s!"Contract version: {Config.contractVersion}"
  return 0

def usage : IO UInt32 := do
  IO.eprintln "Usage: bridge-cli <command> [args]"
  IO.eprintln ""
  IO.eprintln "Commands:"
  IO.eprintln "  verify <file.jsonl>              Auto-detect and verify all domains"
  IO.eprintln "  verify compose <file.jsonl>      Verify compose records"
  IO.eprintln "  verify network <file.jsonl>      Verify network records"
  IO.eprintln "  verify iam <file.jsonl>          Verify IAM records"
  IO.eprintln "  verify xaccount <file.jsonl>     Verify cross-account records"
  IO.eprintln "  verify celtype <file.jsonl>      Verify CEL type records"
  IO.eprintln "  verify all <dir>                 Verify all JSONL in directory"
  IO.eprintln "  check-version <file.jsonl>       Check schema version compatibility"
  IO.eprintln "  version                          Print supported schema versions"
  return 2

def main (args : List String) : IO UInt32 :=
  match args with
  | ["version"] => printVersions
  | ["check-version", path] => checkVersion path
  | ["verify", "all", dir] => verifyAll dir
  | ["verify", "compose", path] => verifyDomain .compose path
  | ["verify", "network", path] => verifyDomain .network path
  | ["verify", "iam", path] => verifyDomain .iam path
  | ["verify", "xaccount", path] => verifyDomain .xaccount path
  | ["verify", "celtype", path] => verifyDomain .celtype path
  | ["verify", path] => verifyOneFile path
  | _ => usage
