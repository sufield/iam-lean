import IamExplainer

open Lean (Json)

structure CliOpts where
  file              : Option String := none
  format            : String := "text"
  account           : Option String := none
  accounts          : Option String := none
  orgId             : Option String := none
  action            : Option String := none
  resource          : Option String := none
  context           : Option String := none
  scpFiles          : List String := []
  rcpFiles          : List String := []
  boundaryFile      : Option String := none
  managementAccount : Bool := false
  serviceLinked     : Bool := false
  needsFile         : Option String := none
  outFile           : Option String := none

def parseOpts (args : List String) : CliOpts :=
  go args {}
where
  go : List String → CliOpts → CliOpts
  | [], opts => opts
  | "--format" :: f :: rest, opts => go rest { opts with format := f }
  | "--account" :: a :: rest, opts => go rest { opts with account := some a }
  | "--accounts" :: a :: rest, opts => go rest { opts with accounts := some a }
  | "--org-id" :: o :: rest, opts => go rest { opts with orgId := some o }
  | "--action" :: a :: rest, opts => go rest { opts with action := some a }
  | "--resource" :: r :: rest, opts => go rest { opts with resource := some r }
  | "--context" :: c :: rest, opts => go rest { opts with context := some c }
  | "--scp" :: f :: rest, opts => go rest { opts with scpFiles := opts.scpFiles ++ [f] }
  | "--rcp" :: f :: rest, opts => go rest { opts with rcpFiles := opts.rcpFiles ++ [f] }
  | "--boundary" :: f :: rest, opts => go rest { opts with boundaryFile := some f }
  | "--management-account" :: rest, opts => go rest { opts with managementAccount := true }
  | "--service-linked" :: rest, opts => go rest { opts with serviceLinked := true }
  | "--needs" :: f :: rest, opts => go rest { opts with needsFile := some f }
  | "--out" :: f :: rest, opts => go rest { opts with outFile := some f }
  | "--" :: rest, opts => go rest opts
  | arg :: rest, opts =>
    if arg.startsWith "--" then go rest opts
    else go rest { opts with file := some arg }

def loadAccounts (path : String) : IO (List String) := do
  let contents ← IO.FS.readFile path
  return contents.splitOn "\n" |>.map String.trim |>.filter (!·.isEmpty)

def buildContext (opts : CliOpts) : IO Context := do
  let accts ← match opts.accounts with
    | some path => loadAccounts path
    | none => pure []
  return { account := opts.account, accounts := accts, orgId := opts.orgId }

def runExplain (opts : CliOpts) : IO UInt32 := do
  match opts.file with
  | none =>
    IO.eprintln "error: missing file argument"
    IO.eprintln "Usage: iamlean explain <file> [--format json|text] [--account ID] [--accounts FILE] [--org-id ID]"
    return 2
  | some path =>
    let contents ← IO.FS.readFile path
    match parsePolicy contents with
    | .error e =>
      IO.eprintln s!"error: {e}"
      return 2
    | .ok (policy, warnings) =>
      let ctx ← buildContext opts
      let kind := detectKind policy.statements
      let kindWarns : List ParseWarning := if kind == .mixed then
        [⟨"document mixes identity and resource-policy statements; evaluating as RESOURCE"⟩] else []
      let lpFindings := evaluate policy
      let xaFindings := policy.statements.flatMap (checkXA ctx kind)
      let xaWarns := policy.statements.flatMap (xaWarnings ctx)
      let allFindings := lpFindings ++ xaFindings
      let allWarnings := warnings ++ kindWarns ++ xaWarns
      let report := buildReport allFindings allWarnings
      if opts.format == "json" then
        IO.println (Json.pretty (reportToJson report))
      else
        IO.print (renderText report)
      if allFindings.isEmpty then return 0 else return 1

def loadCondContext (opts : CliOpts) : IO CondContext := do
  match opts.context with
  | none => pure noContext
  | some path =>
    let contents ← IO.FS.readFile path
    match Json.parse contents with
    | .error e => throw (IO.userError s!"--context parse error: {e}")
    | .ok j =>
      match mkContext j with
      | .error e => throw (IO.userError e)
      | .ok ctx => pure ctx

def runGrants (opts : CliOpts) : IO UInt32 := do
  match opts.file with
  | none =>
    IO.eprintln "error: missing file argument"
    IO.eprintln "Usage: iamlean grants <file> [--format json|text] [--account ID] [--accounts FILE] [--org-id ID]"
    return 2
  | some path =>
    let contents ← IO.FS.readFile path
    match parsePolicy contents with
    | .error e =>
      IO.eprintln s!"error: {e}"
      return 2
    | .ok (policy, warnings) =>
      let ctx ← buildContext opts
      let kind := detectKind policy.statements
      let kindWarns : List ParseWarning := if kind == .mixed then
        [⟨"document mixes identity and resource-policy statements; evaluating as RESOURCE"⟩] else []
      let xaWarns := policy.statements.flatMap (xaWarnings ctx)
      let condCtx ← loadCondContext opts
      let gs := _root_.grants ctx condCtx policy
      let allWarnings := warnings ++ kindWarns ++ xaWarns
      if opts.format == "json" then
        let out : Json := .mkObj [
          ("kind", .str kind.toString),
          ("grants", .arr (gs.map grantToJson).toArray),
          ("warnings", .arr (allWarnings.map fun w => .str w.message).toArray)
        ]
        IO.println (Json.pretty out)
      else
        IO.println s!"Kind: {kind}"
        for w in allWarnings do
          IO.eprintln s!"  WARNING: {w.message}"
        for g in gs do
          let csTag := if g.conditionState == .none_ then "" else s!" cond={g.conditionState}"
          IO.println s!"  [{g.scope}] {g.statement}: {g.principal} ({g.principalType}) → {g.actions}{csTag}"
      return 0

def loadLayerDoc (path : String) : IO (Policy × List ParseWarning) := do
  let contents ← IO.FS.readFile path
  match parsePolicy contents with
  | .ok result => return result
  | .error e => throw (IO.userError s!"{path}: {e}")

def rcpServicesPath : String := "data/rcp-services.txt"

def loadRcpServices : IO (List String) := do
  let contents ← IO.FS.readFile rcpServicesPath
  return contents.splitOn "\n" |>.map String.trim |>.filter (!·.isEmpty)

def runCan (opts : CliOpts) : IO UInt32 := do
  match opts.file with
  | none =>
    IO.eprintln "error: missing file argument"
    IO.eprintln "Usage: iamlean can <file> --action A --resource R [--context F] [--format json] [--scp F]... [--rcp F]... [--boundary F]"
    return 2
  | some path =>
    match opts.action with
    | none =>
      IO.eprintln "error: --action is required for can"
      return 2
    | some act =>
      match opts.resource with
      | none =>
        IO.eprintln "error: --resource is required for can"
        return 2
      | some res =>
        let contents ← IO.FS.readFile path
        match parsePolicy contents with
        | .error e =>
          IO.eprintln s!"error: {e}"
          return 2
        | .ok (policy, parseWarnings) =>
          let buildCtx ← buildContext opts
          let ctx ← loadCondContext opts
          let req : Request := { action := act, resource := res }
          let kind := detectKind policy.statements
          let kindWarns : List ParseWarning := if kind == .mixed then
            [⟨"document mixes identity and resource-policy statements; evaluating as RESOURCE"⟩] else []
          let xaWarns := policy.statements.flatMap (xaWarnings buildCtx)
          let allParseWarnings := parseWarnings ++ kindWarns ++ xaWarns
          let mut warnings : List String := allParseWarnings.map (·.message)
          -- Load layer documents
          let mut scps : List Policy := []
          let mut layerWarns : List ParseWarning := []
          for f in opts.scpFiles do
            let fc ← IO.FS.readFile f
            match parsePolicy fc with
            | .error e => IO.eprintln s!"error: SCP {f}: {e}"; return 2
            | .ok (p, ws) =>
              match validateScp p with
              | some e => IO.eprintln s!"error: {e}"; return 2
              | none => scps := scps ++ [p]; layerWarns := layerWarns ++ ws
          let mut rcps : List Policy := []
          for f in opts.rcpFiles do
            let fc ← IO.FS.readFile f
            match parsePolicy fc with
            | .error e => IO.eprintln s!"error: RCP {f}: {e}"; return 2
            | .ok (p, ws) =>
              match validateRcp p with
              | some e => IO.eprintln s!"error: {e}"; return 2
              | none => rcps := rcps ++ [p]; layerWarns := layerWarns ++ ws
          let (boundary, bndWarns) ← match opts.boundaryFile with
            | none => pure (none, ([] : List ParseWarning))
            | some f => do
              let fc ← IO.FS.readFile f
              match parsePolicy fc with
              | .error e => IO.eprintln s!"error: boundary {f}: {e}"; return 2
              | .ok (p, ws) => pure (some p, ws)
          layerWarns := layerWarns ++ bndWarns
          warnings := warnings ++ layerWarns.map (·.message)
          let layers : Layers :=
            { scps := scps
              rcps := rcps
              boundary := boundary
              managementAccount := opts.managementAccount
              serviceLinked := opts.serviceLinked }
          let rcpServices ← if opts.rcpFiles.isEmpty then pure []
            else try loadRcpServices catch _ => do
              let cwd ← IO.currentDir
              IO.eprintln s!"error: cannot read RCP service list: {cwd / rcpServicesPath}"
              return 2
          -- Evaluate with layers
          let lv := allowsLayered policy req ctx layers rcpServices kind
          -- Condition-level unresolved
          let mut unresolved : List Json := []
          for s in policy.statements do
            let tri := (evalCond ctx s.condBlocks).1
            if tri == .u && stmtMatches s req then
              match s.condition with
              | some cond =>
                match cond with
                | .obj ops =>
                  for (opName, opBody) in ops.toList do
                    match opBody with
                    | .obj keys =>
                      for (key, _) in keys.toList do
                        unresolved := unresolved ++ [.mkObj [("key", .str key), ("operator", .str opName)]]
                    | _ => pure ()
                | _ => pure ()
              | none => pure ()
          warnings := warnings ++ lv.warnings
          let allLayerUnresolved := lv.unresolved
          let hasUnresolved := !unresolved.isEmpty || !allLayerUnresolved.isEmpty
          let verdict := if !lv.allowed then "DENIED"
            else if hasUnresolved then "ALLOWED_UNRESOLVED"
            else "ALLOWED"
          let decidingStmts := policy.statements.filter fun s =>
            stmtMatches s req && (
              (s.effect == .allow && lv.allowed) ||
              (s.effect == .deny && !lv.allowed))
          let stmtNames := decidingStmts.map fun s =>
            match s.sid with | some sid => Json.str sid | none => Json.str s!"Statement[{s.index}]"
          if opts.format == "json" then
            let out : Json := .mkObj [
              ("verdict", .str verdict),
              ("deciding_statements", .arr stmtNames.toArray),
              ("unresolved", .arr unresolved.toArray),
              ("blocked_by", .arr (lv.blockedBy.map Json.str).toArray),
              ("layer_unresolved", .arr (allLayerUnresolved.map Json.str).toArray),
              ("notes", .arr (lv.notes.map Json.str).toArray),
              ("warnings", .arr (warnings.map Json.str).toArray)
            ]
            IO.println (Json.pretty out)
          else
            IO.println s!"Verdict: {verdict}"
            for w in warnings do
              IO.eprintln s!"  WARNING: {w}"
            if !lv.blockedBy.isEmpty then
              IO.println s!"  Blocked by: {", ".intercalate lv.blockedBy}"
            if !allLayerUnresolved.isEmpty then
              IO.println s!"  Layer unresolved: {", ".intercalate allLayerUnresolved}"
            for n in lv.notes do
              IO.println s!"  Note: {n}"
          return 0

def runEmitFixed (opts : CliOpts) : IO UInt32 := do
  match opts.file with
  | none =>
    IO.eprintln "error: missing file argument"
    IO.eprintln "Usage: iamlean emit-fixed <file> --needs <file> [--format json] [--out fixed.json]"
    return 2
  | some path =>
    match opts.needsFile with
    | none =>
      IO.eprintln "error: --needs is required for emit-fixed"
      return 2
    | some needsPath =>
      let contents ← IO.FS.readFile path
      match parsePolicy contents with
      | .error e =>
        IO.eprintln s!"error: {e}"
        return 2
      | .ok (policy, _) =>
        let kind := detectKind policy.statements
        if kind != .identity then
          IO.eprintln s!"error: emit-fixed only supports identity policies (got {kind}); principal narrowing unproven; not supported"
          return 2
        let needsContents ← IO.FS.readFile needsPath
        match parseNeeds needsContents with
        | .error e =>
          IO.eprintln s!"error: {e}"
          return 2
        | .ok needs =>
          let (fixed, report) := emitFixed policy needs
          let origFindings := evaluate policy
          let fixedFindings := evaluate fixed
          let residuals := fixedFindings.map fun f =>
            let reason := if f.controlId == "LP.NOTRESOURCE.ALLOW.001" then "manual: NotResource"
              else if f.controlId == "LP.ESCALATE.PASSROLE.001" then "manual: condition insertion"
              else if f.controlId == "LP.RESOURCE.WILDCARD.001" then
                if report.withheld.any (·.statement == f.location) then "withheld: wildcard resource"
                else "residual"
              else "residual"
            { controlId := f.controlId, statement := f.location, reason : Residual }
          let fullReport := { report with residuals }
          if opts.format == "json" then
            let fixedJson := policyToJson fixed
            let out : Json := .mkObj [
              ("fixed_policy", fixedJson),
              ("transforms", .arr (fullReport.transforms.map fun t =>
                .mkObj [("statement", .str t.statement), ("type", .str t.type), ("detail", .str t.detail)]).toArray),
              ("residual_findings", .arr (fullReport.residuals.map fun r =>
                .mkObj [("id", .str r.controlId), ("statement", .str r.statement), ("reason", .str r.reason)]).toArray),
              ("needs_not_granted", .arr (fullReport.needsNotGranted.map fun n =>
                .mkObj [("action", .str n.action), ("resource", .str n.resource)]).toArray),
              ("withheld", .arr (fullReport.withheld.map fun w =>
                .mkObj [("statement", .str w.statement), ("reason", .str w.reason)]).toArray),
              ("idempotent", .bool fullReport.idempotent),
              ("findings_original", .num origFindings.length),
              ("findings_fixed", .num fixedFindings.length)
            ]
            IO.println (Json.pretty out)
          else
            IO.println s!"Transforms: {fullReport.transforms.length}"
            for t in fullReport.transforms do
              IO.println s!"  {t.type} {t.statement}: {t.detail}"
            if !fullReport.residuals.isEmpty then
              IO.println s!"Residual findings: {fullReport.residuals.length}"
              for r in fullReport.residuals do
                IO.println s!"  {r.controlId} on {r.statement}: {r.reason}"
            if !fullReport.needsNotGranted.isEmpty then
              IO.println s!"Needs not granted: {fullReport.needsNotGranted.length}"
              for n in fullReport.needsNotGranted do
                IO.println s!"  {n.action} on {n.resource}"
            if !fullReport.withheld.isEmpty then
              IO.println s!"Withheld: {fullReport.withheld.length}"
              for w in fullReport.withheld do
                IO.println s!"  {w.statement}: {w.reason}"
            IO.println s!"Idempotent: {fullReport.idempotent}"
            IO.println s!"Findings: {origFindings.length} → {fixedFindings.length}"
          match opts.outFile with
          | some outPath =>
            IO.FS.writeFile outPath (Json.pretty (policyToJson fixed))
          | none => pure ()
          return 0

def main (args : List String) : IO UInt32 := do
  let (cmd, rest) := match args with
    | "explain" :: rest => ("explain", rest)
    | "grants" :: rest => ("grants", rest)
    | "can" :: rest => ("can", rest)
    | "emit-fixed" :: rest => ("emit-fixed", rest)
    | "--help" :: _ => ("help", [])
    | _ => ("help", args)
  if cmd == "help" then
    IO.eprintln "Usage: iamlean <explain|grants|can|emit-fixed> <file> [--format json|text] [--account ID] [--accounts FILE] [--org-id ID]"
    return 0
  let opts := parseOpts rest
  match cmd with
  | "explain" => runExplain opts
  | "grants" => runGrants opts
  | "can" => runCan opts
  | "emit-fixed" => runEmitFixed opts
  | _ => IO.eprintln "Unknown command"; return 2
