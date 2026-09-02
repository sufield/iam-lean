import IamExplainer.Match

open Lean (Json)

structure Need where
  action   : String
  resource : String
deriving BEq

structure Needs where
  needs : List Need

structure Transform where
  statement : String
  type      : String
  detail    : String

structure Residual where
  controlId : String
  statement : String
  reason    : String

structure Withheld where
  statement : String
  reason    : String

structure EmitReport where
  transforms       : List Transform
  residuals        : List Residual
  needsNotGranted  : List Need
  withheld         : List Withheld
  idempotent       : Bool

private def stmtLabel (s : Statement) : String :=
  match s.sid with | some sid => sid | none => s!"Statement[{s.index}]"

def hasWildcard (s : String) : Bool :=
  s.toList.any (· == '*') || s.toList.any (· == '?')

def allNeedResourcesExact (stmt : Statement) (ns : List Need) : Bool :=
  ns.all fun n =>
    if stmtGrantsAction stmt n.action && resourceMatches stmt n.resource
    then !hasWildcard n.resource
    else true

def touchingResources (stmt : Statement) (ns : List Need) : List String :=
  (ns.filterMap fun n =>
    if stmtGrantsAction stmt n.action && resourceMatches stmt n.resource
    then some n.resource
    else none).eraseDups

def narrowAction (stmt : Statement) (ns : List Need) : Option Statement :=
  if stmt.effect != .allow then some stmt
  else
    let literals := (ns.filter (fun n => stmtGrantsAction stmt n.action)
      |>.map (·.action)).eraseDups
    if literals.isEmpty then some stmt
    else
      let needsNarrowAction := match stmt.actions with
        | some acts => acts.any hasWildcard
        | none => false
      let actionChanged := needsNarrowAction || stmt.notActions.isSome
      if actionChanged then
        some { stmt with actions := some literals, notActions := none }
      else some stmt

def narrowResource (s1 stmt : Statement) (ns : List Need) : Statement :=
  if stmt.notResources.isSome then s1
  else
    let tRes := touchingResources stmt ns
    if tRes.isEmpty then s1
    else if allNeedResourcesExact stmt ns then
      if s1.resources == some tRes then s1
      else { s1 with resources := some tRes, notResources := none }
    else s1

def transformStmt (stmt : Statement) (ns : List Need)
    : Option Statement × List Transform × List Withheld :=
  match narrowAction stmt ns with
  | none =>
    (none, [{ statement := stmtLabel stmt, type := "T2",
              detail := "no needed actions granted" }], [])
  | some s1 =>
    if stmt.effect != .allow then (some s1, [], [])
    else
      let label := stmtLabel stmt
      let actionChanged := s1.actions != stmt.actions || s1.notActions != stmt.notActions
      let t1 : List Transform := if actionChanged then
        [{ statement := label, type := "T1",
           detail := s!"actions narrowed to {s1.actions.getD []}" }]
      else []
      let s3 := narrowResource s1 stmt ns
      let hasNotResource := stmt.notResources.isSome
      let tRes := touchingResources stmt ns
      let (t3, w3) : List Transform × List Withheld :=
        if hasNotResource then ([], [⟨label, "NotResource present"⟩])
        else if tRes.isEmpty then ([], [])
        else if allNeedResourcesExact stmt ns then
          if s1.resources == some tRes then ([], [])
          else ([⟨label, "T3", s!"resources narrowed to {tRes}"⟩], [])
        else ([], [⟨label, "wildcard resource in need"⟩])
      (some s3, t1 ++ t3, w3)

def emitFixed (p : Policy) (ns : Needs) : Policy × EmitReport :=
  let results := p.statements.map (transformStmt · ns.needs)
  let newStmts := results.filterMap fun (s, _, _) => s
  let transforms := results.flatMap (·.2.1)
  let withheld := results.flatMap (·.2.2)
  let fixed := { p with statements := newStmts }
  let needsNotGranted := ns.needs.filter fun n =>
    !allows fixed { action := n.action, resource := n.resource } noContext
  let results2 := fixed.statements.map (transformStmt · ns.needs)
  let transforms2 := results2.flatMap (·.2.1)
  let idempotent := transforms2.isEmpty
  (fixed,
   { transforms, residuals := [], needsNotGranted, withheld, idempotent })

private def parseOneNeed (n : Json) : Except String Need := do
  let action ← match n.getObjVal? "action" >>= Json.getStr? with
    | .ok a => .ok a
    | .error _ => .error "each need must have an \"action\" string"
  let resource ← match n.getObjVal? "resource" >>= Json.getStr? with
    | .ok r => .ok r
    | .error _ => .error "each need must have a \"resource\" string"
  if hasWildcard action then
    .error s!"need action \"{action}\" contains wildcards; actions must be literal"
  .ok { action, resource }

def parseNeeds (input : String) : Except String Needs := do
  let json ← Json.parse input |>.mapError (s!"JSON parse error: " ++ ·)
  let needsArr ← match json.getObjVal? "needs" with
    | .ok v => match v with
      | .arr a => .ok a.toList
      | _ => .error "\"needs\" must be an array"
    | .error _ => .error "missing \"needs\" field"
  let needs ← needsArr.mapM parseOneNeed
  .ok { needs }

def stmtToJson (s : Statement) : Json :=
  let sidF := match s.sid with | some sid => [("Sid", .str sid)] | none => []
  let effF := [("Effect", match s.effect with | .allow => .str "Allow" | .deny => .str "Deny")]
  let actF := match s.actions with
    | some acts => [("Action", if acts.length == 1 then .str acts.head!
        else .arr (acts.map Json.str).toArray)]
    | none => []
  let naF := match s.notActions with
    | some na => [("NotAction", .arr (na.map Json.str).toArray)]
    | none => []
  let resF := match s.resources with
    | some res => [("Resource", if res.length == 1 then .str res.head!
        else .arr (res.map Json.str).toArray)]
    | none => []
  let nrF := match s.notResources with
    | some nr => [("NotResource", .arr (nr.map Json.str).toArray)]
    | none => []
  let condF := match s.condition with
    | some c => [("Condition", c)]
    | none => []
  .mkObj (sidF ++ effF ++ actF ++ naF ++ resF ++ nrF ++ condF)

def policyToJson (p : Policy) : Json :=
  let stmts := p.statements.map stmtToJson
  let fields : List (String × Json) := match p.version with
    | some v => [("Version", .str v), ("Statement", .arr stmts.toArray)]
    | none => [("Statement", .arr stmts.toArray)]
  .mkObj fields
