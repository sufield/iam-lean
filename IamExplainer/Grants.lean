import IamExplainer.Policy
import IamExplainer.Principal
import IamExplainer.Match

open Lean (Json ToJson)

inductive CondState where
  | t | f | u | none_
deriving DecidableEq

def CondState.toString : CondState → String
  | .t => "T"
  | .f => "F"
  | .u => "U"
  | .none_ => "NONE"

instance : ToString CondState := ⟨CondState.toString⟩

structure Grant where
  statement      : String
  principal      : String
  principalType  : PrincipalType
  scope          : Scope
  actions        : List String
  resources      : List String
  conditionKeys  : List String
  conditionState : CondState := .none_
  blockedBy      : Option String := none

private def stmtLabel (s : Statement) : String :=
  match s.sid with
  | some sid => sid
  | none     => s!"Statement[{s.index}]"

private def conditionKeys (cond : Option Json) : List String :=
  match cond with
  | none => []
  | some j =>
    match j with
    | .obj kvs =>
      kvs.toList.flatMap fun (_, v) =>
        match v with
        | .obj inner => inner.toList.map fun (k, _) => k
        | _ => []
    | _ => []

private def triToCondState (tri : Tri) : CondState :=
  match tri with
  | .t => .t
  | .f => .f
  | .u => .u

def stmtGrants (ctx : Context) (condCtx : CondContext) (s : Statement) : List Grant :=
  if s.effect != .allow then []
  else
    let label := stmtLabel s
    let acts := match s.actions with
      | some a => a
      | none => match s.notActions with
        | some na => ["* (except " ++ ", ".intercalate na ++ ")"]
        | none => ["*"]
    let res := match s.resources with
      | some r => r
      | none => match s.notResources with
        | some nr => ["* (except " ++ ", ".intercalate nr ++ ")"]
        | none => []
    let ckeys := conditionKeys s.condition
    let cs := match s.condition with
      | none => CondState.none_
      | some _ => triToCondState (evalCond condCtx s.condBlocks).1
    let fromPrincipals := match s.principals with
      | some pj =>
        let ps := parsePrincipals pj
        ps.map fun p =>
          { statement := label, principal := p.value,
            principalType := p.typ, scope := scopeOf ctx p s.condition,
            actions := acts, resources := res, conditionKeys := ckeys,
            conditionState := cs, blockedBy := none : Grant }
      | none => []
    let fromNotPrincipals := match s.notPrincipals with
      | some _ =>
        [{ statement := label, principal := "(all except listed)",
           principalType := .wildcard, scope := .pub,
           actions := acts, resources := res, conditionKeys := ckeys,
           conditionState := cs, blockedBy := none : Grant }]
      | none => []
    fromPrincipals ++ fromNotPrincipals

def grants (ctx : Context) (condCtx : CondContext) (p : Policy) : List Grant :=
  p.statements.flatMap (stmtGrants ctx condCtx)

def grantToJson (g : Grant) : Json :=
  .mkObj [
    ("statement", .str g.statement),
    ("principal", .str g.principal),
    ("principal_type", .str g.principalType.toString),
    ("scope", .str g.scope.toString),
    ("actions", .arr (g.actions.map Json.str).toArray),
    ("resources", .arr (g.resources.map Json.str).toArray),
    ("condition_keys", .arr (g.conditionKeys.map Json.str).toArray),
    ("condition_state", .str g.conditionState.toString),
    ("blocked_by", match g.blockedBy with | some s => .str s | none => .null)
  ]
