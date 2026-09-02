import IamExplainer.Policy
import IamExplainer.Condition
import Seclib.Prim.Context

/-! IAM pattern matching and request evaluation.

Condition evaluation is three-valued (T/F/U). Allow applies when T or U
(grant-preserving); Deny applies only when T (conservative). -/

def matchActionPattern (pattern : String) (action : String) : Bool :=
  matchPattern (toLowerStr pattern) (toLowerStr action)

def matchResourcePattern (pattern : String) (resource : String) : Bool :=
  matchPattern pattern resource

def stmtGrantsAction (s : Statement) (action : String) : Bool :=
  match s.actions, s.notActions with
  | some acts, none => acts.any (matchActionPattern · action)
  | none, some nacts => !(nacts.any (matchActionPattern · action))
  | _, _ => false

def actionMatches (stmt : Statement) (action : String) : Bool :=
  stmtGrantsAction stmt action

def resourceMatches (stmt : Statement) (resource : String) : Bool :=
  match stmt.resources, stmt.notResources with
  | some res, none => res.any (matchResourcePattern · resource)
  | none, some nres => !(nres.any (matchResourcePattern · resource))
  | _, _ => true

def stmtMatches (stmt : Statement) (req : Request) : Bool :=
  actionMatches stmt req.action && resourceMatches stmt req.resource

def Statement.condBlocks (s : Statement) : CondBlocks :=
  (decodeCondBlocks s.condition).1

def allows (p : Policy) (req : Request) (ctx : CondContext) : Bool :=
  let denied := p.statements.any fun s =>
    s.effect == .deny && stmtMatches s req && decide ((evalCond ctx s.condBlocks).1 = .t)
  if denied then false
  else p.statements.any fun s =>
    s.effect == .allow && stmtMatches s req && !decide ((evalCond ctx s.condBlocks).1 = .f)
