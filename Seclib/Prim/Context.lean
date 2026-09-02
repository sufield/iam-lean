import Lean.Data.Json
import Seclib.Prim.Glob

/-! Vendor-neutral authorization request and evaluation context.
No cloud provider noun appears in this module. -/

open Lean (Json)

structure Request where
  action   : String
  resource : String

structure CondContext where
  values   : List (String × Json)
  complete : Bool

def noContext : CondContext := { values := [], complete := false }

def mkContext (j : Json) : Except String CondContext :=
  match j with
  | .obj kvs => .ok { values := kvs.toList, complete := true }
  | _ => .error "--context must be a JSON object"

def CondContext.lookup (ctx : CondContext) (key : String) : Option Json :=
  let lk := toLowerStr key
  ctx.values.find? (fun (k, _) => toLowerStr k == lk) |>.map (·.2)
