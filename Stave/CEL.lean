/-! CEL evaluation semantics — the fragment Stave uses.

Only the operators/functions the 8 starting controls require:
  field access, ==, !=, &&, ||, !, in, contains, startsWith,
  list.exists, list.all, size.

Total by construction — CEL expressions are finite, eval is
structural recursion over Expr. No sorry. -/

inductive Value where
  | str : String → Value
  | num : Int → Value
  | bool : Bool → Value
  | list : List Value → Value
  | record : List (String × Value) → Value
deriving Repr, BEq

namespace Value

def field : Value → String → Option Value
  | .record fields, name => fields.lookup name
  | _, _ => none

def toBool : Value → Option Bool
  | .bool b => some b
  | _ => none

def toStr : Value → Option String
  | .str s => some s
  | _ => none

def toList : Value → Option (List Value)
  | .list l => some l
  | _ => none

def toInt : Value → Option Int
  | .num n => some n
  | _ => none

end Value

inductive Expr where
  | lit : Value → Expr
  | var : String → Expr
  | field : Expr → String → Expr
  | eq : Expr → Expr → Expr
  | ne : Expr → Expr → Expr
  | and : Expr → Expr → Expr
  | or : Expr → Expr → Expr
  | not : Expr → Expr
  | contains : Expr → Expr → Expr
  | startsWith : Expr → Expr → Expr
  | in_ : Expr → Expr → Expr
  | exists_ : Expr → String → Expr → Expr
  | all_ : Expr → String → Expr → Expr
  | size : Expr → Expr
deriving Repr

def eval (env : Value) : Expr → Option Value
  | .lit v => some v
  | .var name => env.field name
  | .field e name => do (← eval env e).field name
  | .eq a b => do
    let va ← eval env a
    let vb ← eval env b
    some (.bool (va == vb))
  | .ne a b => do
    let va ← eval env a
    let vb ← eval env b
    some (.bool (va != vb))
  | .and a b => do
    let va ← (eval env a) >>= Value.toBool
    let vb ← (eval env b) >>= Value.toBool
    some (.bool (va && vb))
  | .or a b => do
    let va ← (eval env a) >>= Value.toBool
    let vb ← (eval env b) >>= Value.toBool
    some (.bool (va || vb))
  | .not e => do
    let v ← (eval env e) >>= Value.toBool
    some (.bool !v)
  | .contains haystack needle => do
    let hs ← (eval env haystack) >>= Value.toStr
    let nd ← (eval env needle) >>= Value.toStr
    some (.bool ((hs.splitOn nd).length != 1))
  | .startsWith e pfx => do
    let s ← (eval env e) >>= Value.toStr
    let p ← (eval env pfx) >>= Value.toStr
    some (.bool (s.startsWith p))
  | .in_ elem list => do
    let v ← eval env elem
    let ls ← (eval env list) >>= Value.toList
    some (.bool (ls.any (· == v)))
  | .exists_ listExpr varName pred => do
    let ls ← (eval env listExpr) >>= Value.toList
    some (.bool (ls.any fun item =>
      match eval (.record ((varName, item) :: match env with
        | .record fs => fs | _ => [])) pred with
      | some (.bool true) => true
      | _ => false))
  | .all_ listExpr varName pred => do
    let ls ← (eval env listExpr) >>= Value.toList
    some (.bool (ls.all fun item =>
      match eval (.record ((varName, item) :: match env with
        | .record fs => fs | _ => [])) pred with
      | some (.bool true) => true
      | _ => false))
  | .size e => do
    match ← eval env e with
    | .list l => some (.num l.length)
    | .str s => some (.num s.length)
    | _ => none

def evalBool (env : Value) (e : Expr) : Bool :=
  match eval env e with
  | some (.bool b) => b
  | _ => false

section Tests

private def testEnv : Value :=
  .record [
    ("name", .str "test"),
    ("count", .num 3),
    ("active", .bool true),
    ("tags", .list [.str "a", .str "b"])
  ]

#guard evalBool testEnv (.eq (.var "name") (.lit (.str "test"))) == true
#guard evalBool testEnv (.eq (.var "name") (.lit (.str "other"))) == false
#guard evalBool testEnv (.and (.var "active") (.lit (.bool true))) == true
#guard evalBool testEnv (.not (.var "active")) == false
#guard evalBool testEnv (.in_ (.lit (.str "a")) (.var "tags")) == true
#guard evalBool testEnv (.in_ (.lit (.str "c")) (.var "tags")) == false
#guard evalBool testEnv (.contains (.var "name") (.lit (.str "es"))) == true
#guard evalBool testEnv (.startsWith (.var "name") (.lit (.str "te"))) == true
#guard evalBool testEnv
  (.exists_ (.var "tags") "t" (.eq (.var "t") (.lit (.str "b")))) == true
#guard evalBool testEnv
  (.all_ (.var "tags") "t" (.ne (.var "t") (.lit (.str "c")))) == true

end Tests
