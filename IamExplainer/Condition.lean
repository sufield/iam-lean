import Lean.Data.Json
import Seclib.Prim
import Seclib.Prim.Glob
import Seclib.Prim.Context

open Lean (Json)

private def contextStrings (val : Json) : List String :=
  match val with
  | .str s => [s]
  | .arr a => a.toList.filterMap fun v => match v with | .str s => some s | _ => none
  | .bool b => [if b then "true" else "false"]
  | _ => []

private def isNegatedOp (op : String) : Bool :=
  op == "StringNotEquals" || op == "StringNotEqualsIgnoreCase" ||
  op == "StringNotLike" || op == "ArnNotEquals" || op == "ArnNotLike"

private def stripModifiers (op : String) : (String × Bool × Bool × Bool) :=
  let stripped :=
    if op.startsWith "ForAnyValue:" then (op.drop 12).toString
    else if op.startsWith "ForAllValues:" then (op.drop 13).toString
    else op
  let forAny := op.startsWith "ForAnyValue:"
  let forAll := op.startsWith "ForAllValues:"
  let base :=
    if stripped.endsWith "IfExists" then (stripped.dropEnd 8).toString
    else stripped
  let ifExists := stripped.endsWith "IfExists"
  (base, ifExists, forAny, forAll)

private def evalOp (base : String) (condVal : String) (ctxVal : String) : Tri :=
  match base with
  | "StringEquals" => if ctxVal == condVal then .t else .f
  | "StringNotEquals" => if ctxVal == condVal then .f else .t
  | "StringEqualsIgnoreCase" => if toLowerStr ctxVal == toLowerStr condVal then .t else .f
  | "StringNotEqualsIgnoreCase" => if toLowerStr ctxVal == toLowerStr condVal then .f else .t
  | "StringLike" => if matchPattern condVal ctxVal then .t else .f
  | "StringNotLike" => if matchPattern condVal ctxVal then .f else .t
  | "ArnEquals" => if ctxVal == condVal then .t else .f
  | "ArnNotEquals" => if ctxVal == condVal then .f else .t
  | "ArnLike" => if matchPattern condVal ctxVal then .t else .f
  | "ArnNotLike" => if matchPattern condVal ctxVal then .f else .t
  | "Bool" => if ctxVal == condVal then .t else .f
  | _ => .u

private def condValues (v : Json) : List String :=
  match v with
  | .str s => [s]
  | .arr a => a.toList.filterMap fun x => match x with | .str s => some s | _ => none
  | .bool b => [if b then "true" else "false"]
  | _ => []

structure CondWarning where
  message : String

def evalNull (condVal : String) (ctx : CondContext) (key : String) : Tri :=
  if !ctx.complete then .u
  else
    let present := ctx.lookup key |>.isSome
    match condVal with
    | "true" => if present then .f else .t
    | "false" => if present then .t else .f
    | _ => .u

def evalKeyOp (base : String) (ifExists forAny forAll : Bool)
    (condVals : List String) (ctx : CondContext) (key : String) :
    Tri × List CondWarning :=
  if base == "Null" then
    match condVals.head? with
    | some cv => (evalNull cv ctx key, [])
    | none => (.u, [])
  else
    let supported := base == "StringEquals" || base == "StringNotEquals" ||
      base == "StringEqualsIgnoreCase" || base == "StringNotEqualsIgnoreCase" ||
      base == "StringLike" || base == "StringNotLike" ||
      base == "ArnEquals" || base == "ArnNotEquals" ||
      base == "ArnLike" || base == "ArnNotLike" ||
      base == "Bool"
    if !supported then
      (.u, [{ message := s!"unsupported condition operator: {base}" }])
    else
      match ctx.lookup key with
      | none =>
        if !ctx.complete then (.u, [])
        else if ifExists then (.t, [])
        else if isNegatedOp base then (.t, [])
        else (.f, [])
      | some ctxJson =>
        let ctxVals := contextStrings ctxJson
        if forAny then
          let r := ctxVals.foldl (fun acc cv =>
            let inner := condVals.foldl (fun acc2 pv => Tri.or acc2 (evalOp base pv cv)) .f
            Tri.or acc inner) .f
          (r, [])
        else if forAll then
          let r := ctxVals.foldl (fun acc cv =>
            let inner := condVals.foldl (fun acc2 pv => Tri.or acc2 (evalOp base pv cv)) .f
            Tri.and acc inner) .t
          (r, [])
        else
          let r := condVals.foldl (fun acc pv =>
            let inner := ctxVals.foldl (fun acc2 cv => Tri.or acc2 (evalOp base pv cv)) .f
            Tri.or acc inner) .f
          (r, [])

-- === Parsed condition structure ===

structure CondKeyVal where
  key : String
  condVals : List String

structure CondOp where
  base : String
  ifExists : Bool
  forAny : Bool
  forAll : Bool
  pairs : List CondKeyVal

abbrev CondBlocks := List CondOp

def decodeCondBlocks (cond : Option Json) : CondBlocks × List CondWarning :=
  match cond with
  | none => ([], [])
  | some j =>
    match j with
    | .obj operators =>
      operators.toList.foldl (fun (blocks, warns) (opName, opBody) =>
        match opBody with
        | .obj keys =>
          let (base, ifExists, forAny, forAll) := stripModifiers opName
          let pairs := keys.toList.map fun (key, val) =>
            { key := key, condVals := condValues val : CondKeyVal }
          (blocks ++ [{ base, ifExists, forAny, forAll, pairs : CondOp }], warns)
        | _ => (blocks, warns ++ [{ message := s!"condition operator {opName}: value must be an object" }])
      ) ([], [])
    | _ => ([], [{ message := "Condition must be an object" }])

-- === Evaluation over CondBlocks (list recursion only) ===

def evalCondInner (ctx : CondContext) (op : CondOp) : List CondKeyVal → Tri × List CondWarning
  | [] => (.t, [])
  | pair :: rest =>
    let rw := evalKeyOp op.base op.ifExists op.forAny op.forAll pair.condVals ctx pair.key
    let acc := evalCondInner ctx op rest
    (Tri.and rw.1 acc.1, rw.2 ++ acc.2)

def evalCond (ctx : CondContext) : CondBlocks → Tri × List CondWarning
  | [] => (.t, [])
  | op :: rest =>
    let inner := evalCondInner ctx op op.pairs
    let acc := evalCond ctx rest
    (Tri.and inner.1 acc.1, inner.2 ++ acc.2)

-- === Proof lemmas ===

private theorem evalKeyOp_noContext (base : String) (ifExists forAny forAll : Bool)
    (cvs : List String) (key : String) :
    (evalKeyOp base ifExists forAny forAll cvs noContext key).1 = .u := by
  simp only [evalKeyOp]
  split
  · split
    · simp [evalNull, noContext]
    · rfl
  · split
    · rfl
    · simp [noContext, CondContext.lookup]

private theorem evalCondInner_noContext_tu (op : CondOp) (pairs : List CondKeyVal) :
    (evalCondInner noContext op pairs).1 = .t ∨ (evalCondInner noContext op pairs).1 = .u := by
  induction pairs with
  | nil => left; rfl
  | cons pair rest ih =>
    have : (evalCondInner noContext op (pair :: rest)).1 =
           Tri.and (evalKeyOp op.base op.ifExists op.forAny op.forAll pair.condVals noContext pair.key).1
                   (evalCondInner noContext op rest).1 := rfl
    rw [this]
    exact Tri.and_tu _ _ (Or.inr (evalKeyOp_noContext ..)) ih

private theorem evalCondInner_noContext_T_nil (op : CondOp) (pairs : List CondKeyVal)
    (h : (evalCondInner noContext op pairs).1 = .t) : pairs = [] := by
  cases pairs with
  | nil => rfl
  | cons pair rest =>
    exfalso
    have : (evalCondInner noContext op (pair :: rest)).1 =
           Tri.and (evalKeyOp op.base op.ifExists op.forAny op.forAll pair.condVals noContext pair.key).1
                   (evalCondInner noContext op rest).1 := rfl
    rw [this, Tri.and_eq_t] at h
    exact absurd h.1 (by rw [evalKeyOp_noContext]; decide)

theorem evalCond_noContext_tu (blocks : CondBlocks) :
    (evalCond noContext blocks).1 = .t ∨ (evalCond noContext blocks).1 = .u := by
  induction blocks with
  | nil => left; rfl
  | cons op rest ih =>
    have : (evalCond noContext (op :: rest)).1 =
           Tri.and (evalCondInner noContext op op.pairs).1 (evalCond noContext rest).1 := rfl
    rw [this]
    exact Tri.and_tu _ _ (evalCondInner_noContext_tu op op.pairs) ih

theorem evalCond_noContext_T_imp (blocks : CondBlocks) (ctx : CondContext)
    (h : (evalCond noContext blocks).1 = .t) :
    (evalCond ctx blocks).1 = .t := by
  induction blocks with
  | nil => exact h
  | cons op rest ih =>
    have hno : (evalCond noContext (op :: rest)).1 =
               Tri.and (evalCondInner noContext op op.pairs).1 (evalCond noContext rest).1 := rfl
    rw [hno, Tri.and_eq_t] at h
    have hnil := evalCondInner_noContext_T_nil op op.pairs h.1
    have hctx : (evalCond ctx (op :: rest)).1 =
                Tri.and (evalCondInner ctx op op.pairs).1 (evalCond ctx rest).1 := rfl
    rw [hctx, hnil]
    show Tri.and (evalCondInner ctx op []).1 (evalCond ctx rest).1 = .t
    have : (evalCondInner ctx op []).1 = Tri.t := rfl
    rw [this]
    show Tri.and .t (evalCond ctx rest).1 = .t
    simp [Tri.and_eq_t]
    exact ih h.2
