import Lean.Data.Json
import Seclib.Domain.PolicySem

open Lean (Json ToJson FromJson)

instance : ToJson Effect where
  toJson
    | .allow => "Allow"
    | .deny  => "Deny"

instance : FromJson Effect where
  fromJson?
    | .str "Allow" => .ok .allow
    | .str "Deny"  => .ok .deny
    | _ => .error "Effect must be exactly \"Allow\" or \"Deny\""

structure Statement where
  sid            : Option String := none
  effect         : Effect
  actions        : Option (List String) := none
  notActions     : Option (List String) := none
  resources      : Option (List String) := none
  notResources   : Option (List String) := none
  condition      : Option Json := none
  principals     : Option Json := none
  notPrincipals  : Option Json := none
  index          : Nat := 0

private def strOrArray? (j : Json) : Except String (List String) :=
  match j with
  | .str s => .ok [s]
  | .arr _ => do
    let arr ← j.getArr?
    arr.toList.mapM fun v => match v with
      | .str s => .ok s
      | _ => .error "expected string in array"
  | _ => .error "expected string or array of strings"

structure ParseWarning where
  message : String
deriving Repr

instance : ToJson ParseWarning where
  toJson w := .str w.message

private def tryField (j : Json) (field : String) (idx : Nat) :
    Option Json → (List ParseWarning) → (Option (List String) × List ParseWarning)
  | none, ws => (none, ws)
  | some _, ws =>
    match j.getObjVal? field >>= strOrArray? with
    | .ok v => (some v, ws)
    | .error e => (none, ws ++ [⟨s!"Statement {idx}: {field}: {e}"⟩])

private def condBaseOp (opName : String) : String :=
  let s := if opName.startsWith "ForAnyValue:" then (opName.drop 12).toString
           else if opName.startsWith "ForAllValues:" then (opName.drop 13).toString
           else opName
  if s.endsWith "IfExists" then (s.dropEnd 8).toString else s

private def isSupportedConditionOp (base : String) : Bool :=
  base == "StringEquals" || base == "StringNotEquals" ||
  base == "StringEqualsIgnoreCase" || base == "StringNotEqualsIgnoreCase" ||
  base == "StringLike" || base == "StringNotLike" ||
  base == "ArnEquals" || base == "ArnNotEquals" ||
  base == "ArnLike" || base == "ArnNotLike" ||
  base == "Bool" || base == "Null"

def parseStatement (j : Json) (idx : Nat) : Except String (Statement × List ParseWarning) := do
  let mut warnings : List ParseWarning := []
  let effect ← match j.getObjVal? "Effect" with
    | .ok v => FromJson.fromJson? v |>.mapError (s!"Statement {idx}: " ++ ·)
    | .error _ => .error s!"Statement {idx}: missing Effect"
  let sid := (j.getObjVal? "Sid" >>= Json.getStr?).toOption
  let actionPresent := (j.getObjVal? "Action").toOption
  let (actions, ws1) := tryField j "Action" idx actionPresent warnings
  warnings := ws1
  let notActionPresent := (j.getObjVal? "NotAction").toOption
  let (notActions, ws2) := tryField j "NotAction" idx notActionPresent warnings
  warnings := ws2
  let resourcePresent := (j.getObjVal? "Resource").toOption
  let (resources, ws3) := tryField j "Resource" idx resourcePresent warnings
  warnings := ws3
  let notResourcePresent := (j.getObjVal? "NotResource").toOption
  let (notResources, ws4) := tryField j "NotResource" idx notResourcePresent warnings
  warnings := ws4
  let (condition, condWarns) ← match j.getObjVal? "Condition" |>.toOption with
    | none => pure (none, [])
    | some c => match c with
      | .obj ops =>
          let bad := ops.toList.find? fun (_, v) => match v with | .obj _ => false | _ => true
          match bad with
          | some (opName, _) =>
              .error s!"Statement {idx}: Condition operator {opName}: value must be an object"
          | none =>
            let cw := ops.toList.filterMap fun (opName, _) =>
              let base := condBaseOp opName
              if !isSupportedConditionOp base then
                some (⟨s!"unsupported condition operator: {base}"⟩ : ParseWarning)
              else none
            pure (some c, cw)
      | _ => .error s!"Statement {idx}: Condition must be an object"
  warnings := warnings ++ condWarns
  let principals := (j.getObjVal? "Principal").toOption
  let notPrincipals := (j.getObjVal? "NotPrincipal").toOption
  -- Validate AWS principal strings (reject non-ARN, non-12-digit)
  let validatePrincipalJson := fun (pj : Json) =>
    let strs : List String := match pj with
      | .str s => [s]
      | .obj kvs => kvs.toList.flatMap fun (key, val) =>
        if key == "AWS" then match val with
          | .str s => [s]
          | .arr a => a.toList.filterMap fun v => match v with | .str s => some s | _ => none
          | _ => []
        else []
      | _ => []
    match strs.find? fun s =>
      s != "*" && !(s.length == 12 && !s.isEmpty && s.toList.all Char.isDigit) && !s.startsWith "arn:" with
    | some bad => Except.error s!"Statement {idx}: invalid AWS principal \"{bad}\": expected 12-digit account id or ARN"
    | none => Except.ok ()
  match principals with
  | some pj => do let _ ← validatePrincipalJson pj
  | none => pure ()
  match notPrincipals with
  | some npj => do let _ ← validatePrincipalJson npj
  | none => pure ()
  if actions.isSome && notActions.isSome then
    warnings := warnings ++ [⟨s!"Statement {idx}: Action and NotAction are mutually exclusive"⟩]
  if resources.isSome && notResources.isSome then
    warnings := warnings ++ [⟨s!"Statement {idx}: Resource and NotResource are mutually exclusive"⟩]
  let hasPrincipal := principals.isSome || notPrincipals.isSome
  if effect == .allow && resourcePresent.isNone && notResourcePresent.isNone && !hasPrincipal then
    warnings := warnings ++ [⟨s!"Statement {idx}: Allow without Resource (required in identity-based policies)"⟩]
  .ok (⟨sid, effect, actions, notActions, resources, notResources, condition, principals, notPrincipals, idx⟩, warnings)

structure Policy where
  version    : Option String := none
  statements : List Statement

def parsePolicy (input : String) : Except String (Policy × List ParseWarning) := do
  let json ← Json.parse input |>.mapError (s!"JSON parse error: " ++ ·)
  let version := (json.getObjVal? "Version" >>= Json.getStr?).toOption
  let stmtJson ← match json.getObjVal? "Statement" with
    | .ok v => .ok v
    | .error _ => .error "missing Statement"
  let stmtArr ← match stmtJson with
    | .arr _ => do
      let a ← stmtJson.getArr?
      .ok a.toList
    | .obj _ => .ok [stmtJson]
    | _ => .error "Statement must be an object or array"
  let mut stmts : List Statement := []
  let mut warnings : List ParseWarning := []
  let mut sids : List String := []
  for i in [:stmtArr.length] do
    let s := stmtArr[i]!
    let (stmt, ws) ← parseStatement s i
    match stmt.sid with
    | some sid =>
      if sids.contains sid then
        warnings := warnings ++ [⟨s!"Duplicate Sid \"{sid}\" at statement {i}"⟩]
      sids := sids ++ [sid]
    | none => pure ()
    stmts := stmts ++ [stmt]
    warnings := warnings ++ ws
  .ok (⟨version, stmts⟩, warnings)
