import Lean.Data.Json
import IamExplainer.Ghost.Aws

/-! Parse ghost-annotated observation fields into RefStatus.

When a reference field in the observation JSON carries
`_ghost: true` plus a `_ghost_kind` discriminator, construct
the appropriate AwsGhostKind and its default GhostAssumption.
When `_ghost` is absent or false, construct RefStatus.resolved. -/

open Lean (Json FromJson)

def parseGhostKind (j : Json) : Option AwsGhostKind := do
  let kind ← (j.getObjValAs? String "_ghost_kind").toOption
  let arn ← (j.getObjValAs? String "_ghost_arn").toOption <|> pure ""
  match kind with
  | "managed_policy" => some (.managedPolicyArn arn)
  | "cross_account_role" =>
    let acct ← (j.getObjValAs? String "_ghost_account").toOption <|> pure ""
    some (.crossAccountRole arn acct)
  | "service_linked_role" =>
    let sp ← (j.getObjValAs? String "_ghost_service_principal").toOption <|> pure ""
    some (.serviceLinkedRole sp)
  | "cross_account_resource" => some (.crossAccountResource arn)
  | "unmodeled_service" => some (.unmodeledService arn)
  | _ => none

def parseRefStatus [FromJson α] (j : Json) : Except String (RefStatus α) := do
  let isGhost := match j.getObjValAs? Bool "_ghost" with
    | .ok true => true
    | _ => false
  if isGhost then
    match parseGhostKind j with
    | some kind => .ok kind.toRefStatus
    | none => .error "ghost reference missing valid _ghost_kind"
  else
    let payload ← FromJson.fromJson? j
    .ok (.resolved payload)

/-! ### #guard tests -/

-- Ghost cross-account role
#guard
  let j := Json.mkObj [
    ("_ghost", Json.bool true),
    ("_ghost_kind", Json.str "cross_account_role"),
    ("_ghost_arn", Json.str "arn:aws:iam::999:role/Audit"),
    ("_ghost_account", Json.str "999")
  ]
  match parseRefStatus (α := String) j with
  | .ok (.ghost _ .overPermissive) => true
  | _ => false

-- Ghost managed policy
#guard
  let j := Json.mkObj [
    ("_ghost", Json.bool true),
    ("_ghost_kind", Json.str "managed_policy"),
    ("_ghost_arn", Json.str "arn:aws:iam::aws:policy/ReadOnly")
  ]
  match parseRefStatus (α := String) j with
  | .ok (.ghost _ .overPermissive) => true
  | _ => false

-- Resolved (no ghost annotation)
#guard
  let j := Json.str "arn:aws:iam::123:role/Admin"
  match parseRefStatus j with
  | .ok (.resolved "arn:aws:iam::123:role/Admin") => true
  | _ => false
