import IamExplainer.Policy
import IamExplainer.Match

open Lean (Json)

inductive PrincipalType where
  | aws | federated | service | canonicalUser | wildcard
deriving BEq

def PrincipalType.toString : PrincipalType → String
  | .aws => "AWS"
  | .federated => "Federated"
  | .service => "Service"
  | .canonicalUser => "CanonicalUser"
  | .wildcard => "Wildcard"

instance : ToString PrincipalType := ⟨PrincipalType.toString⟩

structure Principal where
  typ   : PrincipalType
  value : String
deriving BEq

private def isDigits (s : String) : Bool :=
  !s.isEmpty && s.toList.all Char.isDigit

def isBareAccountId (s : String) : Bool :=
  s.length == 12 && isDigits s

def normPrincipal (s : String) : Principal :=
  if s == "*" then { typ := .wildcard, value := "*" }
  else if isBareAccountId s then { typ := .aws, value := s!"arn:aws:iam::{s}:root" }
  else { typ := .aws, value := s }

private def strOrArrayPrincipal (j : Json) : List String :=
  match j with
  | .str s => [s]
  | .arr a => a.toList.filterMap fun v => match v with
    | .str s => some s
    | _ => none
  | _ => []

def parsePrincipals (j : Json) : List Principal :=
  match j with
  | .str "*" => [{ typ := .wildcard, value := "*" }]
  | .str s => [normPrincipal s]
  | .obj kvs =>
    kvs.toList.flatMap fun (key, val) =>
      let strs := strOrArrayPrincipal val
      match key with
      | "AWS" => strs.map normPrincipal
      | "Federated" => strs.map fun s => { typ := .federated, value := s }
      | "Service" => strs.map fun s => { typ := .service, value := s }
      | "CanonicalUser" => strs.map fun s => { typ := .canonicalUser, value := s }
      | _ => []
  | _ => []

def Principal.isRoot (p : Principal) : Bool :=
  p.typ == .aws && p.value.endsWith ":root"

def Principal.accountId (p : Principal) : Option String :=
  if p.typ != .aws then none
  else if isBareAccountId p.value then some p.value
  else
    let parts := p.value.splitOn ":"
    if parts.length >= 5 then parts[4]? else none

inductive Scope where
  | sameAccount | inOrg | crossOrg | pub | federated | service | unverified
deriving BEq

def Scope.toString : Scope → String
  | .sameAccount => "SAME_ACCOUNT"
  | .inOrg       => "IN_ORG"
  | .crossOrg    => "CROSS_ORG"
  | .pub         => "PUBLIC"
  | .federated   => "FEDERATED"
  | .service     => "SERVICE"
  | .unverified  => "UNVERIFIED"

instance : ToString Scope := ⟨Scope.toString⟩

structure Context where
  account  : Option String := none
  accounts : List String := []
  orgId    : Option String := none

def condOrgIds (cond : Option Json) : List String :=
  match cond with
  | none => []
  | some j =>
    match j with
    | .obj kvs =>
      kvs.toList.flatMap fun (_, v) =>
        match v with
        | .obj inner =>
          inner.toList.flatMap fun (k, val) =>
            if toLowerStr k == "aws:principalorgid" then
              match val with
              | .str s => [s]
              | .arr a => a.toList.filterMap fun v => match v with | .str s => some s | _ => none
              | _ => []
            else []
        | _ => []
    | _ => []

def scopeOf (ctx : Context) (p : Principal) (cond : Option Json) : Scope :=
  match p.typ with
  | .wildcard =>
    match ctx.orgId with
    | none => if ctx.account.isSome then Scope.pub else Scope.unverified
    | some oid =>
      let ids := condOrgIds cond
      if ids.isEmpty then Scope.pub
      else if ids.all (· == oid) then Scope.inOrg
      else Scope.crossOrg
  | .federated => Scope.federated
  | .service => Scope.service
  | .canonicalUser => Scope.unverified
  | .aws =>
    match ctx.account with
    | none => Scope.unverified
    | some acct =>
      match p.accountId with
      | none => Scope.unverified
      | some pid =>
        if pid == acct then Scope.sameAccount
        else if ctx.accounts.contains pid then Scope.inOrg
        else Scope.crossOrg

inductive DocKind where
  | identity | trust | resource | mixed
deriving BEq

def DocKind.toString : DocKind → String
  | .identity => "IDENTITY"
  | .trust    => "TRUST"
  | .resource => "RESOURCE"
  | .mixed    => "MIXED"

instance : ToString DocKind := ⟨DocKind.toString⟩

private def isTrustAction (a : String) : Bool :=
  let la := toLowerStr a
  la == "sts:assumerole" || la == "sts:assumerolewithsaml" ||
  la == "sts:assumerolewithwebidentity" || la == "sts:tagsession" ||
  la == "sts:setsourceidentity" || la == "*"

private def stmtIsTrustShaped (s : Statement) : Bool :=
  s.principals.isSome &&
  s.resources.isNone && s.notResources.isNone &&
  match s.actions with
  | some acts => acts.all isTrustAction
  | none => match s.notActions with
    | some _ => false
    | none => true

def detectKind (stmts : List Statement) : DocKind :=
  let hasPrincipal := stmts.any fun s => s.principals.isSome || s.notPrincipals.isSome
  let hasNoPrincipal := stmts.any fun s => s.principals.isNone && s.notPrincipals.isNone
  if !hasPrincipal then DocKind.identity
  else if hasNoPrincipal then DocKind.mixed
  else if stmts.all stmtIsTrustShaped then DocKind.trust
  else DocKind.resource
