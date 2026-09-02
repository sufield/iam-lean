import IamExplainer.Checks
import IamExplainer.Principal
import IamExplainer.Grants

open Lean (Json)

private def stmtLabel (s : Statement) : String :=
  match s.sid with
  | some sid => sid
  | none     => s!"Statement[{s.index}]"

def condHasKey (cond : Option Json) (key : String) : Bool :=
  match cond with
  | none => false
  | some j =>
    match j with
    | .obj kvs =>
      kvs.toList.any fun (_, v) =>
        match v with
        | .obj inner =>
          inner.toList.any fun (k, _) => toLowerStr k == toLowerStr key
        | _ => false
    | _ => false

private def hasFedSubKey (cond : Option Json) (providerArn : String) : Bool :=
  let parts := providerArn.splitOn "/"
  match parts.getLast? with
  | none => false
  | some provider => condHasKey cond (provider ++ ":sub")

private def principalFindings (ctx : Context) (kind : DocKind) (s : Statement)
    (label : String) (p : Principal) : List Finding :=
  let scope := scopeOf ctx p s.condition
  match scope with
  | .pub =>
    if s.condition.isSome then
      [{ controlId := "XA.PRINCIPAL.PUBLIC.FENCED.001"
         severity := .medium, location := label
         evidence := { path := "Principal", actual := "*" }
         explanation := "Principal \"*\" with a Condition. Fence present, not evaluated."
         fix := { kind := "narrow", suggestion := "Verify condition restricts access to intended principals" } }]
    else
      [{ controlId := "XA.PRINCIPAL.PUBLIC.001"
         severity := .critical, location := label
         evidence := { path := "Principal", actual := "*" }
         explanation := "Principal \"*\" with no Condition. Any AWS account can access this resource."
         fix := { kind := "narrow", suggestion := "Replace Principal \"*\" with specific account ARNs and add conditions" } }]
  | .crossOrg =>
    let rootFinding := if p.isRoot then
      [{ controlId := "XA.PRINCIPAL.ROOT.EXTERNAL.001"
         severity := .high, location := label
         evidence := { path := "Principal", actual := p.value }
         explanation := s!"External account root principal {p.value}. Delegates access to every identity in that account."
         fix := { kind := "narrow", suggestion := "Replace :root with a specific role ARN" } }]
    else []
    let orgFinding :=
      let ids := condOrgIds s.condition
      let foreignIds := match ctx.orgId with
        | some oid => ids.filter (· != oid)
        | none => []
      if foreignIds.isEmpty then []
      else
        let fid := foreignIds.head!
        [{ controlId := "XA.ORGID.FOREIGN.001"
           severity := .critical, location := label
           evidence := { path := "Condition.aws:PrincipalOrgID", actual := fid }
           explanation := s!"aws:PrincipalOrgID is {fid}, not {ctx.orgId.getD "?"}. This statement references a foreign organization."
           fix := { kind := "replace", suggestion := s!"Change aws:PrincipalOrgID to {ctx.orgId.getD "?"}" } }]
    let extIdFinding := if kind == .trust &&
        stmtGrantsAction s "sts:AssumeRole" &&
        !condHasKey s.condition "sts:ExternalId" then
      [{ controlId := "XA.TRUST.EXTERNALID.ABSENT.001"
         severity := .high, location := label
         evidence := { path := "Principal + Condition", actual := s!"cross-org {p.value}, no sts:ExternalId" }
         explanation := "Cross-account trust without sts:ExternalId condition. Vulnerable to confused deputy."
         fix := { kind := "add", suggestion := "Add Condition: {\"StringEquals\": {\"sts:ExternalId\": \"<shared-secret>\"}}" } }]
    else []
    rootFinding ++ orgFinding ++ extIdFinding
  | .federated =>
    let oidcFinding := if (p.value.splitOn ":oidc-provider/").length > 1 && !hasFedSubKey s.condition p.value then
      [{ controlId := "XA.FEDERATED.UNSCOPED.001"
         severity := .high, location := label
         evidence := { path := "Federated + Condition", actual := s!"{p.value}, no :sub key" }
         explanation := "Federated OIDC principal without a :sub condition key. Any identity from this provider can assume the role."
         fix := { kind := "add", suggestion := "Add a <provider>:sub condition to restrict to specific subjects" } }]
    else []
    let samlFinding := if (p.value.splitOn ":saml-provider/").length > 1 &&
        stmtGrantsAction s "sts:AssumeRoleWithSAML" &&
        !condHasKey s.condition "SAML:aud" && !condHasKey s.condition "SAML:sub" then
      [{ controlId := "XA.FEDERATED.SAML.UNSCOPED.001"
         severity := .high, location := label
         evidence := { path := "Federated + Condition", actual := s!"{p.value}, no SAML:aud or SAML:sub" }
         explanation := "SAML provider trust without SAML:aud or SAML:sub condition. Any SAML assertion from this IdP can assume the role."
         fix := { kind := "add", suggestion := "Add Condition: {\"StringEquals\": {\"SAML:aud\": \"https://signin.aws.amazon.com/saml\"}}" } }]
    else []
    oidcFinding ++ samlFinding
  | _ => []

def checkXA (ctx : Context) (kind : DocKind) (s : Statement) : List Finding :=
  if s.effect != .allow then []
  else
    let label := stmtLabel s
    let fromPrincipals := match s.principals with
      | none => []
      | some pj =>
        let ps := parsePrincipals pj
        ps.flatMap (principalFindings ctx kind s label)
    let fromNotPrincipals := match s.notPrincipals with
      | none => []
      | some _ =>
        [{ controlId := "XA.NOTPRINCIPAL.ALLOW.001"
           severity := .critical, location := label
           evidence := { path := "NotPrincipal", actual := "Allow with NotPrincipal" }
           explanation := "Allow with NotPrincipal grants access to all principals except those listed. Dangerous: any new account gains access."
           fix := { kind := "replace", suggestion := "Replace NotPrincipal with an explicit Principal list" } }]
    fromPrincipals ++ fromNotPrincipals

def xaWarnings (ctx : Context) (s : Statement) : List ParseWarning :=
  if s.effect != .allow then []
  else match s.principals with
    | none => []
    | some pj =>
      let ps := parsePrincipals pj
      ps.filterMap fun p =>
        if p.typ == .canonicalUser then
          some ⟨s!"Statement {s.index}: canonical user id is not resolvable to an account from the document"⟩
        else
          let scope := scopeOf ctx p s.condition
          if scope == .unverified then
            let missing := if ctx.account.isNone then "--account"
                           else if ctx.accounts.isEmpty then "--accounts"
                           else "--org-id"
            some ⟨s!"Statement {s.index}: scope UNVERIFIED — supply {missing} to classify"⟩
          else none
