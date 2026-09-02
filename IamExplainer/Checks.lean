import IamExplainer.Policy
import IamExplainer.Match
import Seclib.Prim.Finding

open Lean (Json)

private def stmtLabel (s : Statement) : String :=
  match s.sid with
  | some sid => sid
  | none     => s!"Statement[{s.index}]"

private def isBareWildcard (s : String) : Bool := s == "*"

private def hasConditionKey (cond : Option Json) (key : String) : Bool :=
  match cond with
  | none => false
  | some j =>
    match j with
    | Json.obj kvs =>
      kvs.toList.any fun (_, v) =>
        match v with
        | Json.obj inner =>
          inner.toList.any fun (k, _) => toLowerStr k == toLowerStr key
        | _ => false
    | _ => false

def checkAdminEquiv (s : Statement) : List Finding :=
  if s.effect != .allow then []
  else
    let actWild := match s.actions with
      | some acts => acts.any isBareWildcard
      | none => false
    let resWild := match s.resources with
      | some res => res.any isBareWildcard
      | none => false
    if actWild && resWild then
      [{ controlId := "LP.ADMIN.EQUIV.001"
         severity := .critical
         location := stmtLabel s
         evidence := { path := "Action + Resource", actual := "\"*\" / \"*\"" }
         explanation := "Statement grants all actions on all resources, equivalent to administrator access. Least privilege requires scoping both actions and resources."
         fix := { kind := "narrow"
                  suggestion := "{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\",\"s3:PutObject\"],\"Resource\":\"arn:aws:s3:::my-bucket/*\"}" } }]
    else []

def checkServiceWildcard (s : Statement) : List Finding :=
  if s.effect != .allow then []
  else
    match s.actions with
    | none => []
    | some acts =>
      let wilds := acts.filter fun a => isBareWildcard a || (a.endsWith ":*" && a.length > 2)
      if wilds.isEmpty then []
      else
        [{ controlId := "LP.ACTION.SERVICEWILDCARD.001"
           severity := .high
           location := stmtLabel s
           evidence := { path := "Action", actual := toString wilds }
           explanation := "Statement uses service-level wildcard actions. Least privilege requires listing specific API actions."
           fix := { kind := "narrow"
                    suggestion := "Replace wildcard with specific actions, e.g. [\"s3:GetObject\",\"s3:ListBucket\"]" } }]

def checkResourceWildcard (s : Statement) : List Finding :=
  if s.effect != .allow then []
  else
    match s.resources with
    | none => []
    | some res =>
      if res.any isBareWildcard then
        [{ controlId := "LP.RESOURCE.WILDCARD.001"
           severity := .high
           location := stmtLabel s
           evidence := { path := "Resource", actual := "\"*\"" }
           explanation := "Statement applies to all resources. Least privilege requires scoping to specific ARNs."
           fix := { kind := "narrow"
                    suggestion := "Replace \"*\" with specific ARNs, e.g. \"arn:aws:s3:::my-bucket/*\"" } }]
      else []

def checkNotAction (s : Statement) : List Finding :=
  if s.effect != .allow then []
  else
    match s.notActions with
    | none => []
    | some na =>
      [{ controlId := "LP.NOTACTION.ALLOW.001"
         severity := .high
         location := stmtLabel s
         evidence := { path := "NotAction", actual := toString na }
         explanation := "Allow with NotAction grants all actions except those listed. Any new AWS service or action is automatically allowed. Use explicit Action lists."
         fix := { kind := "replace"
                  suggestion := "Replace NotAction with an explicit Action list of required permissions" } }]

def checkNotResource (s : Statement) : List Finding :=
  if s.effect != .allow then []
  else
    match s.notResources with
    | none => []
    | some nr =>
      [{ controlId := "LP.NOTRESOURCE.ALLOW.001"
         severity := .medium
         location := stmtLabel s
         evidence := { path := "NotResource", actual := toString nr }
         explanation := "Allow with NotResource applies to all resources except those listed. New resources are automatically in scope. Use explicit Resource ARNs."
         fix := { kind := "replace"
                  suggestion := "Replace NotResource with an explicit Resource list" } }]

def checkPassRole (s : Statement) : List Finding :=
  if s.effect != .allow then []
  else if !stmtGrantsAction s "iam:PassRole" then []
  else
    let resWild := match s.resources with
      | some res => res.any isBareWildcard
      | none => false
    let hasPTS := hasConditionKey s.condition "iam:PassedToService"
    if resWild || !hasPTS then
      let reason := if resWild then "Resource \"*\" with iam:PassRole"
                    else "iam:PassRole without iam:PassedToService condition"
      [{ controlId := "LP.ESCALATE.PASSROLE.001"
         severity := .high
         location := stmtLabel s
         evidence := { path := if resWild then "Action + Resource" else "Action + Condition",
                       actual := reason }
         explanation := "iam:PassRole allows passing IAM roles to AWS services. Without resource scoping and iam:PassedToService condition, this enables privilege escalation by passing admin roles to any service."
         fix := { kind := "narrow"
                  suggestion := "{\"Effect\":\"Allow\",\"Action\":\"iam:PassRole\",\"Resource\":\"arn:aws:iam::123456789012:role/MyAppRole\",\"Condition\":{\"StringEquals\":{\"iam:PassedToService\":\"lambda.amazonaws.com\"}}}" } }]
    else []

def evaluate (p : Policy) : List Finding :=
  p.statements.flatMap fun s =>
    let admin := checkAdminEquiv s
    let svc := checkServiceWildcard s
    let res := checkResourceWildcard s
    let na := checkNotAction s
    let nr := checkNotResource s
    let pr := checkPassRole s
    if !admin.isEmpty then
      admin ++ na ++ nr
    else
      svc ++ res ++ na ++ nr ++ pr
