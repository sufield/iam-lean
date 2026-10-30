import Stave.CEL.TypedAST
import Stave.CEL.Controls

/-! `cel![]` — compile-time CEL predicate macro.

Write `cel![env| field > 42]` and get a `CelExpr env .bool` at compile
time, with a type error if the field isn't in `env` with the right type.

Supported forms:
  cel![env| field == lit]        eq (bool/string/int inferred from lit)
  cel![env| field != lit]        ne
  cel![env| field > n]           gtInt
  cel![env| field < n]           ltInt
  cel![env| field >= n]          gteInt
  cel![env| field <= n]          lteInt
  cel![env| field contains s]    containsStr
  cel![env| field missing]       field absence
  cel![env| a && b]              conjunction
  cel![env| a || b]              disjunction
  cel![env| !a]                  negation
  cel![env| (a)]                 grouping -/

declare_syntax_cat cel (behavior := symbol)

syntax ident : cel
syntax num : cel
syntax str : cel
syntax "true" : cel
syntax "false" : cel
syntax:50 cel:51 " == " cel:51 : cel
syntax:50 cel:51 " != " cel:51 : cel
syntax:50 cel:51 " > " cel:51 : cel
syntax:50 cel:51 " < " cel:51 : cel
syntax:50 cel:51 " >= " cel:51 : cel
syntax:50 cel:51 " <= " cel:51 : cel
syntax:50 cel:51 " contains " cel:51 : cel
syntax:35 cel:36 " && " cel:35 : cel
syntax:30 cel:31 " || " cel:30 : cel
syntax:60 "!" cel:60 : cel
syntax ident " missing" : cel
syntax "(" cel ")" : cel

syntax "cel![" ident "|" cel "]" : term

macro_rules
  | `(cel![$env:ident| $fld:ident missing]) =>
    let name := fld.getId.toString
    `(CelExpr.missing (env := $env) (mkFieldPath [$(Lean.quote name)]))

  | `(cel![$env:ident| $fld:ident == true]) =>
    let name := fld.getId.toString
    `(CelExpr.binop CelBinOp.eqBool
        (CelExpr.field (env := $env) (mkFieldPath [$(Lean.quote name)]) (by native_decide))
        (CelExpr.lit (CelLit.bool true)))
  | `(cel![$env:ident| $fld:ident == false]) =>
    let name := fld.getId.toString
    `(CelExpr.binop CelBinOp.eqBool
        (CelExpr.field (env := $env) (mkFieldPath [$(Lean.quote name)]) (by native_decide))
        (CelExpr.lit (CelLit.bool false)))

  | `(cel![$env:ident| $fld:ident != true]) =>
    let name := fld.getId.toString
    `(CelExpr.binop CelBinOp.neBool
        (CelExpr.field (env := $env) (mkFieldPath [$(Lean.quote name)]) (by native_decide))
        (CelExpr.lit (CelLit.bool true)))
  | `(cel![$env:ident| $fld:ident != false]) =>
    let name := fld.getId.toString
    `(CelExpr.binop CelBinOp.neBool
        (CelExpr.field (env := $env) (mkFieldPath [$(Lean.quote name)]) (by native_decide))
        (CelExpr.lit (CelLit.bool false)))

  | `(cel![$env:ident| $fld:ident == $s:str]) =>
    let name := fld.getId.toString
    `(CelExpr.binop CelBinOp.eqStr
        (CelExpr.field (env := $env) (mkFieldPath [$(Lean.quote name)]) (by native_decide))
        (CelExpr.lit (CelLit.string $s)))
  | `(cel![$env:ident| $fld:ident != $s:str]) =>
    let name := fld.getId.toString
    `(CelExpr.binop CelBinOp.neStr
        (CelExpr.field (env := $env) (mkFieldPath [$(Lean.quote name)]) (by native_decide))
        (CelExpr.lit (CelLit.string $s)))

  | `(cel![$env:ident| $fld:ident == $n:num]) =>
    let name := fld.getId.toString
    `(CelExpr.binop CelBinOp.eqInt
        (CelExpr.field (env := $env) (mkFieldPath [$(Lean.quote name)]) (by native_decide))
        (CelExpr.lit (CelLit.int $n)))
  | `(cel![$env:ident| $fld:ident != $n:num]) =>
    let name := fld.getId.toString
    `(CelExpr.binop CelBinOp.neInt
        (CelExpr.field (env := $env) (mkFieldPath [$(Lean.quote name)]) (by native_decide))
        (CelExpr.lit (CelLit.int $n)))

  | `(cel![$env:ident| $fld:ident > $n:num]) =>
    let name := fld.getId.toString
    `(CelExpr.binop CelBinOp.gtInt
        (CelExpr.field (env := $env) (mkFieldPath [$(Lean.quote name)]) (by native_decide))
        (CelExpr.lit (CelLit.int $n)))
  | `(cel![$env:ident| $fld:ident < $n:num]) =>
    let name := fld.getId.toString
    `(CelExpr.binop CelBinOp.ltInt
        (CelExpr.field (env := $env) (mkFieldPath [$(Lean.quote name)]) (by native_decide))
        (CelExpr.lit (CelLit.int $n)))
  | `(cel![$env:ident| $fld:ident >= $n:num]) =>
    let name := fld.getId.toString
    `(CelExpr.binop CelBinOp.gteInt
        (CelExpr.field (env := $env) (mkFieldPath [$(Lean.quote name)]) (by native_decide))
        (CelExpr.lit (CelLit.int $n)))
  | `(cel![$env:ident| $fld:ident <= $n:num]) =>
    let name := fld.getId.toString
    `(CelExpr.binop CelBinOp.lteInt
        (CelExpr.field (env := $env) (mkFieldPath [$(Lean.quote name)]) (by native_decide))
        (CelExpr.lit (CelLit.int $n)))

  | `(cel![$env:ident| $fld:ident contains $s:str]) =>
    let name := fld.getId.toString
    `(CelExpr.binop CelBinOp.containsStr
        (CelExpr.field (env := $env) (mkFieldPath [$(Lean.quote name)]) (by native_decide))
        (CelExpr.lit (CelLit.string $s)))

  | `(cel![$env:ident| $a && $b]) =>
    `(CelExpr.and (cel![$env| $a]) (cel![$env| $b]))
  | `(cel![$env:ident| $a || $b]) =>
    `(CelExpr.or (cel![$env| $a]) (cel![$env| $b]))
  | `(cel![$env:ident| ! $a]) =>
    `(CelExpr.not (cel![$env| $a]))
  | `(cel![$env:ident| ($a)]) =>
    `(cel![$env| $a])

/-! ### Test: macro-generated expressions for CH1/CH2 controls -/

-- Simple predicates
def ctlLogValidation' : CelExpr cloudTrailEnv .bool :=
  cel![cloudTrailEnv| log_file_validation_enabled == false]

def ctlSignedLongExpiry' : CelExpr cdnEnv .bool :=
  cel![cdnEnv| signed_url_default_expiry_seconds > 86400]

def ctlCertExpiryWarn' : CelExpr cdnEnv .bool :=
  cel![cdnEnv| viewer_cert_days_until_expiry < 30]

def ctlCloudFrontWAF' : CelExpr cdnEnv .bool :=
  cel![cdnEnv| waf_web_acl_id missing]

def ctlCredUnused45' : CelExpr iamUserEnv .bool :=
  cel![iamUserEnv| credentials_unused_days > 45]

def ctlAdminCount' : CelExpr iamSummaryEnv .bool :=
  cel![iamSummaryEnv| admin_user_count > 2]

def ctlS3Governance' : CelExpr storageEnv .bool :=
  cel![storageEnv| data_classification missing]

def ctlSGUnrestricted' : CelExpr sgEnv .bool :=
  cel![sgEnv| has_unrestricted_ingress == true]

-- Compound: kind guard + predicate
def ctlLogValidationGuarded : CelExpr cloudTrailEnv .bool :=
  cel![cloudTrailEnv| kind == "trail" && log_file_validation_enabled == false]

def ctlAdminCountGuarded : CelExpr iamSummaryEnv .bool :=
  cel![iamSummaryEnv| kind == "account_summary" && admin_user_count > 2]

-- String contains
def ctlVPCKmsContains : CelExpr vpcEndpointEnv .bool :=
  cel![vpcEndpointEnv| service_name contains ".kms"]

/-! ### Known-answer tests -/

private def mkObs (assetId assetType : String)
    (props : List (String × PropValue)) : Observation :=
  ⟨assetId, assetType, props⟩

example : ctlAdminCount'.toOutcome
    (mkObs "a" "t" [("admin_user_count", .int 5)]) = .«unsafe» := by native_decide
example : ctlAdminCount'.toOutcome
    (mkObs "a" "t" [("admin_user_count", .int 1)]) = .clear := by native_decide
example : ctlCredUnused45'.toOutcome
    (mkObs "a" "t" [("credentials_unused_days", .int 90)]) = .«unsafe» := by native_decide
example : ctlCredUnused45'.toOutcome
    (mkObs "a" "t" [("credentials_unused_days", .int 10)]) = .clear := by native_decide
example : ctlS3Governance'.toOutcome
    (mkObs "a" "t" []) = .«unsafe» := by native_decide
example : ctlS3Governance'.toOutcome
    (mkObs "a" "t" [("data_classification", .str "public")]) = .clear := by native_decide
example : ctlSGUnrestricted'.toOutcome
    (mkObs "a" "t" [("has_unrestricted_ingress", .bool true)]) = .«unsafe» := by native_decide
example : ctlSGUnrestricted'.toOutcome
    (mkObs "a" "t" [("has_unrestricted_ingress", .bool false)]) = .clear := by native_decide
example : ctlLogValidation'.toOutcome
    (mkObs "a" "t" [("log_file_validation_enabled", .bool false)]) = .«unsafe» := by native_decide
example : ctlSignedLongExpiry'.toOutcome
    (mkObs "a" "t" [("signed_url_default_expiry_seconds", .int 172800)]) = .«unsafe» := by native_decide
example : ctlCloudFrontWAF'.toOutcome
    (mkObs "a" "t" []) = .«unsafe» := by native_decide
example : ctlCloudFrontWAF'.toOutcome
    (mkObs "a" "t" [("waf_web_acl_id", .str "acl-123")]) = .clear := by native_decide

-- Compound tests
example : ctlAdminCountGuarded.toOutcome
    (mkObs "a" "t" [("kind", .str "account_summary"),
                     ("admin_user_count", .int 5)]) = .«unsafe» := by native_decide
example : ctlAdminCountGuarded.toOutcome
    (mkObs "a" "t" [("admin_user_count", .int 5)]) = .unevaluable := by native_decide
example : ctlLogValidationGuarded.toOutcome
    (mkObs "a" "t" [("kind", .str "trail"),
                     ("log_file_validation_enabled", .bool false)]) = .«unsafe» := by native_decide
example : ctlLogValidationGuarded.toOutcome
    (mkObs "a" "t" [("kind", .str "trail"),
                     ("log_file_validation_enabled", .bool true)]) = .clear := by native_decide

-- Contains test
example : ctlVPCKmsContains.toOutcome
    (mkObs "a" "t" [("service_name", .str "com.amazonaws.us-east-1.kms")]) = .«unsafe» := by native_decide
example : ctlVPCKmsContains.toOutcome
    (mkObs "a" "t" [("service_name", .str "com.amazonaws.us-east-1.s3")]) = .clear := by native_decide
