import Seclib.Compose.Basic

/-! Implicit dependency semantics.
Formalizes: internal/core/controldef/chain.go:152-204
and chain_engine.go:470-511 (AnnotateDependencies). -/

inductive DependencyFallback where
  | failClosed | failOpen | crossValidate
deriving DecidableEq, Repr

inductive DependencyStatus where
  | unknown | notRun | ranEmpty | ranOK
deriving DecidableEq, Repr

structure ImplicitDep where
  source : String
  fallback : DependencyFallback
  diagnostic : String

def shouldDiagnose (fallback : DependencyFallback) (status : DependencyStatus) : Bool :=
  match fallback, status with
  | .failClosed, .ranOK       => false
  | .failClosed, _            => true
  | .crossValidate, .ranOK    => false
  | .crossValidate, _         => true
  | .failOpen, _              => false

theorem failClosed_diagnoses_notRun :
    shouldDiagnose .failClosed .notRun = true := rfl

theorem failClosed_diagnoses_unknown :
    shouldDiagnose .failClosed .unknown = true := rfl

theorem failOpen_never_diagnoses (status : DependencyStatus) :
    shouldDiagnose .failOpen status = false := by
  cases status <;> rfl

theorem ranOK_never_diagnoses (fb : DependencyFallback) :
    shouldDiagnose fb .ranOK = false := by
  cases fb <;> rfl
