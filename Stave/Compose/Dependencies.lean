import Stave.Compose.Basic

/-! Implicit dependency semantics.
Formalizes: internal/core/controldef/chain.go:152-204
and chain_engine.go:470-511 (AnnotateDependencies). -/

/-- Go source: internal/core/controldef/chain.go:170-184 -/
inductive DependencyFallback where
  | failClosed | failOpen | crossValidate
deriving DecidableEq, Repr

/-- Go source: internal/core/controldef/chain.go:196-203 -/
inductive DependencyStatus where
  | unknown | notRun | ranEmpty | ranOK
deriving DecidableEq, Repr

/-- Go source: internal/core/controldef/chain.go:153-167 -/
structure ImplicitDep where
  source : String
  fallback : DependencyFallback
  diagnostic : String

/-- Go source: internal/core/evaluation/risk/chain_engine.go:492-506 (AnnotateDependencies switch) -/
def shouldDiagnose (fallback : DependencyFallback) (status : DependencyStatus) : Bool :=
  match fallback, status with
  | .failClosed, .ranOK       => false
  | .failClosed, _            => true
  | .crossValidate, .ranOK    => false
  | .crossValidate, _         => true
  | .failOpen, _              => false

/-- Go source: chain_engine.go:494-500 — fail_closed diagnoses on notRun. -/
theorem failClosed_diagnoses_notRun :
    shouldDiagnose .failClosed .notRun = true := rfl

/-- Go source: chain_engine.go:494-500 — fail_closed diagnoses on unknown. -/
theorem failClosed_diagnoses_unknown :
    shouldDiagnose .failClosed .unknown = true := rfl

/-- Go source: chain_engine.go:505-506 — fail_open never annotates. -/
theorem failOpen_never_diagnoses (status : DependencyStatus) :
    shouldDiagnose .failOpen status = false := by
  cases status <;> rfl

/-- Go source: chain_engine.go:494-506 — ranOK never triggers any fallback. -/
theorem ranOK_never_diagnoses (fb : DependencyFallback) :
    shouldDiagnose fb .ranOK = false := by
  cases fb <;> rfl
