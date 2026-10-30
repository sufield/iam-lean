import Stave.Schema.Types
import Stave.Schema.Predicate
import Stave.Evaluate.Observation

/-! Intrinsically typed CEL AST.

An expression `CelExpr env ty` is indexed by a typing environment and
its result type. The constructor set rejects ill-typed CEL at Lean
compile time — you cannot build a `CelExpr` that compares a string
with `>`, or applies `contains` to an int.

This eliminates the `none` branch in `compareValues` (Evaluate/Eval.lean:14)
by construction: every `CelExpr` that typechecks denotes a total function
from observation to `CelResult`. -/

/-! ### CelType — the types a CEL expression can produce -/

inductive CelType where
  | bool
  | string
  | int
  deriving DecidableEq, Repr, Inhabited, BEq

/-! ### Typed literals -/

def CelType.Interp : CelType → Type
  | .bool   => Bool
  | .string => String
  | .int    => Int

inductive CelLit : CelType → Type where
  | bool   (v : Bool)   : CelLit .bool
  | string (v : String) : CelLit .string
  | int    (v : Int)    : CelLit .int
  deriving Repr

def CelLit.val : CelLit ty → CelType.Interp ty
  | .bool v   => v
  | .string v => v
  | .int v    => v

/-! ### Typed binary operators

Each constructor carries the operand types and the result type in its
indices. This is the key restriction: `gtInt` only accepts `.int`
operands, so you cannot construct `gt` on strings. -/

inductive CelBinOp : CelType → CelType → CelType → Type where
  | eqBool      : CelBinOp .bool   .bool   .bool
  | neBool      : CelBinOp .bool   .bool   .bool
  | eqStr       : CelBinOp .string .string .bool
  | neStr       : CelBinOp .string .string .bool
  | eqInt       : CelBinOp .int    .int    .bool
  | neInt       : CelBinOp .int    .int    .bool
  | gtInt       : CelBinOp .int    .int    .bool
  | ltInt       : CelBinOp .int    .int    .bool
  | gteInt      : CelBinOp .int    .int    .bool
  | lteInt      : CelBinOp .int    .int    .bool
  | containsStr : CelBinOp .string .string .bool
  deriving Repr

/-! ### Typing environment

Maps field paths to their expected types. An observation whose fields
match this environment can evaluate any `CelExpr` over it without
hitting the `unevaluable` branch. -/

structure CelEnv where
  bindings : List (FieldPath × CelType)
  deriving Repr

def CelEnv.empty : CelEnv := ⟨[]⟩

def CelEnv.bind (env : CelEnv) (fp : FieldPath) (ty : CelType) : CelEnv :=
  ⟨(fp, ty) :: env.bindings⟩

def CelEnv.lookup (env : CelEnv) (fp : FieldPath) : Option CelType :=
  env.bindings.find? (fun p => p.1 == fp) |>.map (·.2)

def CelEnv.hasBinding (env : CelEnv) (fp : FieldPath) (ty : CelType) : Prop :=
  env.lookup fp = some ty

instance (env : CelEnv) (fp : FieldPath) (ty : CelType) :
    Decidable (env.hasBinding fp ty) :=
  inferInstanceAs (Decidable (env.lookup fp = some ty))

/-! ### CelExpr — intrinsically typed expression tree

The `field` constructor demands a proof that the field path has the
right type in the environment. If no such proof exists (because the
field is absent or has a different type), the expression cannot be
constructed — ill-typed predicates are unrepresentable. -/

inductive CelExpr : CelEnv → CelType → Type where
  | lit     : CelLit ty → CelExpr env ty
  | field   : (fp : FieldPath) → env.hasBinding fp ty → CelExpr env ty
  | binop   : CelBinOp a b r → CelExpr env a → CelExpr env b → CelExpr env r
  | and     : CelExpr env .bool → CelExpr env .bool → CelExpr env .bool
  | or      : CelExpr env .bool → CelExpr env .bool → CelExpr env .bool
  | not     : CelExpr env .bool → CelExpr env .bool
  | missing : (fp : FieldPath) → CelExpr env .bool
  deriving Repr

/-! ### Denotational semantics

`CelBinOp.eval` is total — every well-typed operator produces a value.
No `Option`, no `none` branch. This is the payoff of intrinsic typing:
the `none` in `compareValues` cannot arise. -/

private def strContains (s sub : String) : Bool :=
  (s.splitOn sub).length > 1

def CelBinOp.eval : CelBinOp a b r → CelType.Interp a → CelType.Interp b → CelType.Interp r
  | .eqBool      => fun (x y : Bool)   => x == y
  | .neBool      => fun (x y : Bool)   => !(x == y)
  | .eqStr       => fun (x y : String) => x == y
  | .neStr       => fun (x y : String) => !(x == y)
  | .eqInt       => fun (x y : Int)    => x == y
  | .neInt       => fun (x y : Int)    => !(x == y)
  | .gtInt       => fun (x y : Int)    => decide (x > y)
  | .ltInt       => fun (x y : Int)    => decide (x < y)
  | .gteInt      => fun (x y : Int)    => decide (x ≥ y)
  | .lteInt      => fun (x y : Int)    => decide (x ≤ y)
  | .containsStr => fun (x y : String) => strContains x y

/-! ### Observation-level evaluation

An observation may or may not have a field. `CelExpr.eval` returns
`Option` at the observation boundary: `none` means the field was
missing. The *expression-level* evaluation (binop, and, or) is total. -/

def resolveTyped (obs : Observation) (fp : FieldPath) (ty : CelType) : Option (CelType.Interp ty) :=
  match obs.resolveField fp with
  | none => none
  | some pv =>
    match ty, pv with
    | .bool,   .bool v   => some v
    | .string, .str v    => some v
    | .int,    .int v    => some v
    | _, _ => none

def CelExpr.eval (obs : Observation) : CelExpr env ty → Option (CelType.Interp ty)
  | .lit l          => some l.val
  | .field fp _     => resolveTyped obs fp ty
  | .binop op l r   => do
      let lv ← l.eval obs
      let rv ← r.eval obs
      pure (op.eval lv rv)
  | .and l r        => do
      let lv ← l.eval obs
      let rv ← r.eval obs
      pure (lv && rv)
  | .or l r         => do
      let lv ← l.eval obs
      let rv ← r.eval obs
      pure (lv || rv)
  | .not e          => do
      let v ← e.eval obs
      pure (!v)
  | .missing fp     => some (obs.resolveField fp).isNone

/-! ### Bridge to EvalOutcome

Converts the typed evaluation result to the existing tri-state outcome.
`none` (missing field) maps to `unevaluable` — fail-closed preserved. -/

def CelExpr.toOutcome (obs : Observation) (expr : CelExpr env .bool) : EvalOutcome :=
  match expr.eval obs with
  | some true  => .«unsafe»
  | some false => .clear
  | none       => .unevaluable

/-! ### Erasure to untyped AST

Forgets the type indices, recovering the existing `PredicateRule`.
Used to verify that a typed expression corresponds to its YAML source. -/

def celBinOpToOperator : CelBinOp a b r → Operator
  | .eqBool      => .eq
  | .neBool      => .ne
  | .eqStr       => .eq
  | .neStr       => .ne
  | .eqInt       => .eq
  | .neInt       => .ne
  | .gtInt       => .gt
  | .ltInt       => .lt
  | .gteInt      => .gte
  | .lteInt      => .lte
  | .containsStr => .contains

def celLitToOperand : CelLit ty → Operand
  | .bool v   => .bool v
  | .string v => .str v
  | .int v    => .int v

def CelExpr.erase : CelExpr env ty → PredicateRule
  | .lit _          => .leaf ⟨["_literal"], by decide⟩ .present (.bool true) none
  | .field fp _     => .leaf fp .present (.bool true) none
  | .binop op l r   =>
    match l, r with
    | .field fp _, .lit v => .leaf fp (celBinOpToOperator op) (celLitToOperand v) none
    | _, _               => .allBlock [l.erase, r.erase]
  | .and l r        => .allBlock [l.erase, r.erase]
  | .or l r         => .anyBlock [l.erase, r.erase]
  | .not e          => .allBlock [e.erase]
  | .missing fp     => .leaf fp .missing (.bool true) none

/-! ### Type safety: missing produces a definite outcome

The `missing` constructor always evaluates to `some _`, so it never
hits the `unevaluable` path. This is a structural property of the AST. -/

theorem missing_never_none (obs : Observation) (fp : FieldPath) :
    (CelExpr.missing (env := env) fp).eval obs = some (obs.resolveField fp).isNone := by
  rfl

theorem missing_never_unevaluable (obs : Observation) (fp : FieldPath) :
    (CelExpr.missing (env := env) fp).toOutcome obs ≠ .unevaluable := by
  unfold CelExpr.toOutcome CelExpr.eval
  cases (obs.resolveField fp).isNone <;> simp

/-! ### Literal evaluation is total -/

theorem lit_never_none (obs : Observation) (l : CelLit ty) :
    (CelExpr.lit (env := env) l).eval obs = some l.val := by
  rfl

/-! ### Observation conformance

An observation *conforms* to an environment when every binding resolves
to a value of the declared type. When an observation conforms, every
`CelExpr` over that environment evaluates to `some` — the
`unevaluable` path is unreachable. -/

def ObservationConforms (obs : Observation) (env : CelEnv) : Prop :=
  ∀ fp ty, env.hasBinding fp ty → (resolveTyped obs fp ty).isSome = true

/-! ### Type safety theorem

The main payoff: a well-typed expression evaluated against a conforming
observation always produces a value. `none` (unevaluable) is impossible. -/

theorem type_safety (obs : Observation) (env : CelEnv)
    (hConf : ObservationConforms obs env)
    (expr : CelExpr env ty) :
    (expr.eval obs).isSome = true := by
  induction expr with
  | lit _ => rfl
  | field fp hBind =>
    exact hConf fp _ hBind
  | binop op l r ihl ihr =>
    have ihl := ihl hConf; have ihr := ihr hConf
    simp [CelExpr.eval, bind, Option.bind]
    rw [Option.isSome_iff_exists] at ihl ihr
    obtain ⟨lv, hlv⟩ := ihl
    obtain ⟨rv, hrv⟩ := ihr
    rw [hlv, hrv]; rfl
  | and l r ihl ihr =>
    have ihl := ihl hConf; have ihr := ihr hConf
    simp [CelExpr.eval, bind, Option.bind]
    rw [Option.isSome_iff_exists] at ihl ihr
    obtain ⟨lv, hlv⟩ := ihl
    obtain ⟨rv, hrv⟩ := ihr
    rw [hlv, hrv]; rfl
  | or l r ihl ihr =>
    have ihl := ihl hConf; have ihr := ihr hConf
    simp [CelExpr.eval, bind, Option.bind]
    rw [Option.isSome_iff_exists] at ihl ihr
    obtain ⟨lv, hlv⟩ := ihl
    obtain ⟨rv, hrv⟩ := ihr
    rw [hlv, hrv]; rfl
  | not e ih =>
    have ih := ih hConf
    simp [CelExpr.eval, bind, Option.bind]
    rw [Option.isSome_iff_exists] at ih
    obtain ⟨v, hv⟩ := ih
    rw [hv]; rfl
  | missing _ => rfl

/-! ### Corollary: conforming observation never yields unevaluable -/

theorem no_unevaluable_on_conforming (obs : Observation) (env : CelEnv)
    (hConf : ObservationConforms obs env)
    (expr : CelExpr env .bool) :
    expr.toOutcome obs ≠ .unevaluable := by
  simp [CelExpr.toOutcome]
  have h := type_safety obs env hConf expr
  rw [Option.isSome_iff_exists] at h
  obtain ⟨v, hv⟩ := h
  rw [hv]
  cases v <;> simp
