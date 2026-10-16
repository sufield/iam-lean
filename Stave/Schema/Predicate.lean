import Stave.Schema.Types

/-! Predicate AST for the CEL predicate type system.
Formalizes: internal/core/controldef/predicate.go (UnsafePredicate),
internal/core/controldef/rule.go (PredicateRule),
internal/core/controldef/operand.go (Operand).
The AST is recursive: a PredicateRule can contain nested any/all blocks. -/

/-! ### Operand — polymorphic comparison value
    Go source: internal/core/controldef/operand.go:8
    JSON/YAML values are bool, string, number, or list -/

inductive Operand where
  | bool (v : Bool)
  | str (v : String)
  | int (v : Int)
  | list (vs : List Operand)
deriving Repr, Inhabited

/-! ### PredicateRule — recursive predicate node
    Go source: internal/core/controldef/rule.go:13-23
    Leaf: field × op × value
    Branch: nested any/all of child rules -/

inductive PredicateRule where
  | leaf (field : FieldPath) (op : Operator) (value : Operand) (paramRef : Option ParamRef)
  | anyBlock (rules : List PredicateRule)
  | allBlock (rules : List PredicateRule)
deriving Repr

/-! ### UnsafePredicate — top-level predicate container
    Go source: internal/core/controldef/predicate.go:9-14 -/

structure UnsafePredicate where
  any : List PredicateRule := []
  all : List PredicateRule := []
deriving Repr

def UnsafePredicate.isEmpty (p : UnsafePredicate) : Bool :=
  p.any.isEmpty && p.all.isEmpty

/-! ### Field path extraction
    Walk the predicate AST to collect all referenced field paths.
    Used for schema-predicate consistency checking. -/

partial def PredicateRule.fieldPaths : PredicateRule → List FieldPath
  | .leaf fp _ _ _ => [fp]
  | .anyBlock rules => rules.flatMap PredicateRule.fieldPaths
  | .allBlock rules => rules.flatMap PredicateRule.fieldPaths

def UnsafePredicate.fieldPaths (p : UnsafePredicate) : List FieldPath :=
  p.any.flatMap PredicateRule.fieldPaths ++ p.all.flatMap PredicateRule.fieldPaths

/-! ### Operator usage extraction
    Walk the predicate AST to collect all operators used. -/

partial def PredicateRule.operators : PredicateRule → List Operator
  | .leaf _ op _ _ => [op]
  | .anyBlock rules => rules.flatMap PredicateRule.operators
  | .allBlock rules => rules.flatMap PredicateRule.operators

def UnsafePredicate.operators (p : UnsafePredicate) : List Operator :=
  p.any.flatMap PredicateRule.operators ++ p.all.flatMap PredicateRule.operators
