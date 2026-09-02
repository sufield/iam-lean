/-! Security primitives: three-valued logic and effect type.
Vendor-neutral — no cloud provider noun appears in this module. -/

inductive Tri where
  | t | f | u
deriving Repr, DecidableEq

instance : ToString Tri where
  toString
    | .t => "T"
    | .f => "F"
    | .u => "U"

def Tri.and : Tri → Tri → Tri
  | .f, _ => .f
  | _, .f => .f
  | .t, .t => .t
  | _, _ => .u

def Tri.or : Tri → Tri → Tri
  | .t, _ => .t
  | _, .t => .t
  | .f, .f => .f
  | _, _ => .u

def Tri.not : Tri → Tri
  | .t => .f
  | .f => .t
  | .u => .u

theorem Tri.and_tu (a b : Tri) (ha : a = .t ∨ a = .u) (hb : b = .t ∨ b = .u) :
    Tri.and a b = .t ∨ Tri.and a b = .u := by
  rcases ha with rfl | rfl <;> rcases hb with rfl | rfl <;> simp [Tri.and]

theorem Tri.and_eq_t {a b : Tri} : Tri.and a b = .t ↔ a = .t ∧ b = .t := by
  cases a <;> cases b <;> simp [Tri.and]

inductive Effect where
  | allow | deny
deriving DecidableEq, Inhabited
