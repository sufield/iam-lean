--- reply < 15 words
--- An expression is an abstract syntax tree (Expr) representing any term.
#eval 1 + 1

#eval "Hello" ++ "!"

#eval 2 ^ 3

--- set_option pp.all true
#check 2 ^ 3

#eval String.length "Lean 4"

#eval List.reverse [1, 2, 3]

#check "Hello World"

set_option pp.explicit true
#check 42

#check true

#check [1, 2, 3]

#check String.length
#check List.reverse

#print Nat.add

#reduce 2 + 2

#guard 1 + 1 == 2

theorem two_eq : 1 + 1 = 2 :=
  rfl

#print axioms two_eq

def greet := "Bon jour!"

#check greet
#eval greet

#check Nat
#check String → Bool
