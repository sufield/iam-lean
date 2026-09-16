--- snippet Eval
#eval 1 + 2 + 3

-- snippet String
#eval "11" ++ "22"

#eval s!"{1 + 1} = 2"

--- snippet Function
def mystery x := 2 * x

#eval mystery 123

--- Inline function : backslash fun
#eval (λ x => 2 * x) 123

--- snippet Higher-Order Function
def square (x : Nat) (f : Nat → Nat) := f (f x)

#eval square 5 $ λ x => 2 * x

#eval (. + 1) <$> [1, 2, 3]

#eval (. + 1) <$> (some 5)

#eval (. + 1) <$> none

-- Functor in action: Similar to [1, 2, 3].map {|x| x + 1 }
-- A simple function that increments every number inside a Functor context
def incrementContainer [Functor f] (container : f Nat) : f Nat :=
  -- Use a lambda function: (fun x => x + 1 )
  (fun x => x + 1) <$> container

#eval incrementContainer [1, 2, 3]

-- A simple function demonstrating Applicative application
def applyFunctionContext : Option Nat :=
  -- The context contains a function: (some (. + 5))
  -- The target contains a value: (some 10)
  (some (. + 5)) <*> (some 10)

#eval applyFunctionContext

#eval (some (. + 5)) <*> none
-- Output: none

#eval (none : Option (Nat → Nat)) <*> (some 10)
-- Output: none

#eval (some (. + 5)) <*> (none : Option Nat)

-- A simple function using do-notation (the Monad interface)
def addOneAndDouble (x : Id Nat) : Id Nat := do
  -- The arrow ← extracts the Nat value out of the Id monad
  let value ← x
  -- pure wraps the final answer back into the Id monad
  pure ((value + 1) * 2)

#eval addOneAndDouble (pure 5)
