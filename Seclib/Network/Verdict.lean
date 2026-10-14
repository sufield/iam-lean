import Seclib.Network.Reachability

/-! Three-verdict system: SAT / EVIDENCE_GATED / UNSAT.
Go source: proof.go:11-33 (ProofResult, Counterexample).
Verdict ordering: SAT > EVIDENCE_GATED > UNSAT (proof.go:465). -/

/-- Network proof verdict.
    Go source: proof.go:13 -/
inductive Verdict where
  | sat           -- property violated, counterexample exists
  | evidenceGated -- cannot decide without additional observation
  | unsat         -- property holds in the SG-ingress model
deriving DecidableEq, Repr

/-- Verdict severity rank (lower = worse).
    Go source: proof.go:465 "SAT > EVIDENCE_GATED > UNSAT" -/
def Verdict.rank : Verdict → Nat
  | .sat => 0
  | .evidenceGated => 1
  | .unsat => 2

/-- Counterexample witness for a SAT or EVIDENCE_GATED verdict.
    Go source: proof.go:24-33 -/
structure Counterexample where
  source : String
  destination : String
  port : Nat
  pathType : String
deriving Repr

/-- A proof result pairs a verdict with an optional counterexample.
    Go source: proof.go:11-21 -/
structure ProofResult where
  property : String
  verdict : Verdict
  counterexample : Option Counterexample
deriving Repr
