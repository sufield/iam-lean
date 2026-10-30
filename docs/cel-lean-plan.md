# Lean 4 + CEL Integration — Implementation Plan

## Inventory: What Already Exists

| Layer | Blueprint concept | Current state |
|-------|-------------------|---------------|
| Typed AST | `Operator` (17 variants), `Operand`, `PredicateRule`, `UnsafePredicate` | **Done** in `Schema/Predicate.lean` |
| Typed observations | `Option`-wrapped fields, typed structs per domain | **Done** — 9 structs in `Controls/Types.lean` |
| Evaluator | `evalLeaf`, `evalPredicate`, `evalControl` over generic `Observation` | **Done** in `Evaluate/Eval.lean` |
| Typed evaluators | 16 per-control functions dispatched via `TypedObs` | **Done** in `Controls/Eval.lean` |
| Tri-state logic | `EvalOutcome` (clear/unsafe/unevaluable), `.fires` | **Done** in `Evaluate/Observation.lean` |
| Fail-closed proofs | 55 proofs via `native_decide`, zero sorry | **Done** in `Controls/Proofs.lean` |
| Generic proofs | P1–P5 (fail-closed, determinism, monotonicity, chain composition, ghost conservatism) | **Done** in `Evaluate/Proofs.lean` |
| Differential tests | 32 tests (16 controls × fires/passes), Go + Lean harness | **Done** in `Harness/DiffTest.lean` + Go driver |
| SMT/Datalog ghost | `Ghost/SMT.lean`, `Ghost/Datalog.lean` | **Done** |

## What the Blueprint Adds (net new)

Five layers, ordered by dependency:

### L1. Intrinsically Typed CEL AST

**Goal:** An expression type `CelExpr (env : CelEnv) (ty : CelType)` where
ill-typed CEL is unrepresentable — the constructor set rejects it at Lean
compile time.

**What exists:** `PredicateRule` in `Schema/Predicate.lean` is an
*untyped* AST — a `leaf` can pair any `Operator` with any `Operand`.
Type errors surface at evaluation time (the `none` branch in
`compareValues`). The evaluator is correct but not *intrinsically* safe.

**Work:**
1. Define `CelType` (bool, string, int, list, map, timestamp, duration) — small inductive.
2. Define `CelEnv` as a typed variable context (`List (String × CelType)`).
3. Define `CelExpr : CelEnv → CelType → Type` as an indexed inductive:
   - `var`, `lit`, `binop`, `unop`, `fieldAccess`, `functionCall`
   - Each constructor carries proof that operand types match.
4. Prove `CelExpr` is *total* over well-typed CEL: any well-typed CEL
   string can be parsed into `CelExpr`, and every `CelExpr` denotes
   exactly one value of the right type.
5. Define `erase : CelExpr env ty → PredicateRule` that forgets the type
   indices, recovering the existing untyped AST.

**New file:** `Stave/CEL/TypedAST.lean`

**Depends on:** `Schema/Predicate.lean`, `Schema/Types.lean`

### L2. `cel![]` Compile-Time Macro

**Goal:** Write `cel![field.encryption.enabled == true]` in Lean and get a
`CelExpr` at compile time, with a type error if the expression is ill-typed.

**What exists:** Nothing — evaluators are hand-written per control.

**Work:**
1. Write a Lean 4 `macro_rules` / `syntax` extension that parses a
   CEL-like surface syntax.
2. The macro elaborates into `CelExpr` constructors. If the expression
   is ill-typed against the environment, elaboration fails with a
   readable error.
3. Support the operators CH1/CH2 already use: `==`, `!=`, `>`, `<`,
   `missing`, `present`, `in`, `contains`.
4. Write tests: one macro invocation per CH1/CH2 control predicate,
   asserting it elaborates to the same `PredicateRule` the hand-written
   evaluator implements (via `erase`).

**New file:** `Stave/CEL/Macro.lean`

**Depends on:** L1

### L3. Formal Invariant Verification (∀-proofs)

**Goal:** Prove security properties that hold for *all* possible
observations, not just the fixtures in CH1/CH2.

**What exists:** 55 proofs in `Controls/Proofs.lean`, but they are
*known-answer tests* — each proves a concrete observation evaluates to a
specific outcome. The generic proofs in `Evaluate/Proofs.lean` (P1–P5)
are universal but only cover structural properties (monotonicity, fail-closed),
not predicate-specific invariants.

**Work:**
1. For each of the 16 controls, prove:
   - **Fail-closed universality:** `∀ obs, <required field missing> → fires obs = true`
   - **Correctness:** `∀ obs, <bad value> → fires obs = true` and `∀ obs, <good value> → fires obs = false`
2. These are stronger than the `native_decide` proofs because they
   quantify over *all* `Option` combinations, not just 2–3 concrete inputs.
3. Prove composition: if controls A and B both fire on an observation, the
   chain containing {A, B} fires (connecting L3 proofs to the existing
   chain composition proof in `Evaluate/Proofs.lean`).
4. For intrinsically typed controls (L1), prove that type safety implies
   the evaluator never reaches the `unevaluable` branch — a well-typed
   `CelExpr` always produces `clear` or `unsafe`, never `unevaluable`.

**New file:** `Stave/CEL/Invariants.lean`

**Depends on:** L1, existing `Controls/Eval.lean` + `Evaluate/Proofs.lean`

### L4. CelResult Tri-State with Error Provenance

**Goal:** Replace the flat `EvalOutcome` with a richer `CelResult` that
carries *why* evaluation failed — the error provenance.

**What exists:** `EvalOutcome` is a 3-constructor enum. The `unevaluable`
arm carries no information about *which* field was missing or *what* type
mismatch occurred.

**Work:**
1. Define `CelResult`:
   ```
   inductive CelResult (α : Type) where
     | ok (val : α)
     | error (reason : CelError)
   ```
   where `CelError` tracks: missing field (which `FieldPath`), type mismatch
   (expected vs actual `CelType`), or division by zero.
2. Define `CelResult.fires` preserving fail-closed: `error _ → true`.
3. Prove `CelResult.fires` is compatible with `EvalOutcome.fires`:
   `∀ r, toEvalOutcome r = .unevaluable → r.fires = true`.
4. Migrate the 16 typed evaluators to return `CelResult Bool` instead of
   `EvalOutcome`. The `fires` semantics must not change — prove this.
5. Update `Controls/Proofs.lean` — the 55 proofs should still go through
   with `native_decide` since the observable behavior is unchanged.

**New file:** `Stave/CEL/Result.lean`

**Depends on:** L1 (uses `CelType` for error reporting)

### L5. Verified Compilation (Lean → CEL)

**Goal:** A function `compile : CelExpr env ty → String` that emits CEL
source text, with a proof that compiling and then evaluating produces
the same result as evaluating the `CelExpr` directly.

**What exists:** Nothing — CEL is hand-written YAML, Lean evaluators are
hand-written separately, and differential tests check they agree on
fixtures.

**Work:**
1. Define `compile : CelExpr env CelType.bool → String` that emits CEL
   source syntax.
2. Define `celEval : String → Observation → CelResult Bool` as the
   *specification* of Go's CEL engine (axiomatized, not implemented in
   Lean — this is the trust boundary).
3. State the correctness theorem:
   `∀ env expr obs, celEval (compile expr) obs = evalCelExpr expr obs`
4. This cannot be fully proved without axiomatizing the Go CEL engine.
   The realistic milestone is:
   - Prove `compile` is total and well-formed (emits valid CEL syntax).
   - Prove `compile ∘ parse = id` (round-trip on the Lean side).
   - Use differential testing (extend the existing harness) to validate
     the axiom empirically.

**New file:** `Stave/CEL/Compile.lean`

**Depends on:** L1, L4

## Implementation Status

All five layers complete. Zero sorry, 32/32 differential tests, 118 build jobs.

| Layer | Commit | Lines | Key Result |
|-------|--------|-------|------------|
| L1 | `2f68270` | ~292 | `type_safety`, `no_unevaluable_on_conforming` |
| L4 | `2f68270` | ~150 | `CelResult` monad, `evalResult_to_option` consistency |
| L2 | `2c26ec9` | ~217 | 14 syntax forms, compound recursion, 20 known-answer tests |
| L3 | `d72b863` | ~342 | 26 ∀-quantified theorems, chain bridge |
| L5 | `68868a0` | ~119 | `compile` total, round-trip on 8+3 expressions |

## File Layout

```
Stave/CEL/
  TypedAST.lean       L1: CelType, CelEnv, CelExpr indexed inductive
  Macro.lean           L2: cel![] syntax extension
  Invariants.lean      L3: ∀-quantified security proofs
  Result.lean          L4: CelResult with error provenance
  Compile.lean         L5: CelExpr → CEL string + correctness
Stave/CEL.lean         Module root (imports all 5)
```

## Verification Gates

Each layer ships only when:

1. `lake build` passes (all proofs typecheck)
2. `make lean-verify` passes (zero sorry)
3. `make difftest` passes (32 differential tests still green)
4. For L4: the 55 proofs in `Controls/Proofs.lean` still hold after migration

## What This Does NOT Include

- **Rewriting the 16 hand-written evaluators** — they stay as-is. L1/L2
  provide a *parallel* path for new controls; migration is a separate task.
- **Implementing a CEL parser in Lean** — the `cel![]` macro handles a
  subset sufficient for Stave predicates, not arbitrary CEL.
- **Axiom-free verified compilation** — L5 axiomatizes the Go CEL engine.
  Full verification would require reimplementing Go's CEL in Lean, which
  is out of scope.
- **CH3 control extraction** — next batch of controls is a separate task
  that would *use* L2 once it ships.
