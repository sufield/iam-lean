#!/usr/bin/env bash
set -euo pipefail

# Blueprint CI gates: axiom-gated \leanok (Gate A) and theorem parity (Gate B).
# Run after `lake build`.

BLUEPRINT_SRC="blueprint/src"
TAINT="sorryAx\|Lean.ofReduceBool\|Lean.trustCompiler"
FAIL=0

# --- Gate A: axiom-gated \leanok ---

echo "=== Gate A: axiom-gated \\leanok ==="

mapfile -t leanok_decls < <(
  for f in "$BLUEPRINT_SRC"/*.tex; do
    [ -f "$f" ] || continue
    # Extract \lean{Name} where \leanok follows in the same environment
    perl -ne '
      if (/\\lean\{([^}]+)\}/) { $cur = $1 }
      if (/\\leanok/ && $cur) { print "$cur\n"; $cur = "" }
      if (/\\begin\{/) { $cur = "" }
    ' "$f"
  done
)

gate_a_total=${#leanok_decls[@]}
gate_a_clean=0

if [ "$gate_a_total" -eq 0 ]; then
  echo "  No \\leanok'd declarations found."
else
  for decl in "${leanok_decls[@]}"; do
    output=$(lake env lean --run <<LEAN 2>&1 || true
import IamExplainer
import Seclib
#print axioms $decl
LEAN
)
    if echo "$output" | grep -q "$TAINT"; then
      echo "  TAINTED: $decl"
      echo "    $output" | grep "$TAINT"
      FAIL=1
    else
      gate_a_clean=$((gate_a_clean + 1))
    fi
  done
  echo "  $gate_a_clean/$gate_a_total clean"
fi

# --- Gate B: theorem parity ---
# Every public theorem/lemma in Seclib/ and IamExplainer/ appears in
# exactly one \lean{} reference in blueprint/src/*.tex.
# Handles namespaces by tracking open namespace blocks.

echo ""
echo "=== Gate B: theorem parity ==="

# Extract fully-qualified theorem names from Lean source.
# Tracks `namespace X` / `end X` to prefix names.
mapfile -t lean_theorems < <(
  for f in $(find Seclib/ IamExplainer/ -name "*.lean" ! -path "*/.lake/*" | sort); do
    awk '
      /^namespace / { ns = $2 }
      /^end /       { ns = "" }
      /^theorem /   { name = $2; sub(/[^a-zA-Z0-9_.].*/, "", name); if (ns) print ns "." name; else print name }
      /^lemma /     { name = $2; sub(/[^a-zA-Z0-9_.].*/, "", name); if (ns) print ns "." name; else print name }
    ' "$f"
  done | sort -u
)

# Collect all \lean{} references from blueprint
mapfile -t blueprint_refs < <(
  grep -ohP '\\lean\{\K[^}]+' "$BLUEPRINT_SRC"/*.tex 2>/dev/null | sort
)

lean_count=${#lean_theorems[@]}
missing=0

for thm in "${lean_theorems[@]}"; do
  count=0
  for ref in "${blueprint_refs[@]}"; do
    if [ "$ref" = "$thm" ]; then
      count=$((count + 1))
    fi
  done
  if [ "$count" -eq 0 ]; then
    echo "  MISSING in blueprint: $thm"
    missing=$((missing + 1))
    FAIL=1
  elif [ "$count" -gt 1 ]; then
    echo "  DUPLICATE in blueprint: $thm (${count}x)"
    FAIL=1
  fi
done

matched=$((lean_count - missing))
echo "  $matched/$lean_count theorems have blueprint nodes"

if [ "$FAIL" -ne 0 ]; then
  echo ""
  echo "GATES FAILED"
  exit 1
else
  echo ""
  echo "GATES PASSED"
  echo "  Gate A: $gate_a_clean/$gate_a_total axiom-clean"
  echo "  Gate B: $matched/$lean_count parity"
fi
