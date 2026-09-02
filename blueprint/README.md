# Blueprint — Local Build

## Prerequisites

```bash
# Lean toolchain (elan installs from lean-toolchain automatically)
curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh

# leanblueprint (provides plastex + checkdecls support)
pip install leanblueprint
# — or —
uv tool install leanblueprint

# PDF (optional): xelatex + latexmk + mathtools
sudo apt install texlive-xetex texlive-latex-extra latexmk
```

## Build

All commands run from `projects/iam-explainer/`.

```bash
# 1. Build the Lean project
lake build

# 2. Check that all \lean{} declarations exist
lake exe checkdecls blueprint/lean_decls

# 3. Run the blueprint gates (axiom purity + theorem parity)
bash scripts/blueprint_gates.sh

# 4. Build the web site
PLASTEX=$(python3 -c "import shutil; print(shutil.which('plastex'))")
(cd blueprint/src && "$PLASTEX" -c plastex.cfg web.tex)

# 5. Serve locally
python3 -m http.server 8000 --directory blueprint/web
# Open http://localhost:8000
```

## Pages

- `index.html` — table of contents
- `dep_graph_document.html` — interactive dependency graph (53 nodes)
- `chap-*.html` — chapter pages

## PDF (optional)

```bash
cd blueprint/src && latexmk -r latexmkrc
# Output: blueprint/src/print.pdf
```

## Regenerate lean_decls

After adding `\lean{}` refs to the TeX sources:

```bash
grep -ohP '\\lean\{\K[^}]+' blueprint/src/*.tex | sort -u > blueprint/lean_decls
```

## Monorepo note

`leanblueprint new/web/checkdecls` commands expect the git root to contain
the lakefile. This project is at `projects/iam-explainer/` inside a monorepo,
so we invoke `plastex` and `lake exe checkdecls` directly instead.
