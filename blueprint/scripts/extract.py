#!/usr/bin/env python3
"""Extract declarations from Lean source and generate mdBook content.

Reads all .lean files under Seclib/ and IamExplainer/ (plus Main.lean),
extracts theorem/lemma/def/structure/instance declarations with status,
and writes:
  - book/src/modules/<Module>.md   per-file pages
  - book/src/catalog.md            flat theorem catalog
  - book/src/graph.md              Mermaid dependency graph
  - book/src/SUMMARY.md            mdBook table of contents
"""

import os
import re
import sys
from pathlib import Path
from dataclasses import dataclass, field

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BOOK_SRC = REPO_ROOT / "blueprint" / "book" / "src"
GITHUB_BASE = None  # set from remote


@dataclass
class Decl:
    kind: str          # theorem, lemma, def, structure, instance
    name: str          # bare name
    fqn: str           # fully-qualified (with namespace prefix)
    file: str          # relative path
    line: int
    signature: str     # full signature text
    docstring: str     # docstring if any
    has_sorry: bool
    namespace: str

    @property
    def status(self) -> str:
        if self.kind in ("def", "structure", "instance"):
            return "definition"
        if self.has_sorry:
            return "sorry"
        return "proved"

    @property
    def badge(self) -> str:
        s = self.status
        if s == "proved":
            return "🟢 proved"
        elif s == "sorry":
            return "🟡 sorry"
        else:
            return "⚪ definition"

    @property
    def module(self) -> str:
        p = self.file.replace("/", ".").removesuffix(".lean")
        return p


def detect_github_base() -> str:
    """Try to detect GitHub URL from git remote."""
    import subprocess
    try:
        url = subprocess.check_output(
            ["git", "remote", "get-url", "origin"],
            cwd=REPO_ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
        # git@github.com:user/repo.git -> https://github.com/user/repo
        if url.startswith("git@"):
            url = url.replace(":", "/").replace("git@", "https://")
        url = url.removesuffix(".git")
        return url
    except Exception:
        return "https://github.com/OWNER/REPO"


def get_default_branch() -> str:
    import subprocess
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=REPO_ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return "main"


def parse_lean_file(path: Path) -> list[Decl]:
    """Parse a single .lean file for declarations."""
    rel = str(path.relative_to(REPO_ROOT))
    text = path.read_text()
    lines = text.split("\n")
    decls = []
    namespace = ""

    # Track docstrings (lines starting with /-- ... -/)
    pending_doc = ""

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Track docstrings
        if stripped.startswith("/-!") or stripped.startswith("/--"):
            doc_lines = [stripped]
            while i < len(lines) - 1 and "-/" not in lines[i]:
                i += 1
                doc_lines.append(lines[i].strip())
            pending_doc = " ".join(doc_lines)
            pending_doc = re.sub(r"/[-!]+\s*", "", pending_doc)
            pending_doc = re.sub(r"\s*-/", "", pending_doc)
            pending_doc = pending_doc.strip()
            i += 1
            continue

        # Track namespace
        ns_match = re.match(r"^namespace\s+(\S+)", line)
        if ns_match:
            namespace = ns_match.group(1)
            i += 1
            continue
        if re.match(r"^end\s+", line):
            namespace = ""
            i += 1
            continue

        # Match declarations
        decl_match = re.match(
            r"^(private\s+|protected\s+)?(theorem|lemma|def|structure|instance)\s+(\S+)",
            line
        )
        if decl_match:
            visibility = (decl_match.group(1) or "").strip()
            kind = decl_match.group(2)
            name = decl_match.group(3)

            # Skip private declarations
            if visibility == "private":
                pending_doc = ""
                i += 1
                continue

            # Collect full signature until := or where or :=  by
            sig_lines = [line]
            j = i + 1
            while j < len(lines):
                sl = lines[j].strip()
                if sl.startswith(":= by") or sl == ":= by" or ":= by" in lines[j]:
                    sig_lines.append(lines[j])
                    break
                if sl.startswith(":=") or sl == ":=" or re.match(r"\s+:=", lines[j]):
                    sig_lines.append(lines[j])
                    break
                if sl.startswith("where"):
                    sig_lines.append(lines[j])
                    break
                if sl == "" or (not sl.startswith("(") and not sl.startswith("{")
                                and not sl.startswith("[") and not sl.startswith(":")
                                and not sl.startswith("→") and not sl.startswith("->")
                                and not sl.startswith("|")):
                    break
                sig_lines.append(lines[j])
                j += 1

            sig = "\n".join(sig_lines)
            # Trim everything after :=
            sig = re.sub(r"\s*:=.*", "", sig, flags=re.DOTALL).strip()

            # Check for sorry in the proof body
            has_sorry = False
            if kind in ("theorem", "lemma"):
                # Scan from declaration to next top-level declaration or EOF
                body_start = i
                body_end = len(lines)
                for k in range(i + 1, len(lines)):
                    if re.match(r"^(private\s+|protected\s+)?(theorem|lemma|def|structure|instance|namespace|end|section)\s", lines[k]):
                        body_end = k
                        break
                body = "\n".join(lines[body_start:body_end])
                has_sorry = bool(re.search(r"\bsorry\b", body))

            fqn = f"{namespace}.{name}" if namespace else name
            # Clean name of type annotations
            name = re.sub(r"\s*[:{(].*", "", name)
            fqn = re.sub(r"\s*[:{(].*", "", fqn)

            decls.append(Decl(
                kind=kind, name=name, fqn=fqn,
                file=rel, line=i + 1,
                signature=sig, docstring=pending_doc,
                has_sorry=has_sorry, namespace=namespace,
            ))
            pending_doc = ""
        else:
            if stripped and not stripped.startswith("--") and not stripped.startswith("import") and not stripped.startswith("open"):
                pending_doc = ""

        i += 1

    return decls


def collect_dependencies(decls: list[Decl]) -> dict[str, list[str]]:
    """Build dependency edges by scanning proof bodies for references."""
    name_set = {d.fqn for d in decls} | {d.name for d in decls}
    deps: dict[str, list[str]] = {}

    for d in decls:
        if d.kind not in ("theorem", "lemma"):
            continue
        # Read the proof body
        path = REPO_ROOT / d.file
        lines = path.read_text().split("\n")
        body_start = d.line - 1
        body_end = len(lines)
        for k in range(body_start + 1, len(lines)):
            if re.match(r"^(private\s+|protected\s+)?(theorem|lemma|def|structure|instance|namespace|end)\s", lines[k]):
                body_end = k
                break
        body = "\n".join(lines[body_start:body_end])

        found = set()
        for other in decls:
            if other.fqn == d.fqn:
                continue
            # Check for bare name or fqn in body
            for n in [other.fqn, other.name]:
                if re.search(r'\b' + re.escape(n) + r'\b', body):
                    found.add(other.fqn)
                    break
        deps[d.fqn] = sorted(found)
    return deps


def write_module_page(module_name: str, decls: list[Decl], branch: str):
    """Write a per-module markdown page."""
    slug = module_name.replace(".", "_")
    out = BOOK_SRC / "modules" / f"{slug}.md"
    out.parent.mkdir(parents=True, exist_ok=True)

    lines = [f"# {module_name}\n"]

    for d in decls:
        src_link = f"{GITHUB_BASE}/blob/{branch}/{d.file}#L{d.line}"
        lines.append(f"### {d.name} — {d.badge}")
        lines.append(f"*{d.kind}* · [source]({src_link})\n")
        if d.docstring:
            lines.append(f"> {d.docstring}\n")
        lines.append(f"```lean\n{d.signature}\n```\n")

    out.write_text("\n".join(lines))
    return slug


def write_catalog(all_decls: list[Decl], branch: str):
    """Write the flat theorem catalog — the landing page."""
    out = BOOK_SRC / "catalog.md"

    theorems = [d for d in all_decls if d.kind in ("theorem", "lemma")]
    proved = sum(1 for d in theorems if d.status == "proved")
    sorry = sum(1 for d in theorems if d.status == "sorry")
    total = len(theorems)

    lines = [
        "# Theorem Catalog\n",
        f"**{proved}** proved · **{sorry}** sorry · **{total}** total\n",
        "| Status | Name | Module | Description |",
        "|--------|------|--------|-------------|",
    ]

    for d in sorted(theorems, key=lambda x: (x.status != "proved", x.fqn)):
        src_link = f"{GITHUB_BASE}/blob/{branch}/{d.file}#L{d.line}"
        desc = d.docstring[:80] if d.docstring else ""
        mod_slug = d.module.replace(".", "_")
        lines.append(
            f"| {d.badge} | [{d.fqn}]({src_link}) | [{d.module}](modules/{mod_slug}.md) | {desc} |"
        )

    out.write_text("\n".join(lines))


def write_graph(all_decls: list[Decl], deps: dict[str, list[str]]):
    """Write the Mermaid dependency graph page."""
    out = BOOK_SRC / "graph.md"

    # Build node id mapping (sanitize for Mermaid)
    def node_id(fqn: str) -> str:
        return fqn.replace(".", "_")

    theorems_and_defs = [d for d in all_decls if d.kind in ("theorem", "lemma", "def")]
    # Only include nodes that appear in deps (as source or target)
    dep_nodes = set()
    for src, targets in deps.items():
        if targets:
            dep_nodes.add(src)
            dep_nodes.update(targets)

    lines = [
        "# Dependency Graph\n",
        "Nodes: 🟢 proved, 🟡 sorry, ⚪ definition. Click to navigate.\n",
        "```mermaid",
        "graph TD",
    ]

    # Style classes
    lines.append("    classDef proved fill:#22c55e,stroke:#166534,color:#fff")
    lines.append("    classDef sorry fill:#eab308,stroke:#a16207,color:#fff")
    lines.append("    classDef defn fill:#9ca3af,stroke:#4b5563,color:#fff")

    # Nodes
    for d in theorems_and_defs:
        if d.fqn not in dep_nodes and d.fqn not in deps:
            continue
        nid = node_id(d.fqn)
        label = d.name
        cls = "proved" if d.status == "proved" else ("sorry" if d.status == "sorry" else "defn")
        mod_slug = d.module.replace(".", "_")
        lines.append(f'    {nid}["{label}"]')
        lines.append(f"    class {nid} {cls}")

    # Edges
    for src, targets in deps.items():
        for tgt in targets:
            lines.append(f"    {node_id(src)} --> {node_id(tgt)}")

    lines.append("```")
    out.write_text("\n".join(lines))


def write_summary(modules: list[str]):
    """Write SUMMARY.md for mdBook."""
    out = BOOK_SRC / "SUMMARY.md"
    lines = [
        "# Summary\n",
        "[Theorem Catalog](catalog.md)",
        "[Dependency Graph](graph.md)\n",
        "# Modules\n",
    ]
    for mod in sorted(modules):
        slug = mod.replace(".", "_")
        lines.append(f"- [{mod}](modules/{slug}.md)")

    out.write_text("\n".join(lines))


def main():
    global GITHUB_BASE
    GITHUB_BASE = detect_github_base()
    branch = get_default_branch()

    # Collect all .lean files
    lean_files = []
    for root_dir in ["Seclib", "IamExplainer"]:
        for p in sorted((REPO_ROOT / root_dir).rglob("*.lean")):
            if ".lake" not in str(p):
                lean_files.append(p)
    main_lean = REPO_ROOT / "Main.lean"
    if main_lean.exists():
        lean_files.append(main_lean)

    # Parse
    all_decls: list[Decl] = []
    module_decls: dict[str, list[Decl]] = {}

    for f in lean_files:
        decls = parse_lean_file(f)
        if decls:
            mod = decls[0].module
            module_decls[mod] = decls
            all_decls.extend(decls)

    # Dependencies
    deps = collect_dependencies(all_decls)

    # Ensure output dirs
    (BOOK_SRC / "modules").mkdir(parents=True, exist_ok=True)

    # Write pages
    modules = []
    for mod, decls in sorted(module_decls.items()):
        slug = write_module_page(mod, decls, branch)
        modules.append(mod)

    write_catalog(all_decls, branch)
    write_graph(all_decls, deps)
    write_summary(modules)

    # Stats
    theorems = [d for d in all_decls if d.kind in ("theorem", "lemma")]
    proved = sum(1 for d in theorems if d.status == "proved")
    sorry = sum(1 for d in theorems if d.status == "sorry")
    defs = sum(1 for d in all_decls if d.status == "definition")
    print(f"Extracted {len(all_decls)} declarations from {len(lean_files)} files")
    print(f"  {proved} proved, {sorry} sorry, {defs} definitions")
    print(f"  {len(modules)} module pages, {sum(len(v) for v in deps.values())} dependency edges")


if __name__ == "__main__":
    main()
