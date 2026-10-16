#!/usr/bin/env python3
"""Generate chain-composition bridge JSONL from stave evaluation.

For each chain firing and near-miss, emits a JSONL record with the chain
definition (controls + threshold) and the failing controls, so the Lean
checker can verify chainFires/chainDistance agree with the Go engine.

Usage:
  python3 bridge_gen.py [--stave-dir DIR] [--fixtures DIR...] -o bridge.jsonl
"""

import argparse
import json
import os
import subprocess
import sys
import yaml
from pathlib import Path


def load_chain_defs(chains_dir: Path) -> dict:
    """Load chain YAML definitions keyed by chain ID."""
    defs = {}
    for f in sorted(chains_dir.glob("*.yaml")):
        with open(f) as fh:
            chain = yaml.safe_load(fh)
        if chain and "id" in chain:
            defs[chain["id"]] = {
                "controls": chain.get("controls", []),
                "threshold": chain.get("escalation_threshold", len(chain.get("controls", []))),
                "severity": chain.get("compound_severity", "medium"),
            }
    return defs


def find_obs_dirs(fixture_roots: list[Path]) -> list[Path]:
    """Find all observation directories under fixture roots."""
    dirs = []
    for root in fixture_roots:
        for dirpath, dirnames, filenames in os.walk(root):
            if any(f.endswith(".json") for f in filenames):
                p = Path(dirpath)
                if p.name == "observations" or any(f.endswith(".json") for f in filenames):
                    dirs.append(p)
                    dirnames.clear()  # don't recurse into subdirs
    return sorted(set(dirs))


def run_stave(stave_bin: str, obs_dir: Path) -> dict | None:
    """Run stave apply and return parsed JSON output."""
    result = subprocess.run(
        [stave_bin, "apply",
         "--observations", str(obs_dir),
         "--include-atomic",
         "--eval-time", "2026-08-01T15:00:00Z",
         "--format", "json"],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode not in (0, 3, 5):  # 3=violations, 5=indeterminate
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def extract_records(output: dict, chain_defs: dict, fixture: str) -> list[dict]:
    """Extract bridge records from stave output."""
    records = []

    for cf in output.get("chain_findings", []):
        chain_id = cf["chain"]
        defn = chain_defs.get(chain_id)
        if not defn:
            continue
        failing = cf.get("controls_failing", [])
        missing = cf.get("missing_safeguards", [])
        records.append({
            "chain_id": chain_id,
            "controls": defn["controls"],
            "threshold": defn["threshold"],
            "failing": failing,
            "missing": missing,
            "verdict": "fires",
            "distance": 0,
            "fixture": fixture,
        })

    for nm in output.get("near_miss_chains", []):
        chain_id = nm["chain"]
        defn = chain_defs.get(chain_id)
        if not defn:
            continue
        failing = nm.get("controls_failing", [])
        missing_ctl = nm.get("missing_control", "")
        records.append({
            "chain_id": chain_id,
            "controls": defn["controls"],
            "threshold": defn["threshold"],
            "failing": failing,
            "missing_control": missing_ctl,
            "verdict": "near_miss",
            "distance": 1,
            "fixture": fixture,
        })

    return records


def main():
    p = argparse.ArgumentParser(description="Generate chain bridge JSONL")
    p.add_argument("--stave-dir", type=Path,
                   default=Path(__file__).resolve().parents[2] / "../../bizacademy/stave",
                   help="Path to stave repo root")
    p.add_argument("--fixtures", type=Path, nargs="+",
                   help="Fixture root directories to scan")
    p.add_argument("-o", "--output", type=Path, required=True,
                   help="Output JSONL file")
    args = p.parse_args()

    stave_dir = args.stave_dir.resolve()
    stave_bin = stave_dir / "stave"
    chains_dir = stave_dir / "internal" / "chains"

    if not stave_bin.exists():
        print(f"stave binary not found at {stave_bin}", file=sys.stderr)
        sys.exit(1)

    chain_defs = load_chain_defs(chains_dir)
    print(f"Loaded {len(chain_defs)} chain definitions", file=sys.stderr)

    fixture_roots = args.fixtures or [
        stave_dir / ".." / "ctf",
        stave_dir / "internal" / "fixtures" / "labs",
    ]

    obs_dirs = find_obs_dirs(fixture_roots)
    print(f"Found {len(obs_dirs)} observation directories", file=sys.stderr)

    all_records = []
    for obs_dir in obs_dirs:
        output = run_stave(str(stave_bin), obs_dir)
        if output is None:
            continue
        try:
            fixture_name = str(obs_dir.resolve().relative_to(stave_dir.parent.resolve()))
        except ValueError:
            fixture_name = str(obs_dir)
        records = extract_records(output, chain_defs, fixture_name)
        if records:
            print(f"  {fixture_name}: {len(records)} records", file=sys.stderr)
        all_records.extend(records)

    with open(args.output, "w") as f:
        for r in all_records:
            f.write(json.dumps(r, separators=(",", ":")) + "\n")

    fires = sum(1 for r in all_records if r["verdict"] == "fires")
    near = sum(1 for r in all_records if r["verdict"] == "near_miss")
    print(f"Total: {fires} fires, {near} near_miss, {len(all_records)} records",
          file=sys.stderr)


if __name__ == "__main__":
    main()
