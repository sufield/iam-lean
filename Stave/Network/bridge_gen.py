#!/usr/bin/env python3
"""Generate network prover bridge JSONL from Go test fixtures.

Runs each prover property against test graph fixtures constructed
inline, exports JSONL records for the Lean checker.

Usage:
  python3 bridge_gen.py --stave-dir DIR -o bridge.jsonl
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path


def run_prover_tests(stave_dir: Path) -> list[dict]:
    """Run network prover Go tests and extract results."""
    result = subprocess.run(
        ["go", "test", "-v", "-run", "TestProve|TestCanReach", "-count=1",
         "./internal/core/network/..."],
        capture_output=True, text=True, timeout=120,
        cwd=str(stave_dir),
    )
    records = []
    current_test = None
    for line in result.stdout.splitlines():
        if line.startswith("=== RUN"):
            current_test = line.split()[-1]
        elif line.startswith("--- PASS:") or line.startswith("--- FAIL:"):
            test_name = line.split()[1]
            passed = line.startswith("--- PASS:")

            # Map test name to property + expected verdict
            props = extract_property_verdict(test_name)
            if props:
                records.append({
                    "test_name": test_name,
                    "property": props["property"],
                    "expected_verdict": props["verdict"],
                    "go_passed": passed,
                })
    return records


def extract_property_verdict(test_name: str) -> dict | None:
    """Map Go test name to property and expected verdict."""
    mapping = {
        "TestProveBastionSSH_Enforced": ("bastion-ssh", "UNSAT"),
        "TestProveBastionSSH_Bypassed": ("bastion-ssh", "SAT"),
        "TestProveBastionSSH_PeeringBypass": ("bastion-ssh", "SAT"),
        "TestProveBastionSSH_IPv6ExternalBypass": ("bastion-ssh", "SAT"),
        "TestProveBastionSSH_CaseInsensitiveEnvironment": ("bastion-ssh", "SAT_OR_UNSAT"),
        "TestProveBastionSSH_CaseInsensitiveBastion": ("bastion-ssh", "SAT_OR_UNSAT"),
        "TestProveBastionSSH_VacuousNoProduction": ("bastion-ssh", "VACUOUS"),
        "TestProveBastionSSH_VacuousNoBastions": ("bastion-ssh", "VACUOUS"),
        "TestProveBastionSSH_EmptyGraph": ("bastion-ssh", "VACUOUS"),
        "TestProveProdDevIsolation_Isolated": ("prod-dev-isolation", "UNSAT"),
        "TestProveProdDevIsolation_Connected": ("prod-dev-isolation", "SAT"),
        "TestProveProdDevIsolation_VacuousNoDev": ("prod-dev-isolation", "VACUOUS"),
        "TestProveDatabaseIsolation_Isolated": ("database-isolation", "UNSAT"),
        "TestProveDatabaseIsolation_Exposed": ("database-isolation", "SAT"),
        "TestProveDatabaseIsolation_ExternalIngress": ("database-isolation", "SAT"),
        "TestProveDatabaseIsolation_VacuousNoDatabase": ("database-isolation", "VACUOUS"),
        "TestProveFirewallMandatory_Enforced": ("firewall-mandatory", "UNSAT"),
        "TestProveFirewallMandatory_Bypassed": ("firewall-mandatory", "SAT"),
        "TestProveFirewallMandatory_VacuousNoSubnets": ("firewall-mandatory", "VACUOUS"),
        "TestProveFirewallMandatory_VacuousNoFirewall": ("firewall-mandatory", "VACUOUS"),
        "TestProveTransitiveSSH_SAT": ("transitive-ssh", "SAT"),
        "TestProveTransitiveSSH_UNSAT": ("transitive-ssh", "UNSAT"),
        "TestProveTransitiveEgress_SAT": ("transitive-egress", "SAT"),
        "TestProveTransitiveEgress_UNSAT": ("transitive-egress", "UNSAT"),
        "TestProveTransitiveEgress_VacuousNoIsolated": ("transitive-egress", "VACUOUS"),
        "TestProveTransitiveEgress_BuildGraph_SAT": ("transitive-egress", "SAT"),
        "TestProveTransitiveEgress_BuildGraph_UNSAT": ("transitive-egress", "UNSAT"),
        "TestProveTransitiveEgress_BuildGraph_EvidenceGated": ("transitive-egress", "EVIDENCE_GATED"),
    }
    # Also handle table-driven tests
    if test_name.startswith("TestTransitiveEgressFixtures/"):
        sub = test_name.split("/", 1)[1]
        fixture_verdicts = {
            "writeup": "SAT",
            "remediated": "UNSAT",
            "gated": "EVIDENCE_GATED",
            "partial-main-table": "SAT",
            "partial-precedence-sat-over-gated": "SAT",
            "partial-gated-over-unsat": "EVIDENCE_GATED",
            "partial-unknown-target": "EVIDENCE_GATED",
            "partial-uppercase-target": "SAT",
            "partial-no-isolated-host": "VACUOUS",
            "partial-all-ports": "SAT",
            "partial-blackhole": "SAT",
        }
        if sub in fixture_verdicts:
            return {"property": "transitive-egress", "verdict": fixture_verdicts[sub]}
        return None

    if test_name in mapping:
        prop, verdict = mapping[test_name]
        return {"property": prop, "verdict": verdict}
    return None


def main():
    p = argparse.ArgumentParser(description="Generate network bridge JSONL")
    p.add_argument("--stave-dir", type=Path, required=True, help="Path to stave repo root")
    p.add_argument("-o", "--output", type=Path, required=True, help="Output JSONL file")
    args = p.parse_args()

    stave_dir = args.stave_dir.resolve()

    records = run_prover_tests(stave_dir)
    print(f"Extracted {len(records)} test records", file=sys.stderr)

    # Filter out non-verdict tests
    verdict_records = [r for r in records if r["expected_verdict"] not in ("SAT_OR_UNSAT",)]
    print(f"Writing {len(verdict_records)} verdict records", file=sys.stderr)

    by_verdict = {}
    for r in verdict_records:
        v = r["expected_verdict"]
        by_verdict[v] = by_verdict.get(v, 0) + 1

    for v, c in sorted(by_verdict.items()):
        print(f"  {v}: {c}", file=sys.stderr)

    with open(args.output, "w") as f:
        for r in verdict_records:
            f.write(json.dumps(r, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
