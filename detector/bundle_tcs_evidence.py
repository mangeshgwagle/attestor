#!/usr/bin/env python3
"""Assemble the TCS pilot evidence bundle from owned/synthetic fixtures.

Runs the two demo scripts, writes their JSON + rendered output into
tcs_pilot_evidence/, and emits a MANIFEST plus a README that is explicit that
this is evidence of reproducible analysis -- not a request for TCS deployment or
any scanning of client/production systems without InfoSec authorization.
"""
from __future__ import annotations
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
OUT = HERE.parent / "tcs_pilot_evidence"


def _capture(callable) -> str:
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = callable()
    return buf.getvalue(), rc


def main() -> int:
    import demo_tcs_case
    import demo_asm_tcs

    OUT.mkdir(parents=True, exist_ok=True)

    case_out, rc1 = _capture(demo_tcs_case.main)
    if rc1 != 0:
        print("demo_tcs_case failed", file=sys.stderr)
        return rc1
    asm_out, rc2 = _capture(demo_asm_tcs.main)
    if rc2 != 0:
        print("demo_asm_tcs failed", file=sys.stderr)
        return rc2

    (OUT / "case_tcs.txt").write_text(case_out, encoding="utf-8")
    (OUT / "asm_tcs.txt").write_text(asm_out, encoding="utf-8")

    # reproducible structured evidence
    case_json = json.loads(case_out.split("\nCHAIN:")[0])
    (OUT / "case_tcs.json").write_text(json.dumps(case_json, indent=2, sort_keys=True), encoding="utf-8")
    asm_tail = asm_out[asm_out.rfind("{") :]
    asm_summary = json.loads(asm_tail)
    (OUT / "asm_tcs.json").write_text(json.dumps(asm_summary, indent=2, sort_keys=True), encoding="utf-8")

    manifest = {
        "bundle": "tcs-pilot-evidence",
        "attestor": case_json["analyzer"],
        "generated_by": "bundle_tcs_evidence.py",
        "mode": "offline static analysis, no execution, no network, synthetic/owned fixtures only",
        "claims": {
            "weak_asm_fixture_rules": asm_summary["weak_fixture_asm_rules"],
            "weak_cpp_fixture_findings": asm_summary["weak_fixture_cpp_findings"],
            "clean_10k_asm_findings": asm_summary["clean_10k_asm_findings"],
            "case_chain_intact": case_json["chain_intact"],
            "case_proven": case_json["proven"],
            "honesty_gate_blocked_unproven": case_json["honesty_gate_blocked_unproven"],
        },
        "files": ["case_tcs.txt", "case_tcs.json", "asm_tcs.txt", "asm_tcs.json", "README.md"],
    }
    (OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    readme = (
        "# TCS Pilot Evidence Bundle\n\n"
        "This folder is **evidence**, not a deployment request.\n\n"
        "It contains reproducible, offline static-analysis results produced by\n"
        "Attestor 4.2 (analyzer identity 4.1.4) on **owned and synthetic** fixtures\n"
        "only. No client, production, or TCS system was scanned or executed.\n\n"
        "## What it shows\n"
        "- `case_tcs.*` -- one finding carried through the evidence spine\n"
        "  (case_file42.py). The tamper-evident hash chain is intact, the honesty\n"
        "  gate refused an unproven fix, and the result is marked proven only\n"
        "  because a regression test was observed to fail before the fix.\n"
        "- `asm_tcs.*` -- a deliberately weak x86-64 fixture tripping the dangerous\n"
        "  pattern rules (execve / stack-pivot / NOP-sled / W^X), while a 10,000-line\n"
        "  clean multi-function program produced **zero** findings.\n\n"
        "## How to verify\n"
        "    cd ..\\.owen42_codex_final\\Attestor 4.2\\detector\n"
        "    python -I -B -X utf8 demo_tcs_case.py\n"
        "    python -I -B -X utf8 demo_asm_tcs.py\n\n"
        "## Authorization note\n"
        "Any scan of a TCS held-out repository requires explicit InfoSec\n"
        "authorization and a sponsored lab. See bench_tcs42.py (auth-gated).\n"
    )
    (OUT / "README.md").write_text(readme, encoding="utf-8")

    print("wrote bundle to", OUT)
    print(json.dumps(manifest["claims"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
