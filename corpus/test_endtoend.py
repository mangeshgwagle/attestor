#!/usr/bin/env python3
"""End-to-end smoke test: scan corpus samples -> JSON findings -> Metasploit .rc

Creates:
  corpus/test_findings.json   (Attestor findings on vulnerable Juliet samples)
  corpus/test_findings.rc     (Metasploit resource script from bridge)

Not committed utility - lives in corpus/, gitignored samples are inputs.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "detector"))

import detect
import nativescan
from external_eval import cwes_for, load_rule_cwe_map
from metasploit_bridge import write_rc

_RULE_MAP = load_rule_cwe_map()

# Sample vulnerable entries across the CWEs the engine is expected to detect,
# pulled from the manifest (no guessing at filenames).
WANT_CWES = {"CWE-134", "CWE-190", "CWE-197", "CWE-23", "CWE-36", "CWE-252"}


def main() -> int:
    picked: dict[str, int] = {}
    samples: list[dict] = []
    with open(os.path.join(HERE, "manifest.jsonl"), encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            if not row["vulnerable"] or row["cwe"] not in WANT_CWES:
                continue
            if picked.get(row["cwe"], 0) >= 2:          # max 2 per CWE
                continue
            picked[row["cwe"]] = picked.get(row["cwe"], 0) + 1
            samples.append(row)

    findings: list[dict] = []
    for row in samples:
        path = os.path.join(ROOT, row["path"])
        if not os.path.exists(path):
            continue
        for f in detect.scan_file(path):
            findings.append({"path": f.path, "rule": f.rule,
                             "cwe": list(detect.covered_cwes(f.rule))})
        for f in nativescan.scan_file(path):
            findings.append({"path": f.path, "rule": f.rule,
                             "cwe": cwes_for(f.rule, _RULE_MAP)})

    out_json = os.path.join(HERE, "test_findings.json")
    Path(out_json).write_text(json.dumps(findings, indent=2))
    print(f"[+] wrote {out_json} ({len(findings)} findings)")

    out_rc = os.path.join(HERE, "test_findings.rc")
    write_rc(findings, out_rc, rhosts="192.168.56.101", lhost="192.168.56.1")
    print(f"[+] wrote {out_rc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
