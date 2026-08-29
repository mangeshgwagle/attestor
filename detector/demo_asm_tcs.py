#!/usr/bin/env python3
"""TCS pilot evidence demo: x86-64 / C++ findings on owned synthetic fixtures.

Shows that Attestor 4.2 flags the dangerous patterns in a deliberately-weak asm
fixture and a C++ fixture, while remaining silent on a 10,000-line clean,
multi-function x86-64 program (no execve, no stack pivot, no NOP sled, no W^X).
No target code is executed; this is static analysis evidence only.
"""
from __future__ import annotations
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import detect

ROOT = Path(__file__).resolve().parent.parent.parent.parent / "Owen-Desktop-Cyber-4.3"


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def scan(name: str, lang: str, deep: bool = True) -> dict:
    p = ROOT / "challenges" / name
    text = p.read_text(encoding="utf-8")
    findings = detect.scan_source(text, name, lang, deep=deep)
    return {
        "file": name,
        "lang": lang,
        "sha256": sha(p),
        "lines": text.count("\n") + 1,
        "total_findings": len(findings),
        "asm_rules_fired": sorted({f.rule for f in findings if f.rule.startswith("asm-")}),
        "severities": sorted({f.severity for f in findings}),
        "sample": [{"rule": f.rule, "line": f.line, "severity": f.severity,
                    "message": f.message} for f in findings[:8]],
    }


def main() -> int:
    results = [
        scan("asm_challenge_500.asm", "asm"),
        scan("cpp_challenge_200.cpp", "cpp"),
        scan("asm_10000_multi.asm", "asm"),
    ]
    for r in results:
        print("FILE %s  lines=%d  findings=%d  asm-rules=%s"
              % (r["file"], r["lines"], r["total_findings"], r["asm_rules_fired"]))
    clean = results[2]
    if clean["total_findings"] != 0:
        print("UNEXPECTED: clean 10k file produced findings", file=sys.stderr)
        return 2
    payload = {
        "runs": results,
        "summary": {
            "weak_fixture_asm_rules": results[0]["asm_rules_fired"],
            "weak_fixture_cpp_findings": results[1]["total_findings"],
            "clean_10k_asm_findings": results[2]["total_findings"],
        },
    }
    print(json.dumps(payload["summary"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
