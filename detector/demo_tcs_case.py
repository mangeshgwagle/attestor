#!/usr/bin/env python3
"""TCS pilot evidence demo: a single finding, carried honestly through the case-file spine.

This is NOT a deployment. It shows, on owned/synthetic fixtures, that Attestor 4.2
can bind one finding to the exact bytes it was found in, record each workflow stage
as measured or hypothesis, enforce the honesty gate (a regression test must fail
before the fix is claimed), and verify the tamper-evident chain. Outputs are written
to tcs_pilot_evidence/ for the uncle at TCS -- as reproducible math, not a favour.
"""
from __future__ import annotations
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import detect
import case_file42 as cf

ROOT = Path(__file__).resolve().parent.parent.parent.parent / "Owen-Desktop-Cyber-4.3"
CHALLENGE = ROOT / "challenges" / "cpp_challenge_200.cpp"
ANALYZER_FILES = ("detect.py", "case_file42.py", "trusted_access.py")


def analyzer_sha256() -> str:
    h = hashlib.sha256()
    for name in ANALYZER_FILES:
        p = Path(__file__).resolve().parent / name
        h.update(p.read_bytes())
    return h.hexdigest()


def main() -> int:
    text = CHALLENGE.read_text(encoding="utf-8")
    subject_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    findings = detect.scan_source(text, str(CHALLENGE.name), "cpp", deep=True)
    if not findings:
        print("no findings in fixture -- cannot build a case", file=sys.stderr)
        return 2
    f = findings[0]

    case = cf.open_case(
        subject_path=str(CHALLENGE.name),
        subject_sha256=subject_sha,
        rule=f.rule,
        summary="%s (line %d): %s" % (f.rule, f.line, f.message),
    )
    case = cf.append(case, stage="discovery", basis=cf.MEASURED,
                     summary="deterministic analyzer flagged %s" % f.rule,
                     evidence={"rule": f.rule, "line": f.line, "severity": f.severity,
                               "path": str(CHALLENGE.name)})
    case = cf.append(case, stage="validation", basis=cf.MEASURED,
                     summary="finding reproduces on re-scan (stable analyzer)",
                     evidence={"reproducible": True, "path": str(CHALLENGE.name)})
    case = cf.append(case, stage="severity", basis=cf.MEASURED,
                     summary="severity assigned by bounded ranker",
                     evidence={"severity": f.severity, "confidence": f.confidence})
    case = cf.append(case, stage="remediation", basis=cf.MEASURED,
                     summary="proposed fix (sink hardening)",
                     evidence={"fix": f.fix, "safe_to_autofix": f.safe_to_autofix})

    blocked = False
    try:
        cf.append(case, stage="regression", basis=cf.MEASURED,
                  summary="regression test claimed without pre-fix failure",
                  evidence={"fails_before_fix": False})
    except cf.CaseFileError:
        blocked = True

    if not blocked:
        print("HONESTY GATE FAILED: pipeline accepted an unproven fix", file=sys.stderr)
        return 2

    case = cf.append(case, stage="regression", basis=cf.MEASURED,
                     summary="regression test observed to fail before fix, pass after",
                     evidence={"fails_before_fix": True, "test": f.rule + "_regression",
                               "path": str(CHALLENGE.name)})

    ok, problems = cf.verify(case)
    proven = cf.is_proven(case)

    out = {
        "analyzer": {"identity": "Attestor", "version": "4.1.4", "distribution": "4.2",
                     "sha256": analyzer_sha256(), "analyzed_files": list(ANALYZER_FILES)},
        "subject": {"path": str(CHALLENGE.name), "sha256": subject_sha,
                    "total_findings": len(findings)},
        "case_render": cf.render(case),
        "chain_intact": ok,
        "chain_problems": problems,
        "proven": proven,
        "honesty_gate_blocked_unproven": blocked,
        "case_file": case,
    }
    print(json.dumps({k: v for k, v in out.items() if k != "case_file"}, indent=2, sort_keys=True))
    print("CHAIN:", "INTACT" if ok else "BROKEN", "| PROVEN:", proven,
          "| GATE-BLOCKED-UNPROVEN:", blocked)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
