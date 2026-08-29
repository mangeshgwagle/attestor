#!/usr/bin/env python3
"""The training flywheel: turn every scan into data that makes Owen Coder better.

Attestor finds candidates. Some are real (TP), many are noise (FP). Today that
judgement is thrown away. The flywheel captures it: each triaged finding becomes
an {instruction, output} training pair -- drop-in for training_data_merged.jsonl
-- teaching the model to make the same call next time. Over scans, Owen Coder
learns YOUR codebase's true/false-positive boundary, which is the one thing a
generic GPT model can never have. That is the moat.

Labels come from three sources, best first:
  1. human review (a reviewer marks report/suppress) -- gold
  2. Owen Coder itself (auto-label the 'review' bucket) -- silver / weak labels
  3. triage priors (high priority => likely TP, suppressed => likely FP) -- bronze

    python3 flywheel.py harvest ROOT --out pairs.jsonl     # generate pairs
    python3 flywheel.py harvest ROOT --auto                # + Owen Coder labels
"""
from __future__ import annotations

import argparse
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import triage

CONTEXT_LINES = 6


def _snippet(path: str, line: int, radius: int = CONTEXT_LINES) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return ""
    if not line or line < 1:
        return "".join(lines[:radius]).rstrip()
    lo = max(0, line - radius // 2 - 1)
    hi = min(len(lines), line + radius // 2)
    return "".join(lines[lo:hi]).rstrip()


def _lang(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    return {
        ".py": "python", ".js": "javascript", ".jsx": "javascript",
        ".ts": "typescript", ".tsx": "typescript", ".java": "java",
        ".go": "go", ".rb": "ruby", ".php": "php", ".c": "c",
        ".cpp": "cpp", ".h": "c", ".rs": "rust",
    }.get(ext, "")


def finding_to_pair(finding: dict, label: str, reasoning: str = "") -> dict:
    """Build one {instruction, output} pair. label in {'true_positive','false_positive'}."""
    path = finding.get("path") or finding.get("file") or ""
    line = finding.get("line") or finding.get("line_start") or 0
    rule = finding.get("rule_id", "")
    sev = finding.get("severity", "")
    desc = finding.get("description", "")
    snippet = _snippet(path, line) if path else ""
    lang = _lang(path)

    fence = f"```{lang}\n{snippet}\n```" if snippet else ""
    instruction = (
        f"A static analyzer flagged this code with rule `{rule}` "
        f"({sev}): {desc}\n{fence}\n"
        f"Is this a real, exploitable security issue, or a false positive? "
        f"Answer and justify briefly."
    )

    if label == "true_positive":
        verdict = "This is a real issue."
        default_reason = (
            f"The {rule} finding is valid: the flagged pattern is reachable and "
            f"exploitable in this context. It should be fixed, not suppressed."
        )
    else:
        verdict = "This is a false positive."
        default_reason = (
            f"The {rule} finding does not represent a real risk here -- the pattern "
            f"appears in non-exploitable context (e.g. vendored/library code, a "
            f"constant table, or a sanitized path). Safe to suppress."
        )
    output = f"{verdict} {reasoning or default_reason}"
    return {"instruction": instruction, "output": output}


def pairs_from_triage(findings: list[dict]) -> list[dict]:
    """Bronze labels: derive weak TP/FP labels from triage priority alone."""
    triaged = triage.triage_all(findings)
    pairs = []
    for t in triaged:
        if t.action == "report":
            pairs.append(finding_to_pair(t.finding, "true_positive"))
        elif t.action == "suppress":
            pairs.append(finding_to_pair(t.finding, "false_positive"))
        # 'review' bucket left for human or Owen Coder to label
    return pairs


def auto_label_review_bucket(findings: list[dict], model: str | None = None) -> list[dict]:
    """Silver labels: ask Owen Coder to adjudicate the ambiguous 'review' bucket."""
    try:
        import ai_engine
    except ImportError:
        return []
    if not ai_engine.is_available():
        return []

    triaged = triage.triage_all(findings)
    review = [t.finding for t in triaged if t.action == "review"]
    pairs = []
    for finding in review:
        path = finding.get("path", "")
        line = finding.get("line", 0)
        snippet = _snippet(path, line)
        rule = finding.get("rule_id", "")
        prompt = (
            f"Rule {rule} flagged:\n```\n{snippet}\n```\n"
            f"Reply with exactly 'TRUE_POSITIVE: <reason>' or "
            f"'FALSE_POSITIVE: <reason>'."
        )
        try:
            answer = ai_engine.ask_text(prompt, model=model) if hasattr(ai_engine, "ask_text") else ""
        except Exception:
            answer = ""
        if not answer:
            continue
        up = answer.strip().upper()
        if up.startswith("TRUE_POSITIVE"):
            pairs.append(finding_to_pair(finding, "true_positive", answer.split(":", 1)[-1].strip()))
        elif up.startswith("FALSE_POSITIVE"):
            pairs.append(finding_to_pair(finding, "false_positive", answer.split(":", 1)[-1].strip()))
    return pairs


def harvest(root: str, out_path: str, auto: bool = False,
            model: str | None = None) -> dict:
    findings = _collect_aggregate(root)
    pairs = pairs_from_triage(findings)
    silver = 0
    if auto:
        auto_pairs = auto_label_review_bucket(findings, model=model)
        silver = len(auto_pairs)
        pairs.extend(auto_pairs)

    written = append_pairs(pairs, out_path)
    return {
        "root": root, "findings": len(findings),
        "pairs_generated": len(pairs), "silver_labels": silver,
        "out": out_path, "total_lines_in_file": written,
    }


def append_pairs(pairs: list[dict], out_path: str) -> int:
    seen = set()
    if os.path.exists(out_path):
        try:
            with open(out_path, encoding="utf-8") as f:
                for ln in f:
                    ln = ln.strip()
                    if ln:
                        try:
                            seen.add(json.loads(ln)["instruction"])
                        except (json.JSONDecodeError, KeyError):
                            pass
        except OSError:
            pass
    added = 0
    with open(out_path, "a", encoding="utf-8") as f:
        for p in pairs:
            if p["instruction"] in seen:
                continue
            f.write(json.dumps(p, ensure_ascii=False) + "\n")
            seen.add(p["instruction"])
            added += 1
    return len(seen)


def _collect_aggregate(root: str) -> list[dict]:
    out: list[dict] = []
    for modname, cat in [("secret_scanner", "secrets"), ("exploit_detector", None),
                         ("iac_scanner", None), ("js_scanner", None)]:
        try:
            mod = __import__(modname)
            for f in mod.scan_directory(root):
                out.append({
                    "path": getattr(f, "path", ""),
                    "line": getattr(f, "line", 0),
                    "rule_id": getattr(f, "rule_id", ""),
                    "severity": getattr(f, "severity", "MEDIUM"),
                    "description": getattr(f, "description", ""),
                    "category": cat or getattr(f, "category", ""),
                })
        except Exception:
            continue
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    h = sub.add_parser("harvest", help="generate training pairs from a scan")
    h.add_argument("root")
    h.add_argument("--out", default="flywheel_pairs.jsonl")
    h.add_argument("--auto", action="store_true", help="use Owen Coder for silver labels")
    h.add_argument("--model", default=None)
    args = ap.parse_args(argv)

    if args.cmd == "harvest":
        stats = harvest(args.root, args.out, auto=args.auto, model=args.model)
        print(json.dumps(stats, indent=2))
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
