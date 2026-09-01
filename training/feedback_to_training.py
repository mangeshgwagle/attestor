#!/usr/bin/env python3
"""Feedback-to-training pipeline -- memory verdicts become training data.

Reads TP/FP feedback from Attestor's memory system and generates new
training pairs that teach the model from real-world deployment experience.
Each codebase Attestor scans becomes a data source.

This is the feedback loop that makes Attestor get better over time:
  1. Attestor scans code, produces findings
  2. User marks findings as TP or FP
  3. This script reads those verdicts + the source code
  4. Generates instruction/output pairs for the next training round
  5. Merge into training data, retrain owen-coder

    python feedback_to_training.py /path/to/project
    python feedback_to_training.py /path/to/project --out feedback_pairs.jsonl
    python feedback_to_training.py --scan-all ~/projects/*/
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))

DETECT_TEMPLATE = """Analyze this code for security vulnerabilities. Report what you find.

File: {path}
```
{code}
```"""

TP_OUTPUT = """CATEGORY: {category}
CWE: {cwe}
SEVERITY: {severity}
DESCRIPTION: {description}
LINE: {line}
EXPLOITABLE: YES
REASONING: {reason}"""

FP_OUTPUT = """After careful analysis, this code is NOT vulnerable to {rule_id}.

VERDICT: FALSE POSITIVE
REASONING: {reason}
The pattern matched by the static analyzer is a false alarm because the code {explanation}."""

FIX_TEMPLATE = """Fix the security vulnerability in this code.

Vulnerability: {description}
File: {path}
Line: {line}

```
{code}
```"""


def extract_feedback_pairs(project_root: str,
                           min_code_lines: int = 3) -> list[dict]:
    try:
        import memory
    except ImportError:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                        "..", "detector"))
        import memory

    mem = memory.Memory(project_root)
    mem._load()

    if not mem._feedback:
        return [], Counter()

    root = Path(project_root).resolve()
    pairs = []
    stats = Counter()

    for finding_hash, entry in mem._feedback.items():
        verdict = entry.get("verdict")
        reason = entry.get("reason", "")
        if verdict not in ("tp", "fp"):
            stats["skipped_defer"] += 1
            continue

        finding = _reconstruct_finding(finding_hash, mem)
        if not finding:
            stats["no_finding_data"] += 1
            continue

        path = finding.get("path", finding.get("file", ""))
        line = finding.get("line", 0)
        rule = finding.get("rule_id", finding.get("rule", "unknown"))

        code = _read_code_context(root, path, line)
        if not code or len(code.splitlines()) < min_code_lines:
            stats["no_code"] += 1
            continue

        if verdict == "tp":
            detect_pair = {
                "instruction": DETECT_TEMPLATE.format(path=path, code=code),
                "output": TP_OUTPUT.format(
                    category=finding.get("category", "security"),
                    cwe=finding.get("cwe", "Unknown"),
                    severity=finding.get("severity", "MEDIUM"),
                    description=finding.get("description", rule),
                    line=line,
                    reason=reason or "Confirmed by manual review",
                ),
                "_meta": {
                    "source": "feedback",
                    "verdict": "tp",
                    "rule": rule,
                    "project": os.path.basename(project_root),
                    "generated": datetime.now(timezone.utc).isoformat(),
                },
            }
            pairs.append(detect_pair)
            stats["tp_detect"] += 1

        elif verdict == "fp":
            explanation = reason or "does not match the vulnerability pattern in this context"
            fp_pair = {
                "instruction": DETECT_TEMPLATE.format(path=path, code=code),
                "output": FP_OUTPUT.format(
                    rule_id=rule,
                    reason=reason or "Pattern match does not indicate real vulnerability",
                    explanation=explanation,
                ),
                "_meta": {
                    "source": "feedback",
                    "verdict": "fp",
                    "rule": rule,
                    "project": os.path.basename(project_root),
                    "generated": datetime.now(timezone.utc).isoformat(),
                },
            }
            pairs.append(fp_pair)
            stats["fp_detect"] += 1

    return pairs, stats


def _reconstruct_finding(finding_hash: str, mem) -> dict | None:
    stats = mem.get_stats()
    rule_counts = stats.get("rule_counts", {})
    file_counts = stats.get("file_counts", {})

    for rule in rule_counts:
        for filepath in file_counts:
            for line in range(1, 5000):
                candidate = {
                    "path": filepath, "line": line,
                    "rule_id": rule,
                }
                from memory import _finding_hash
                if _finding_hash(candidate) == finding_hash:
                    return candidate
    return None


def _read_code_context(root: Path, path: str, line: int,
                       window: int = 20) -> str:
    if os.path.isabs(path):
        full = Path(path)
    else:
        full = root / path
    if not full.exists():
        return ""
    try:
        with open(full, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return ""
    start = max(0, line - window - 1)
    end = min(len(lines), line + window)
    return "".join(lines[start:end])


def generate_rule_calibration_pairs(project_root: str) -> list[dict]:
    try:
        import memory
    except ImportError:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                        "..", "detector"))
        import memory

    mem = memory.Memory(project_root)
    noisy = mem.get_noisy_rules(min_feedback=5)
    pairs = []

    for rule_info in noisy:
        rule = rule_info["rule"]
        precision = rule_info["precision"]
        tp = rule_info["tp"]
        fp = rule_info["fp"]

        if precision < 0.3:
            pair = {
                "instruction": (
                    f"Static analysis rule {rule} flagged code in this project. "
                    f"Historical data: {tp} true positives, {fp} false positives "
                    f"(precision: {precision:.0%}). Should findings from this rule "
                    f"be treated as high or low confidence?"
                ),
                "output": (
                    f"Rule {rule} has very low precision ({precision:.0%}) in this "
                    f"codebase. Out of {tp + fp} reviewed findings, only {tp} were "
                    f"real vulnerabilities. Findings from this rule should be treated "
                    f"as LOW confidence and reviewed carefully before acting on them. "
                    f"Consider tuning the rule or adding project-specific suppressions."
                ),
                "_meta": {
                    "source": "feedback_calibration",
                    "rule": rule,
                    "precision": precision,
                },
            }
            pairs.append(pair)

    return pairs


def scan_multiple_projects(project_dirs: list[str],
                           out_path: str = "feedback_training_data.jsonl"):
    all_pairs = []
    total_stats = Counter()

    for proj in project_dirs:
        proj = os.path.expanduser(proj)
        if not os.path.isdir(proj):
            continue
        mem_dir = os.path.join(proj, ".attestor", "memory")
        if not os.path.isdir(mem_dir):
            continue

        print(f"  Processing {proj}...")
        pairs, stats = extract_feedback_pairs(proj)
        cal_pairs = generate_rule_calibration_pairs(proj)
        all_pairs.extend(pairs)
        all_pairs.extend(cal_pairs)
        for k, v in stats.items():
            total_stats[k] += v
        print(f"    {len(pairs)} feedback pairs, {len(cal_pairs)} calibration pairs")

    seen = set()
    unique = []
    for p in all_pairs:
        key = hashlib.md5(p["instruction"].strip().encode()).hexdigest()
        if key not in seen:
            seen.add(key)
            unique.append(p)

    out_dir = os.path.dirname(os.path.abspath(__file__))
    out_full = os.path.join(out_dir, out_path)
    with open(out_full, "w", encoding="utf-8") as f:
        for p in unique:
            f.write(json.dumps({
                "instruction": p["instruction"],
                "output": p["output"],
            }, ensure_ascii=False) + "\n")

    print(f"\n  Feedback training data: {len(unique)} pairs -> {out_path}")
    for k, v in total_stats.most_common():
        print(f"    {k:20s}: {v}")

    return unique


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Generate training data from memory feedback")
    parser.add_argument("projects", nargs="+", help="project directories")
    parser.add_argument("--out", default="feedback_training_data.jsonl")
    parser.add_argument("--scan-all", action="store_true",
                        help="treat args as glob patterns")
    args = parser.parse_args()

    import glob
    dirs = []
    for p in args.projects:
        if args.scan_all or "*" in p:
            dirs.extend(glob.glob(os.path.expanduser(p)))
        else:
            dirs.append(p)

    scan_multiple_projects(dirs, args.out)


if __name__ == "__main__":
    main()
