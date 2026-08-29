#!/usr/bin/env python3
"""
audit.py -- review a whole codebase and write a report.

Point it at a directory of source you legitimately have -- a repo you were added
to, a zip you were handed -- and Attestor runs BOTH engines over the entire tree (the
regex detector across C/C++/Haskell/Python/JS + secrets, and the deepscan AST
analyzer on the Python), aggregates everything, and produces a report you can hand
to a team: a summary, the most common issues, the files that need the most
attention, and every finding grouped by file. Markdown and SARIF too.

    python3 audit.py ./their_repo
    python3 audit.py ./src --severity HIGH --format md --out review.md
    python3 audit.py ./src --format sarif > review.sarif
"""
from __future__ import annotations

import argparse
import json
import os

import deepscan
import detect
import rarebugs


def audit(paths, deep: bool = True, min_severity: str = "LOW") -> dict:
    """Scan every source file under paths with both engines; group the findings."""
    threshold = detect.SEVERITY_ORDER[min_severity]
    files = detect.collect_paths(paths)
    per_file = {}
    all_findings = []
    for path in files:
        findings = detect.scan_file(path, deep=deep)
        if path.lower().endswith((".py", ".pyw")):
            findings += deepscan.scan_path(path)
            findings += rarebugs.scan_path(path)
        findings = [f for f in findings
                    if detect.SEVERITY_ORDER[f.severity] >= threshold]
        findings.sort(key=detect.Finding.sort_key)
        if findings:
            per_file[path] = findings
        all_findings += findings
    return {"files_scanned": len(files),
            "files_with_findings": len(per_file),
            "findings": all_findings,
            "per_file": per_file}


def _by_severity(findings) -> dict:
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _by_rule(findings):
    counts = {}
    for f in findings:
        counts[f.rule] = counts.get(f.rule, 0) + 1
    return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)


def _top_files(per_file, limit: int = 10):
    return sorted(per_file.items(), key=lambda kv: len(kv[1]), reverse=True)[:limit]


def _rel(path: str, root: str) -> str:
    """Path relative to the audited root (so reports read cleanly, not ../../..)."""
    base = root if os.path.isdir(root) else os.path.dirname(root)
    try:
        return os.path.relpath(path, base) if base else path
    except ValueError:
        return path


def report_text(result: dict, root: str) -> str:
    findings = result["findings"]
    sev = _by_severity(findings)
    out = [f"Code review -- {root}", "=" * 64,
           f"scanned {result['files_scanned']} files; {len(findings)} finding(s) in "
           f"{result['files_with_findings']} file(s)",
           f"  HIGH {sev['HIGH']}   MEDIUM {sev['MEDIUM']}   LOW {sev['LOW']}"]
    rules = _by_rule(findings)
    if rules:
        out += ["", "most common issues:"]
        for rule, n in rules[:10]:
            out.append(f"  {n:>4}  {rule}")
    top = _top_files(result["per_file"])
    if top:
        out += ["", "files needing the most attention:"]
        for path, fs in top:
            out.append(f"  {len(fs):>4}  {_rel(path, root)}")
    if result["per_file"]:
        out += ["", "findings:"]
        for path in sorted(result["per_file"]):
            out.append(f"\n{_rel(path, root)}:")
            for x in result["per_file"][path]:
                out.append(f"  L{x.line} [{x.severity}] {x.rule}: {x.fix}")
    else:
        out += ["", "no issues found. clean, by Attestor's rules."]
    return "\n".join(out)


def report_markdown(result: dict, root: str) -> str:
    findings = result["findings"]
    sev = _by_severity(findings)
    lines = [f"# Code review — `{root}`", "",
             f"Scanned **{result['files_scanned']}** source files; found "
             f"**{len(findings)}** issue(s) across "
             f"**{result['files_with_findings']}** file(s).",
             "", "## Summary", "", "| Severity | Count |", "|---|---|",
             f"| HIGH | {sev['HIGH']} |",
             f"| MEDIUM | {sev['MEDIUM']} |",
             f"| LOW | {sev['LOW']} |"]
    rules = _by_rule(findings)
    if rules:
        lines += ["", "## Most common issues", "", "| Rule | Count |", "|---|---|"]
        for rule, n in rules[:12]:
            lines.append(f"| `{rule}` | {n} |")
    top = _top_files(result["per_file"])
    if top:
        lines += ["", "## Files needing the most attention", "", "| File | Issues |", "|---|---|"]
        for path, fs in top:
            lines.append(f"| `{_rel(path, root)}` | {len(fs)} |")
    if result["per_file"]:
        lines += ["", "## Findings"]
        for path in sorted(result["per_file"]):
            fs = result["per_file"][path]
            lines += ["", f"### `{_rel(path, root)}` ({len(fs)})", ""]
            for x in fs:
                lines.append(f"- **L{x.line}** `[{x.severity}]` `{x.rule}` — {x.fix}")
    else:
        lines += ["", "No issues found — clean by Attestor's rules."]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="folders or files to review")
    ap.add_argument("--no-deep", action="store_true",
                    help="skip the higher-recall (noisier) rule tier")
    ap.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH"], default="LOW")
    ap.add_argument("--format", choices=["text", "md", "sarif"], default="text")
    ap.add_argument("--out", help="write the report here instead of stdout")
    args = ap.parse_args(argv)

    result = audit(args.paths, deep=not args.no_deep, min_severity=args.severity)
    root = args.paths[0]
    if args.format == "sarif":
        text = json.dumps(detect.to_sarif(result["findings"]), indent=2)
    elif args.format == "md":
        text = report_markdown(result, root)
    else:
        text = report_text(result, root)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"reviewed {result['files_scanned']} files, {len(result['findings'])} "
              f"finding(s) -> {args.out}")
    else:
        print(text)
    return min(len(result["findings"]), 250)


if __name__ == "__main__":
    raise SystemExit(main())
