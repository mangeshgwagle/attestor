#!/usr/bin/env python3
"""Diff-only scanning -- scan only files changed in a git diff / PR.

Runs the dataflow engines (Python + JS/TS) only on files that changed,
then filters findings to lines actually modified. Makes CI integration
practical on large repos: scan a 100k-line codebase in seconds by only
analyzing the PR diff.

Usage:
    # scan uncommitted changes:
    python -m diff_scan .

    # scan changes vs a branch:
    python -m diff_scan . --base main

    # scan staged changes only:
    python -m diff_scan . --staged

    # output as SARIF for GitHub Code Scanning:
    python -m diff_scan . --base main --sarif results.sarif
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

PY_EXTENSIONS = {".py"}
JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
ALL_EXTENSIONS = PY_EXTENSIONS | JS_EXTENSIONS


@dataclass
class DiffFile:
    path: str
    status: str  # A=added, M=modified, D=deleted, R=renamed
    changed_lines: set[int] = field(default_factory=set)


def get_changed_files(root: str = ".", base: str = "",
                      staged: bool = False) -> list[DiffFile]:
    args = ["git", "diff", "--name-status", "--no-renames"]
    if staged:
        args.append("--cached")
    elif base:
        args.append(f"{base}...HEAD")
    try:
        r = subprocess.run(args, capture_output=True, text=True, cwd=root, timeout=30)
        if r.returncode != 0:
            return []
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    files = []
    for line in r.stdout.strip().splitlines():
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        status, path = parts[0][0], parts[1]
        ext = os.path.splitext(path)[1]
        if ext not in ALL_EXTENSIONS:
            continue
        if status == "D":
            continue
        df = DiffFile(path=os.path.join(root, path), status=status)
        df.changed_lines = _get_changed_lines(root, path, base, staged)
        files.append(df)
    return files


def _get_changed_lines(root: str, path: str, base: str,
                       staged: bool) -> set[int]:
    args = ["git", "diff", "-U0"]
    if staged:
        args.append("--cached")
    elif base:
        args.append(f"{base}...HEAD")
    args.append("--")
    args.append(path)
    try:
        r = subprocess.run(args, capture_output=True, text=True, cwd=root, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return set()

    lines = set()
    for m in re.finditer(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", r.stdout):
        start = int(m.group(1))
        count = int(m.group(2)) if m.group(2) else 1
        lines.update(range(start, start + count))
    return lines


def scan_diff(root: str = ".", base: str = "", staged: bool = False,
              context_lines: int = 5) -> list[dict]:
    """Scan only changed files, filter to findings near changed lines."""
    changed = get_changed_files(root, base, staged)
    if not changed:
        return []

    py_files = [f.path for f in changed if os.path.splitext(f.path)[1] in PY_EXTENSIONS]
    js_files = [f.path for f in changed if os.path.splitext(f.path)[1] in JS_EXTENSIONS]

    line_sets = {f.path: f.changed_lines for f in changed}
    all_findings = []

    if py_files:
        try:
            import dataflow
            findings = dataflow.scan_paths(py_files)
            all_findings += dataflow.to_dict(findings)
        except Exception:
            pass

    if js_files:
        try:
            import dataflow_js
            findings = dataflow_js.scan_paths(js_files)
            all_findings += dataflow_js.to_dict(findings)
        except Exception:
            pass

    filtered = []
    for f in all_findings:
        fpath = f.get("sink_file") or f.get("file") or ""
        fline = int(f.get("sink_line") or f.get("line") or 0)
        changed = line_sets.get(fpath, set())
        if not changed:
            abs_path = os.path.abspath(fpath)
            changed = line_sets.get(abs_path, set())
        if _near_changed(fline, changed, context_lines):
            f["diff_relevant"] = True
            filtered.append(f)

    return filtered


def _near_changed(line: int, changed_lines: set[int], ctx: int) -> bool:
    if not changed_lines:
        return True
    return any(abs(line - cl) <= ctx for cl in changed_lines)


def render(findings: list[dict], changed_files: list[DiffFile] | None = None) -> str:
    if not findings:
        n = len(changed_files) if changed_files else 0
        return f"  Diff scan: {n} file(s) changed, no new findings."
    lines = [
        f"\n  Diff Scan -- {len(findings)} finding(s) in changed code",
        "  " + "=" * 62,
    ]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for f in sorted(findings, key=lambda x: order.get(
            (x.get("severity") or "MEDIUM").upper(), 9)):
        sev = (f.get("severity") or "MEDIUM").upper()
        vuln = f.get("sink_type") or f.get("category") or "unknown"
        cwe = f.get("cwe") or ""
        sink_file = os.path.basename(f.get("sink_file") or f.get("file") or "?")
        sink_line = f.get("sink_line") or f.get("line") or 0
        lang = f.get("language") or "python"
        lines.append(f"\n  [{sev}] {vuln} ({cwe}) at {sink_file}:{sink_line} [{lang}]")
        trace = f.get("trace") or []
        if trace:
            lines.append(f"    trace: {len(trace)} step(s)")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="attestor-diff-scan",
        description="Scan only files changed in the git diff.")
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--base", "-b", default="",
                    help="base branch/commit to diff against (default: working tree)")
    ap.add_argument("--staged", action="store_true",
                    help="scan only staged changes")
    ap.add_argument("--context", type=int, default=5,
                    help="finding must be within N lines of a changed line (default: 5)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--sarif", metavar="FILE",
                    help="write SARIF output to FILE")
    args = ap.parse_args(argv)

    changed = get_changed_files(args.root, args.base, args.staged)
    findings = scan_diff(args.root, args.base, args.staged, args.context)

    if args.sarif:
        import sarif_output
        sarif_output.write(findings, args.sarif)
        sys.stderr.write(f"  wrote {args.sarif} ({len(findings)} finding(s))\n")

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        print(render(findings, changed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
