#!/usr/bin/env python3
"""
review.py -- review a Python *change*, not the whole file.

grade.py judges a file as it stands; this judges what a change did to it. Give it
the old and new versions and it reports only what the diff INTRODUCED -- the
findings present in the new version but not the old -- plus what it FIXED, and the
A-F grade delta. Pre-existing noise is ignored, so the review is about your diff
and nothing else.

Findings are matched by (rule + the exact source line text), so moving code up or
down never looks like a new bug -- only genuinely new problems count. It fuses
every Python engine grade.py uses (detect + deepscan + rarebugs), so a change that
introduces a rare bug, a security smell, or a complexity blow-up all show up.

Exit code = number of introduced findings, so CI can fail a change that adds bugs:

    review.py old/app.py new/app.py          # compare two files
    review.py app.py --git                    # compare app.py against its git HEAD
    review.py app.py --git --ref v1.2.0       # ...against a tag/branch/commit
    review.py old.py new.py --json            # machine-readable
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from collections import Counter

import grade
import metrics

_SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _git_show(ref: str, path: str) -> str:
    """The contents of `path` at git `ref` (e.g. HEAD), or '' if unavailable."""
    try:
        proc = subprocess.run(["git", "show", "%s:%s" % (ref, path)],
                              capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout if proc.returncode == 0 else ""


def _findings_of(src: str, path: str) -> list:
    """(rule, severity, line, text, message) for every Python finding in `src`.
    text is the stripped source line -- the anchor that survives line shifts."""
    if not src.strip():
        return []
    lines = src.splitlines()
    _fg, findings, _funcs = grade.grade_source(src, path, metrics.DEFAULT_LIMITS)
    out = []
    for finding in findings:
        text = lines[finding.line - 1].strip() if 0 < finding.line <= len(lines) else ""
        message = getattr(finding, "message", "")
        out.append((finding.rule, finding.severity, finding.line, text, message))
    return out


def _diff(old: list, new: list) -> tuple:
    """(introduced, fixed) as multisets keyed on (rule, source-line-text), so the
    same finding relocated is neither introduced nor fixed."""
    old_keys = Counter((rule, text) for rule, _s, _l, text, _m in old)
    introduced = []
    for item in new:
        key = (item[0], item[3])
        if old_keys[key] > 0:
            old_keys[key] -= 1
        else:
            introduced.append(item)
    new_keys = Counter((rule, text) for rule, _s, _l, text, _m in new)
    fixed = []
    for item in old:
        key = (item[0], item[3])
        if new_keys[key] > 0:
            new_keys[key] -= 1
        else:
            fixed.append(item)
    return introduced, fixed


def review(old_src: str, new_src: str, old_path: str, new_path: str) -> dict:
    limits = metrics.DEFAULT_LIMITS
    introduced, fixed = _diff(_findings_of(old_src, old_path), _findings_of(new_src, new_path))
    introduced.sort(key=lambda f: _SEV_ORDER.get(f[1], 4))
    before = grade.grade_source(old_src, old_path, limits)[0] if old_src.strip() else None
    after = grade.grade_source(new_src, new_path, limits)[0]
    return {"introduced": introduced, "fixed": fixed, "before": before, "after": after}


def review_files(old_path: str, new_path: str) -> dict:
    return review(_read(old_path), _read(new_path), old_path, new_path)


def review_git(path: str, ref: str = "HEAD") -> dict:
    return review(_git_show(ref, path), _read(path), path, path)


def _grade_arrow(before, after) -> str:
    if before is None:
        return "%s (%d)" % (after.grade, after.score)
    return "%s (%d) -> %s (%d)" % (before.grade, before.score, after.grade, after.score)


def render(result: dict, label: str) -> str:
    introduced, fixed = result["introduced"], result["fixed"]
    lines = ["review: %s" % label,
             "  grade %s   |   +%d introduced, -%d fixed"
             % (_grade_arrow(result["before"], result["after"]), len(introduced), len(fixed))]
    if introduced:
        lines.append("  introduced by this change:")
        for rule, severity, line, _text, message in introduced:
            detail = (" -- " + message) if message else ""
            lines.append("    [%s] %s at line %d%s" % (severity, rule, line, detail))
    else:
        lines.append("  no new findings -- this change adds no detectable problems.")
    if fixed:
        lines.append("  fixed by this change: " + ", ".join(sorted({f[0] for f in fixed})))
    return "\n".join(lines)


def _as_json(result: dict) -> str:
    import json
    before, after = result["before"], result["after"]
    payload = {
        "before": {"grade": before.grade, "score": before.score} if before else None,
        "after": {"grade": after.grade, "score": after.score},
        "introduced": [{"rule": r, "severity": s, "line": l, "message": m}
                       for r, s, l, _t, m in result["introduced"]],
        "fixed": sorted({f[0] for f in result["fixed"]}),
    }
    return json.dumps(payload, indent=2)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="OLD NEW, or a single file with --git")
    ap.add_argument("--git", action="store_true",
                    help="compare the single given file against its version at --ref")
    ap.add_argument("--ref", default="HEAD", help="git ref to compare against (default HEAD)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    if args.git:
        if len(args.paths) != 1:
            ap.error("--git takes exactly one file to compare against its git history")
        result = review_git(args.paths[0], args.ref)
        label = "%s (working tree vs %s)" % (args.paths[0], args.ref)
    else:
        if len(args.paths) != 2:
            ap.error("give OLD and NEW file paths, or one file with --git")
        result = review_files(args.paths[0], args.paths[1])
        label = args.paths[1]

    print(_as_json(result) if args.json else render(result, label))
    return min(len(result["introduced"]), 250)


if __name__ == "__main__":
    sys.exit(main())
