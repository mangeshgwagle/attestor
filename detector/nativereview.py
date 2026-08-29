#!/usr/bin/env python3
"""
nativereview.py -- review a C/C++/Assembly *change*, not the whole file.

Point it at the old and new versions of a file and it reports only what the change
INTRODUCED -- the findings that are in the new version but were not in the old --
plus what it FIXED, and the grade delta. Pre-existing noise is ignored, so the
review is about your diff and nothing else. Findings are matched by (rule + the
exact source line text), so moving code up or down never looks like a new bug.

Exit code = number of introduced findings, so CI can fail a change that adds bugs:

    nativereview.py old/parser.c new/parser.c
    # from git:  git show HEAD:parser.c > /tmp/old.c && nativereview.py /tmp/old.c parser.c
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter

import nativegrade


def _lines(path: str) -> list:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    except OSError:
        return []


def _findings_with_text(path: str) -> list:
    """(rule, severity, line, text, message) for every finding, text = the source
    line stripped -- the anchor that survives line-number shifts."""
    lines = _lines(path)
    out = []
    for line, rule, severity, message in nativegrade._findings(path):
        text = lines[line - 1].strip() if 0 < line <= len(lines) else ""
        out.append((rule, severity, line, text, message))
    return out


def _diff(old: list, new: list) -> tuple:
    """(introduced, fixed): findings only in new, and findings only in old,
    compared as a multiset keyed on (rule, source-line-text)."""
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


def review(old_path: str, new_path: str) -> dict:
    introduced, fixed = _diff(_findings_with_text(old_path), _findings_with_text(new_path))
    before = nativegrade.grade_file(old_path)[0]
    after = nativegrade.grade_file(new_path)[0]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    introduced.sort(key=lambda f: order.get(f[1], 5))
    return {"introduced": introduced, "fixed": fixed,
            "before": before, "after": after}


def render(result: dict, new_path: str) -> str:
    before, after = result["before"], result["after"]
    introduced, fixed = result["introduced"], result["fixed"]
    arrow = "%s (%d) -> %s (%d)" % (before.grade, before.score, after.grade, after.score)
    lines = ["native review: %s" % new_path,
             "  grade %s   |   +%d introduced, -%d fixed"
             % (arrow, len(introduced), len(fixed))]
    if introduced:
        lines.append("  introduced by this change:")
        for rule, severity, line, _text, message in introduced:
            lines.append("    [%s] %s at line %d -- %s" % (severity, rule, line, message))
    else:
        lines.append("  no new findings -- this change adds no detectable bugs.")
    if fixed:
        lines.append("  fixed by this change: " + ", ".join(sorted({f[0] for f in fixed})))
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("old", help="the previous version of the file")
    ap.add_argument("new", help="the changed version of the file")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    result = review(args.old, args.new)
    if args.json:
        import json
        payload = {
            "before": {"grade": result["before"].grade, "score": result["before"].score},
            "after": {"grade": result["after"].grade, "score": result["after"].score},
            "introduced": [{"rule": r, "severity": s, "line": l, "message": m}
                           for r, s, l, _t, m in result["introduced"]],
            "fixed": sorted({f[0] for f in result["fixed"]}),
        }
        print(json.dumps(payload, indent=2))
    else:
        print(render(result, args.new))
    return min(len(result["introduced"]), 250)


if __name__ == "__main__":
    sys.exit(main())
