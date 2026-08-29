#!/usr/bin/env python3
"""
reproducer.py -- make the smallest runnable proof for an Attestor finding.

Given source code and a finding, Attestor keeps deleting lines while the same rule is
still detected. The result is a tiny bug file plus a plain unittest that proves
the detector catches it. This is for debugging rules, filing reports, and feeding
Patch Forge with a concrete failing case.
"""
from __future__ import annotations

import argparse
import ast
import os

import detect
import harvest


def _ext(path: str) -> str:
    return os.path.splitext(path)[1].lower() or ".py"


def _has_rule(source: str, ext: str, rule: str) -> bool:
    try:
        if ext in (".py", ".pyw") and rule != "syntax-error":
            ast.parse(source)
        return any(f.rule == rule for f in harvest.scan_content(source, ext))
    except Exception:                           # noqa: BLE001 -- invalid shrink, keep searching
        return False


def minimize(source: str, ext: str, rule: str) -> str:
    """Greedy line minimizer that preserves the target rule."""
    if not _has_rule(source, ext, rule):
        return source
    lines = source.splitlines()
    changed = True
    while changed and len(lines) > 1:
        changed = False
        for i in range(len(lines)):
            trial = lines[:i] + lines[i + 1:]
            text = "\n".join(trial) + "\n"
            if text.strip() and _has_rule(text, ext, rule):
                lines = trial
                changed = True
                break
    text = "\n".join(lines)
    return text + ("\n" if text else "")


def make(source: str, path: str, finding) -> dict:
    ext = _ext(path)
    tiny = minimize(source, ext, finding.rule)
    bug_name = "repro_" + finding.rule.replace("-", "_") + ext
    test_name = "test_repro_" + finding.rule.replace("-", "_") + ".py"
    test_source = (
        "import os\n"
        "import unittest\n"
        "import detect\n\n\n"
        "class Reproducer(unittest.TestCase):\n"
        "    def test_%s_is_detected(self):\n"
        "        here = os.path.dirname(__file__)\n"
        "        path = os.path.join(here, %r)\n"
        "        rules = {f.rule for f in detect.scan_file(path, deep=True)}\n"
        "        self.assertIn(%r, rules)\n\n\n"
        "if __name__ == '__main__':\n"
        "    unittest.main(verbosity=2)\n"
    ) % (finding.rule.replace("-", "_"), bug_name, finding.rule)
    return {
        "rule": finding.rule,
        "severity": finding.severity,
        "original_path": path,
        "bug_file": bug_name,
        "test_file": test_name,
        "bug_source": tiny,
        "test_source": test_source,
        "command": "python %s" % test_name,
    }


def first_for_file(path: str) -> dict | None:
    with open(path, encoding="utf-8", errors="replace") as fh:
        source = fh.read()
    findings = harvest.scan_content(source, _ext(path))
    if not findings:
        return None
    findings.sort(key=detect.Finding.sort_key)
    return make(source, path, findings[0])


def write(repro: dict, out_dir: str) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    bug_path = os.path.join(out_dir, repro["bug_file"])
    test_path = os.path.join(out_dir, repro["test_file"])
    with open(bug_path, "w", encoding="utf-8") as fh:
        fh.write(repro["bug_source"])
    with open(test_path, "w", encoding="utf-8") as fh:
        fh.write(repro["test_source"])
    return [bug_path, test_path]


def render(repro: dict | None) -> str:
    if repro is None:
        return "Bug Reproducer: no finding to reproduce."
    lines = [
        "Bug Reproducer for %s" % repro["rule"],
        "=" * (19 + len(repro["rule"])),
        "original: %s" % repro["original_path"],
        "bug file: %s" % repro["bug_file"],
        "test file: %s" % repro["test_file"],
        "run: %s" % repro["command"],
        "",
        repro["bug_source"].rstrip(),
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", help="source file with at least one Attestor finding")
    ap.add_argument("--out-dir", default="attestor_reproducer")
    args = ap.parse_args(argv)

    repro = first_for_file(args.file)
    print(render(repro))
    if repro is None:
        return 1
    written = write(repro, args.out_dir)
    print("\nwrote reproducer:")
    for path in written:
        print("  " + path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
