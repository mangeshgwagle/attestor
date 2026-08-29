#!/usr/bin/env python3
"""Rewrite Attestor's findings into the shape a task asked for.

Why this is a file and not a `-c` one-liner
-------------------------------------------
It used to be one. The agent adapter delivers commands by *typing them into a
tmux session*, so every newline in a `python -c` script arrives as an Enter
keypress and the shell receives the thing in pieces. Rewriting it as a single
physical line fixed that and it still failed, because a 500-character line
typed into a terminal has its own problems -- wrapping, quoting, and the pane
capture losing track of what was echoed.

A file has none of those failure modes. It is copied in beside the detector and
invoked with four plain arguments.

Faithfulness
------------
Every finding of the requested class survives, whichever file it names.
Filtering out findings on files the task expects to be clean would manufacture
precision Attestor has not earned -- and the negative control in those tasks exists
precisely to catch a tool that reports everything.
"""
from __future__ import annotations

import json
import sys


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print("usage: tb_report.py <detector-dir> <findings.json> <out.json> "
              "[cwe]", file=sys.stderr)
        return 2
    detector, findings_path, out_path = argv[1], argv[2], argv[3]
    want = argv[4] if len(argv) > 4 else ""

    sys.path.insert(0, detector)
    import detect

    try:
        with open(findings_path, encoding="utf-8") as handle:
            rows = json.load(handle)
    except (OSError, ValueError) as error:
        print("could not read %s: %s" % (findings_path, error), file=sys.stderr)
        # An empty report is still a report: the task should fail on the
        # findings, not on a missing file that hides why.
        rows = []

    if isinstance(rows, dict):
        rows = rows.get("findings", [])

    out = []
    for finding in rows:
        if not isinstance(finding, dict):
            continue
        cwe = detect.RULE_CWE.get(finding.get("rule"), "")
        if want and cwe != want:
            continue
        path = str(finding.get("path", "")).replace("\\", "/").rsplit("/", 1)[-1]
        out.append({"path": path, "line": finding.get("line"), "cwe": cwe})

    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(out, handle)
    print("wrote %d finding(s) to %s" % (len(out), out_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
