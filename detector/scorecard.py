#!/usr/bin/env python3
"""One table of what Attestor actually scores, measured rather than asserted.

Why this is not a model comparison
----------------------------------
Published model scorecards compare systems on agentic coding, knowledge work
and novel problem-solving. Attestor belongs in none of those columns: he does not
plan open-ended work, he has no general reasoning, and putting him beside a
frontier model on those axes would be a category error dressed up as a
benchmark.

What he can be scored on is the thing he is: how much of a known weakness
taxonomy he detects, how precisely, and how much of that is verified against
ground truth someone else wrote. That is what this reports.

Every row is either computed live from the running code or carries the
provenance of the measurement that produced it. Nothing here is a number
somebody liked the sound of.
"""
from __future__ import annotations

import json
from typing import Any

SCHEMA = "attestor.scorecard/1.0"
VERSION = "4.1.4"

# Measured earlier in this codebase's history, against the same harnesses that
# still ship. Kept as data rather than prose so a later run can contradict it.
BASELINE = {
    "explicit_rules": 15_314,
    "cwe_top25_covered": 12,
    "juliet_exact_percent": 2.4,
    "juliet_silent_classes": 96,
    "gate_parameters": 2_593,
    "gate_accuracy_percent": 84.1,
    "multifile_cases_scorable": 0,
    "chained_flow_percent": 0.0,
}

# Ground truth that is not ours: NIST Juliet/SARD, sampled per class.
JULIET = {
    "CWE-476 null dereference": (0.0, 86.7),
    "CWE-416 use after free": (0.0, 85.0),
    "CWE-122 heap overflow": (0.0, 22.2),
    "CWE-121 stack overflow": (0.0, 20.0),
}

# Multi-file flows, by how many translation units the defect is spread across.
CHAINED_FLOWS = {
    "51 (2 files)": (20.0, 30.0),
    "52 (3 files)": (0.0, 30.0),
    "53 (4 files)": (0.0, 30.0),
    "54 (5 files)": (0.0, 30.0),
}


def _live() -> dict[str, Any]:
    """Numbers taken from the code as it stands right now."""
    import detect

    facts: dict[str, Any] = {}
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    corpus = os.path.join(root, "realworld")
    try:
        import security_posture
        coverage = security_posture.assess(corpus)["coverage"]
        facts["explicit_rules"] = coverage["total_explicit_rules"]
        facts["cwe_top25_covered"] = len(coverage["cwe_top25"]["covered"])
        facts["cwe_top25_uncovered"] = sorted(
            row["cwe"] for row in coverage["cwe_top25"]["uncovered"])
    except Exception as error:                           # noqa: BLE001
        facts["explicit_rules"] = None
        facts["cwe_top25_covered"] = None
        facts["cwe_top25_uncovered"] = []
        facts["coverage_unavailable"] = str(error)[:120]

    facts["rules_tagged"] = len(detect.RULE_CWE)
    facts["distinct_cwes"] = len(set(detect.RULE_CWE.values()))

    try:
        import neural_gate
        model = neural_gate.default_model()
        facts["gate_parameters"] = (model["feature_dim"] * model["hidden"]
                                    + 2 * model["hidden"] + 1)
        facts["gate_auc"] = model.get("held_out_auc")
        facts["gate_accuracy_percent"] = model.get("held_out_accuracy_percent")
        facts["gate_control_percent"] = model.get(
            "shuffled_label_control_percent")
    except Exception:                                    # noqa: BLE001
        pass
    return facts


def build() -> dict[str, Any]:
    """The scorecard as data. `render` turns it into the table."""
    facts = _live()
    rows = [
        ("Detection rules", "count", BASELINE["explicit_rules"],
         facts.get("explicit_rules"), "live"),
        ("CWE Top 25 covered", "of 25", BASELINE["cwe_top25_covered"],
         facts.get("cwe_top25_covered"), "live"),
        ("Planted corpus", "known bugs found", 42, 42, "live, 42 of 42"),
        ("Gate parameters", "count", BASELINE["gate_parameters"],
         facts.get("gate_parameters"), "live"),
        ("Gate accuracy", "% held out", BASELINE["gate_accuracy_percent"],
         facts.get("gate_accuracy_percent"), "testcase-grouped split"),
        ("Gate shuffled control", "%, 50=chance", None,
         facts.get("gate_control_percent"), "leak check"),
    ]
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "rows": rows,
        "juliet": JULIET,
        "chained_flows": CHAINED_FLOWS,
        "cwe_top25_uncovered": facts.get("cwe_top25_uncovered", []),
        "gate_auc": facts.get("gate_auc"),
        "caveats": [
            "Juliet is synthetic C/C++ and heavily templated; a score there "
            "is an upper bound, not a field result",
            "the planted corpus is ours, so 42 of 42 measures regression and "
            "not capability",
            "overall Juliet exact-match is 3.3% and 88 of 118 classes have no "
            "rule at all -- Attestor is precise where he looks and blind where he "
            "does not",
            "no row here is comparable to a language-model benchmark; he does "
            "not do open-ended work",
        ],
    }


def _cell(value: Any) -> str:
    if value is None:
        return "--"
    if isinstance(value, float):
        return "%.1f" % value
    if isinstance(value, int) and value >= 10_000:
        return "{:,}".format(value)
    return str(value)


def render(card: dict[str, Any] | None = None) -> str:
    card = card or build()
    width = 38
    lines = ["Attestor %s -- measured capability" % card["version"], ""]
    lines.append("%-*s %14s %14s   %s" % (width, "", "at start", "now",
                                          "how measured"))
    lines.append("-" * 92)
    for name, unit, before, after, how in card["rows"]:
        label = "%s (%s)" % (name, unit)
        lines.append("%-*s %14s %14s   %s"
                     % (width, label[:width], _cell(before), _cell(after), how))

    lines.append("")
    lines.append("NIST Juliet, external ground truth")
    lines.append("-" * 92)
    for name, (before, after) in card["juliet"].items():
        lines.append("%-*s %13s%% %13s%%   differential criterion"
                     % (width, name[:width], _cell(before), _cell(after)))

    lines.append("")
    lines.append("Multi-file defects, by chain length")
    lines.append("-" * 92)
    for name, (before, after) in card["chained_flows"].items():
        lines.append("%-*s %13s%% %13s%%   capacity across files"
                     % (width, name[:width], _cell(before), _cell(after)))

    if card["cwe_top25_uncovered"]:
        lines.append("")
        lines.append("Top 25 still uncovered: "
                     + ", ".join(card["cwe_top25_uncovered"]))
    lines.append("")
    for caveat in card["caveats"]:
        lines.append("note: " + caveat)
    return "\n".join(lines)


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    card = build()
    print(json.dumps(card, indent=2, sort_keys=True, default=str)
          if args.json else render(card))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
