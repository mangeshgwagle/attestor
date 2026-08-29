#!/usr/bin/env python3
"""
grade.py -- Attestor's verdict: one letter, backed by every engine.

detect.py finds bugs by regex, deepscan.py finds them by AST, metrics.py measures
how hard the code is to maintain (cyclomatic *and* cognitive complexity). grade.py
fuses all three into the single answer a lead actually wants: *how strong is this
code, and what do I fix first?*

Per file it computes a 0-100 score and an A-F grade from:
  - static findings (detect + deepscan), weighted by severity, and
  - functions over the cyclomatic / cognitive / size limits,
then prints a ranked, do-this-first list. The exit code is the number of files
below the pass grade, so CI can gate: "nothing ships below a B".

    python3 grade.py app.py                 # one file, full breakdown
    python3 grade.py src/ --pass B          # gate a tree at B or better
    python3 grade.py src/ --json            # machine-readable

(An earlier build reported a Halstead maintainability index too; it was dropped
because that formula conflates file size with quality -- it scored clean,
well-factored modules "unmaintainable" purely for being long, which is the exact
false alarm Attestor refuses to raise. Cognitive complexity carries that signal
honestly instead.)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass

import deepscan
import detect
import metrics
import rarebugs

SEVERITY_PENALTY = {"HIGH": 15, "MEDIUM": 6, "LOW": 2}
SEVERITY_SCORE_CAP = {"HIGH": 69}
SYNTAX_ERROR_SCORE_CAP = 49
# Penalty per over-threshold function, by which limit it blew.
COMPLEXITY_PENALTY = {"cognitive": 5, "complexity": 3, "length": 2, "nesting": 2, "args": 2}
# Maintainability is the secondary axis: complexity alone caps its damage here, so
# a bug-free but complex file bottoms out around a D. Reaching F takes real
# findings -- correctness dominates the grade, exactly as a reviewer weighs it.
COMPLEXITY_PENALTY_CAP = 35
GRADE_BANDS = ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F"))


@dataclass
class FileGrade:
    path: str
    score: int
    grade: str
    findings_high: int
    findings_medium: int
    findings_low: int
    worst_cognitive: int
    worst_cyclomatic: int
    functions: int
    over_threshold: int


def letter(score: int) -> str:
    for cutoff, name in GRADE_BANDS:
        if score >= cutoff:
            return name
    return "F"


def _rank(name: str) -> int:
    order = "FDCBA"
    return order.index(name) if name in order else 0


def _detect_findings(path: str) -> list:
    """Regex-engine findings for a real file. Grading a bare snippet passes a
    placeholder path with no file behind it, so the regex engine is skipped and
    only the AST engine runs -- an explicit skip, not a swallowed error."""
    try:
        return detect.scan_file(path)
    except OSError:
        return []


def _static_findings(src: str, path: str) -> list:
    """detect + deepscan + rarebugs findings, deduped by (line, rule)."""
    seen = set()
    unique = []
    for finding in _detect_findings(path) + deepscan.analyze(src, path) + rarebugs.analyze(src, path):
        key = (finding.line, finding.rule)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def _score(findings: list, funcs: list, limits: dict) -> int:
    finding_penalty = sum(SEVERITY_PENALTY.get(f.severity, 2) for f in findings)
    complexity_penalty = 0
    for metric in funcs:
        for limit in metric.exceeded(limits):
            complexity_penalty += COMPLEXITY_PENALTY.get(limit, 2)
    score = max(0, 100 - finding_penalty - min(complexity_penalty, COMPLEXITY_PENALTY_CAP))
    if any(f.rule == "syntax-error" for f in findings):
        return min(score, SYNTAX_ERROR_SCORE_CAP)
    if any(f.severity == "HIGH" for f in findings):
        score = min(score, SEVERITY_SCORE_CAP["HIGH"])
    return score


def grade_source(src: str, path: str, limits: dict) -> tuple:
    """Return (FileGrade, findings, funcs) for one file's source."""
    findings = _static_findings(src, path)
    funcs = metrics.analyze_source(src, path)
    score = _score(findings, funcs, limits)
    sev = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        sev[finding.severity] = sev.get(finding.severity, 0) + 1
    over = [m for m in funcs if m.exceeded(limits)]
    fg = FileGrade(
        path=path, score=score, grade=letter(score),
        findings_high=sev["HIGH"], findings_medium=sev["MEDIUM"], findings_low=sev["LOW"],
        worst_cognitive=max((m.cognitive for m in funcs), default=0),
        worst_cyclomatic=max((m.complexity for m in funcs), default=0),
        functions=len(funcs), over_threshold=len(over))
    return fg, findings, funcs


def improvements(findings: list, funcs: list, limits: dict, top: int = 6) -> list:
    """The highest-impact fixes first: serious findings, then the gnarliest funcs."""
    sev_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    items = ["[%s] %s at %s:%d" % (f.severity, f.rule, f.path, f.line)
             for f in sorted(findings, key=lambda x: sev_rank.get(x.severity, 3))
             if f.severity in ("HIGH", "MEDIUM")]
    gnarly = sorted((m for m in funcs if m.exceeded(limits)),
                    key=lambda x: (x.cognitive, x.complexity), reverse=True)
    items += ["split %s (cognitive %d, cyclomatic %d) at %s:%d"
              % (m.qualname, m.cognitive, m.complexity, m.path, m.line) for m in gnarly]
    return items[:top]


def _bar(score: int) -> str:
    filled = round(score / 5)
    return "[" + "#" * filled + "-" * (20 - filled) + "]"


def _format_file(fg: FileGrade, tips: list) -> str:
    lines = ["%s  %s  %d/100  %s" % (fg.grade, _bar(fg.score), fg.score, fg.path),
             "  findings: %d high, %d medium, %d low   |   worst function: "
             "cognitive %d, cyclomatic %d   |   %d/%d over threshold"
             % (fg.findings_high, fg.findings_medium, fg.findings_low,
                fg.worst_cognitive, fg.worst_cyclomatic, fg.over_threshold, fg.functions)]
    if tips:
        lines.append("  fix first:")
        lines += ["    - " + t for t in tips]
    return "\n".join(lines)


def _read(path: str, errors: list[str] | None = None):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError as exc:
        message = "%s: cannot read: %s" % (path, exc)
        if errors is None:
            print("grade error: " + message, file=sys.stderr)
        else:
            errors.append(message)
        return None


def _python_paths(paths, errors: list[str]) -> list[str]:
    out = []
    for path in paths:
        if os.path.isdir(path):
            out.extend(metrics.collect_paths([path]))
        elif os.path.isfile(path):
            if path.lower().endswith((".py", ".pyw")):
                out.append(path)
            else:
                errors.append("%s: unsupported input type" % path)
        else:
            errors.append("%s: path does not exist" % path)
    return out


def collect(paths, limits: dict = None, top: int = 6,
            errors: list[str] | None = None) -> list:
    """Grade every .py under `paths`, worst score first: [(FileGrade, tips), ...]."""
    limits = limits or metrics.DEFAULT_LIMITS
    graded = []
    own_errors = errors if errors is not None else []
    for path in _python_paths(paths, own_errors):
        src = _read(path, own_errors)
        if src is None:
            continue
        fg, findings, funcs = grade_source(src, path, limits)
        graded.append((fg, improvements(findings, funcs, limits, top)))
    graded.sort(key=lambda pair: pair[0].score)
    if errors is None:
        for message in own_errors:
            print("grade error: " + message, file=sys.stderr)
    return graded


def failures(graded: list, passing: str) -> list:
    return [fg for fg, _ in graded if _rank(fg.grade) < _rank(passing)]


def render(graded: list, passing: str = "C") -> str:
    lines = []
    for fg, tips in graded:
        lines.append(_format_file(fg, tips))
        lines.append("")
    if graded:
        avg = round(sum(fg.score for fg, _ in graded) / len(graded))
        worst = min((fg.grade for fg, _ in graded), key=_rank)
        lines.append("%d file(s): average %d/100, worst grade %s. %d below %s."
                     % (len(graded), avg, worst, len(failures(graded, passing)), passing))
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="Python files or directories")
    ap.add_argument("--pass", dest="passing", default="C", choices=["A", "B", "C", "D", "F"],
                    help="minimum grade a file must earn (default C); exit code counts failures")
    ap.add_argument("--top", type=int, default=6, help="max 'fix first' items per file")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    errors = []
    graded = collect(args.paths, top=args.top, errors=errors)
    if not graded and not errors:
        errors.append("no Python source files were found")
    for message in errors:
        print("grade error: " + message, file=sys.stderr)
    if args.json:
        print(json.dumps([{**asdict(fg), "fix_first": tips} for fg, tips in graded], indent=2))
    else:
        print(render(graded, args.passing))
    return 2 if errors else min(len(failures(graded, args.passing)), 250)


if __name__ == "__main__":
    sys.exit(main())
