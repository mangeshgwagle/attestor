#!/usr/bin/env python3
"""
nativegrade.py -- one letter for C / C++ / Assembly, backed by every native engine.

The C-family cousin of grade.py. It fuses nativescan.py (the long bug net),
polyglot.py (the curated tiny-error net), and nativemetrics.py (cyclomatic +
cognitive complexity) into a single 0-100 score and A-F grade per file, plus a
ranked, do-this-first list. Correctness dominates: real findings can sink a file
to F, while complexity alone caps out around a D. Exit code = files below the pass
grade, so CI can gate a whole native tree in one command.

    python3 nativegrade.py engine.c parser.cpp
    python3 nativegrade.py src/ --pass B
    python3 nativegrade.py src/ --json
"""
from __future__ import annotations

import argparse
import functools
import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

import nativemetrics
import nativepool
import nativescan
import polyglot

SEVERITY_PENALTY = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 6, "LOW": 2, "INFO": 1}
SEVERITY_SCORE_CAP = {"CRITICAL": 49, "HIGH": 69, "MEDIUM": 79}
COMPLEXITY_PENALTY = {"cognitive": 5, "cyclomatic": 3, "length": 2, "nesting": 2}
COMPLEXITY_PENALTY_CAP = 35
GRADE_BANDS = ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F"))


@dataclass
class FileGrade:
    path: str
    score: int
    grade: str
    critical: int
    high: int
    medium: int
    low_info: int
    worst_cognitive: int
    worst_cyclomatic: int
    functions: int
    over_threshold: int
    compiler_verified: bool
    compiler: str
    compile_status: str


def letter(score: int) -> str:
    for cutoff, name in GRADE_BANDS:
        if score >= cutoff:
            return name
    return "F"


def _rank(name: str) -> int:
    order = "FDCBA"
    return order.index(name) if name in order else 0


def _norm(finding) -> tuple:
    """(line, rule, severity, message) from either scanner's Finding shape."""
    message = getattr(finding, "message", None) or getattr(finding, "detail", "")
    return (finding.line, finding.rule, finding.severity, message)


def _findings(path: str) -> list:
    seen = set()
    out = []
    for finding in nativescan.scan_file(path) + polyglot.scan_file(Path(path)):
        line, rule, severity, message = _norm(finding)
        key = (line, rule)
        if key not in seen:
            seen.add(key)
            out.append((line, rule, severity, message))
    return out


def _compiler_check(path: str) -> tuple[str, str, str]:
    """Return (status, compiler, detail) after a non-executing syntax check."""
    lang = nativescan.language_for(path)
    if lang not in ("c", "cpp"):
        return "unavailable", "", "no -fsyntax-only verifier is configured for assembly"
    names = ("g++", "clang++", "c++") if lang == "cpp" else ("gcc", "clang", "cc")
    compiler = next((shutil.which(name) for name in names if shutil.which(name)), None)
    if not compiler:
        return "unavailable", "", "no GCC/Clang compiler was found on PATH"
    command = [compiler, "-fsyntax-only", "-x", "c++" if lang == "cpp" else "c",
               os.path.abspath(path)]
    try:
        run = subprocess.run(
            command, cwd=os.path.dirname(os.path.abspath(path)) or None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            errors="replace", timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "unavailable", compiler, "%s: %s" % (type(exc).__name__, exc)
    if run.returncode == 0:
        return "verified", compiler, "compiler accepted the source with -fsyntax-only"
    output = (run.stderr or run.stdout or "compiler rejected the source").strip()
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    detail = next((line for line in lines if "error:" in line.lower()),
                  lines[0] if lines else output)
    return "failed", compiler, detail[:500]


def _score(findings: list, funcs: list, limits: dict) -> int:
    finding_penalty = sum(SEVERITY_PENALTY.get(sev, 2) for _l, _r, sev, _m in findings)
    complexity_penalty = 0
    for metric in funcs:
        for limit in metric.exceeded(limits):
            complexity_penalty += COMPLEXITY_PENALTY.get(limit, 2)
    score = max(0, 100 - finding_penalty - min(complexity_penalty, COMPLEXITY_PENALTY_CAP))
    for severity in ("CRITICAL", "HIGH", "MEDIUM"):
        if any(sev == severity for _l, _r, sev, _m in findings):
            score = min(score, SEVERITY_SCORE_CAP[severity])
            break
    return score


def grade_file(path: str) -> tuple:
    findings = _findings(path)
    compile_status, compiler, compile_detail = _compiler_check(path)
    if compile_status == "failed":
        findings.append((1, "native-compile-error", "CRITICAL", compile_detail))
    elif compile_status != "verified":
        findings.append((1, "native-compile-unverified", "MEDIUM", compile_detail))
    funcs = nativemetrics.analyze_file(path)
    limits = nativemetrics.DEFAULT_LIMITS
    score = _score(findings, funcs, limits)
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for _l, _r, sev, _m in findings:
        counts[sev] = counts.get(sev, 0) + 1
    over = [m for m in funcs if m.exceeded(limits)]
    fg = FileGrade(
        path=path, score=score, grade=letter(score),
        critical=counts["CRITICAL"], high=counts["HIGH"], medium=counts["MEDIUM"],
        low_info=counts["LOW"] + counts["INFO"],
        worst_cognitive=max((m.cognitive for m in funcs), default=0),
        worst_cyclomatic=max((m.cyclomatic for m in funcs), default=0),
        functions=len(funcs), over_threshold=len(over),
        compiler_verified=compile_status == "verified",
        compiler=os.path.basename(compiler) if compiler else "",
        compile_status=compile_status)
    return fg, findings, funcs


def improvements(findings: list, funcs: list, top: int = 6) -> list:
    limits = nativemetrics.DEFAULT_LIMITS
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    serious = sorted((f for f in findings if f[2] in ("CRITICAL", "HIGH", "MEDIUM")),
                     key=lambda f: order.get(f[2], 5))
    items = ["[%s] %s at line %d" % (sev, rule, line) for line, rule, sev, _m in serious]
    gnarly = sorted((m for m in funcs if m.exceeded(limits)),
                    key=lambda m: (m.cognitive, m.cyclomatic), reverse=True)
    items += ["split %s (cognitive %d, cyclomatic %d) at line %d"
              % (m.name, m.cognitive, m.cyclomatic, m.line) for m in gnarly]
    return items[:top]


def _grade_pair(path: str, top: int = 6) -> tuple:
    """Top-level (picklable) worker for the process pool: path -> (FileGrade, tips)."""
    fg, findings, funcs = grade_file(path)
    return fg, improvements(findings, funcs, top)


def collect(paths, top: int = 6, jobs: int = 1,
            errors: list[str] | None = None) -> list:
    own_errors = errors if errors is not None else []
    files = nativescan.collect_paths(paths, own_errors)
    worker = functools.partial(_grade_pair, top=top)
    graded = list(nativepool.pmap(worker, files, jobs))
    graded.sort(key=lambda pair: pair[0].score)
    if errors is None:
        for message in own_errors:
            print("grade error: " + message, file=sys.stderr)
    return graded


def failures(graded: list, passing: str) -> list:
    return [fg for fg, _ in graded if _rank(fg.grade) < _rank(passing)]


def _bar(score: int) -> str:
    filled = round(score / 5)
    return "[" + "#" * filled + "-" * (20 - filled) + "]"


def _format_file(fg: FileGrade, tips: list) -> str:
    lines = ["%s  %s  %d/100  %s" % (fg.grade, _bar(fg.score), fg.score, fg.path),
             "  findings: %d critical, %d high, %d medium, %d low/info   |   "
             "worst function: cognitive %d, cyclomatic %d   |   %d/%d over threshold"
             % (fg.critical, fg.high, fg.medium, fg.low_info,
                fg.worst_cognitive, fg.worst_cyclomatic, fg.over_threshold, fg.functions),
             "  compile: %s%s" % (fg.compile_status,
                                    " via " + fg.compiler if fg.compiler else "")]
    if tips:
        lines.append("  fix first:")
        lines += ["    - " + t for t in tips]
    return "\n".join(lines)


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
    ap.add_argument("paths", nargs="+", help="C/C++/Assembly files or directories")
    ap.add_argument("--pass", dest="passing", default="C", choices=["A", "B", "C", "D", "F"],
                    help="minimum grade a file must earn (default C); exit code counts failures")
    ap.add_argument("--top", type=int, default=6, help="max 'fix first' items per file")
    ap.add_argument("--jobs", type=int, default=1,
                    help="parallel worker processes (0 = all cores)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    errors = []
    graded = collect(args.paths, args.top, args.jobs, errors=errors)
    if not graded and not errors:
        errors.append("no native source files were found")
    for message in errors:
        print("grade error: " + message, file=sys.stderr)
    if args.json:
        print(json.dumps([{**asdict(fg), "fix_first": tips} for fg, tips in graded], indent=2))
    else:
        print(render(graded, args.passing))
    return 2 if errors else min(len(failures(graded, args.passing)), 250)


if __name__ == "__main__":
    sys.exit(main())
