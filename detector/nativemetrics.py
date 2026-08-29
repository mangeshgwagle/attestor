#!/usr/bin/env python3
"""
nativemetrics.py -- complexity for C, C++, and Assembly, the way metrics.py does Python.

No compiler and no parser: it blanks comments and string/char literals (reusing
detect.blank_c_like), matches braces to find function/method bodies (labels for
assembly), and counts the decision points inside each. Two numbers per function:

  - cyclomatic complexity -- 1 + each branch: if / for / while / case / catch /
    goto, plus every && and || and every ?: ternary. (else adds no new path.)
  - cognitive complexity  -- SonarSource-style: a branch nested inside others
    costs more, so a pyramid of ifs scores far above a flat sequence with the
    same cyclomatic number. This is the sharper reviewer's-eye signal.

Also length (source lines) and max nesting depth. Approximate by design -- it is a
fast estimate, not a C frontend -- but it flags the functions a human should split
before they rot, exactly like the Python engine. Exit code = functions over the
limits, so CI can gate on it.

    python3 nativemetrics.py engine.c core.cpp        # per-function report
    python3 nativemetrics.py src/ --max-cognitive 12  # stricter, recurse a tree
    python3 nativemetrics.py boot.s --json            # machine-readable
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass

import detect
import nativepool

DEFAULT_LIMITS = {"cyclomatic": 10, "cognitive": 15, "length": 60, "nesting": 4}

SUFFIX_LANG = {
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hh": "cpp", ".hpp": "cpp", ".hxx": "cpp",
    ".s": "asm", ".S": "asm", ".asm": "asm", ".nasm": "asm",
}
SKIP_DIRS = {".git", ".hg", ".svn", "build", "dist", "target", "node_modules"}

_CONTROL = ("if", "for", "while", "case", "catch", "goto")
_CONTROL_SET = set(_CONTROL) | {"switch", "else", "do", "return", "sizeof"}
# A function/method header: ends with NAME(params) + optional C++ qualifiers.
# The qualifier run and the trailing-return run are kept in separate groups on
# purpose.  Folding them into one alternation lets '\s' be matched either by its
# own branch or inside the trailing-return character class, so a header such as
# "f() -> a -> a -> a ... =" can be split exponentially many ways and hangs the
# backtracking engine.  No branch below shares a first character with another,
# and '-' is outside [\w:<>,*&\s], so every split point here is forced.
_FUNC_HEADER = re.compile(
    r"([A-Za-z_]\w*)\s*\([^;{}]*\)"
    r"(?:const|noexcept|override|final|mutable|volatile|\s)*"
    r"(?:->[\w:<>,*&\s]+)*$")
# Conditional branch mnemonics across x86, ARM, MIPS, RISC-V, 68k.
_ASM_BRANCH = re.compile(
    r"^\s*(?:j(?:e|ne|z|nz|g|ge|l|le|a|ae|b|be|s|ns|o|no|c|nc|p|np|cxz)|"
    r"b(?:eq|ne|lt|le|gt|ge|hi|ls|mi|pl|vs|vc|cc|cs|cond|nz|z)|"
    r"cbz|cbnz|tbz|tbnz|loop\w*|bc\w+)\b", re.I)
_ASM_LABEL = re.compile(r"^([A-Za-z_.$][\w.$]*)\s*:")


@dataclass
class FuncMetric:
    path: str
    name: str
    line: int
    language: str
    cyclomatic: int
    cognitive: int
    length: int
    nesting: int

    def exceeded(self, limits: dict) -> list[str]:
        over = []
        if self.cyclomatic > limits["cyclomatic"]:
            over.append("cyclomatic")
        if self.cognitive > limits["cognitive"]:
            over.append("cognitive")
        if self.length > limits["length"]:
            over.append("length")
        if self.nesting > limits["nesting"]:
            over.append("nesting")
        return over


# --------------------------------------------------------------------------- #
# C / C++
# --------------------------------------------------------------------------- #
def _header_name(header: str):
    """The callable a '{'-opening header names, or None if it isn't a function."""
    match = _FUNC_HEADER.search(header)
    if match and match.group(1) not in _CONTROL_SET:
        return match.group(1)
    return None


def _pop_body(stack: list, bodies: list, i: int, line: int, blanked: str) -> None:
    if not stack:
        return
    open_i, open_line, name = stack.pop()
    if name is not None:
        bodies.append((name, open_line, line, blanked[open_i:i + 1]))


def _c_bodies(blanked: str):
    """(name, start_line, end_line, body_text) per function/method body. Brace
    matching on blanked code; a body is a '{...}' whose header names a callable."""
    stack = []
    bodies = []
    line = 1
    seg_start = 0
    for i, ch in enumerate(blanked):
        if ch == "\n":
            line += 1
        elif ch == "{":
            stack.append((i, line, _header_name(blanked[seg_start:i])))
            seg_start = i + 1
        elif ch == "}":
            _pop_body(stack, bodies, i, line, blanked)
            seg_start = i + 1
        elif ch == ";":
            seg_start = i + 1
    return bodies


def _depth_at(body: str) -> list:
    """Brace depth in front of each character (function body top level = 0)."""
    depths = []
    depth = -1                      # the body's own opening brace lifts us to 0
    for ch in body:
        if ch == "{":
            depths.append(max(depth, 0))
            depth += 1
        elif ch == "}":
            depth -= 1
            depths.append(max(depth, 0))
        else:
            depths.append(max(depth, 0))
    return depths


def _c_cyclomatic(body: str) -> int:
    count = 1
    for keyword in _CONTROL:
        count += len(re.findall(r"\b" + keyword + r"\b", body))
    count += body.count("&&") + body.count("||")
    count += len(re.findall(r"\?[^:]", body))         # ternary, roughly
    return count


def _c_cognitive(body: str) -> int:
    depths = _depth_at(body)
    total = 0
    for match in re.finditer(r"\b(?:if|for|while|case|catch)\b", body):
        total += 1 + depths[match.start()]
    total += body.count("&&") + body.count("||")
    return total


def _c_nesting(body: str) -> int:
    depths = _depth_at(body)
    return max(depths) if depths else 0


def _analyze_c(text: str, path: str, lang: str) -> list:
    blanked = "\n".join(detect.blank_c_like(text))
    out = []
    for name, start, end, body in _c_bodies(blanked):
        out.append(FuncMetric(path, name, start, lang,
                              _c_cyclomatic(body), _c_cognitive(body),
                              end - start + 1, _c_nesting(body)))
    return out


# --------------------------------------------------------------------------- #
# Assembly -- "functions" are labels; complexity is conditional branching.
# --------------------------------------------------------------------------- #
def _analyze_asm(text: str, path: str) -> list:
    lines = text.splitlines()
    labels = []
    for idx, raw in enumerate(lines, start=1):
        stripped = re.split(r"[;#]", raw, maxsplit=1)[0]
        match = _ASM_LABEL.match(stripped)
        if match:
            labels.append((match.group(1), idx))
    out = []
    for pos, (name, start) in enumerate(labels):
        end = labels[pos + 1][1] - 1 if pos + 1 < len(labels) else len(lines)
        span = lines[start:end]
        branches = sum(1 for ln in span if _ASM_BRANCH.match(re.split(r"[;#]", ln, maxsplit=1)[0]))
        out.append(FuncMetric(path, name, start, "asm",
                              1 + branches, branches, max(end - start + 1, 1), 0))
    return out


def analyze_text(text: str, path: str, lang: str) -> list:
    if lang in ("c", "cpp"):
        return _analyze_c(text, path, lang)
    if lang == "asm":
        return _analyze_asm(text, path)
    return []


def language_for(path: str) -> str:
    return SUFFIX_LANG.get(os.path.splitext(path)[1], "")


def analyze_file(path: str) -> list:
    lang = language_for(path)
    if not lang:
        return []
    with open(path, encoding="utf-8", errors="replace") as fh:
        return analyze_text(fh.read(), path, lang)


def collect_paths(paths) -> list:
    out = []
    for raw in paths:
        if os.path.isdir(raw):
            for root, dirs, files in os.walk(raw):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                out += [os.path.join(root, f) for f in sorted(files) if language_for(f)]
        elif language_for(raw) or os.path.isfile(raw):
            out.append(raw)
    return out


def _fmt(metrics: list, limits: dict, top: int) -> str:
    if top:
        shown = sorted(metrics, key=lambda m: (m.cognitive, m.cyclomatic), reverse=True)[:top]
        title = "top %d by cognitive complexity" % top
    else:
        shown = sorted((m for m in metrics if m.exceeded(limits)),
                       key=lambda m: (m.cognitive, m.cyclomatic), reverse=True)
        title = "functions over threshold"
    if not shown:
        return "no functions over threshold (%d measured)." % len(metrics)
    lines = [title, "=" * 70,
             "  %-30s %4s %4s %4s %4s %4s" % ("function", "lng", "cyc", "cog", "len", "nst")]
    for m in shown:
        over = set(m.exceeded(limits))

        def mark(name, value, over=over):
            return ("%d*" % value) if name in over else str(value)

        where = "%s:%d %s" % (os.path.basename(m.path), m.line, m.name)
        lines.append("  %-30s %4s %4s %4s %4s %4s" % (
            where[:30], m.language, mark("cyclomatic", m.cyclomatic),
            mark("cognitive", m.cognitive), mark("length", m.length),
            mark("nesting", m.nesting)))
    lines.append("  (* = over limit; cyc=cyclomatic cog=cognitive len=lines nst=nesting)")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="C/C++/Assembly files or directories")
    ap.add_argument("--max-cyclomatic", type=int, default=DEFAULT_LIMITS["cyclomatic"])
    ap.add_argument("--max-cognitive", type=int, default=DEFAULT_LIMITS["cognitive"])
    ap.add_argument("--max-length", type=int, default=DEFAULT_LIMITS["length"])
    ap.add_argument("--max-nesting", type=int, default=DEFAULT_LIMITS["nesting"])
    ap.add_argument("--top", type=int, default=0, help="show the N gnarliest, ignore limits")
    ap.add_argument("--jobs", type=int, default=1,
                    help="parallel worker processes (0 = all cores)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    limits = {"cyclomatic": args.max_cyclomatic, "cognitive": args.max_cognitive,
              "length": args.max_length, "nesting": args.max_nesting}
    metrics = []
    for group in nativepool.pmap(analyze_file, collect_paths(args.paths), args.jobs):
        metrics += group

    flagged = [m for m in metrics if m.exceeded(limits)]
    if args.json:
        print(json.dumps([{**asdict(m), "over": m.exceeded(limits)} for m in metrics], indent=2))
    else:
        print(_fmt(metrics, limits, args.top))
        if not args.top:
            print("%d of %d function(s) over threshold." % (len(flagged), len(metrics)))
    return min(len(flagged), 250)


if __name__ == "__main__":
    sys.exit(main())
