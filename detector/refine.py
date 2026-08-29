#!/usr/bin/env python3
"""
refine.py -- Attestor improves code by looking at it again, and again, and again.

The loop you'd draw on a napkin: read the code, examine it with every engine, find
the errors it *can mechanically fix*, rewrite a better version, then look again --
and keep looking until nothing improves. Then print the result.

The thing that makes this safe (most auto-fixers aren't): every candidate rewrite
must **strictly reduce the finding count and still parse**, or it is discarded.
The loop therefore only ever climbs -- it cannot make code worse, and it stops at
a fixed point where no fix helps. It authors nothing from scratch (that needs a
template via codegen.py or a key via brain.py); it *refines* what it's given.

Fixes it knows, all verified before they're kept:
  - remove an import nothing uses,
  - narrow a bare `except:` to `except Exception:`,
  - add `timeout=` to a requests/subprocess call that has none.

    python3 refine.py messy.py               # print the improved code (report on stderr)
    python3 refine.py messy.py > clean.py    # ...pipe it somewhere
    python3 refine.py messy.py --write       # rewrite the file in place
"""
from __future__ import annotations

import argparse
import ast
import os
import re
import sys
import tempfile

import deepscan
import detect
import grade
import metrics


def _parses(src: str) -> bool:
    try:
        ast.parse(src)
        return True
    except SyntaxError:
        return False


def _scan_all(src: str, path: str) -> list:
    """Every finding both engines see, deduped. deepscan reads source directly;
    detect needs a file, so the candidate is written to a short-lived temp file."""
    findings = list(deepscan.analyze(src, path))
    fd, tmp = tempfile.mkstemp(suffix=".py")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(src)
        findings += detect.scan_file(tmp)
    finally:
        os.remove(tmp)
    seen = set()
    unique = []
    for finding in findings:
        key = (finding.line, finding.rule)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def _imported_name(line: str):
    """The single name a lone `import`/`from ... import` binds, else None."""
    try:
        node = ast.parse(line.strip()).body[0]
    except (SyntaxError, IndexError):
        return None
    if isinstance(node, (ast.Import, ast.ImportFrom)) and len(node.names) == 1:
        alias = node.names[0]
        return alias.asname or alias.name.split(".")[0]
    return None


def _fix_unused_import(src: str, finding) -> list:
    lines = src.split("\n")
    i = finding.line - 1
    if not 0 <= i < len(lines):
        return []
    name = _imported_name(lines[i])
    if name is None:
        return []
    elsewhere = "\n".join(lines[:i] + lines[i + 1:])
    if re.search(r"\b" + re.escape(name) + r"\b", elsewhere):
        return []                       # bound name is used somewhere -> never touch it
    candidate = "\n".join(lines[:i] + lines[i + 1:])
    return [(candidate, "removed unused import '%s' (line %d)" % (name, finding.line))]


def _fix_bare_except(src: str, finding) -> list:
    lines = src.split("\n")
    i = finding.line - 1
    if not 0 <= i < len(lines):
        return []
    fixed = re.sub(r"\bexcept\s*:", "except Exception:", lines[i])
    if fixed == lines[i]:
        return []
    candidate = "\n".join(lines[:i] + [fixed] + lines[i + 1:])
    return [(candidate, "narrowed bare 'except:' to 'except Exception:' (line %d)" % finding.line)]


def _fix_timeout(src: str, finding) -> list:
    lines = src.split("\n")
    i = finding.line - 1
    if not 0 <= i < len(lines):
        return []
    line = lines[i]
    match = re.search(r"\b(?:requests|subprocess)\.\w+\s*\(", line)
    if not match:
        return []
    close = _matching_paren(line, line.index("(", match.end() - 1))
    if close < 0:
        return []                       # spans multiple lines -> leave for a human
    head = line[:close]
    insert = "timeout=30" if head.rstrip().endswith("(") else ", timeout=30"
    fixed = head + insert + line[close:]
    candidate = "\n".join(lines[:i] + [fixed] + lines[i + 1:])
    return [(candidate, "added timeout=30 to the call on line %d" % finding.line)]


def _matching_paren(line: str, open_idx: int) -> int:
    depth = 0
    for j in range(open_idx, len(line)):
        if line[j] == "(":
            depth += 1
        elif line[j] == ")":
            depth -= 1
            if depth == 0:
                return j
    return -1


def _one_line_fix(src: str, finding, pattern: str, repl, note: str) -> list:
    """Apply a regex substitution to the finding's line only; keep it if it changed."""
    lines = src.split("\n")
    i = finding.line - 1
    if not 0 <= i < len(lines):
        return []
    fixed = re.sub(pattern, repl, lines[i])
    if fixed == lines[i]:
        return []
    candidate = "\n".join(lines[:i] + [fixed] + lines[i + 1:])
    return [(candidate, note % finding.line)]


def _fix_eq_none(src: str, finding) -> list:
    """`x == None` -> `x is None`, `x != None` -> `x is not None`. None is a
    singleton, so identity is both correct and the documented style."""
    def repl(match):
        return "is None" if match.group(1) == "==" else "is not None"
    return _one_line_fix(src, finding, r"(==|!=)\s*None\b", repl,
                         "compared to None with 'is' (line %d)")


def _fix_is_literal(src: str, finding) -> list:
    """`x is 5` -> `x == 5`, `x is not 'a'` -> `x != 'a'`. 'is' on a number or
    string tests identity, which is not guaranteed; comparison is what was meant.
    (None/True/False keep 'is' -- the lookahead only matches numeric/string literals.)"""
    lines = src.split("\n")
    i = finding.line - 1
    if not 0 <= i < len(lines):
        return []
    fixed = re.sub(r"\bis\s+not\s+(?=[-'\"0-9])", "!= ", lines[i])
    fixed = re.sub(r"\bis\s+(?=[-'\"0-9])", "== ", fixed)
    if fixed == lines[i]:
        return []
    candidate = "\n".join(lines[:i] + [fixed] + lines[i + 1:])
    return [(candidate, "used '=='/'!=' instead of 'is' on a literal (line %d)" % finding.line)]


_FIXERS = {
    "unused-import": _fix_unused_import,
    "bare-except": _fix_bare_except,
    "py-bare-except": _fix_bare_except,
    "py-requests-no-timeout": _fix_timeout,
    "py-subprocess-no-timeout": _fix_timeout,
    "py-eq-none": _fix_eq_none,
    "is-literal": _fix_is_literal,
    "py-is-literal": _fix_is_literal,
}


def _candidates(src: str, finding) -> list:
    fixer = _FIXERS.get(finding.rule)
    return fixer(src, finding) if fixer else []


def refine(src: str, path: str = "<refine>", rounds: int = 50) -> tuple:
    """Examine -> fix -> re-examine, until nothing improves. Returns (code, log).
    A fix is kept only if the candidate parses and has strictly fewer findings, so
    the finding count drops every accepted round and the loop always terminates."""
    current = src
    changes = []
    for _ in range(rounds):
        findings = _scan_all(current, path)
        if not findings:
            break
        chosen = _best_fix(current, findings, path, len(findings))
        if chosen is None:
            break                       # fixed point: no fix reduces the count
        current, note = chosen
        changes.append(note)
    return current, changes


def _best_fix(src: str, findings: list, path: str, baseline: int):
    """First candidate that parses and strictly lowers the finding count."""
    for finding in findings:
        for candidate, note in _candidates(src, finding):
            if _parses(candidate) and len(_scan_all(candidate, path)) < baseline:
                return candidate, note
    return None


def _summary(path: str, before, after, changes: list) -> str:
    lines = ["# Attestor refine: %s" % path,
             "#   grade %s (%d/100) -> %s (%d/100), %d fix(es) applied"
             % (before.grade, before.score, after.grade, after.score, len(changes))]
    lines += ["#   - " + note for note in changes]
    if not changes:
        lines.append("#   (already at a fixed point -- nothing safe to improve)")
    return "\n".join(lines)


def report(path: str, rounds: int = 50) -> tuple:
    """Refine a file and return (summary + improved code, remaining findings) --
    the embeddable form used by superattestor and the UI."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        src = fh.read()
    limits = metrics.DEFAULT_LIMITS
    before = grade.grade_source(src, path, limits)[0]
    improved, changes = refine(src, path, rounds)
    after = grade.grade_source(improved, path, limits)[0]
    text = _summary(path, before, after, changes) + "\n\n" + improved
    return text, min(len(_scan_all(improved, path)), 250)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", help="a Python file to refine")
    ap.add_argument("--rounds", type=int, default=50, help="max examine/fix passes")
    ap.add_argument("--write", action="store_true", help="rewrite the file in place")
    args = ap.parse_args(argv)

    try:
        with open(args.path, encoding="utf-8", errors="replace") as fh:
            src = fh.read()
    except OSError as exc:
        print("cannot read %s: %s" % (args.path, exc), file=sys.stderr)
        return 2

    limits = metrics.DEFAULT_LIMITS
    before = grade.grade_source(src, args.path, limits)[0]
    improved, changes = refine(src, args.path, args.rounds)
    after = grade.grade_source(improved, args.path, limits)[0]

    print(_summary(args.path, before, after, changes), file=sys.stderr)
    if args.write:
        if improved != src:
            with open(args.path, "w", encoding="utf-8") as fh:
                fh.write(improved)
            print("# wrote improved code -> " + args.path, file=sys.stderr)
    else:
        sys.stdout.write(improved)
    return min(len(_scan_all(improved, args.path)), 250)


if __name__ == "__main__":
    sys.exit(main())
