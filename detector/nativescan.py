#!/usr/bin/env python3
"""
nativescan.py -- Attestor's expanded C / C++ / Assembly bug net.

polyglot.py catches a curated handful; this is the long net. It blanks comments
and string/char literals first (via detect.blank_c_like) so a keyword inside a
string never trips a rule, then runs a big registry of line-local checks plus a
few multi-line ones. Every finding carries severity, a plain-English reason, and
the fix. Exit code = number of findings, so CI can gate on it.

    python3 nativescan.py server.c parser.cpp        # human report
    python3 nativescan.py src/ --min-severity HIGH   # recurse, only the serious ones
    python3 nativescan.py boot.s --json              # machine-readable

It reads and reports only -- it never executes, edits, or phones home. With no
parser it is deliberately conservative: it would rather stay quiet than cry wolf.
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

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SUFFIX_LANG = {
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hh": "cpp", ".hpp": "cpp", ".hxx": "cpp",
    ".s": "asm", ".S": "asm", ".asm": "asm", ".nasm": "asm",
}
SKIP_DIRS = {".git", ".hg", ".svn", "build", "dist", "target", "node_modules"}
MAX_BYTES = 512 * 1024
C = frozenset({"c", "cpp"})
CPP = frozenset({"cpp"})


def _input_problem(path: str) -> str | None:
    try:
        size = os.path.getsize(path)
        if size > MAX_BYTES:
            return "file is too large (%d bytes; limit is %d)" % (size, MAX_BYTES)
        with open(path, "rb") as handle:
            if b"\x00" in handle.read(8192):
                return "file appears to be binary"
    except OSError as exc:
        return "cannot read: %s" % exc
    return None


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    language: str
    rule: str
    severity: str
    message: str
    fix: str

    def sort_key(self):
        return (SEVERITY_RANK.get(self.severity, 9), self.path, self.line, self.rule)


@dataclass(frozen=True)
class Rule:
    rid: str
    langs: frozenset
    severity: str
    pattern: "re.Pattern"
    message: str
    fix: str


def _r(rid, langs, severity, pattern, message, fix):
    return Rule(rid, langs, severity, re.compile(pattern), message, fix)


# --------------------------------------------------------------------------- #
# The long net. Each rule matches one blanked line (string/comment content is
# already spaces, so these never fire inside a literal). Ordered roughly by bite.
# --------------------------------------------------------------------------- #
LINE_RULES = [
    _r("native-gets", C, "CRITICAL", r"\bgets\s*\(",
       "gets() cannot be bounded and always risks a buffer overflow",
       "use fgets(buf, sizeof buf, stdin) and strip the newline."),
    _r("native-system-nonliteral", C, "HIGH", r"\bsystem\s*\(\s*[A-Za-z_]",
       "system() on a non-literal string is a command-injection channel",
       "avoid system(); use execve with a fixed argv, or a vetted allowlist."),
    _r("native-format-string", C, "HIGH",
       r"\b(?:printf|fprintf|sprintf|snprintf|syslog)\s*\(\s*(?:[A-Za-z_]\w*\s*[,)]|stderr\s*,\s*[A-Za-z_]\w*\s*[,)])",
       "the format argument is a variable, not a literal -- a format-string bug",
       "pass a fixed format: printf(\"%s\", user) instead of printf(user)."),
    _r("native-strcpy", C, "HIGH", r"\bstrcpy\s*\(",
       "strcpy() does not bound the copy and overruns on a long source",
       "use strncpy/strlcpy with the destination size, or snprintf."),
    _r("native-strcat", C, "HIGH", r"\bstrcat\s*\(",
       "strcat() does not bound the append and overruns on a long source",
       "use strncat/strlcat with the remaining space, or snprintf."),
    _r("native-sprintf", C, "HIGH", r"\bsprintf\s*\(",
       "sprintf() has no size limit and overflows the destination buffer",
       "use snprintf(buf, sizeof buf, ...)."),
    _r("native-atoi", C, "LOW", r"\bato(?:i|l|ll|f)\s*\(",
       "atoi/atol/atof cannot report errors -- a bad string reads as 0",
       "use strtol/strtod and check endptr and errno."),
    _r("native-malloc-no-cast-check", C, "LOW", r"\b(?:malloc|calloc|realloc)\s*\(",
       "allocation result must be null-checked before use",
       "check the returned pointer for NULL before dereferencing it."),
    _r("native-assign-in-if", C, "MEDIUM", r"\b(?:if|while)\s*\(\s*[A-Za-z_][\w.\->\[\] ]*\s=\s(?!=)",
       "a single '=' in a condition assigns instead of comparing",
       "use '==', or wrap a deliberate assignment in an extra pair of parens."),
    _r("native-eq-bool", C, "LOW", r"==\s*(?:true|false|TRUE|FALSE)\b",
       "comparing to a boolean literal is redundant and error-prone",
       "test the value directly: 'if (ok)' or 'if (!ok)'."),
    _r("native-float-equality", C, "LOW", r"[=!]=\s*-?\d+\.\d+",
       "exact == on a floating literal rarely holds after arithmetic",
       "compare against an epsilon: fabs(a - b) < 1e-9."),
    _r("native-signed-overflow-check", C, "HIGH",
       r"\b([A-Za-z_]\w*)\s*\+\s*(?:\d+|[A-Za-z_]\w*)\s*<\s*\1\b",
       "overflow check relies on evaluating x + n before the comparison; signed overflow is undefined",
       "check before adding, e.g. x > INT_MAX - n."),
    _r("native-strict-aliasing-cast", C, "HIGH",
       r"\(\s*(?:float|double|int|long|short|char|u?int\d+_t)\s*\*\s*\)\s*&\s*[A-Za-z_]\w*",
       "address is cast to an unrelated pointer type; this can violate strict aliasing under optimization",
       "use memcpy, a union with care, or redesign the representation."),
    _r("native-strlen-in-for", C, "MEDIUM", r"\bfor\s*\([^;]*;[^;]*\bstrlen\s*\(",
       "strlen() in a loop condition is recomputed every iteration -- O(n^2)",
       "hoist the length into a variable before the loop."),
    _r("native-return-address-of-local", C, "HIGH", r"\breturn\s+&\s*[A-Za-z_]\w*\s*;",
       "returning the address of a local -- the stack frame is gone on return",
       "return by value, or allocate on the heap / pass an out-parameter."),
    _r("native-goto", C, "INFO", r"\bgoto\b",
       "goto tangles control flow and defeats scoped cleanup",
       "prefer structured loops; if used for cleanup, keep it single-target."),
    _r("native-macro-semicolon", C, "LOW", r"^\s*#\s*define\s+\w+(?:\([^)]*\))?\s+.*;\s*$",
       "a #define ending in ';' injects a stray semicolon at each use site",
       "drop the trailing ';' from the macro body."),
    _r("native-float-loop-counter", C, "LOW", r"\bfor\s*\(\s*(?:float|double)\s",
       "a floating-point loop counter drifts and can miss its bound",
       "count with an integer and derive the float inside the loop."),
    # C++ flavour
    _r("native-using-namespace-header", CPP, "MEDIUM", r"^\s*using\s+namespace\s+",
       "'using namespace' (especially in a header) leaks names into every includer",
       "qualify names (std::) or use narrow 'using std::name;' in a .cpp scope."),
    _r("native-catch-by-value", CPP, "MEDIUM", r"\bcatch\s*\(\s*(?!\.\.\.)[A-Za-z_][\w:<>]*\s+[A-Za-z_]\w*\s*\)",
       "catching an exception by value slices derived types and copies",
       "catch by const reference: catch (const std::exception& e)."),
    _r("native-delete-this", CPP, "HIGH", r"\bdelete\s+this\b",
       "'delete this' is a footgun -- any later member access is undefined",
       "manage lifetime with a factory/owner or std::shared_ptr instead."),
    _r("native-new-delete", CPP, "INFO", r"\b(?:new|delete)\b(?!\s*[\)\]])",
       "raw new/delete leaks on exceptions and early returns",
       "prefer std::make_unique / std::make_shared and RAII containers."),
    _r("native-endl-flush", CPP, "INFO", r"<<\s*std::endl",
       "std::endl flushes every time; in a loop that is a lot of syscalls",
       "use '\\n' and flush once at the end if you need to."),
    _r("native-c-cast", CPP, "LOW", r"\(\s*(?:int|char|float|double|void|unsigned|long|short)\s*\*?\s*\)\s*[A-Za-z_(]",
       "a C-style cast is unchecked and hides const/reinterpret intent",
       "use static_cast / reinterpret_cast / const_cast to say what you mean."),
]

# Named assembly labels (numeric GAS-local labels like '1:' may legally repeat and
# start with a digit, so they never match here -- keeping the check false-positive-free).
_ASM_LABEL = re.compile(r"^([A-Za-z_.$][\w.$]*)\s*:")
_UNSIGNED_SUB = re.compile(
    r"\b(?:size_t|unsigned(?:\s+(?:int|long|short|char))?|u?int\d+_t)\s+"
    r"([A-Za-z_]\w*)\s*=\s*[^;]*\b[A-Za-z_]\w*\s*-\s*[A-Za-z_]\w*")
_CPP_MAP_DECL = re.compile(r"\b(?:std::)?(?:unordered_)?map\s*<[^;]+>\s+([A-Za-z_]\w*)")
_CPP_VECTOR_DECL = re.compile(r"\b(?:std::)?vector\s*<\s*([A-Za-z_]\w*)\s*>\s+([A-Za-z_]\w*)")


def _blank(text: str, lang: str) -> list:
    if lang in C:
        return detect.blank_c_like(text)
    return text.splitlines()


def _line_findings(blanked: list, path: str, lang: str) -> list:
    out = []
    for idx, line in enumerate(blanked, start=1):
        for rule in LINE_RULES:
            if lang in rule.langs and rule.pattern.search(line):
                out.append(Finding(path, idx, lang, rule.rid, rule.severity,
                                   rule.message, rule.fix))
    return out


def _call_arguments(text: str, open_index: int) -> list[str]:
    """Split a C call's top-level arguments, preserving string literal text."""
    args, current = [], []
    depth = 1
    quote = None
    i = open_index + 1
    while i < len(text) and depth:
        char = text[i]
        if quote:
            current.append(char)
            if char == "\\" and i + 1 < len(text):
                current.append(text[i + 1]); i += 2; continue
            if char == quote:
                quote = None
        elif char in ('"', "'"):
            quote = char; current.append(char)
        elif char == "(":
            depth += 1; current.append(char)
        elif char == ")":
            depth -= 1
            if depth:
                current.append(char)
        elif char == "," and depth == 1:
            args.append("".join(current).strip()); current = []
        else:
            current.append(char)
        i += 1
    if current or args:
        args.append("".join(current).strip())
    return args if depth == 0 else []


_C_STRING = re.compile(r"(?:u8|[uUL])?\"((?:\\.|[^\"\\])*)\"")
_SCAN_STRING = re.compile(r"%(?P<suppress>\*)?(?P<width>\d*)(?:l)?s")


def _scanf_findings(literal_lines: list, blanked: list, path: str, lang: str) -> list:
    text = "\n".join(literal_lines)
    code = "\n".join(blanked)
    out = []
    for match in re.finditer(r"\b(scanf|fscanf|sscanf)\s*\(", text):
        if not re.match(r"(?:scanf|fscanf|sscanf)\s*\(", code[match.start():]):
            continue
        args = _call_arguments(text, text.find("(", match.start()))
        fmt_index = 0 if match.group(1) == "scanf" else 1
        if len(args) <= fmt_index:
            continue
        pieces = _C_STRING.findall(args[fmt_index])
        if not pieces:
            continue                         # dynamic format: another rule owns it
        fmt = "".join(pieces).replace("%%", "")
        unsafe = any(not spec.group("suppress") and not spec.group("width")
                     for spec in _SCAN_STRING.finditer(fmt))
        if unsafe:
            line = text.count("\n", 0, match.start()) + 1
            out.append(Finding(
                path, line, lang, "native-scanf-unbounded", "HIGH",
                "scanf-family %s conversion has no field width and can overflow its destination"
                % "%s",
                "give every string conversion a destination-sized width (for example %31s), "
                "or use fgets and parse."))
    return out


_LOCAL_POINTER = re.compile(
    r"(?:^|[;{}])\s*(?:const\s+|volatile\s+|static\s+)*(?:struct\s+[A-Za-z_]\w*|"
    r"[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\s*(?:const\s*)?\*+\s*"
    r"(?:const\s+)?([A-Za-z_]\w*)\b", re.M)
_SIZEOF_IN_BOUNDED_CALL = re.compile(
    r"\b(?P<call>mem(?:set|cpy|move)|strn(?:cpy|cat))\s*\([^;]*?"
    r"\bsizeof\s*(?:\(\s*(?P<paren>[A-Za-z_]\w*)\s*\)|"
    r"(?P<bare>[A-Za-z_]\w*))", re.S)


def _sizeof_pointer_findings(blanked: list, path: str, lang: str) -> list:
    text = "\n".join(blanked)
    pointers = set(detect.build_ctx(lang, blanked, blanked).pointer_params)
    pointers.update(match.group(1) for match in _LOCAL_POINTER.finditer(text))
    out = []
    for match in _SIZEOF_IN_BOUNDED_CALL.finditer(text):
        name = match.group("paren") or match.group("bare")
        if name not in pointers:
            continue
        line = text.count("\n", 0, match.start()) + 1
        out.append(Finding(
            path, line, lang,
            "native-memset-sizeof-ptr" if match.group("call").startswith("mem")
            else "native-strncpy-size",
            "HIGH" if match.group("call").startswith("mem") else "MEDIUM",
            "sizeof(%s) measures a pointer in this call, not the pointed-to buffer" % name,
            "pass the actual destination capacity, use sizeof(array) while it is still an "
            "array, or carry the length explicitly."))
    return out


def _multi_line_findings(blanked: list, path: str, lang: str) -> list:
    out = []
    unsigned_subtractions = {}
    map_vars = set()
    vector_value_vars = {}
    for idx, line in enumerate(blanked, start=1):
        sub = _UNSIGNED_SUB.search(line)
        if sub:
            unsigned_subtractions[sub.group(1)] = idx
        for name, decl_line in list(unsigned_subtractions.items()):
            if re.search(r"\b%s\s*<\s*0\b" % re.escape(name), line) \
                    or re.search(r"\b0\s*>\s*%s\b" % re.escape(name), line):
                out.append(Finding(
                    path, idx, lang, "native-unsigned-underflow-check", "HIGH",
                    "unsigned subtraction stored in %r is compared against zero; it can never be negative"
                    % name,
                    "compare operands before subtracting, e.g. if (used > capacity)."))
                del unsigned_subtractions[name]
        if lang != "cpp":
            continue
        map_decl = _CPP_MAP_DECL.search(line)
        if map_decl:
            map_vars.add(map_decl.group(1))
        for var in sorted(map_vars):
            if re.search(r"\b%s\s*\[[^\]]+\]" % re.escape(var), line):
                out.append(Finding(
                    path, idx, lang, "native-cpp-map-operator-insert", "MEDIUM",
                    "std::map/unordered_map operator[] mutates the map when the key is absent",
                    "use find(), contains(), or at() for read-only lookup."))
        vector_decl = _CPP_VECTOR_DECL.search(line)
        if vector_decl:
            vector_value_vars[vector_decl.group(2)] = vector_decl.group(1)
        for var, base in sorted(vector_value_vars.items()):
            pushed = re.search(r"\b%s\s*\.\s*(?:push_back|emplace_back)\s*\(\s*([A-Za-z_]\w*)\s*\{"
                               % re.escape(var), line)
            if pushed and pushed.group(1) != base:
                out.append(Finding(
                    path, idx, lang, "native-cpp-object-slicing", "HIGH",
                    "vector stores %s by value but receives %s; derived state/virtual dispatch can be sliced"
                    % (base, pushed.group(1)),
                    "store polymorphic values via unique_ptr/shared_ptr or references, not by-value base objects."))
    out += _sizeof_pointer_findings(blanked, path, lang)
    return out


# GAS records stack permissions per object file. If *any* linked object omits
# `.note.GNU-stack`, the linker gives the whole program an executable stack --
# a hand-written .S is the usual culprit, and the consequence is program-wide
# rather than local to the file that forgot it.
_ASM_GNU_STACK = re.compile(r"\.section\s+\.note\.GNU-stack", re.I)
_ASM_INSTRUCTION = re.compile(
    r"^\s+(?:mov|push|pop|call|ret|jmp|lea|add|sub|xor|test|cmp|int|syscall)",
    re.I)
_ASM_PUSH = re.compile(r"^\s+push[qlwb]?\b", re.I)
_ASM_POP = re.compile(r"^\s+pop[qlwb]?\b", re.I)
_ASM_LEAVE = re.compile(r"^\s+leave\b", re.I)
_ASM_RET = re.compile(r"^\s+ret[qfnw]?\b", re.I)
_ASM_RSP_ADJUST = re.compile(
    r"^\s+(?:add|sub|mov)[qlwb]?\s+.*,\s*%?[re]sp\b", re.I)


def _asm_code_lines(text: str):
    """(line number, code) with comments stripped and blank lines dropped."""
    for index, raw in enumerate(text.splitlines(), start=1):
        code = re.split(r"[;#]|//", raw, maxsplit=1)[0].rstrip()
        if code.strip():
            yield index, code


def _asm_findings(text: str, path: str) -> list:
    """Assembly rules are kept deliberately few and false-positive-free.

    Most real asm bugs need dataflow, so the bar is that a rule must be
    decidable from the text alone: a duplicate label every assembler rejects,
    a missing stack-permission note the linker acts on program-wide, and a
    prologue whose pushes are never undone before the matching `ret`.
    """
    out = []
    seen = {}
    lines = list(_asm_code_lines(text))

    for idx, code in lines:
        match = _ASM_LABEL.match(code)
        if match:
            name = match.group(1)
            if name in seen:
                out.append(Finding(path, idx, "asm", "native-asm-duplicate-label", "HIGH",
                                  "label %r is defined again (first at line %d)" % (name, seen[name]),
                                  "give each label a unique name; assemblers reject duplicates."))
            else:
                seen[name] = idx

    has_code = any(_ASM_INSTRUCTION.match(code) for _, code in lines)
    if has_code and not any(_ASM_GNU_STACK.search(code) for _, code in lines):
        first = next(idx for idx, code in lines if _ASM_INSTRUCTION.match(code))
        out.append(Finding(
            path, first, "asm", "native-asm-exec-stack", "HIGH",
            "this object declares no .note.GNU-stack, so the linker marks the "
            "stack executable for the entire program, not just this file",
            'append `.section .note.GNU-stack,"",@progbits` '
            "(%progbits on ARM)."))

    # Deliberately narrow: only when a path pushes, never pops, never issues
    # `leave`, never moves the stack pointer back, and still returns. Anything
    # less certain is a dataflow question and is left alone.
    pushes: list[int] = []
    for idx, code in lines:
        if _ASM_LABEL.match(code):
            pushes = []
        elif _ASM_PUSH.match(code):
            pushes.append(idx)
        elif (_ASM_POP.match(code) or _ASM_LEAVE.match(code)
              or _ASM_RSP_ADJUST.match(code)):
            pushes = []
        elif _ASM_RET.match(code) and pushes:
            out.append(Finding(
                path, idx, "asm", "native-asm-stack-imbalance", "HIGH",
                "this path pushes %d value(s) (first at line %d) then returns "
                "without popping them or restoring the stack pointer; `ret` "
                "takes whatever was pushed last as its return address"
                % (len(pushes), pushes[0]),
                "balance every push with a pop, or restore the stack pointer "
                "with `leave` or an explicit add before `ret`."))
            pushes = []
    return out


def scan_text(text: str, path: str, lang: str) -> list:
    if lang in C:
        blanked = _blank(text, lang)
        findings = _line_findings(blanked, path, lang)
        findings += _multi_line_findings(blanked, path, lang)
        findings += _scanf_findings(detect.blank_comments(text, lang), blanked, path, lang)
    elif lang == "asm":
        findings = _asm_findings(text, path)
    else:
        return []
    findings.sort(key=Finding.sort_key)
    return findings


def language_for(path: str) -> str:
    return SUFFIX_LANG.get(os.path.splitext(path)[1], "")


def scan_file(path: str) -> list:
    lang = language_for(path)
    if not lang:
        return []
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return []
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    return scan_text(text, path, lang)


def collect_paths(paths, errors: list[str] | None = None) -> list:
    out = []
    for raw in paths:
        if os.path.isdir(raw):
            for root, dirs, files in os.walk(raw):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for filename in sorted(files):
                    path = os.path.join(root, filename)
                    if language_for(path):
                        problem = _input_problem(path)
                        if problem is None:
                            out.append(path)
                        elif errors is not None and problem.startswith("cannot read"):
                            errors.append("%s: %s" % (path, problem))
        elif os.path.isfile(raw):
            if not language_for(raw):
                if errors is not None:
                    errors.append("%s: unsupported native input type" % raw)
                continue
            problem = _input_problem(raw)
            if problem:
                if errors is not None:
                    errors.append("%s: %s" % (raw, problem))
            else:
                out.append(raw)
        elif errors is not None:
            errors.append("%s: path does not exist" % raw)
    return out


def scan(paths, min_severity: str = "INFO", jobs: int = 1) -> list:
    threshold = SEVERITY_RANK.get(min_severity, 4)
    findings = []
    for group in nativepool.pmap(scan_file, collect_paths(paths), jobs):
        findings += [f for f in group if SEVERITY_RANK.get(f.severity, 9) <= threshold]
    findings.sort(key=Finding.sort_key)
    return findings


def render(findings: list) -> str:
    if not findings:
        return "0 native findings. clean."
    lines = []
    for f in findings:
        lines.append("[%s] %s:%d  %s (%s)" % (f.severity, f.path, f.line, f.rule, f.language))
        lines.append("  " + f.message)
        lines.append("  fix: " + f.fix)
    lines.append("")
    lines.append("%d finding(s)." % len(findings))
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="C/C++/Assembly files or directories")
    ap.add_argument("--min-severity", choices=list(SEVERITY_RANK), default="INFO")
    ap.add_argument("--jobs", type=int, default=1,
                    help="parallel worker processes (0 = all cores)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    errors = []
    files = collect_paths(args.paths, errors)
    if not files and not errors:
        errors.append("no scannable native source files were found")
    findings = scan(files, args.min_severity, args.jobs)
    for message in errors:
        print("scan error: " + message, file=sys.stderr)
    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print(render(findings))
    return 2 if errors else min(len(findings), 250)


if __name__ == "__main__":
    sys.exit(main())
