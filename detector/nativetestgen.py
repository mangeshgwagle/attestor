#!/usr/bin/env python3
"""
nativetestgen.py -- scaffold a C/C++ test harness from a source file.

It reads a .c/.cpp file, finds the functions you define (blanking comments and
strings first so it never trips on a keyword in a literal), and writes a test file
with one stub per function: inputs declared and zero-initialised, the call wired
up, and a TODO where the expected value goes.

Honest limit: Attestor has no oracle -- it cannot know what your function *should*
return -- so it scaffolds the structure and leaves the assertion for you. That is
still the tedious 80%: every function discovered, every signature wired, a harness
that compiles and runs and reports pass/fail. You fill in the truth.

    python3 nativetestgen.py math.c                 # print test_math.c to stdout
    python3 nativetestgen.py shapes.cpp --out t.cpp # write it to a file
"""
from __future__ import annotations

import argparse
import os
import re
import sys

import detect

_SKIP = {"if", "for", "while", "switch", "catch", "return", "sizeof", "else",
         "do", "main", "operator"}
_SIG_HEADER = re.compile(
    r"^\s*([A-Za-z_][\w\s\*&:<>]*?)\b([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*"
    r"(?:const|noexcept|override|final)?\s*$")
SUFFIX_LANG = {".c": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp"}


def _split_params(params: str) -> list:
    """Top-level comma split (respects <> and () nesting)."""
    parts = []
    depth = 0
    current = []
    for ch in params:
        if ch in "<(":
            depth += 1
        elif ch in ">)":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current))
    return [p.strip() for p in parts if p.strip() and p.strip() != "void"]


def _init_for(ptype: str, lang: str) -> str:
    low = ptype.lower()
    if "*" in ptype or "[]" in ptype:
        return "nullptr" if lang == "cpp" else "NULL"
    if re.search(r"\bbool\b", low):
        return "false"
    if re.search(r"\b(?:float|double)\b", low):
        return "0.0"
    # whole-word match only, so 'struct Point' is not mistaken for an int via "po*int*"
    if re.search(r"\b(?:int|char|long|short|size_t|unsigned|u?int\d+_t)\b", low):
        return "0"
    return "{}" if lang == "cpp" else "{0}"  # value-init C++; zero-init C aggregates


def _param_name(param: str, index: int) -> str:
    match = re.search(r"([A-Za-z_]\w*)\s*(?:\[\s*\d*\s*\])?\s*$", param)
    if not match:
        return "arg%d" % index
    candidate = match.group(1)
    prefix = param[:match.start(1)].strip()
    type_words = {
        "auto", "bool", "char", "char8_t", "char16_t", "char32_t", "double",
        "float", "int", "long", "short", "signed", "unsigned", "void", "wchar_t",
    }
    qualifiers = {"class", "const", "enum", "restrict", "struct", "typename",
                  "union", "volatile"}
    prefix_words = set(re.findall(r"[A-Za-z_]\w*", prefix))
    if not prefix or prefix.rstrip().endswith("::") or candidate in type_words \
            or prefix_words and prefix_words <= qualifiers:
        return "arg%d" % index
    return candidate


def _array_suffix(param: str, name: str) -> str:
    match = re.search(r"\b%s\s*(\[\s*\d*\s*\])\s*$" % re.escape(name), param)
    return match.group(1).replace(" ", "") if match else ""


def _param_type(param: str, name: str) -> str:
    idx = param.rfind(name)
    return param[:idx].strip() if idx >= 0 else param.strip()


def _is_void_return(ret: str) -> bool:
    clean = ret.strip()
    return bool(clean) and "*" not in clean and clean.split()[-1] == "void"


def _result_type(ret: str) -> str:
    """Drop function-only specifiers that are illegal on a local result variable."""
    return re.sub(
        r"^(?:(?:static|inline|constexpr|consteval|constinit|extern|virtual|friend)\s+)+",
        "", ret.strip())


def _scope_context(lines: list[str]) -> list[tuple[tuple[str, ...], bool]]:
    """Namespace names and whether each line is inside a class/struct."""
    depth = 0
    scopes = []                         # (kind, name, opening depth)
    result = []
    namespace_rx = re.compile(
        r"\bnamespace(?:\s+([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*))?\s*\{")
    class_rx = re.compile(r"\b(?:class|struct)\s+[A-Za-z_]\w*[^;{]*\{")
    for line in lines:
        for match in namespace_rx.finditer(line):
            name = match.group(1) or ""
            opening = depth + line[:match.end()].count("{") - line[:match.end()].count("}")
            scopes.append(("namespace", name, max(opening, depth + 1)))
        for match in class_rx.finditer(line):
            opening = depth + line[:match.end()].count("{") - line[:match.end()].count("}")
            scopes.append(("class", "", max(opening, depth + 1)))
        namespaces = tuple(
            part for kind, name, _level in scopes if kind == "namespace"
            for part in ([name] if not name or "::" not in name else name.split("::")))
        result.append((namespaces, any(kind == "class" for kind, _name, _level in scopes)))
        depth += line.count("{") - line.count("}")
        scopes = [scope for scope in scopes if scope[2] <= depth]
    return result


def _stub_identifier(name: str) -> str:
    return re.sub(r"\W+", "_", name).strip("_") or "function"


def functions(text: str, lang: str) -> list:
    """(return_type, name, [(type, name, array_suffix), ...]) for each function definition."""
    blanked = detect.blank_c_like(text)
    contexts = _scope_context(blanked) if lang == "cpp" else [((), False)] * len(blanked)
    out = []
    header = []
    for raw, (namespaces, in_class) in zip(blanked, contexts):
        line = raw.strip()
        if not line or line.startswith("#"):
            header = []
            continue
        before_brace = raw.split("{", 1)[0]
        header.append(before_brace)
        if "{" not in raw:
            if ";" in raw or "}" in raw:
                header = []
            continue
        candidate = " ".join(part.strip() for part in header if part.strip())
        header = []
        match = _SIG_HEADER.match(candidate)
        if not match:
            continue
        ret, name, params = match.groups()
        if name in _SKIP or in_class or ret.rstrip().endswith("::") \
                or re.search(r"\btemplate\s*<", ret):
            continue
        if namespaces:
            if any(not part for part in namespaces):  # anonymous namespace: not callable here
                continue
            name = "::".join(namespaces + (name,))
        if name.split("::")[-1] in _SKIP:
            continue
        parsed = []
        for i, param in enumerate(_split_params(params)):
            pname = _param_name(param, i)
            parsed.append((_param_type(param, pname) or "int", pname,
                           _array_suffix(param, pname)))
        out.append((ret.strip(), name, parsed))
    return out


def _stub(func: tuple, lang: str, stub_name: str | None = None) -> str:
    ret, name, params = func
    test_name = stub_name or _stub_identifier(name)
    lines = ["static void test_%s(void) {" % test_name,
             "    /* TODO: choose meaningful inputs and the expected result. */"]
    args = []
    for param in params:
        ptype, pname = param[:2]
        array_suffix = param[2] if len(param) > 2 else ""
        if array_suffix:
            suffix = array_suffix if array_suffix != "[]" else "[1]"
            lines.append("    %s %s%s = {0};" % (ptype, pname, suffix))
        elif "*" in ptype and re.search(r"\bchar\b", ptype):
            storage = pname + "_storage"
            const = "const " if re.search(r"\bconst\b", ptype) else ""
            lines.append("    %schar %s[256] = {0};" % (const, storage))
            lines.append("    %s %s = %s;" % (ptype, pname, storage))
        elif lang == "cpp" and "&" in ptype and "&&" not in ptype:
            storage = pname + "_storage"
            base = re.sub(r"\bconst\b|\bvolatile\b|&", "", ptype).strip()
            lines.append("    %s %s = %s;" % (base, storage, _init_for(base, lang)))
            lines.append("    %s %s = %s;" % (ptype, pname, storage))
        else:
            lines.append("    %s %s = %s;" % (ptype, pname, _init_for(ptype, lang)))
        args.append(pname)
    call = "%s(%s)" % (name, ", ".join(args))
    result_type = _result_type(ret)
    if result_type and not _is_void_return(result_type):
        lines.append("    %s result = %s;" % (result_type, call))
        lines.append("    (void)result;")
        lines.append("    /* assert(result == EXPECTED); */")
    else:
        lines.append("    %s;" % call)
    lines.append("}")
    return "\n".join(lines)


def generate(text: str, source_name: str, lang: str) -> str:
    funcs = functions(text, lang)
    header = os.path.splitext(os.path.basename(source_name))[0] + ".h"
    include = "#include <cassert>\n#include <cstdio>" if lang == "cpp" \
        else "#include <assert.h>\n#include <stdio.h>"
    parts = [
        "/* test harness scaffolded by Attestor (nativetestgen). Fill in the TODOs. */",
        include,
        '#include "%s"   /* adjust to the header that declares these functions */' % header,
        "",
    ]
    if not funcs:
        parts.append("/* no function definitions found to scaffold. */")
        return "\n".join(parts) + "\n"
    counts = {}
    named = []
    for func in funcs:
        name = func[1]
        counts[name] = counts.get(name, 0) + 1
        base = _stub_identifier(name)
        stub_name = base if counts[name] == 1 else "%s_%d" % (base, counts[name])
        named.append((func, stub_name))
    parts += [_stub(func, lang, stub_name) + "\n" for func, stub_name in named]
    parts.append("int main(void) {")
    parts += ["    test_%s();" % stub_name for _func, stub_name in named]
    parts.append('    printf("all %d scaffolded test(s) ran\\n");' % len(funcs))
    parts.append("    return 0;")
    parts.append("}")
    return "\n".join(parts) + "\n"


def language_for(path: str) -> str:
    return SUFFIX_LANG.get(os.path.splitext(path)[1], "")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", help="a .c or .cpp file to scaffold tests for")
    ap.add_argument("--out", help="write the harness here (default: stdout)")
    args = ap.parse_args(argv)

    lang = language_for(args.path)
    if not lang:
        print("not a C/C++ source file: " + args.path, file=sys.stderr)
        return 2
    try:
        with open(args.path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        print("cannot read %s: %s" % (args.path, exc), file=sys.stderr)
        return 2

    harness = generate(text, args.path, lang)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(harness)
        print("wrote %s (%d function stubs)" % (args.out, harness.count("static void test_")),
              file=sys.stderr)
    else:
        sys.stdout.write(harness)
    return 0


if __name__ == "__main__":
    sys.exit(main())
