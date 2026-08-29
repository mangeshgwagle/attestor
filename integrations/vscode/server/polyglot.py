#!/usr/bin/env python3
"""polyglot.py -- tiny-bug detector for C, C++, Haskell, and Assembly.

This is Attestor's low-level microscope. It is intentionally defensive and local:
read files, report suspicious patterns, do not execute anything. The focus is on
small mistakes that are easy to miss in review: empty control bodies, wrong
allocation sizes, temporary C++ locks, partial Haskell functions, and assembly
state hazards.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path

MAX_BYTES = 512 * 1024
SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv",
    "dist", "build", "target", ".stack-work",
}
LANG_BY_SUFFIX = {
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hh": "cpp", ".hpp": "cpp", ".hxx": "cpp", ".hs": "haskell",
    ".s": "asm", ".S": "asm", ".asm": "asm", ".nasm": "asm",
}
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    language: str
    rule: str
    severity: str
    confidence: float
    detail: str
    fix: str

    def sort_key(self):
        return (
            SEVERITY_RANK.get(self.severity, 9),
            -self.confidence,
            self.path,
            self.line,
            self.rule,
        )


def _finding(path: str, line: int, language: str, rule: str, severity: str,
             confidence: float, detail: str, fix: str) -> Finding:
    return Finding(path, line, language, rule, severity, round(confidence, 2),
                   detail, fix)


def _strip_line_comment(line: str, language: str) -> str:
    if language in {"c", "cpp"}:
        return line.split("//", 1)[0]
    if language == "haskell":
        return line.split("--", 1)[0]
    if language == "asm":
        return re.split(r"[;#]", line, maxsplit=1)[0]
    return line


def _single_equals(condition: str) -> bool:
    return bool(re.search(r"(?<![=!<>])=(?!=)", condition))


def _scan_c_family(text: str, path: str, language: str) -> list[Finding]:
    findings = []
    lines = text.splitlines()
    new_arrays = {}
    moved_names = {}
    local_strings = set()
    for idx, raw in enumerate(lines, start=1):
        line = _strip_line_comment(raw, language)
        stripped = line.strip()
        if not stripped:
            continue
        if re.match(r"^(?:if|for|while)\s*\(.*\)\s*;\s*$", stripped):
            findings.append(_finding(
                path, idx, language, "polyglot-empty-control-body", "HIGH", 0.88,
                "control statement has an immediate semicolon, so its body is empty",
                "Remove the stray semicolon or add braces around the intended body."))
        cond = re.match(r"^(?:if|while)\s*\((.*)\)", stripped)
        if cond and _single_equals(cond.group(1)):
            findings.append(_finding(
                path, idx, language, "polyglot-assignment-in-condition", "MEDIUM", 0.78,
                "condition contains a single assignment operator",
                "Use == for comparison or wrap intentional assignment in extra parentheses."))
        malloc_match = re.search(
            r"\b([A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*sizeof\s*\(\s*\1\s*\)\s*\)",
            line)
        if malloc_match:
            findings.append(_finding(
                path, idx, language, "polyglot-malloc-sizeof-pointer", "HIGH", 0.90,
                "allocation uses sizeof(pointer variable), usually allocating pointer-size bytes",
                "Allocate sizeof *ptr or sizeof(type), then check the allocation result."))
        realloc_match = re.search(r"\b([A-Za-z_]\w*)\s*=\s*realloc\s*\(\s*\1\s*,", line)
        if realloc_match:
            findings.append(_finding(
                path, idx, language, "polyglot-direct-realloc", "MEDIUM", 0.86,
                "direct realloc assignment loses the original pointer if allocation fails",
                "Assign realloc to a temporary pointer, then replace the original after success."))
        if re.search(r"\bscanf\s*\(\s*\"%s\"", line):
            findings.append(_finding(
                path, idx, language, "polyglot-unbounded-scanf-string", "HIGH", 0.92,
                "scanf with %s has no field width and can overflow the destination",
                "Add a maximum width or use fgets plus explicit parsing."))
        if "strncpy(" in line and not any("= '\\0'" in later or '= "\\0"' in later
                                         for later in lines[idx:idx + 3]):
            findings.append(_finding(
                path, idx, language, "polyglot-strncpy-may-not-terminate", "MEDIUM", 0.76,
                "strncpy may leave the destination without a null terminator",
                "Reserve one byte, copy at most size - 1, and set the last byte to '\\0'."))
        arr = re.search(r"\b([A-Za-z_]\w*)\s*=\s*new\s+[A-Za-z_:]\w*\s*\[", line)
        if arr:
            new_arrays[arr.group(1)] = idx
        delete_match = re.search(r"\bdelete\s+([A-Za-z_]\w*)\s*;", line)
        if delete_match and delete_match.group(1) in new_arrays:
            findings.append(_finding(
                path, idx, language, "polyglot-delete-array-with-delete", "HIGH", 0.92,
                "memory allocated with new[] is released with delete instead of delete[]",
                "Use delete[] or, better, replace raw ownership with std::vector/unique_ptr."))
        if language == "cpp":
            if re.search(r"\bstd::lock_guard\s*<[^>]+>\s*\([^;]+\)\s*;", stripped):
                findings.append(_finding(
                    path, idx, language, "polyglot-temporary-lock-guard", "HIGH", 0.93,
                    "unnamed lock_guard temporary unlocks at the end of this statement",
                    "Bind the lock_guard to a named local variable for the intended scope."))
            string_decl = re.search(r"\bstd::string\s+([A-Za-z_]\w*)\b", line)
            if string_decl:
                local_strings.add(string_decl.group(1))
            cstr_return = re.search(r"\breturn\s+([A-Za-z_]\w*)\.c_str\s*\(\s*\)", line)
            if cstr_return and cstr_return.group(1) in local_strings:
                findings.append(_finding(
                    path, idx, language, "polyglot-return-local-cstr", "HIGH", 0.88,
                    "returns a pointer into a local std::string that dies on return",
                    "Return std::string or store the string in caller-owned storage."))
            if re.search(r"\bstd::string_view\s+[A-Za-z_]\w*\s*=\s*std::string\s*\(", line):
                findings.append(_finding(
                    path, idx, language, "polyglot-string-view-temporary", "HIGH", 0.86,
                    "string_view is bound to a temporary std::string",
                    "Keep the std::string alive or use std::string for ownership."))
            catch_value = re.search(r"\bcatch\s*\(\s*(?:const\s+)?std::\w+\s+([A-Za-z_]\w*)\s*\)", line)
            if catch_value:
                findings.append(_finding(
                    path, idx, language, "polyglot-catch-exception-by-value", "LOW", 0.80,
                    "exception is caught by value, which can slice derived exception types",
                    "Catch exceptions as const references."))
            move_match = re.search(r"\bstd::move\s*\(\s*([A-Za-z_]\w*)\s*\)", line)
            if move_match:
                moved_names[move_match.group(1)] = idx
            for name, moved_line in list(moved_names.items()):
                if idx > moved_line and idx <= moved_line + 3 and re.search(r"\b" + re.escape(name) + r"\b", line):
                    findings.append(_finding(
                        path, idx, language, "polyglot-use-after-move-shape", "MEDIUM", 0.70,
                        "object is used shortly after std::move, where its value may be unspecified",
                        "Avoid reading moved-from objects except for destruction or reassignment."))
                    moved_names.pop(name, None)
    return findings


def _scan_haskell(text: str, path: str) -> list[Finding]:
    findings = []
    partials = ("head", "tail", "last", "init", "fromJust", "read")
    for idx, raw in enumerate(text.splitlines(), start=1):
        line = _strip_line_comment(raw, "haskell")
        for name in partials:
            if re.search(r"(?<![A-Za-z0-9_'])" + re.escape(name) + r"(?![A-Za-z0-9_'])", line):
                findings.append(_finding(
                    path, idx, "haskell", "polyglot-hs-partial-function", "MEDIUM", 0.84,
                    f"partial function {name} can crash on ordinary inputs",
                    "Pattern match, return Maybe/Either, or use a total helper."))
                break
        if re.search(r"(?<![A-Za-z0-9_'])foldl(?!')\s", line):
            findings.append(_finding(
                path, idx, "haskell", "polyglot-hs-lazy-foldl", "MEDIUM", 0.90,
                "lazy foldl can build a large thunk chain and hide space leaks",
                "Use Data.List.foldl' for strict accumulation."))
        if "unsafePerformIO" in line:
            findings.append(_finding(
                path, idx, "haskell", "polyglot-hs-unsafe-perform-io", "HIGH", 0.91,
                "unsafePerformIO can break referential transparency and duplicate effects",
                "Keep effects in IO or isolate this behind a heavily audited boundary."))
        if re.search(r"\blength\s+\S+\s*(?:==|>|/=)\s*0\b", line):
            findings.append(_finding(
                path, idx, "haskell", "polyglot-hs-length-emptiness", "LOW", 0.78,
                "length-based emptiness check traverses the whole structure",
                "Use null for emptiness checks."))
        if re.search(r"(?<![A-Za-z0-9_'])undefined(?![A-Za-z0-9_'])", line) or \
                re.search(r"(?<![A-Za-z0-9_'])error\s+\"", line):
            findings.append(_finding(
                path, idx, "haskell", "polyglot-hs-bottom-value", "HIGH", 0.82,
                "bottom value can turn a rare path into a runtime crash",
                "Return a typed error value or make the impossible state unrepresentable."))
        if "!!" in line:
            findings.append(_finding(
                path, idx, "haskell", "polyglot-hs-partial-index", "MEDIUM", 0.85,
                "list indexing with !! crashes on out-of-range input",
                "Use safe indexing that returns Maybe, or pattern match structurally."))
    return findings


_DIV_WORD = "d" + "iv"


def _scan_asm(text: str, path: str) -> list[Finding]:
    findings = []
    lines = text.splitlines()
    stack_depth = 0
    for idx, raw in enumerate(lines, start=1):
        line = _strip_line_comment(raw, "asm").strip().lower()
        if not line:
            continue
        if re.match(r"^[a-z_.$][\w.$]*:", line):
            stack_depth = 0
            continue
        if re.match(r"\bpush\b", line):
            stack_depth += 1
        if re.match(r"\bpop\b", line) and stack_depth > 0:
            stack_depth -= 1
        if re.match(r"\bret\b", line) and stack_depth:
            findings.append(_finding(
                path, idx, "asm", "polyglot-asm-stack-imbalance", "HIGH", 0.74,
                "function returns while push/pop depth appears imbalanced",
                "Restore every saved register and stack slot before ret."))
            stack_depth = 0
        if re.match(r"\b(?:idiv|div)\b", line):
            window = "\n".join(_strip_line_comment(x, "asm").lower()
                               for x in lines[max(0, idx - 5):idx - 1])
            prepared = any(token in window for token in (
                "xor edx, edx", "xor rdx, rdx", "cdq", "cqo", "cwd"))
            if not prepared:
                findings.append(_finding(
                    path, idx, "asm", "polyglot-asm-division-high-half", "HIGH", 0.79,
                    "division uses implicit high-half register, but no nearby preparation was seen",
                    "Clear/sign-extend the high half (xor edx,edx, cdq, cqo, etc.) before division."))
        if re.match(r"\brep\s+(?:movs|stos)", line):
            window = "\n".join(_strip_line_comment(x, "asm").lower()
                               for x in lines[max(0, idx - 8):idx - 1])
            if "cld" not in window:
                findings.append(_finding(
                    path, idx, "asm", "polyglot-asm-direction-flag", "MEDIUM", 0.72,
                    "rep string instruction depends on the direction flag, but no nearby cld was seen",
                    "Clear DF with cld before forward rep movs/stos unless reverse traversal is intended."))
        if "call" in line and "rsp" in line and re.search(r"sub\s+rsp\s*,\s*8\b", line):
            findings.append(_finding(
                path, idx, "asm", "polyglot-asm-stack-alignment-shape", "LOW", 0.55,
                "stack alignment around a call is suspicious",
                "Keep ABI-required stack alignment before calls."))
    return findings


def language_for(path: Path) -> str:
    return LANG_BY_SUFFIX.get(path.suffix, "")


def collect_paths(paths) -> list[Path]:
    out = []
    for raw in paths:
        root = Path(raw)
        if root.is_file() and language_for(root):
            out.append(root)
        elif root.is_dir():
            for current, dirs, files in os.walk(root):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for name in files:
                    path = Path(current) / name
                    if language_for(path):
                        out.append(path)
    return sorted(out, key=lambda item: str(item).lower())


def scan_file(path: Path) -> list[Finding]:
    lang = language_for(path)
    if not lang:
        return []
    try:
        if path.stat().st_size > MAX_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    label = str(path)
    if lang in {"c", "cpp"}:
        return _scan_c_family(text, label, lang)
    if lang == "haskell":
        return _scan_haskell(text, label)
    if lang == "asm":
        return _scan_asm(text, label)
    return []


def scan(paths) -> dict:
    files = collect_paths(paths)
    findings = []
    for path in files:
        findings.extend(scan_file(path))
    findings.sort(key=Finding.sort_key)
    return {"scanned_files": len(files), "findings": findings}


def summary(findings: list[Finding]) -> dict:
    counts = {key: 0 for key in SEVERITY_RANK}
    by_language = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
        by_language[finding.language] = by_language.get(finding.language, 0) + 1
    return {"severity": counts, "languages": by_language}


def render(report: dict) -> str:
    findings = report["findings"]
    totals = summary(findings)
    lines = [
        "Polyglot tiny-error report",
        "=" * 64,
        "Scanned files: %d" % report["scanned_files"],
        "Findings: %d" % len(findings),
        "Severity: " + ", ".join("%s=%d" % (key, totals["severity"].get(key, 0))
                                  for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")),
        "",
    ]
    if not findings:
        lines.append("No C/C++/Haskell/Assembly tiny-error findings.")
        return "\n".join(lines)
    for finding in findings:
        lines.extend([
            "[%s] %s:%d  %s" % (
                finding.severity, finding.path, finding.line, finding.rule),
            "  language: %s  confidence: %.2f" % (
                finding.language, finding.confidence),
            "  detail: " + finding.detail,
            "  fix: " + finding.fix,
            "",
        ])
    return "\n".join(lines).rstrip()


def to_json(report: dict) -> str:
    payload = {
        "scanned_files": report["scanned_files"],
        "summary": summary(report["findings"]),
        "findings": [asdict(item) for item in report["findings"]],
    }
    return json.dumps(payload, indent=2)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="C/C++/Haskell/Assembly files or folders")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    report = scan(args.paths)
    print(to_json(report) if args.json else render(report))
    return min(len(report["findings"]), 250)


if __name__ == "__main__":
    raise SystemExit(main())
