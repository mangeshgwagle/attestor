#!/usr/bin/env python3
"""Bounded, deterministic, parsing-only polyglot IR for Attestor 3.5.

The module builds a deliberately modest common representation for JavaScript,
TypeScript, Java, C#, Go, Rust, C/C++, and PHP.  It reads source and declarative
manifest files; it never imports a target module, runs a compiler/build script,
executes target code, starts a process, or uses the network.

This is a lexical index, not a compiler front end.  Every report says so and
records files it could not read completely.  Consumers must not treat a missing
edge as proof that an edge does not exist.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any


SCHEMA = "attestor-polyglot-ir/3.5"
ANALYSIS_LEVEL = "bounded-lexical"
MAX_FILES = 10_000
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_ITEMS_PER_KIND = 10_000

SKIP_DIRS = {
    ".git", ".hg", ".svn", ".idea", ".vscode", "__pycache__",
    "node_modules", "vendor", ".venv", "venv", "dist", "build",
    "target", "bin", "obj", ".gradle", ".cargo", ".next", "coverage",
}

LANGUAGE_BY_SUFFIX = {
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".mts": "typescript", ".cts": "typescript", ".java": "java",
    ".cs": "csharp", ".go": "go", ".rs": "rust", ".c": "c",
    ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hh": "cpp", ".hpp": "cpp", ".hxx": "cpp", ".php": "php",
    ".phtml": "php",
}

_MANIFEST_NAMES = {
    "package.json": "npm", "package-lock.json": "npm-lock",
    "tsconfig.json": "typescript-config", "jsconfig.json": "javascript-config",
    "pom.xml": "maven", "go.mod": "go-mod", "go.sum": "go-sum",
    "cargo.toml": "cargo", "cargo.lock": "cargo-lock",
    "composer.json": "composer", "composer.lock": "composer-lock",
    "nuget.config": "nuget", "cmakepresets.json": "cmake-presets",
}

_IDENT = r"[A-Za-z_$][A-Za-z0-9_$]*"
_QUALIFIED = _IDENT + r"(?:\s*(?:\.|::|->|\\)\s*" + _IDENT + r")*"
_CALL_EXCLUSIONS = {
    "if", "for", "while", "switch", "catch", "return", "throw", "new",
    "sizeof", "typeof", "alignof", "decltype", "static_cast",
    "dynamic_cast", "reinterpret_cast", "const_cast", "function", "func",
    "fn", "match", "foreach", "echo", "isset", "empty", "include",
    "require", "require_once", "include_once", "defined", "delete",
}


def _sha(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def deterministic_json(value: Any, *, pretty: bool = False) -> str:
    """Serialize an IR or cache input deterministically."""
    if pretty:
        return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def language_for(path: Path) -> str:
    return LANGUAGE_BY_SUFFIX.get(path.suffix.lower(), "")


def manifest_kind(path: Path) -> str:
    lower = path.name.lower()
    if lower in _MANIFEST_NAMES:
        return _MANIFEST_NAMES[lower]
    if lower.endswith(".csproj") or lower.endswith(".fsproj") or lower.endswith(".vbproj"):
        return "dotnet-project"
    if lower.endswith(".sln"):
        return "dotnet-solution"
    return ""


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _strip_comments(text: str, language: str) -> str:
    """Replace comments with spaces while preserving strings and line offsets."""
    out = list(text)
    size = len(text)
    i = 0
    quote = ""
    escaped = False
    block_depth = 0
    while i < size:
        char = text[i]
        nxt = text[i + 1] if i + 1 < size else ""
        if block_depth:
            if language == "rust" and char == "/" and nxt == "*":
                out[i] = out[i + 1] = " "
                block_depth += 1
                i += 2
                continue
            if char == "*" and nxt == "/":
                out[i] = out[i + 1] = " "
                block_depth -= 1
                i += 2
                continue
            if char != "\n":
                out[i] = " "
            i += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            i += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            i += 1
            continue
        if char == "/" and nxt == "*":
            out[i] = out[i + 1] = " "
            block_depth = 1
            i += 2
            continue
        if char == "/" and nxt == "/":
            while i < size and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if language == "php" and char == "#" and nxt != "[":
            while i < size and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


def _mask_literals(text: str) -> str:
    """Mask quoted content without changing offsets or newlines."""
    out = list(text)
    quote = ""
    escaped = False
    for i, char in enumerate(text):
        if quote:
            if char != "\n":
                out[i] = " "
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            out[i] = " "
            quote = char
    return "".join(out)


def _balanced_gap(text: str, path: str) -> list[dict[str, Any]]:
    masked = _mask_literals(text)
    pairs = {"(": ")", "[": "]", "{": "}"}
    reverse = {value: key for key, value in pairs.items()}
    stack: list[tuple[str, int]] = []
    for offset, char in enumerate(masked):
        if char in pairs:
            stack.append((char, offset))
        elif char in reverse:
            if not stack or stack[-1][0] != reverse[char]:
                return [{"path": path, "line": _line(text, offset),
                         "kind": "parse-shape",
                         "message": "unbalanced closing delimiter; lexical IR may be incomplete"}]
            stack.pop()
    if stack:
        char, offset = stack[-1]
        return [{"path": path, "line": _line(text, offset),
                 "kind": "parse-shape",
                 "message": "unclosed delimiter; lexical IR may be incomplete"}]
    return []


def _module_name(text: str, language: str, fallback: str) -> str:
    patterns = {
        "java": r"\bpackage\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*;",
        "csharp": r"\bnamespace\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)",
        "go": r"(?m)^\s*package\s+([A-Za-z_]\w*)\b",
        "php": r"\bnamespace\s+([A-Za-z_]\w*(?:\\[A-Za-z_]\w*)*)\s*;",
    }
    match = re.search(patterns.get(language, r"(?!x)x"), text)
    return match.group(1).replace("\\", ".") if match else fallback


def _imports(text: str, language: str, path: str) -> list[dict[str, Any]]:
    if language == "go":
        found = []
        single = re.compile(
            r"(?m)^\s*import\s+(?:[A-Za-z_.][A-Za-z0-9_.]*\s+)?[\"`]([^\"`\r\n]+)[\"`]")
        for match in single.finditer(text):
            found.append({"path": path, "line": _line(text, match.start()),
                          "kind": "import", "specifier": match.group(1)[:512]})
        for block in re.finditer(r"\bimport\s*\(([^)]{0,65536})\)", text, flags=re.DOTALL):
            for match in re.finditer(
                    r"(?m)^\s*(?:[A-Za-z_.][A-Za-z0-9_.]*\s+)?[\"`]([^\"`\r\n]+)[\"`]",
                    block.group(1)):
                offset = block.start(1) + match.start()
                found.append({"path": path, "line": _line(text, offset),
                              "kind": "import", "specifier": match.group(1)[:512]})
        return sorted(found, key=lambda item: (item["line"], item["specifier"]))
    patterns: list[tuple[str, str]] = []
    if language in {"javascript", "typescript"}:
        patterns = [
            ("module", r"\b(?:import|export)\s+(?:[^;\n]*?\s+from\s+)?['\"]([^'\"\r\n]+)['\"]"),
            ("require", r"\brequire\s*\(\s*['\"]([^'\"\r\n]+)['\"]\s*\)"),
            ("dynamic", r"\bimport\s*\(\s*['\"]([^'\"\r\n]+)['\"]\s*\)"),
        ]
    elif language == "java":
        patterns = [("import", r"(?m)^\s*import\s+(?:static\s+)?([A-Za-z_]\w*(?:\.[A-Za-z_*]\w*)*)\s*;")]
    elif language == "csharp":
        patterns = [("using", r"(?m)^\s*(?:global\s+)?using\s+(?:[A-Za-z_]\w*\s*=\s*)?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*;")]
    elif language == "rust":
        patterns = [
            ("use", r"(?m)^\s*(?:pub\s+)?use\s+([^;\r\n]+)\s*;"),
            ("module", r"(?m)^\s*(?:pub\s+)?mod\s+([A-Za-z_]\w*)\s*;"),
            ("extern", r"(?m)^\s*extern\s+crate\s+([A-Za-z_]\w*)\s*;"),
        ]
    elif language in {"c", "cpp"}:
        patterns = [("include", r"(?m)^\s*#\s*include\s*[<\"]([^>\"\r\n]+)[>\"]")]
    elif language == "php":
        patterns = [
            ("use", r"(?m)^\s*use\s+([A-Za-z_]\w*(?:\\[A-Za-z_]\w*)*)"),
            ("require", r"\b(?:require|require_once|include|include_once)\s*\(?\s*['\"]([^'\"\r\n]+)['\"]"),
        ]
    found = []
    for kind, pattern in patterns:
        for match in re.finditer(pattern, text):
            specifier = " ".join(match.group(1).split())[:512]
            found.append({"path": path, "line": _line(text, match.start()),
                          "kind": kind, "specifier": specifier})
    return sorted(found, key=lambda item: (item["line"], item["kind"], item["specifier"]))


def _types(text: str, language: str, path: str) -> list[dict[str, Any]]:
    pattern_by_language = {
        "javascript": r"\b(class)\s+(" + _IDENT + r")",
        "typescript": r"\b(class|interface|type|enum|namespace)\s+(" + _IDENT + r")",
        "java": r"\b(class|interface|enum|record|@interface)\s+(" + _IDENT + r")",
        "csharp": r"\b(class|interface|struct|record|enum)\s+(" + _IDENT + r")",
        "go": r"\btype\s+(" + _IDENT + r")\s+(struct|interface|[A-Za-z_]\w*)",
        "rust": r"\b(struct|enum|trait|union|type)\s+(" + _IDENT + r")",
        "c": r"\b(struct|enum|union)\s+(" + _IDENT + r")",
        "cpp": r"\b(class|struct|enum|union)\s+(" + _IDENT + r")",
        "php": r"\b(class|interface|trait|enum)\s+(" + _IDENT + r")",
    }
    pattern = pattern_by_language[language]
    found = []
    for match in re.finditer(pattern, text):
        if language == "go":
            name, kind = match.group(1), match.group(2)
        else:
            kind, name = match.group(1), match.group(2)
        found.append({"path": path, "line": _line(text, match.start()),
                      "kind": kind.lstrip("@"), "name": name})
    return found


def _parameter_count(raw: str) -> int | None:
    value = raw.strip()
    if not value:
        return 0
    if len(value) > 4096 or "(" in value or ")" in value:
        return None
    return value.count(",") + 1


def _functions(text: str, language: str, path: str) -> list[dict[str, Any]]:
    patterns: list[tuple[str, str]] = []
    if language in {"javascript", "typescript"}:
        patterns = [
            ("function", r"\b(?:async\s+)?function\s*\*?\s*(" + _IDENT + r")\s*\(([^()]{0,4096})\)"),
            ("arrow", r"\b(?:const|let|var)\s+(" + _IDENT + r")\s*(?::[^=\n]{0,256})?=\s*(?:async\s*)?\(([^()]{0,4096})\)\s*=>"),
        ]
    elif language == "go":
        patterns = [("function", r"\bfunc\s+(?:\([^()]{0,512}\)\s*)?(" + _IDENT + r")\s*\(([^()]{0,4096})\)")]
    elif language == "rust":
        patterns = [("function", r"\b(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(" + _IDENT + r")\s*\(([^()]{0,4096})\)")]
    elif language == "php":
        patterns = [("function", r"\bfunction\s*&?\s*(" + _IDENT + r")\s*\(([^()]{0,4096})\)")]
    else:
        # This bounded signature shape intentionally ignores macros and complex
        # declarators.  Coverage metadata makes that limitation explicit.
        patterns = [("method-or-function",
                     r"(?m)^\s*(?:(?:@[A-Za-z_$][\w$]*(?:\([^\r\n)]{0,512}\))?|\[[^\]\r\n]{0,512}\])\s*)*"
                     r"(?:(?:public|private|protected|internal|static|final|abstract|virtual|override|sealed|synchronized|native|extern|inline|constexpr|friend|template\s*<[^>]{0,256}>)\s+){0,8}"
                     r"(?:[A-Za-z_$][\w$:<>,.?\[\]*&\s]{0,256}\s+)?(" + _IDENT + r")\s*\(([^()]{0,4096})\)\s*(?:const\s*)?(?:throws\s+[^\{;]+)?\{")]
    found = []
    for kind, pattern in patterns:
        for match in re.finditer(pattern, text):
            name = match.group(1)
            if name in _CALL_EXCLUSIONS:
                continue
            line_number = _line(text, match.start())
            source_line = text.splitlines()[line_number - 1] if text.splitlines() else ""
            if re.search(r"\b(?:class|interface|struct|record|enum|union|trait)\s+" +
                         re.escape(name) + r"\s*\(", source_line):
                continue
            found.append({"path": path, "line": _line(text, match.start()),
                          "kind": kind, "name": name,
                          "parameter_count": _parameter_count(match.group(2))})
    unique = {(item["line"], item["name"], item["kind"]): item for item in found}
    return sorted(unique.values(), key=lambda item: (item["line"], item["name"], item["kind"]))


def _calls(text: str, functions: list[dict[str, Any]], path: str) -> list[dict[str, Any]]:
    masked = _mask_literals(text)
    declaration_lines = {(item["line"], item["name"]) for item in functions}
    found = []
    pattern = re.compile(r"(?<![\w$])(" + _QUALIFIED + r")\s*\(")
    for match in pattern.finditer(masked):
        target = re.sub(r"\s+", "", match.group(1))
        short = re.split(r"\.|::|->|\\", target)[-1]
        line = _line(masked, match.start())
        if short in _CALL_EXCLUSIONS or (line, short) in declaration_lines:
            continue
        found.append({"path": path, "line": line, "target": target[:512],
                      "resolution": "unresolved-lexical"})
    unique = {(item["line"], item["target"]): item for item in found}
    return sorted(unique.values(), key=lambda item: (item["line"], item["target"]))


def _routes(text: str, language: str, path: str) -> list[dict[str, Any]]:
    patterns: list[tuple[str, str]] = []
    if language in {"javascript", "typescript"}:
        patterns = [
            ("$1", r"\b(?:app|router|server|fastify)\s*\.\s*(get|post|put|patch|delete|options|head|use)\s*\(\s*['\"]([^'\"\r\n]+)['\"]"),
            ("$1", r"@\s*(Get|Post|Put|Patch|Delete|Options|Head)\s*\(\s*['\"]([^'\"\r\n]+)['\"]"),
        ]
    elif language == "java":
        patterns = [("$1", r"@\s*(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\s*\(\s*(?:value\s*=\s*)?['\"]([^'\"\r\n]+)['\"]")]
    elif language == "csharp":
        patterns = [
            ("$1", r"\[\s*(HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete|Route)\s*\(\s*['\"]([^'\"\r\n]+)['\"]"),
            ("$1", r"\bMap(Get|Post|Put|Patch|Delete)\s*\(\s*['\"]([^'\"\r\n]+)['\"]"),
        ]
    elif language == "go":
        patterns = [("$1", r"\b(HandleFunc|Handle|GET|POST|PUT|PATCH|DELETE)\s*\(\s*['\"]([^'\"\r\n]+)['\"]")]
    elif language == "rust":
        patterns = [
            ("$1", r"#\s*\[\s*(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"\r\n]+)['\"]"),
            ("route", r"\.\s*route\s*\(\s*['\"]([^'\"\r\n]+)['\"]"),
        ]
    elif language == "php":
        patterns = [("$1", r"\bRoute\s*::\s*(get|post|put|patch|delete|options|any)\s*\(\s*['\"]([^'\"\r\n]+)['\"]")]
    found = []
    for method_hint, pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            if match.lastindex == 2:
                method, route = match.group(1), match.group(2)
            else:
                method, route = method_hint, match.group(1)
            method = re.sub(r"(?:mapping|http|map)", "", method, flags=re.IGNORECASE) or "route"
            if method.casefold() in {"handle", "handlefunc"}:
                method = "ANY"
            found.append({"path": path, "line": _line(text, match.start()),
                          "method": method.upper(), "route": route[:1024],
                          "evidence": "literal-lexical"})
    return sorted(found, key=lambda item: (item["line"], item["method"], item["route"]))


def _manifest(path: str, kind: str, raw: bytes, text: str) -> dict[str, Any]:
    """Return names and structure only; never retain manifest values or scripts."""
    result: dict[str, Any] = {"path": path, "kind": kind, "sha256": _sha(raw),
                              "bytes": len(raw), "keys": [], "dependencies": [],
                              "parse_gap": ""}
    if kind in {"npm", "npm-lock", "typescript-config", "javascript-config",
                "composer", "composer-lock", "cmake-presets"}:
        try:
            value = json.loads(text)
        except (json.JSONDecodeError, UnicodeError):
            result["parse_gap"] = "invalid JSON; manifest names were not extracted"
            return result
        if isinstance(value, dict):
            result["keys"] = sorted(str(key)[:256] for key in value)[:2_000]
            for section in ("dependencies", "devDependencies", "peerDependencies",
                            "optionalDependencies", "require", "require-dev", "packages"):
                members = value.get(section)
                if isinstance(members, dict):
                    result["dependencies"].extend(str(key)[:512] for key in members
                                                  if key and key != "")
            if kind in {"typescript-config", "javascript-config"}:
                options = value.get("compilerOptions")
                if isinstance(options, dict):
                    result["keys"].extend("compilerOptions." + str(key)[:220]
                                          for key in options)
    elif kind in {"cargo", "cargo-lock"}:
        sections = re.findall(r"(?m)^\s*\[([^\]\r\n]{1,256})\]", text)
        result["keys"] = sorted(set(sections))[:2_000]
        in_dependencies = False
        for line in text.splitlines():
            section = re.match(r"\s*\[([^\]]+)\]", line)
            if section:
                in_dependencies = section.group(1).lower().endswith("dependencies")
                continue
            if in_dependencies:
                dependency = re.match(r"\s*([A-Za-z0-9_.-]+)\s*=", line)
                if dependency:
                    result["dependencies"].append(dependency.group(1))
    elif kind == "go-mod":
        for match in re.finditer(r"(?m)^\s*(?:require\s+)?([A-Za-z0-9._~/-]+)\s+v\d", text):
            result["dependencies"].append(match.group(1))
        result["keys"] = sorted(set(re.findall(r"(?m)^\s*(module|go|toolchain|require|replace|exclude|retract)\b", text)))
    elif kind in {"maven", "dotnet-project", "nuget"}:
        result["keys"] = sorted(set(re.findall(r"<([A-Za-z_][A-Za-z0-9_.:-]*)\b", text)))[:2_000]
        result["dependencies"] = sorted(set(re.findall(
            r"<(?:PackageReference|dependency|artifactId)\b[^>]*(?:Include\s*=\s*['\"]([^'\"]+)['\"]|>\s*([^<\s]+))",
            text, flags=re.IGNORECASE)))[:2_000]
        result["dependencies"] = [next((part for part in item if part), "")
                                  for item in result["dependencies"]]
    result["keys"] = sorted(set(result["keys"]))[:2_000]
    result["dependencies"] = sorted(set(filter(None, result["dependencies"])))[:5_000]
    return result


def _parse_source(relative: str, language: str, raw: bytes, text: str,
                  decode_gap: bool) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    commentless = _strip_comments(text, language)
    fallback = Path(relative).with_suffix("").as_posix().replace("/", ".")
    functions = _functions(commentless, language, relative)
    record = {
        "path": relative, "language": language, "sha256": _sha(raw),
        "bytes": len(raw), "module": _module_name(commentless, language, fallback),
        "imports": _imports(commentless, language, relative),
        "types": _types(_mask_literals(commentless), language, relative),
        "functions": functions,
        "calls": _calls(commentless, functions, relative),
        "routes": _routes(commentless, language, relative),
        "analysis_level": ANALYSIS_LEVEL,
    }
    gaps = _balanced_gap(commentless, relative)
    if decode_gap:
        gaps.append({"path": relative, "line": 1, "kind": "decode-replacement",
                     "message": "invalid UTF-8 bytes were replaced; lexical IR may be incomplete"})
    for kind in ("imports", "types", "functions", "calls", "routes"):
        if len(record[kind]) > MAX_ITEMS_PER_KIND:
            record[kind] = record[kind][:MAX_ITEMS_PER_KIND]
            gaps.append({"path": relative, "line": 1, "kind": "item-boundary",
                         "message": kind + " exceeded the per-file item boundary"})
    return record, gaps


def _safe_relative(root: Path, path: Path) -> str:
    resolved = path.resolve(strict=False)
    return resolved.relative_to(root).as_posix()


def _candidates(requested: Path, root: Path) -> tuple[list[Path], list[dict[str, Any]]]:
    gaps: list[dict[str, Any]] = []
    if requested.is_file():
        return [requested], gaps
    candidates: list[Path] = []
    for current, directories, filenames in os.walk(requested, followlinks=False):
        here = Path(current)
        kept = []
        for name in sorted(directories, key=str.casefold):
            child = here / name
            if name in SKIP_DIRS:
                continue
            if child.is_symlink():
                try:
                    label = _safe_relative(root, child)
                except (OSError, ValueError):
                    label = name
                gaps.append({"path": label, "line": 1, "kind": "symlink-skipped",
                             "message": "directory symlinks are not followed"})
                continue
            kept.append(name)
        directories[:] = kept
        for name in sorted(filenames, key=str.casefold):
            item = here / name
            if language_for(item) or manifest_kind(item):
                candidates.append(item)
    # Sort lexically without resolving links.  Resolution happens under the
    # guarded path check before a candidate is read.
    return sorted(candidates, key=lambda item: item.relative_to(root).as_posix().casefold()), gaps


def analyze(root: str | os.PathLike[str], *, max_files: int = MAX_FILES,
            max_file_bytes: int = MAX_FILE_BYTES,
            max_total_bytes: int = MAX_TOTAL_BYTES) -> dict[str, Any]:
    """Build the bounded common IR.  Failures become explicit coverage gaps."""
    if not all(isinstance(value, int) and value > 0 for value in
               (max_files, max_file_bytes, max_total_bytes)):
        raise ValueError("analysis boundaries must be positive integers")
    requested_text = os.fspath(root)
    report: dict[str, Any] = {
        "schema": SCHEMA, "analysis_level": ANALYSIS_LEVEL, "root": "",
        "files": [], "modules": [], "imports": [], "types": [],
        "functions": [], "calls": [], "routes": [], "manifests": [],
        "parse_gaps": [],
        "coverage": {
            "complete": False, "supported_files_discovered": 0,
            "completeness_kind": "bounded-input-coverage-only",
            "semantic_complete": False,
            "source_files_parsed": 0, "manifest_files_parsed": 0,
            "bytes_read": 0, "languages": {},
            "limits": {"max_files": max_files, "max_file_bytes": max_file_bytes,
                       "max_total_bytes": max_total_bytes},
            "limitations": [
                "lexical extraction does not resolve types, overloads, macros, or dynamic dispatch",
                "generated, vendored, binary, oversized, unreadable, and linked files may be skipped",
                "no target code, build scripts, package hooks, compilers, or network services are run",
            ],
        },
    }
    try:
        if "\0" in requested_text:
            raise ValueError("NUL byte in path")
        requested = Path(requested_text).expanduser().resolve()
    except (OSError, RuntimeError, ValueError, TypeError) as exc:
        report["parse_gaps"].append({"path": "<invalid>", "line": 1,
                                     "kind": "invalid-root", "message": str(exc)[:300]})
        return report
    report["root"] = str(requested)
    if not requested.exists() or not (requested.is_dir() or requested.is_file()):
        report["parse_gaps"].append({"path": str(requested), "line": 1,
                                     "kind": "invalid-root",
                                     "message": "analysis root is not a file or directory"})
        return report
    scan_root = requested.parent if requested.is_file() else requested
    try:
        candidates, discovery_gaps = _candidates(requested, scan_root)
    except (OSError, ValueError) as exc:
        report["parse_gaps"].append({"path": str(requested), "line": 1,
                                     "kind": "discovery-error", "message": str(exc)[:300]})
        return report
    report["parse_gaps"].extend(discovery_gaps)
    report["coverage"]["supported_files_discovered"] = len(candidates)
    total = 0
    for index, path in enumerate(candidates):
        try:
            relative = _safe_relative(scan_root, path)
        except (OSError, ValueError):
            report["parse_gaps"].append({"path": path.name, "line": 1,
                                         "kind": "path-escape",
                                         "message": "candidate resolves outside the analysis root"})
            continue
        if index >= max_files:
            report["parse_gaps"].append({"path": relative, "line": 1,
                                         "kind": "file-boundary",
                                         "message": "file boundary reached; remaining files were not read"})
            break
        if path.is_symlink():
            report["parse_gaps"].append({"path": relative, "line": 1,
                                         "kind": "symlink-skipped",
                                         "message": "file symlinks are not read"})
            continue
        try:
            size = path.stat().st_size
        except OSError as exc:
            report["parse_gaps"].append({"path": relative, "line": 1,
                                         "kind": "unreadable", "message": str(exc)[:300]})
            continue
        if size > max_file_bytes:
            report["parse_gaps"].append({"path": relative, "line": 1,
                                         "kind": "file-too-large",
                                         "message": "file exceeds the configured byte boundary"})
            continue
        if total + size > max_total_bytes:
            report["parse_gaps"].append({"path": relative, "line": 1,
                                         "kind": "total-byte-boundary",
                                         "message": "total byte boundary reached; file was not read"})
            continue
        try:
            with path.open("rb") as handle:
                raw = handle.read(max_file_bytes + 1)
        except OSError as exc:
            report["parse_gaps"].append({"path": relative, "line": 1,
                                         "kind": "unreadable", "message": str(exc)[:300]})
            continue
        if len(raw) > max_file_bytes:
            report["parse_gaps"].append({"path": relative, "line": 1,
                                         "kind": "file-grew-too-large",
                                         "message": "file crossed the byte boundary while being read"})
            continue
        if b"\0" in raw[:8192]:
            report["parse_gaps"].append({"path": relative, "line": 1,
                                         "kind": "binary-skipped",
                                         "message": "NUL bytes indicate a non-text file"})
            continue
        total += len(raw)
        report["coverage"]["bytes_read"] = total
        try:
            text = raw.decode("utf-8")
            decode_gap = False
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
            decode_gap = True
        kind = manifest_kind(path)
        if kind:
            manifest = _manifest(relative, kind, raw, text)
            report["manifests"].append(manifest)
            report["coverage"]["manifest_files_parsed"] += 1
            if manifest["parse_gap"]:
                report["parse_gaps"].append({"path": relative, "line": 1,
                                             "kind": "manifest-parse",
                                             "message": manifest["parse_gap"]})
        language = language_for(path)
        if language:
            record, gaps = _parse_source(relative, language, raw, text, decode_gap)
            report["files"].append(record)
            report["parse_gaps"].extend(gaps)
            report["coverage"]["source_files_parsed"] += 1
            stats = report["coverage"]["languages"].setdefault(
                language, {"files": 0, "bytes": 0, "analysis_level": ANALYSIS_LEVEL})
            stats["files"] += 1
            stats["bytes"] += len(raw)
    for record in report["files"]:
        report["modules"].append({"path": record["path"], "language": record["language"],
                                  "name": record["module"]})
        for key in ("imports", "types", "functions", "calls", "routes"):
            report[key].extend(record[key])
    for key in ("files", "modules", "imports", "types", "functions", "calls",
                "routes", "manifests", "parse_gaps"):
        report[key] = sorted(report[key], key=lambda item: deterministic_json(item))
    bounded_gap_kinds = {"invalid-root", "discovery-error", "path-escape", "unreadable",
                         "file-too-large", "file-boundary", "total-byte-boundary",
                         "file-grew-too-large", "binary-skipped", "symlink-skipped",
                         "decode-replacement", "parse-shape", "manifest-parse",
                         "item-boundary"}
    report["coverage"]["complete"] = not any(
        item.get("kind") in bounded_gap_kinds for item in report["parse_gaps"])
    return report


def content_fingerprint(report: dict[str, Any]) -> str:
    """Hash the portable IR content, excluding the machine-specific root."""
    portable = {key: value for key, value in report.items() if key != "root"}
    return _sha(deterministic_json(portable))


__all__ = [
    "SCHEMA", "ANALYSIS_LEVEL", "MAX_FILES", "MAX_FILE_BYTES",
    "MAX_TOTAL_BYTES", "analyze", "content_fingerprint", "deterministic_json",
    "language_for", "manifest_kind",
]
