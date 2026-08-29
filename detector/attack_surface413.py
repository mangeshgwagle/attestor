#!/usr/bin/env python3
"""Attestor 4.1.3 bounded attack-surface and web/API security analysis.

This module is deliberately defensive and static.  It reads a bounded,
content-addressed snapshot of source and configuration files, but never imports
or executes target code, starts a child process, contacts a network service, or
writes to the target.  A reported attack path is static evidence about a
possible route through the program; it is not a claim that exploitation was
attempted or proved at runtime.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import heapq
import json
import os
import re
import stat
from collections import Counter, deque
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable, Mapping, Sequence


VERSION = "4.1.3"
SCHEMA = "attestor.attack-surface/4.1"

MAX_FILES_HARD = 10_000
MAX_FILE_BYTES_HARD = 4 * 1024 * 1024
MAX_TOTAL_BYTES_HARD = 128 * 1024 * 1024
MAX_AST_NODES_HARD = 2_000_000
MAX_GRAPH_NODES_HARD = 50_000
MAX_GRAPH_EDGES_HARD = 100_000
MAX_FINDINGS_HARD = 10_000
MAX_ATTACK_PATHS_HARD = 2_000
MAX_GAPS_HARD = 10_000
MAX_DIRECTORY_ENTRIES_HARD = 100_000
MAX_EVIDENCE_PER_FINDING = 8
MAX_PATH_DEPTH = 12
MAX_SAFE_TEXT = 4_096
MAX_REPORT_BYTES = 30 * 1024 * 1024

_SKIP_DIRECTORIES = frozenset({
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", ".venv", "venv", "node_modules", "vendor",
    "dist", "build", "target", ".terraform", ".next", ".gradle", "bin",
    "obj", "coverage", "htmlcov",
})
_TEXT_SUFFIXES = frozenset({
    ".py", ".pyw", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts",
    ".cts", ".java", ".kt", ".kts", ".go", ".rs", ".rb", ".php", ".cs",
    ".scala", ".swift", ".c", ".cc", ".cpp", ".h", ".hpp", ".sql", ".graphql",
    ".gql", ".json", ".json5", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".conf", ".properties", ".xml", ".env", ".tf", ".hcl", ".proto",
})
_TEXT_NAMES = frozenset({
    "dockerfile", "containerfile", "gemfile", "procfile", "nginx.conf",
    "apache2.conf", "httpd.conf", "openapi", "swagger",
})
_LANGUAGE = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".mts": "typescript", ".cts": "typescript",
    ".yaml": "yaml", ".yml": "yaml", ".json": "json", ".toml": "toml",
    ".tf": "terraform", ".sql": "sql", ".graphql": "graphql", ".gql": "graphql",
}
_BIDI_CONTROLS = frozenset({
    0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2066, 0x2067, 0x2068, 0x2069,
})
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_BASE = {"critical": 48, "high": 38, "medium": 26, "low": 14, "info": 5}


class AttackSurface413Error(ValueError):
    """Raised for invalid caller-controlled limits or report data."""


@dataclass(frozen=True)
class Limits:
    """Caller-adjustable budgets with non-bypassable hard ceilings."""

    max_files: int = 2_500
    max_file_bytes: int = 1024 * 1024
    max_total_bytes: int = 32 * 1024 * 1024
    max_ast_nodes: int = 350_000
    max_graph_nodes: int = 8_000
    max_graph_edges: int = 16_000
    max_findings: int = 2_000
    max_attack_paths: int = 300
    max_gaps: int = 2_000
    max_directory_entries: int = 20_000

    def __post_init__(self) -> None:
        ceilings = {
            "max_files": MAX_FILES_HARD,
            "max_file_bytes": MAX_FILE_BYTES_HARD,
            "max_total_bytes": MAX_TOTAL_BYTES_HARD,
            "max_ast_nodes": MAX_AST_NODES_HARD,
            "max_graph_nodes": MAX_GRAPH_NODES_HARD,
            "max_graph_edges": MAX_GRAPH_EDGES_HARD,
            "max_findings": MAX_FINDINGS_HARD,
            "max_attack_paths": MAX_ATTACK_PATHS_HARD,
            "max_gaps": MAX_GAPS_HARD,
            "max_directory_entries": MAX_DIRECTORY_ENTRIES_HARD,
        }
        for name, ceiling in ceilings.items():
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= ceiling:
                raise AttackSurface413Error(
                    f"{name} must be an integer between 1 and {ceiling}")

    def public(self) -> dict[str, int]:
        return dict(sorted(asdict(self).items()))


@dataclass(frozen=True)
class _Source:
    path: str
    language: str
    raw: bytes
    text: str
    sha256: str
    decoded_with_replacement: bool


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise AttackSurface413Error("report evidence must be bounded JSON data") from exc


def _sha(value: Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _stable_id(prefix: str, value: Any) -> str:
    return prefix + _sha(value)[:24]


def _safe_text(value: Any, maximum: int = MAX_SAFE_TEXT) -> str:
    """Escape terminal controls and bidi controls in every source-derived label."""
    raw = str(value)
    pieces: list[str] = []
    used = 0
    for char in raw:
        point = ord(char)
        replacement = (
            f"\\u{point:04X}"
            if point < 0x20 or 0x7F <= point <= 0x9F or point in _BIDI_CONTROLS
            else char
        )
        if used + len(replacement) > maximum:
            pieces.append("...")
            break
        pieces.append(replacement)
        used += len(replacement)
    return "".join(pieces)


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _language(path: str) -> str:
    pure = PurePosixPath(path)
    name = pure.name.casefold()
    if name in {"dockerfile", "containerfile"}:
        return "container"
    return _LANGUAGE.get(pure.suffix.casefold(), "text")


def _eligible(name: str) -> bool:
    pure = PurePosixPath(name)
    folded = pure.name.casefold()
    return (
        pure.suffix.casefold() in _TEXT_SUFFIXES
        or folded in _TEXT_NAMES
        or folded.startswith(".env.")
        or folded in {".env", "docker-compose.yml", "docker-compose.yaml",
                      "compose.yml", "compose.yaml", "openapi.yaml",
                      "openapi.yml", "swagger.yaml", "swagger.yml"}
    )


def _link_or_reparse(metadata: os.stat_result) -> bool:
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse)


def _gap(kind: str, path: str = "", detail: str = "") -> dict[str, str]:
    row = {"kind": kind, "path": _safe_text(path.replace("\\", "/"), 4_096)}
    if detail:
        row["detail"] = _safe_text(detail, 512)
    return row


def _read_regular(path: Path, expected: os.stat_result, cap: int) -> tuple[bytes, str]:
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            return b"", "non-regular-file"
        if _link_or_reparse(opened):
            return b"", "link-or-reparse-file"
        expected_identity = (
            int(getattr(expected, "st_dev", 0)), int(getattr(expected, "st_ino", 0)))
        opened_identity = (
            int(getattr(opened, "st_dev", 0)), int(getattr(opened, "st_ino", 0)))
        # CPython's Windows DirEntry cache may expose zero device/inode values
        # even though fstat has the real file identity.  Compare identities only
        # when both observations provide them, then retain size/mtime as a
        # portable mutation guard.
        if (all(expected_identity) and all(opened_identity)
                and expected_identity != opened_identity):
            return b"", "file-changed-during-snapshot"
        if (
            int(getattr(expected, "st_size", -1)) != int(opened.st_size)
            or int(getattr(expected, "st_mtime_ns", -1))
            != int(getattr(opened, "st_mtime_ns", -1))
        ):
            return b"", "file-changed-during-snapshot"
        if opened.st_size > cap:
            return b"", "max-file-bytes"
        remaining = cap + 1
        chunks: list[bytes] = []
        while remaining:
            part = os.read(descriptor, min(64 * 1024, remaining))
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        raw = b"".join(chunks)
        if len(raw) > cap:
            return b"", "max-file-bytes"
        return raw, ""
    finally:
        os.close(descriptor)


def _snapshot(root: Path, limits: Limits) -> tuple[
        list[_Source], list[dict[str, str]], list[str], dict[str, Any]]:
    gaps: list[dict[str, str]] = []
    hits: set[str] = set()
    sources: list[_Source] = []
    total = 0
    considered = 0
    root_is_file = root.is_file()
    scope = root.parent if root_is_file else root
    pending: list[tuple[Path, str]] = (
        [(scope, "")] if not root_is_file else []
    )
    candidates: list[tuple[Path, str, os.stat_result]] = []

    if root_is_file:
        if not _eligible(root.name):
            gaps.append(_gap("unsupported-file-type", root.name))
        else:
            try:
                metadata = root.lstat()
                candidates.append((root, root.name, metadata))
            except OSError as exc:
                gaps.append(_gap("file-unreadable", root.name, type(exc).__name__))

    while pending and considered < limits.max_files:
        directory, prefix = pending.pop()
        try:
            directory_metadata = directory.lstat()
            if (_link_or_reparse(directory_metadata)
                    or not stat.S_ISDIR(directory_metadata.st_mode)):
                gaps.append(_gap("link-or-reparse-excluded", prefix))
                continue
            with os.scandir(directory) as iterator:
                entries = heapq.nsmallest(
                    limits.max_directory_entries + 1, iterator,
                    key=lambda item: (item.name.casefold(), item.name),
                )
        except OSError as exc:
            gaps.append(_gap("directory-unreadable", prefix, type(exc).__name__))
            continue
        if len(entries) > limits.max_directory_entries:
            entries.pop()
            hits.add("max_directory_entries")
            gaps.append(_gap(
                "max-directory-entries", prefix, str(limits.max_directory_entries)))
        child_directories: list[tuple[Path, str]] = []
        for entry in entries:
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            portable = relative.replace("\\", "/")
            if len(portable) > 4_096:
                gaps.append(_gap("path-too-long", portable[:4_096]))
                continue
            path = Path(entry.path)
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                gaps.append(_gap("entry-unreadable", portable, type(exc).__name__))
                continue
            if _link_or_reparse(metadata):
                gaps.append(_gap("link-or-reparse-excluded", portable))
                continue
            if stat.S_ISDIR(metadata.st_mode):
                if entry.name.casefold() not in _SKIP_DIRECTORIES:
                    child_directories.append((path, portable))
                continue
            if not stat.S_ISREG(metadata.st_mode) or not _eligible(entry.name):
                continue
            if considered >= limits.max_files:
                hits.add("max_files")
                gaps.append(_gap("max-files", ".", str(limits.max_files)))
                break
            considered += 1
            candidates.append((path, portable, metadata))
        for child in reversed(child_directories):
            pending.append(child)

    if pending:
        hits.add("max_files")
        gaps.append(_gap("max-files", ".", str(limits.max_files)))

    # Candidate order is independent of filesystem enumeration order.
    candidates.sort(key=lambda row: (row[1].casefold(), row[1]))
    for path, relative, metadata in candidates:
        if metadata.st_size > limits.max_file_bytes:
            hits.add("max_file_bytes")
            gaps.append(_gap("max-file-bytes", relative, str(metadata.st_size)))
            continue
        remaining = limits.max_total_bytes - total
        if remaining <= 0 or metadata.st_size > remaining:
            hits.add("max_total_bytes")
            gaps.append(_gap("max-total-bytes", relative, str(limits.max_total_bytes)))
            continue
        try:
            resolved_candidate = path.resolve(strict=True)
            resolved_candidate.relative_to(scope)
            if os.path.normcase(str(resolved_candidate)) != os.path.normcase(
                    str(path.absolute())):
                gaps.append(_gap("link-in-path-excluded", relative))
                continue
            raw, problem = _read_regular(path, metadata, min(limits.max_file_bytes, remaining))
        except (OSError, ValueError) as exc:
            gaps.append(_gap("file-unreadable", relative, type(exc).__name__))
            continue
        if problem:
            if problem in {"max-file-bytes"}:
                hits.add("max_file_bytes")
            gaps.append(_gap(problem, relative))
            continue
        total += len(raw)
        try:
            text = raw.decode("utf-8")
            replacement = False
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
            replacement = True
            gaps.append(_gap("utf8-decoded-with-replacement", relative))
        sources.append(_Source(
            path=_safe_text(relative.replace("\\", "/"), 4_096),
            language=_language(relative),
            raw=raw,
            text=text,
            sha256=_sha(raw),
            decoded_with_replacement=replacement,
        ))

    if len(gaps) > limits.max_gaps:
        hits.add("max_gaps")
        marker = _gap("gap-output-truncated", ".", str(limits.max_gaps))
        gaps = (
            sorted(gaps, key=_canonical)[:max(0, limits.max_gaps - 1)]
            + [marker]
        )
    else:
        gaps.sort(key=_canonical)
    inventory = {
        "scope_kind": "file" if root_is_file else "directory",
        "files_considered": considered,
        "files_loaded": len(sources),
        "total_bytes": total,
        "decoded_with_replacement": sum(
            1 for source in sources if source.decoded_with_replacement),
        "snapshot_sha256": _sha([
            {"path": source.path, "size": len(source.raw), "sha256": source.sha256}
            for source in sources
        ]),
    }
    return sources, gaps, sorted(hits), inventory


def _portable_document_path(value: Any) -> str:
    if not isinstance(value, (str, os.PathLike)):
        raise AttackSurface413Error("document path must be text or path-like")
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or "\x00" in raw or len(raw) > 4_096:
        raise AttackSurface413Error("document path is invalid")
    portable = raw.replace("\\", "/")
    parts = portable.split("/")
    windows = PureWindowsPath(raw)
    if (
        portable.startswith("/")
        or windows.is_absolute()
        or bool(windows.drive)
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise AttackSurface413Error("document path must stay within the snapshot")
    return PurePosixPath(portable).as_posix()


def _document_value(row: Any) -> tuple[Any, Any, str]:
    """Return path, content, and optional declared digest without executing hooks."""
    if isinstance(row, Mapping):
        path = row.get("path")
        declared = row.get("sha256", "")
        for key in ("content", "raw", "text", "_content"):
            if key in row:
                return path, row[key], str(declared) if declared else ""
        return path, None, str(declared) if declared else ""
    path = getattr(row, "path", None)
    declared = getattr(row, "sha256", "")
    try:
        content = getattr(row, "content")
    except (AttributeError, OSError, ValueError):
        content = getattr(row, "_content", None)
    return path, content, str(declared) if declared else ""


def _sources_from_documents(
        documents: Any, limits: Limits,
) -> tuple[list[_Source], list[dict[str, str]], list[str], dict[str, Any]]:
    """Normalize a caller-supplied immutable snapshot without touching the target."""
    if documents is None:
        raise AttackSurface413Error("snapshot_or_documents may not be null here")
    snapshot_root = getattr(documents, "root", "")
    values: Iterable[Any]
    if hasattr(documents, "files") and not isinstance(documents, Mapping):
        values = getattr(documents, "files")
    elif isinstance(documents, Mapping):
        if "path" in documents and any(
                key in documents for key in ("content", "raw", "text", "_content")):
            values = [documents]
        else:
            # Sort a bounded smallest subset so mapping insertion order cannot
            # change the report.
            selected = heapq.nsmallest(
                limits.max_files + 1, documents.items(),
                key=lambda item: (str(item[0]).casefold(), str(item[0])),
            )
            values = [
                {"path": key, "content": value} for key, value in selected
            ]
    elif isinstance(documents, Sequence) and not isinstance(
            documents, (str, bytes, bytearray, memoryview)):
        values = documents
    else:
        raise AttackSurface413Error(
            "snapshot_or_documents must be a snapshot, mapping, or document sequence")

    sources: list[_Source] = []
    gaps: list[dict[str, str]] = []
    hits: set[str] = set()
    total = 0
    considered = 0
    seen: set[str] = set()
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise AttackSurface413Error("snapshot documents are not iterable") from exc
    for row in iterator:
        if considered >= limits.max_files:
            hits.add("max_files")
            gaps.append(_gap("max-files", ".", str(limits.max_files)))
            break
        considered += 1
        try:
            raw_path, content, declared = _document_value(row)
            path = _portable_document_path(raw_path)
        except (AttackSurface413Error, TypeError, ValueError) as exc:
            gaps.append(_gap("invalid-document", ".", type(exc).__name__))
            continue
        collision = path.casefold()
        if collision in seen:
            gaps.append(_gap("duplicate-document-path", path))
            continue
        seen.add(collision)
        if not _eligible(path):
            continue
        if isinstance(content, str):
            if len(content) > limits.max_file_bytes:
                hits.add("max_file_bytes")
                gaps.append(_gap("max-file-bytes", path, str(len(content))))
                continue
            raw = content.encode("utf-8")
        elif isinstance(content, (bytes, bytearray, memoryview)):
            raw = bytes(content)
        else:
            gaps.append(_gap("document-content-unavailable", path))
            continue
        if len(raw) > limits.max_file_bytes:
            hits.add("max_file_bytes")
            gaps.append(_gap("max-file-bytes", path, str(len(raw))))
            continue
        if total + len(raw) > limits.max_total_bytes:
            hits.add("max_total_bytes")
            gaps.append(_gap("max-total-bytes", path, str(limits.max_total_bytes)))
            continue
        digest = _sha(raw)
        if declared and (
                not re.fullmatch(r"[0-9a-f]{64}", declared)
                or declared != digest):
            gaps.append(_gap("document-digest-mismatch", path))
            continue
        total += len(raw)
        try:
            text = raw.decode("utf-8")
            replacement = False
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
            replacement = True
            gaps.append(_gap("utf8-decoded-with-replacement", path))
        sources.append(_Source(
            path=_safe_text(path, 4_096),
            language=_language(path),
            raw=raw,
            text=text,
            sha256=digest,
            decoded_with_replacement=replacement,
        ))
    sources.sort(key=lambda source: (source.path.casefold(), source.path))
    gaps.sort(key=_canonical)
    if len(gaps) > limits.max_gaps:
        hits.add("max_gaps")
        gaps = gaps[:limits.max_gaps]
    inventory = {
        "scope_kind": "provided-snapshot",
        "files_considered": considered,
        "files_loaded": len(sources),
        "total_bytes": total,
        "decoded_with_replacement": sum(
            1 for source in sources if source.decoded_with_replacement),
        "snapshot_sha256": _sha([
            {"path": source.path, "size": len(source.raw), "sha256": source.sha256}
            for source in sources
        ]),
    }
    if snapshot_root:
        inventory["provided_snapshot_root"] = _safe_text(snapshot_root, 4_096)
    return sources, gaps, sorted(hits), inventory


def _dotted(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _dotted(node.value)
        return (left + "." if left else "") + node.attr
    return ""


def _literal(node: ast.AST | None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return _safe_text(node.value, 1_024)
    return ""


def _module_for(path: str) -> str:
    pure = PurePosixPath(path)
    parts = list(pure.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _scope_nodes(root: ast.AST) -> Iterable[ast.AST]:
    """Walk one function body without attributing nested functions to its owner."""
    pending = list(reversed(list(ast.iter_child_nodes(root))))
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        yield node
        pending.extend(reversed(list(ast.iter_child_nodes(node))))


def _qualified_definitions(
        tree: ast.AST, module: str,
) -> list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, str]]:
    rows: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, str]] = []

    def visit_body(body: Sequence[ast.stmt], owners: tuple[str, ...]) -> None:
        for node in body:
            if isinstance(node, ast.ClassDef):
                visit_body(node.body, (*owners, node.name))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualified = ".".join(
                    part for part in (module, *owners, node.name) if part)
                rows.append((node, qualified))
                visit_body(node.body, (*owners, node.name))

    visit_body(getattr(tree, "body", ()), ())
    return sorted(rows, key=lambda row: (row[0].lineno, row[1]))


def _expr_tainted(node: ast.AST | None, tainted: set[str]) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Name) and node.id in tainted:
        return True
    dotted = _dotted(node)
    lowered = dotted.casefold()
    if (
        lowered.startswith(("request.", "req.", "flask.request.", "django.request."))
        or lowered in {"request", "req"}
    ):
        return True
    if isinstance(node, ast.Call):
        callee = _dotted(node.func).casefold()
        if callee in {
            "input", "builtins.input", "request.args.get", "request.form.get",
            "request.values.get", "request.get_json", "request.headers.get",
            "request.cookies.get", "os.getenv", "sys.stdin.read",
        }:
            return True
    return any(_expr_tainted(child, tainted) for child in ast.iter_child_nodes(node))


def _targets(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        return {name for child in node.elts for name in _targets(child)}
    return set()


def _decorator_name(node: ast.AST) -> str:
    return _dotted(node.func if isinstance(node, ast.Call) else node)


def _route_from_decorators(
        decorators: Sequence[ast.expr],
) -> tuple[str, list[str], list[dict[str, Any]], bool]:
    route = ""
    methods: list[str] = []
    evidence: list[dict[str, Any]] = []
    auth = False
    for decorator in decorators:
        name = _decorator_name(decorator)
        folded = name.casefold()
        tail = folded.rsplit(".", 1)[-1]
        if tail in {
                "login_required", "permission_required", "authorize",
                "authenticated", "requires_auth", "jwt_required",
                "require_auth", "require_permission"}:
            auth = True
        if isinstance(decorator, ast.Call) and (
                folded.endswith((".route", ".get", ".post", ".put", ".patch", ".delete"))
                or folded in {"route", "api_view"}):
            if decorator.args:
                route = _literal(decorator.args[0])
            final = folded.rsplit(".", 1)[-1].upper()
            if final in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                methods.append(final)
            for keyword in decorator.keywords:
                if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple)):
                    methods.extend(
                        str(item.value).upper()
                        for item in keyword.value.elts
                        if isinstance(item, ast.Constant) and isinstance(item.value, str)
                    )
            evidence.append({"line": getattr(decorator, "lineno", 1), "kind": "route-decorator"})
    return route, sorted(set(methods or ["ANY"])), evidence, auth


def _auth_in_scope(nodes: Sequence[ast.AST]) -> list[int]:
    lines: set[int] = set()
    for node in nodes:
        if isinstance(node, ast.Call):
            callee = _dotted(node.func).casefold()
            tail = callee.rsplit(".", 1)[-1]
            if tail in {
                    "authorize", "check_permission", "check_access", "is_owner",
                    "require_role", "verify_scope", "jwt_required",
                    "login_required", "require_auth"}:
                lines.add(getattr(node, "lineno", 1))
    return sorted(lines)


def _evidence(
        source: _Source, line: int, kind: str, *, state: str = "proven",
) -> dict[str, Any]:
    return {
        "path": source.path,
        "line": max(1, int(line)),
        "kind": kind,
        "evidence_state": state,
        "source_sha256": source.sha256,
    }


class _Results:
    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}
        self.findings: dict[tuple[str, str, int], dict[str, Any]] = {}
        self.entrypoints: list[dict[str, Any]] = []
        self.sinks: list[dict[str, Any]] = []
        self.functions: list[dict[str, Any]] = []
        self.imports: list[dict[str, Any]] = []
        self.services: list[dict[str, Any]] = []
        self.gaps: list[dict[str, str]] = []
        self.hits: set[str] = set()

    def add_gap(self, kind: str, path: str = "", detail: str = "") -> None:
        if len(self.gaps) < self.limits.max_gaps:
            self.gaps.append(_gap(kind, path, detail))
        else:
            self.hits.add("max_gaps")

    def node(self, kind: str, identity: Mapping[str, Any], **fields: Any) -> str:
        identifier = _stable_id("N413-", {"kind": kind, **identity})
        if identifier not in self.nodes:
            if len(self.nodes) >= self.limits.max_graph_nodes:
                self.hits.add("max_graph_nodes")
                return ""
            self.nodes[identifier] = {
                "id": identifier, "kind": kind, **identity, **fields,
            }
        return identifier

    def edge(
            self, kind: str, source: str, target: str,
            evidence: Sequence[Mapping[str, Any]], *, state: str = "inferred",
    ) -> str:
        if not source or not target:
            return ""
        body = {"kind": kind, "source": source, "target": target}
        identifier = _stable_id("E413-", body)
        if identifier not in self.edges:
            if len(self.edges) >= self.limits.max_graph_edges:
                self.hits.add("max_graph_edges")
                return ""
            self.edges[identifier] = {
                "id": identifier, **body, "evidence_state": state,
                "evidence": [dict(row) for row in evidence[:MAX_EVIDENCE_PER_FINDING]],
            }
        return identifier

    def finding(
            self, *, rule: str, title: str, category: str, severity: str,
            source: _Source, line: int, evidence: Sequence[Mapping[str, Any]],
            claim: str, state: str = "inferred", cwe: str = "",
            remediation: str = "", factors: Sequence[Mapping[str, Any]] = (),
            gaps: Sequence[str] = (),
    ) -> str:
        key = (rule, source.path, max(1, int(line)))
        if key in self.findings:
            return self.findings[key]["id"]
        if len(self.findings) >= self.limits.max_findings:
            self.hits.add("max_findings")
            return ""
        direct = [dict(row) for row in evidence[:MAX_EVIDENCE_PER_FINDING]]
        observed_factors = [dict(row) for row in factors]
        score = _SEVERITY_BASE.get(severity, 5)
        for factor in observed_factors:
            if factor.get("observed") is True:
                score += max(-30, min(30, int(factor.get("weight", 0))))
        score = max(0, min(100, score))
        band = "critical" if score >= 85 else "high" if score >= 65 else \
            "medium" if score >= 40 else "low"
        identity = {"rule": rule, "path": source.path, "line": key[2]}
        identifier = _stable_id("AS413-", identity)
        self.findings[key] = {
            "id": identifier,
            "rule": rule,
            "title": title,
            "category": category,
            "severity": severity,
            "cwe": cwe,
            "path": source.path,
            "line": key[2],
            "claim": claim,
            "evidence_state": state,
            "evidence": direct,
            "exploitability": {
                "score": score,
                "band": band,
                "evidence_state": "inferred",
                "factors": observed_factors,
                "runtime_exploitability": "unverified",
            },
            "gaps": sorted({_safe_text(item, 512) for item in gaps}),
            "remediation": remediation,
        }
        return identifier


def _factor(
        name: str, observed: bool | None, weight: int,
        evidence: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    state = "proven" if observed is not None else "unverified"
    return {
        "name": name,
        "observed": observed,
        "weight": weight if observed is True else 0,
        "evidence_state": state,
        "evidence": [dict(row) for row in evidence[:2]],
    }


def _python_imports(tree: ast.AST, module: str, source: _Source) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                rows.append({
                    "path": source.path, "module": module,
                    "binding": alias.asname or alias.name.split(".")[0],
                    "target": alias.name, "line": node.lineno,
                    "evidence": [_evidence(source, node.lineno, "python-import")],
                })
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parts = module.split(".")[:-1]
                keep = max(0, len(parts) - node.level + 1)
                base = ".".join([*parts[:keep], *([base] if base else [])])
            for alias in node.names:
                target = ".".join(filter(None, (base, alias.name)))
                rows.append({
                    "path": source.path, "module": module,
                    "binding": alias.asname or alias.name,
                    "target": target, "line": node.lineno,
                    "evidence": [_evidence(source, node.lineno, "python-import")],
                })
    return rows


def _analyze_python(
        source: _Source, results: _Results, ast_budget: list[int],
) -> None:
    try:
        tree = ast.parse(source.text, filename=source.path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError) as exc:
        results.add_gap("python-parse-failed", source.path, type(exc).__name__)
        return
    count = 0
    try:
        for _ in ast.walk(tree):
            count += 1
            if count > ast_budget[0]:
                results.hits.add("max_ast_nodes")
                results.add_gap("max-ast-nodes", source.path, str(results.limits.max_ast_nodes))
                return
    except RecursionError:
        results.add_gap("python-ast-recursion-limit", source.path)
        return
    ast_budget[0] -= count
    module = _module_for(source.path)
    results.imports.extend(_python_imports(tree, module, source))

    definitions = _qualified_definitions(tree, module)
    for function, qualified in definitions:
        nodes = list(_scope_nodes(function))
        route, methods, route_evidence, decorated_auth = _route_from_decorators(
            function.decorator_list)
        auth_lines = _auth_in_scope(nodes)
        function_evidence = [_evidence(source, function.lineno, "function-definition")]
        function_row = {
            "path": source.path,
            "module": module,
            "name": function.name,
            "qualified": qualified,
            "line": function.lineno,
            "calls": [],
            "auth_lines": auth_lines,
            "entrypoint": bool(route),
            "evidence": function_evidence,
        }
        results.functions.append(function_row)
        function_node = results.node(
            "function",
            {"path": source.path, "qualified": _safe_text(qualified, 1_024),
             "line": function.lineno},
            evidence_state="proven", evidence=function_evidence,
        )
        if route:
            endpoint_evidence = [
                _evidence(source, int(row["line"]), str(row["kind"]))
                for row in route_evidence
            ]
            endpoint_node = results.node(
                "entrypoint",
                {"path": source.path, "route": route,
                 "methods": methods, "line": function.lineno},
                evidence_state="proven", evidence=endpoint_evidence,
            )
            results.edge(
                "dispatches-to", endpoint_node, function_node,
                endpoint_evidence, state="proven")
            results.entrypoints.append({
                "node": endpoint_node, "function_node": function_node,
                "function": qualified, "path": source.path, "line": function.lineno,
                "route": route, "methods": methods,
                "auth_evidence": [
                    _evidence(source, line, "authorization-check")
                    for line in auth_lines
                ] + ([_evidence(source, function.lineno, "authentication-decorator")]
                     if decorated_auth else []),
                "evidence": endpoint_evidence,
            })

        parameters = {
            argument.arg for argument in [
                *function.args.posonlyargs, *function.args.args,
                *function.args.kwonlyargs,
            ]
        }
        # Function parameters are tracked as externally *possible* inputs.  A
        # caller edge or route can later make that path reachable, but a bare
        # parameter alone is never described as proven request control.
        tainted = set(parameters)
        assignments = [
            node for node in nodes
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
        ]
        for _ in range(4):
            changed = False
            for assignment in assignments:
                if isinstance(assignment, ast.Assign):
                    value = assignment.value
                    targets = {
                        name for target in assignment.targets for name in _targets(target)}
                else:
                    value = assignment.value
                    targets = _targets(assignment.target)
                if _expr_tainted(value, tainted):
                    before = len(tainted)
                    tainted.update(targets)
                    changed = changed or len(tainted) != before
            if not changed:
                break

        import_map = {
            row["binding"]: row["target"]
            for row in results.imports if row["path"] == source.path
        }
        for node in nodes:
            if not isinstance(node, ast.Call):
                continue
            callee = _dotted(node.func)
            if not callee:
                continue
            first, dot, rest = callee.partition(".")
            resolved = import_map.get(first, first) + (dot + rest if dot else "")
            if "." not in resolved and resolved not in {"eval", "exec", "open"}:
                resolved = f"{module}.{resolved}".strip(".")
            call_evidence = [_evidence(source, node.lineno, "call-site")]
            function_row["calls"].append({
                "callee": _safe_text(resolved, 1_024), "line": node.lineno,
                "evidence": call_evidence,
            })
            lowered = callee.casefold()
            argument = node.args[0] if node.args else None
            primary_controlled = _expr_tainted(argument, tainted)
            keyword_controlled = any(
                _expr_tainted(keyword.value, tainted) for keyword in node.keywords)
            controlled = primary_controlled
            sink_category = ""
            rule = ""
            title = ""
            severity = "high"
            cwe = ""
            if lowered.endswith((".execute", ".executemany", ".raw", ".rawquery")):
                sink_category, rule, title, cwe = (
                    "sql-injection", "as413-sql-injection",
                    "Potential request-controlled SQL construction", "CWE-89")
                controlled = primary_controlled or any(
                    keyword.arg and keyword.arg.casefold() in {
                        "query", "sql", "statement"}
                    and _expr_tainted(keyword.value, tainted)
                    for keyword in node.keywords)
            elif lowered in {"os.system", "os.popen"} or (
                    lowered.startswith("subprocess.") and any(
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                        for keyword in node.keywords)):
                sink_category, rule, title, cwe = (
                    "command-injection", "as413-command-injection",
                    "Potential request-controlled command execution", "CWE-78")
                severity = "critical"
                controlled = primary_controlled or any(
                    keyword.arg and keyword.arg.casefold() in {
                        "args", "command", "cmd"}
                    and _expr_tainted(keyword.value, tainted)
                    for keyword in node.keywords)
            elif lowered in {"eval", "exec", "builtins.eval", "builtins.exec"}:
                sink_category, rule, title, cwe = (
                    "code-injection", "as413-code-injection",
                    "Potential request-controlled dynamic code evaluation", "CWE-95")
                severity = "critical"
                controlled = primary_controlled or any(
                    keyword.arg and keyword.arg.casefold() in {"source", "code"}
                    and _expr_tainted(keyword.value, tainted)
                    for keyword in node.keywords)
            elif lowered in {
                    "requests.get", "requests.post", "requests.put", "requests.patch",
                    "requests.delete", "requests.request", "httpx.get", "httpx.post",
                    "httpx.request", "urllib.request.urlopen", "aiohttp.request"}:
                sink_category, rule, title, cwe = (
                    "ssrf", "as413-ssrf",
                    "Potential request-controlled outbound request", "CWE-918")
                controlled = primary_controlled or any(
                    keyword.arg and keyword.arg.casefold() in {"url", "uri"}
                    and _expr_tainted(keyword.value, tainted)
                    for keyword in node.keywords)
            elif lowered.endswith((
                    ".get_or_404", ".findbyid", ".find_by_id", ".findunique",
                    ".query.get", ".objects.get", ".filter_by", ".filter",
                    ".where")):
                sink_category, rule, title, cwe = (
                    "authorization", "as413-potential-idor",
                    "Object lookup may require an ownership check", "CWE-639")
                severity = "medium"
                controlled = primary_controlled or keyword_controlled

            if sink_category:
                sink_node = results.node(
                    "security-sink",
                    {"path": source.path, "category": sink_category,
                     "callee": _safe_text(callee, 256), "line": node.lineno},
                    evidence_state="proven", evidence=call_evidence,
                )
                results.edge(
                    "contains-sink", function_node, sink_node, call_evidence,
                    state="proven")
                results.sinks.append({
                    "node": sink_node, "function_node": function_node,
                    "function": qualified, "path": source.path, "line": node.lineno,
                    "category": sink_category, "controlled": controlled,
                    "evidence": call_evidence,
                })
                if controlled:
                    auth_evidence = [
                        _evidence(source, line, "authorization-check")
                        for line in auth_lines
                    ] + (
                        [_evidence(
                            source, function.lineno, "authentication-decorator")]
                        if decorated_auth else []
                    )
                    route_or_request = bool(route) or any(
                        _expr_tainted(argument, set()) for argument in node.args)
                    factors = [
                        _factor(
                            "request-controlled-dataflow",
                            True if route_or_request else None,
                            22, call_evidence if route_or_request else ()),
                        _factor(
                            "function-parameter-dataflow",
                            True if not route_or_request else None,
                            10, function_evidence if not route_or_request else ()),
                        _factor("same-function-entrypoint", bool(route), 12,
                                [_evidence(source, function.lineno, "route-handler")]
                                if route else []),
                        _factor("authorization-control-observed",
                                True if auth_evidence else None, -15, auth_evidence),
                    ]
                    finding_id = results.finding(
                        rule=rule, title=title, category=sink_category,
                        severity=severity, source=source, line=node.lineno,
                        evidence=call_evidence + (
                            [_evidence(source, function.lineno, "route-handler")]
                            if route else []),
                        claim=(
                            "Static evidence connects "
                            + ("route or request-derived data" if route_or_request
                               else "a function parameter")
                            + f" to a {sink_category} sink. Runtime exploitability "
                              "and external control are unverified."
                        ),
                        state="inferred", cwe=cwe, factors=factors,
                        gaps=(
                            ["runtime routing, framework behavior, and deployed controls "
                             "were not executed"]
                            + ([] if route_or_request else
                               ["external control of the function parameter is unverified"])
                            + ([] if auth_evidence else
                               ["authorization or ownership enforcement was not proven"])
                        ),
                        remediation=(
                            "Use context-appropriate parameterization or allowlisting and "
                            "enforce authorization before the sensitive operation."
                        ),
                    )
                    if sink_node in results.nodes:
                        results.nodes[sink_node]["finding_id"] = finding_id

            if lowered.endswith("set_cookie"):
                keywords = {keyword.arg.casefold(): keyword.value
                            for keyword in node.keywords if keyword.arg}
                weaknesses: list[str] = []
                for flag in ("secure", "httponly"):
                    value = keywords.get(flag)
                    if value is None or (
                            isinstance(value, ast.Constant) and value.value is False):
                        weaknesses.append(flag)
                same_site = keywords.get("samesite")
                if same_site is None or (
                        isinstance(same_site, ast.Constant)
                        and str(same_site.value).casefold() == "none"):
                    weaknesses.append("samesite")
                if weaknesses:
                    results.finding(
                        rule="as413-insecure-cookie",
                        title="Session cookie attributes may be incomplete",
                        category="session-security", severity="medium",
                        source=source, line=node.lineno, evidence=call_evidence,
                        claim=(
                            "The statically visible cookie call does not prove secure, "
                            "HttpOnly, and restrictive SameSite attributes."
                        ),
                        state="inferred", cwe="CWE-614",
                        factors=[_factor("cookie-call-observed", True, 8, call_evidence)],
                        gaps=["framework defaults and upstream response rewriting are unverified"],
                        remediation=(
                            "Set Secure and HttpOnly explicitly and choose a restrictive "
                            "SameSite policy appropriate to the application."
                        ),
                    )

            redirect_values = [
                keyword.value for keyword in node.keywords
                if keyword.arg and keyword.arg.casefold() in {
                    "redirect_uri", "redirect_url", "callback_url", "return_to"}
            ]
            if (
                redirect_values
                and any(token in lowered for token in (
                    "oauth", "authorize", "authorization_url", "login"))
                and any(_expr_tainted(value, tainted) for value in redirect_values)
            ):
                evidence = [_evidence(source, node.lineno, "dynamic-oauth-redirect")]
                sink = results.node(
                    "security-sink",
                    {"path": source.path, "category": "oauth",
                     "callee": _safe_text(callee, 256), "line": node.lineno},
                    evidence_state="proven", evidence=evidence)
                results.edge(
                    "contains-sink", function_node, sink, evidence, state="proven")
                results.sinks.append({
                    "node": sink, "function_node": function_node,
                    "function": qualified, "path": source.path, "line": node.lineno,
                    "category": "oauth", "controlled": True, "evidence": evidence,
                })
                finding_id = results.finding(
                    rule="as413-oauth-dynamic-redirect",
                    title="OAuth redirect URI may be input-controlled",
                    category="oauth", severity="high", source=source,
                    line=node.lineno, evidence=evidence,
                    claim=(
                        "A value tracked from a function parameter or request is supplied "
                        "to an OAuth/login redirect parameter. Exact registration and "
                        "runtime validation are unverified."
                    ),
                    state="inferred", cwe="CWE-601",
                    factors=[
                        _factor("input-derived-redirect", True, 20, evidence),
                        _factor("exact-redirect-registration", None, 0),
                    ],
                    gaps=[
                        "identity-provider redirect registration was not queried",
                        "runtime normalization and exact comparison are unverified",
                    ],
                    remediation=(
                        "Select redirects from server-side identifiers and compare "
                        "normalized redirect URIs exactly against registration."
                    ),
                )
                if sink in results.nodes:
                    results.nodes[sink]["finding_id"] = finding_id

    # Django-style URL tables bind a literal route to a view outside the view's
    # function body.  Credit the route syntax, but keep dispatch inferred.
    for node in _scope_nodes(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = _dotted(node.func).casefold()
        if callee.rsplit(".", 1)[-1] not in {"path", "re_path"} or len(node.args) < 2:
            continue
        route = _literal(node.args[0])
        view = _dotted(node.args[1])
        if not route or not view:
            continue
        line = getattr(node, "lineno", 1)
        evidence = [_evidence(source, line, "django-url-binding")]
        endpoint = results.node(
            "entrypoint",
            {"path": source.path, "route": route, "methods": ["ANY"], "line": line},
            evidence_state="proven", evidence=evidence)
        binding_map = {
            row["binding"]: row["target"]
            for row in results.imports if row["path"] == source.path
        }
        first, dot, rest = view.partition(".")
        resolved_view = binding_map.get(first, first) + (dot + rest if dot else "")
        qualified_view = (
            resolved_view if "." in resolved_view
            else f"{module}.{resolved_view}".strip(".")
        )
        target_identity = next(
            ({
                "path": row["path"], "qualified": _safe_text(row["qualified"], 1_024),
                "line": row["line"],
            } for row in results.functions
             if row["path"] == source.path and row["qualified"] == qualified_view),
            None,
        )
        target = (
            _stable_id("N413-", {"kind": "function", **target_identity})
            if target_identity else ""
        )
        results.edge("dispatches-to", endpoint, target, evidence, state="inferred")
        results.entrypoints.append({
            "node": endpoint, "function_node": target,
            "function": _safe_text(qualified_view, 1_024),
            "path": source.path, "line": line, "route": route,
            "methods": ["ANY"], "auth_evidence": [], "evidence": evidence,
        })


_JS_ROUTE = re.compile(
    r"\b(?:app|router|server)\s*\.\s*(get|post|put|patch|delete|all|use)\s*"
    r"\(\s*([\"'`])([^\"'`\r\n]{0,1000})\2", re.IGNORECASE)
_JS_IMPORT = re.compile(
    r"(?:\bimport\s+(?:[^;\r\n]*?\s+from\s+)?|\brequire\s*\(\s*)"
    r"([\"'])([^\"'\r\n]{1,1000})\1", re.IGNORECASE)
_URL_LITERAL = re.compile(
    r"https?://([A-Za-z0-9][A-Za-z0-9._-]{0,252})(?::\d{1,5})?", re.IGNORECASE)


def _analyze_javascript(source: _Source, results: _Results) -> None:
    module = _module_for(source.path)
    function_name = f"{module}.<module>".strip(".")
    function_evidence = [_evidence(source, 1, "module-scope")]
    function_node = results.node(
        "function",
        {"path": source.path, "qualified": function_name, "line": 1},
        evidence_state="proven", evidence=function_evidence,
    )
    function = {
        "path": source.path, "module": module, "name": "<module>",
        "qualified": function_name, "line": 1, "calls": [],
        "auth_lines": [], "entrypoint": False, "evidence": function_evidence,
    }
    results.functions.append(function)
    for match in _JS_IMPORT.finditer(source.text):
        target = _safe_text(match.group(2), 1_024)
        results.imports.append({
            "path": source.path, "module": module, "binding": "",
            "target": target, "line": _line(source.text, match.start()),
            "evidence": [_evidence(
                source, _line(source.text, match.start()), "javascript-import")],
        })
    for match in _JS_ROUTE.finditer(source.text):
        method = match.group(1).upper()
        route = _safe_text(match.group(3), 1_024)
        line = _line(source.text, match.start())
        evidence = [_evidence(source, line, "javascript-route")]
        endpoint = results.node(
            "entrypoint",
            {"path": source.path, "route": route, "methods": [method], "line": line},
            evidence_state="proven", evidence=evidence,
        )
        results.edge("dispatches-to", endpoint, function_node, evidence, state="inferred")
        # Only explicit middleware in the route declaration is credited.
        declaration = source.text[match.start():min(len(source.text), match.start() + 800)]
        auth = bool(re.search(
            r"\b(?:authenticate|authorize|requireAuth|verifyToken|passport\.)\b",
            declaration, re.IGNORECASE))
        auth_evidence = [_evidence(source, line, "route-auth-middleware")] if auth else []
        results.entrypoints.append({
            "node": endpoint, "function_node": function_node,
            "function": function_name, "path": source.path, "line": line,
            "route": route, "methods": [method],
            "auth_evidence": auth_evidence, "evidence": evidence,
        })
        function["entrypoint"] = True

    line_patterns = [
        (
            "as413-sql-injection", "sql-injection",
            "Potential request-controlled SQL construction", "high", "CWE-89",
            re.compile(
                r"\b(?:query|execute|raw)\s*\(\s*(?:"
                r"req(?:uest)?\s*\.|"
                r"`[^`\r\n]*\$\{[^}]*req(?:uest)?\s*\.|"
                r"[\"'][^\"'\r\n]*[\"']\s*\+\s*req(?:uest)?\s*\.)",
                re.IGNORECASE),
        ),
        (
            "as413-command-injection", "command-injection",
            "Potential request-controlled command execution", "critical", "CWE-78",
            re.compile(
                r"\b(?:(?:exec|execSync)\s*\([^;\r\n]*req(?:uest)?\s*\.|"
                r"spawn\s*\(\s*req(?:uest)?\s*\.)",
                re.IGNORECASE),
        ),
        (
            "as413-code-injection", "code-injection",
            "Potential request-controlled dynamic code evaluation", "critical", "CWE-95",
            re.compile(r"\b(?:eval|Function)\s*\([^;\r\n]*req(?:uest)?\s*\.",
                       re.IGNORECASE),
        ),
        (
            "as413-ssrf", "ssrf",
            "Potential request-controlled outbound request", "high", "CWE-918",
            re.compile(
                r"\b(?:fetch|axios\s*\.\s*(?:get|post|request)|request)\s*"
                r"\(\s*(?:req(?:uest)?\s*\.|"
                r"`[^`\r\n]*\$\{[^}]*req(?:uest)?\s*\.|"
                r"[\"'][^\"'\r\n]*[\"']\s*\+\s*req(?:uest)?\s*\.)",
                re.IGNORECASE),
        ),
        (
            "as413-potential-idor", "authorization",
            "Object lookup may require an ownership check", "medium", "CWE-639",
            re.compile(
                r"\b(?:findById|findUnique|findOne|getById)\s*"
                r"\([^;\r\n]*req(?:uest)?\s*\.\s*params", re.IGNORECASE),
        ),
        (
            "as413-oauth-dynamic-redirect", "oauth",
            "OAuth redirect URI may be input-controlled", "high", "CWE-601",
            re.compile(
                r"\b(?:authorize|authorizationUrl|oauth[A-Za-z0-9_]*)\s*\("
                r"[^;\r\n]*(?:redirect_uri|redirectUrl|callbackUrl)\s*:"
                r"[^;\r\n]*req(?:uest)?\s*\.", re.IGNORECASE),
        ),
    ]
    for rule, category, title, severity, cwe, pattern in line_patterns:
        for match in pattern.finditer(source.text):
            line = _line(source.text, match.start())
            evidence = [_evidence(source, line, "request-to-sensitive-call")]
            sink = results.node(
                "security-sink",
                {"path": source.path, "category": category,
                 "callee": "lexically-matched-call", "line": line},
                evidence_state="proven", evidence=evidence,
            )
            results.edge("contains-sink", function_node, sink, evidence, state="proven")
            results.sinks.append({
                "node": sink, "function_node": function_node,
                "function": function_name, "path": source.path, "line": line,
                "category": category, "controlled": True, "evidence": evidence,
            })
            finding_id = results.finding(
                rule=rule, title=title, category=category, severity=severity,
                source=source, line=line, evidence=evidence,
                claim=(
                    "Lexical static evidence places request-derived data in a "
                    "sensitive call. Parser-grade and runtime exploitability evidence "
                    "are unavailable for this adapter."
                ),
                state="inferred", cwe=cwe,
                factors=[
                    _factor("request-token-in-sensitive-call", True, 18, evidence),
                    _factor("parser-grade-dataflow", None, 0),
                ],
                gaps=[
                    "JavaScript and TypeScript analysis is bounded lexical evidence",
                    "runtime routing and deployed controls were not executed",
                ],
                remediation=(
                    "Validate with the language compiler and use parameterization, "
                    "allowlisting, and object-level authorization as appropriate."
                ),
            )
            if sink in results.nodes:
                results.nodes[sink]["finding_id"] = finding_id

    cookie = re.compile(r"\b(?:res|response)\s*\.\s*cookie\s*\(([^;\r\n]{0,1500})",
                        re.IGNORECASE)
    for match in cookie.finditer(source.text):
        call = match.group(1)
        missing = [
            flag for flag in ("secure", "httponly", "samesite")
            if not re.search(rf"\b{flag}\s*:", call, re.IGNORECASE)
        ]
        if missing:
            line = _line(source.text, match.start())
            evidence = [_evidence(source, line, "cookie-call")]
            results.finding(
                rule="as413-insecure-cookie",
                title="Session cookie attributes may be incomplete",
                category="session-security", severity="medium",
                source=source, line=line, evidence=evidence,
                claim=(
                    "The visible cookie call does not explicitly establish every "
                    "recommended cookie attribute."
                ),
                state="inferred", cwe="CWE-614",
                factors=[_factor("cookie-call-observed", True, 8, evidence)],
                gaps=["framework defaults and response rewriting are unverified"],
                remediation=(
                    "Set Secure, HttpOnly, and an appropriate SameSite policy explicitly."
                ),
            )


def _config_findings(source: _Source, results: _Results) -> None:
    """Detect only explicit web/auth configuration evidence."""
    rules: list[tuple[str, str, str, str, str, re.Pattern[str], str]] = [
        (
            "as413-csrf-disabled", "csrf", "CSRF protection is explicitly disabled",
            "high", "CWE-352",
            re.compile(
                r"(?:WTF_CSRF_ENABLED|CSRF_ENABLED|csrfProtection|verifyCsrfToken)"
                r"\s*[:=]\s*(?:false|False|0)|"
                r"\b(?:csrf\s*\.\s*exempt|csrf_exempt)\b",
                re.IGNORECASE),
            "Enable framework CSRF protection for state-changing cookie-authenticated requests.",
        ),
        (
            "as413-unsafe-cors", "cors", "CORS policy explicitly permits a wildcard origin",
            "high", "CWE-942",
            re.compile(
                r"Access-Control-Allow-Origin\s*[:=]\s*[\"']?\*|"
                r"\borigins?\s*[:=]\s*[\"']\*|"
                r"\borigin\s*:\s*(?:true|[\"']\*[\"'])",
                re.IGNORECASE),
            "Use a normalized allowlist of trusted origins and avoid credentialed wildcards.",
        ),
        (
            "as413-jwt-verification-disabled", "jwt",
            "JWT signature verification is explicitly disabled",
            "critical", "CWE-347",
            re.compile(
                r"verify_signature[\"']?\s*[:=]\s*(?:false|False|0)|"
                r"(?:jwt|token)[^\r\n]{0,160}\bverify\s*[:=]\s*(?:false|False)|"
                r"\bjwt\s*\.\s*decode\s*\([^;\r\n]*\bverify\s*=\s*False",
                re.IGNORECASE),
            "Require signature, issuer, audience, lifetime, and algorithm validation.",
        ),
        (
            "as413-jwt-none-algorithm", "jwt",
            "JWT configuration explicitly allows the none algorithm",
            "critical", "CWE-327",
            re.compile(
                r"\balgorithms?\s*[:=]\s*\[[^\]\r\n]*[\"']none[\"']|"
                r"\balg(?:orithm)?\s*[:=]\s*[\"']none[\"']",
                re.IGNORECASE),
            "Pin an asymmetric or keyed algorithm appropriate to the trust model.",
        ),
        (
            "as413-oauth-state-disabled", "oauth",
            "OAuth state validation is explicitly disabled",
            "high", "CWE-352",
            re.compile(
                r"(?:validate_state|verify_state|use_state|state_required)"
                r"\s*[:=]\s*(?:false|False|0)", re.IGNORECASE),
            "Generate, bind, and verify a one-use OAuth state value.",
        ),
        (
            "as413-oauth-pkce-disabled", "oauth",
            "OAuth PKCE is explicitly disabled",
            "high", "CWE-345",
            re.compile(
                r"(?:use_pkce|pkce_enabled|require_pkce)"
                r"\s*[:=]\s*(?:false|False|0)|"
                r"code_challenge_method\s*[:=]\s*[\"']plain[\"']",
                re.IGNORECASE),
            "Require PKCE with S256 for public and browser-mediated clients.",
        ),
        (
            "as413-oauth-wildcard-redirect", "oauth",
            "OAuth redirect configuration contains a wildcard",
            "high", "CWE-601",
            re.compile(
                r"(?:redirect_uri|redirect_uris|callback_url)\s*[:=]"
                r"[^\r\n]{0,300}[\"'][^\"'\r\n]*\*[^\"'\r\n]*[\"']",
                re.IGNORECASE),
            "Register exact normalized redirect URIs and compare them exactly.",
        ),
    ]
    for rule, category, title, severity, cwe, pattern, remediation in rules:
        for match in pattern.finditer(source.text):
            line = _line(source.text, match.start())
            evidence = [_evidence(source, line, "explicit-security-configuration")]
            results.finding(
                rule=rule, title=title, category=category, severity=severity,
                source=source, line=line, evidence=evidence,
                claim=(
                    "The source contains an explicit configuration matching this "
                    "security-sensitive condition. Deployment overrides are unverified."
                ),
                state="inferred", cwe=cwe,
                factors=[
                    _factor("explicit-weak-configuration", True, 24, evidence),
                    _factor("deployment-reachability", None, 0),
                ],
                gaps=["active deployment configuration was not executed or queried"],
                remediation=remediation,
            )

    # Request smuggling is only raised when both conflicting framing headers are
    # visibly accepted, copied, or constructed near one another.
    content_length_lines = sorted({
        _line(source.text, match.start())
        for index, match in enumerate(re.finditer(
            r"\bContent-Length\b", source.text, re.IGNORECASE))
        if index < 512
    })
    transfer_encoding_lines = sorted({
        _line(source.text, match.start())
        for index, match in enumerate(re.finditer(
            r"\bTransfer-Encoding\b", source.text, re.IGNORECASE))
        if index < 512
    })
    pair: tuple[int, int] | None = None
    left_index = right_index = 0
    while (
        left_index < len(content_length_lines)
        and right_index < len(transfer_encoding_lines)
    ):
        left_line = content_length_lines[left_index]
        right_line = transfer_encoding_lines[right_index]
        if abs(left_line - right_line) <= 20:
            pair = (left_line, right_line)
            break
        if left_line < right_line:
            left_index += 1
        else:
            right_index += 1
    if pair is not None:
        left_line, right_line = pair
        evidence = [
            _evidence(source, left_line, "content-length-header-handling"),
            _evidence(source, right_line, "transfer-encoding-header-handling"),
        ]
        results.finding(
            rule="as413-request-smuggling-framing-conflict",
            title="Conflicting HTTP framing headers are handled together",
            category="request-smuggling", severity="high",
            source=source, line=min(left_line, right_line), evidence=evidence,
            claim=(
                "Static evidence shows Content-Length and Transfer-Encoding handling "
                "within a bounded region. Whether conflicting requests are rejected "
                "consistently across every proxy hop is unverified."
            ),
            state="inferred", cwe="CWE-444",
            factors=[
                _factor("both-framing-headers-observed", True, 18, evidence),
                _factor("proxy-parser-differential", None, 0),
            ],
            gaps=[
                "proxy topology and HTTP parser behavior were not exercised",
                "a framing differential is not proven by static co-occurrence",
            ],
            remediation=(
                "Reject ambiguous framing, normalize once at the edge, and ensure "
                "every proxy and origin uses the same HTTP parsing policy."
            ),
        )


def _discover_services(sources: Sequence[_Source], results: _Results) -> None:
    for source in sources:
        name = PurePosixPath(source.path).name.casefold()
        if name not in {
                "docker-compose.yml", "docker-compose.yaml", "compose.yml",
                "compose.yaml"}:
            continue
        in_services = False
        service_indent = -1
        direct_indent: int | None = None
        for number, raw_line in enumerate(source.text.splitlines(), start=1):
            stripped = raw_line.strip()
            indent = len(raw_line) - len(raw_line.lstrip(" "))
            if stripped == "services:":
                in_services = True
                service_indent = indent
                direct_indent = None
                continue
            if in_services and stripped and indent <= service_indent:
                in_services = False
            match = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]{0,127}):\s*$", stripped)
            if (in_services and stripped and not stripped.startswith("#")
                    and indent > service_indent and direct_indent is None):
                direct_indent = indent
            if in_services and match and indent == direct_indent:
                service = _safe_text(match.group(1), 128)
                evidence = [_evidence(source, number, "compose-service")]
                node = results.node(
                    "service", {"name": service, "path": source.path, "line": number},
                    evidence_state="proven", evidence=evidence)
                results.services.append({
                    "node": node, "name": service, "path": source.path,
                    "line": number, "evidence": evidence,
                })


def _discover_api_contracts(sources: Sequence[_Source], results: _Results) -> None:
    methods = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
    for source in sources:
        name = PurePosixPath(source.path).name.casefold()
        if not (
            name.startswith(("openapi.", "swagger."))
            or re.search(r"(?m)^\s*(?:openapi|swagger)\s*:", source.text[:16_384])
        ):
            continue
        observed: list[tuple[str, str, int, bool]] = []
        if source.language == "json":
            try:
                def strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
                    result: dict[str, Any] = {}
                    for key, value in pairs:
                        if key in result:
                            raise ValueError("duplicate JSON member")
                        result[key] = value
                    return result

                document = json.loads(source.text, object_pairs_hook=strict_pairs)
                paths = document.get("paths", {}) if isinstance(document, Mapping) else {}
                global_security = (
                    bool(document.get("security")) if isinstance(document, Mapping) else False)
                if isinstance(paths, Mapping):
                    for route, operations in paths.items():
                        if not isinstance(route, str) or not route.startswith("/"):
                            continue
                        line = _line(
                            source.text,
                            max(0, source.text.find(json.dumps(route))),
                        )
                        if isinstance(operations, Mapping):
                            for method, operation in operations.items():
                                if str(method).casefold() not in methods:
                                    continue
                                auth = global_security or (
                                    isinstance(operation, Mapping)
                                    and bool(operation.get("security")))
                                observed.append((
                                    _safe_text(route, 1_024),
                                    str(method).upper(), line, auth))
            except (json.JSONDecodeError, ValueError, TypeError, RecursionError, MemoryError):
                results.add_gap("openapi-json-parse-failed", source.path)
                continue
        else:
            lines = source.text.splitlines()
            in_paths = False
            paths_indent = -1
            route = ""
            route_indent = -1
            route_line = 1
            for number, raw in enumerate(lines, start=1):
                stripped = raw.strip()
                indent = len(raw) - len(raw.lstrip(" "))
                if stripped == "paths:":
                    in_paths = True
                    paths_indent = indent
                    continue
                if in_paths and stripped and indent <= paths_indent:
                    in_paths = False
                    route = ""
                route_match = re.match(r"^(/[^:\r\n]{0,1000}):\s*$", stripped)
                if in_paths and route_match and indent > paths_indent:
                    route = _safe_text(route_match.group(1), 1_024)
                    route_indent = indent
                    route_line = number
                    continue
                method_match = re.match(
                    r"^(get|post|put|patch|delete|options|head|trace):\s*$",
                    stripped, re.IGNORECASE)
                if route and method_match and indent > route_indent:
                    observed.append((
                        route, method_match.group(1).upper(), route_line, False))
        for route, method, line, auth in sorted(set(observed)):
            evidence = [_evidence(source, line, "openapi-operation")]
            auth_evidence = (
                [_evidence(source, line, "openapi-security-requirement")] if auth else [])
            endpoint = results.node(
                "entrypoint",
                {"path": source.path, "route": route,
                 "methods": [method], "line": line},
                evidence_state="proven", evidence=evidence)
            results.entrypoints.append({
                "node": endpoint, "function_node": "",
                "function": "", "path": source.path, "line": line,
                "route": route, "methods": [method],
                "auth_evidence": auth_evidence, "evidence": evidence,
            })


def _resolve_relative_module(path: str, target: str) -> str:
    if not target.startswith("."):
        return target.replace("/", ".").removesuffix(".js").removesuffix(".ts")
    base = PurePosixPath(path).parent
    combined = base.joinpath(target)
    parts: list[str] = []
    for part in combined.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    if parts:
        final = PurePosixPath(parts[-1]).stem
        parts[-1] = final
    return ".".join(parts)


def _build_graph(sources: Sequence[_Source], results: _Results) -> None:
    file_nodes: dict[str, str] = {}
    module_files: dict[str, str] = {}
    function_nodes: dict[str, str] = {}
    for source in sources:
        evidence = [_evidence(source, 1, "snapshot-file")]
        node = results.node(
            "file", {"path": source.path, "language": source.language},
            evidence_state="proven", evidence=evidence)
        file_nodes[source.path] = node
        module_files[_module_for(source.path)] = node
    for row in results.functions:
        identity = {
            "path": row["path"], "qualified": _safe_text(row["qualified"], 1_024),
            "line": row["line"],
        }
        node = _stable_id("N413-", {"kind": "function", **identity})
        if node in results.nodes:
            function_nodes[row["qualified"]] = node
            results.edge(
                "declared-in", file_nodes.get(row["path"], ""), node,
                row["evidence"], state="proven")
    for entry in results.entrypoints:
        if entry.get("function_node"):
            continue
        target = function_nodes.get(entry.get("function", ""), "")
        if target:
            entry["function_node"] = target
            results.edge(
                "dispatches-to", entry["node"], target, entry["evidence"],
                state="inferred")

    for row in results.imports:
        target_module = _resolve_relative_module(row["path"], row["target"])
        target_file = module_files.get(target_module)
        if target_file is None:
            # Python from-import targets often include a symbol suffix.
            pieces = target_module.split(".")
            for end in range(len(pieces) - 1, 0, -1):
                candidate = ".".join(pieces[:end])
                if candidate in module_files:
                    target_file = module_files[candidate]
                    break
        if target_file:
            results.edge(
                "imports", file_nodes.get(row["path"], ""), target_file,
                row["evidence"], state="proven")

    known_by_tail: dict[str, list[str]] = {}
    for qualified in function_nodes:
        known_by_tail.setdefault(qualified.rsplit(".", 1)[-1], []).append(qualified)
    for row in results.functions:
        caller = function_nodes.get(row["qualified"], "")
        for call in row["calls"]:
            callee_name = call["callee"]
            callee = function_nodes.get(callee_name, "")
            if not callee:
                candidates = known_by_tail.get(callee_name.rsplit(".", 1)[-1], [])
                if len(candidates) == 1:
                    callee = function_nodes[candidates[0]]
            if callee:
                results.edge(
                    "invokes", caller, callee, call["evidence"], state="inferred")

    services = {row["name"].casefold(): row for row in results.services}
    for source in sources:
        owner = file_nodes.get(source.path, "")
        for match in _URL_LITERAL.finditer(source.text):
            hostname = match.group(1).casefold()
            if hostname not in services:
                continue
            line = _line(source.text, match.start())
            evidence = [_evidence(source, line, "literal-service-url")]
            results.edge(
                "calls-service", owner, services[hostname]["node"],
                evidence, state="inferred")


def _attack_paths(results: _Results) -> list[dict[str, Any]]:
    adjacency: dict[str, list[tuple[str, str]]] = {}
    for edge in results.edges.values():
        adjacency.setdefault(edge["source"], []).append((edge["target"], edge["id"]))
    for rows in adjacency.values():
        rows.sort()
    sink_nodes = {row["node"]: row for row in results.sinks}
    output: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for entry in sorted(results.entrypoints, key=lambda row: (
            row["path"], row["line"], row["route"])):
        start = entry["node"]
        queue: deque[tuple[str, list[str], list[str]]] = deque([(start, [start], [])])
        visited_depth: dict[str, int] = {start: 0}
        while queue and len(output) < results.limits.max_attack_paths:
            current, node_path, edge_path = queue.popleft()
            if current in sink_nodes and current != start:
                signature = tuple(node_path)
                if signature not in seen:
                    seen.add(signature)
                    sink = sink_nodes[current]
                    finding_id = results.nodes.get(current, {}).get("finding_id", "")
                    finding = next(
                        (row for row in results.findings.values()
                         if row["id"] == finding_id), None)
                    if finding:
                        path_exploitability = {
                            **finding["exploitability"],
                            "factors": [
                                dict(row)
                                for row in finding["exploitability"]["factors"]
                            ],
                        }
                        static_path_evidence = [
                            evidence
                            for edge_id in edge_path
                            for evidence in results.edges.get(
                                edge_id, {}).get("evidence", [])[:1]
                        ][:4]
                        path_exploitability["factors"].append({
                            "name": "entrypoint-to-sink-static-reachability",
                            "observed": True,
                            "weight": 15,
                            "evidence_state": "inferred",
                            "evidence": static_path_evidence,
                        })
                        adjustment = 15
                        auth_already_scored = any(
                            row.get("name") == "authorization-control-observed"
                            and row.get("observed") is True
                            for row in path_exploitability["factors"])
                        if entry["auth_evidence"] and not auth_already_scored:
                            path_exploitability["factors"].append({
                                "name": "entrypoint-authentication-control-observed",
                                "observed": True,
                                "weight": -15,
                                "evidence_state": "proven",
                                "evidence": entry["auth_evidence"][:2],
                            })
                            adjustment -= 15
                        score = max(0, min(
                            100, int(path_exploitability["score"]) + adjustment))
                        path_exploitability["score"] = score
                        path_exploitability["band"] = (
                            "critical" if score >= 85 else
                            "high" if score >= 65 else
                            "medium" if score >= 40 else "low")
                        path_exploitability["evidence_state"] = "inferred"
                    else:
                        path_exploitability = {
                            "score": 0, "band": "low",
                            "evidence_state": "unverified",
                            "runtime_exploitability": "unverified",
                            "factors": [],
                        }
                    output.append({
                        "id": _stable_id("AP413-", {
                            "nodes": node_path, "edges": edge_path}),
                        "entrypoint": start,
                        "sink": current,
                        "nodes": node_path,
                        "edges": edge_path,
                        "finding_id": finding_id,
                        "category": sink["category"],
                        "evidence_state": "inferred",
                        "runtime_exploitability": "unverified",
                        "exploitability": path_exploitability,
                        "gaps": [
                            "the path is a bounded static reachability hypothesis",
                            "runtime dispatch and deployed controls were not exercised",
                        ],
                    })
            if len(node_path) >= MAX_PATH_DEPTH:
                continue
            for target, edge_id in adjacency.get(current, []):
                if target in node_path:
                    continue
                depth = len(node_path)
                if visited_depth.get(target, MAX_PATH_DEPTH + 1) < depth:
                    continue
                visited_depth[target] = depth
                queue.append((target, [*node_path, target], [*edge_path, edge_id]))
        if len(output) >= results.limits.max_attack_paths:
            results.hits.add("max_attack_paths")
            break
    return sorted(output, key=lambda row: row["id"])


_TRIAGE_REACHABLE_OPEN = "reachable-from-unauthenticated-entrypoint"
_TRIAGE_REACHABLE_AUTH = "reachable-behind-authentication-control"
_TRIAGE_NO_PATH = "no-static-path-from-a-discovered-entrypoint"
_TRIAGE_UNKNOWN = "reachability-unknown"
_TRIAGE_GRADES = (
    _TRIAGE_REACHABLE_OPEN, _TRIAGE_REACHABLE_AUTH,
    _TRIAGE_NO_PATH, _TRIAGE_UNKNOWN,
)
# Review order, not a risk score. A grade orders work; it does not claim that a
# lower-ranked finding is safe.
_TRIAGE_RANK = {name: index for index, name in enumerate(_TRIAGE_GRADES)}


def _apply_reachability_triage(results: _Results, paths: Sequence[Mapping[str, Any]],
                               findings: Sequence[dict[str, Any]]) -> None:
    """Fold entrypoint reachability back onto each finding, in place.

    Why this exists
    ---------------
    `_attack_paths` already proves the expensive part: which sinks a discovered
    entry point can statically reach, and whether that route crossed an
    authentication control. Until now that knowledge lived only on the path
    objects, so the findings list -- the thing a reviewer actually works
    through -- showed several hundred entries that all looked equally
    unverified. The evidence to order them was computed and then dropped.

    What the grade means, and what it must never mean
    -------------------------------------------------
    A grade orders review effort. It is not a claim about runtime, and
    `runtime_exploitability` stays `unverified` on every finding regardless of
    grade -- nothing here executes anything.

    The two "not reachable" cases are deliberately kept apart, and that
    distinction is the honest core of this function:

    * `no-static-path-from-a-discovered-entrypoint` means entry points *were*
      found and none of them reached this sink. That is real, if bounded,
      evidence for deprioritising.
    * `reachability-unknown` means no entry point was discovered at all -- a
      library, or a framework this analyzer cannot parse. Nothing was learned,
      so the finding must not be pushed down the queue. Collapsing these two
      into one "low priority" bucket would silently bury findings in exactly
      the codebases where the analyzer understood the least, which is the
      failure mode that makes people stop trusting a triage feature.
    """
    by_finding: dict[str, list[Mapping[str, Any]]] = {}
    for path in paths:
        identifier = path.get("finding_id")
        if isinstance(identifier, str) and identifier:
            by_finding.setdefault(identifier, []).append(path)

    entrypoints_discovered = len(results.entrypoints)
    for finding in findings:
        reaching = by_finding.get(finding["id"], [])
        if reaching:
            # A path counts as authentication-gated only when the traversal
            # recorded the control itself, not merely because a route existed.
            gated = []
            for path in reaching:
                factors = path.get("exploitability", {}).get("factors", [])
                gated.append(any(
                    row.get("name") in {
                        "entrypoint-authentication-control-observed",
                        "authorization-control-observed"}
                    and row.get("observed") is True
                    for row in factors))
            all_gated = all(gated)
            grade = _TRIAGE_REACHABLE_AUTH if all_gated else _TRIAGE_REACHABLE_OPEN
            hops = min(max(0, len(path.get("nodes", [])) - 1) for path in reaching)
            basis = (
                "every discovered route to this sink crossed an authentication "
                "control" if all_gated else
                "at least one discovered route reaches this sink without an "
                "observed authentication control")
        elif entrypoints_discovered:
            grade = _TRIAGE_NO_PATH
            hops = 0
            basis = (
                "%d entry point(s) were discovered and none statically reached "
                "this sink" % entrypoints_discovered)
        else:
            grade = _TRIAGE_UNKNOWN
            hops = 0
            basis = (
                "no entry point was discovered, so reachability could not be "
                "assessed either way")
        finding["triage"] = {
            "grade": grade,
            "rank": _TRIAGE_RANK[grade],
            "basis": basis,
            "reaching_path_count": len(reaching),
            "shortest_path_hops": hops,
            "entry_points_discovered": entrypoints_discovered,
            "evidence_state": "inferred",
            # Restated here so a consumer reading only the triage block cannot
            # mistake a review grade for a runtime finding.
            "runtime_exploitability": "unverified",
        }


def _triage_summary(findings: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Roll the grades up so the queue size is visible without reading findings."""
    counts = {name: 0 for name in _TRIAGE_GRADES}
    for finding in findings:
        grade = finding.get("triage", {}).get("grade")
        if grade in counts:
            counts[grade] += 1
    return {
        "by_grade": counts,
        "review_first": counts[_TRIAGE_REACHABLE_OPEN],
        "semantics": (
            "Grades order review effort from bounded static reachability. They "
            "are not runtime proof, and 'reachability-unknown' means nothing "
            "was learned rather than that the finding is low risk."
        ),
    }


def _threat_model(results: _Results) -> dict[str, Any]:
    assets: list[dict[str, Any]] = []
    category_assets = {
        "sql-injection": ("application data stores", "data"),
        "authorization": ("tenant and object-level data", "data"),
        "command-injection": ("host execution integrity", "execution"),
        "code-injection": ("application execution integrity", "execution"),
        "ssrf": ("internal services and outbound network trust", "network"),
        "session-security": ("sessions and authentication tokens", "identity"),
        "jwt": ("token signing and identity assertions", "identity"),
        "oauth": ("authorization grants and redirect integrity", "identity"),
        "csrf": ("authenticated user actions", "identity"),
        "request-smuggling": ("HTTP request routing integrity", "routing"),
    }
    findings = list(results.findings.values())
    file_evidence = [
        row["evidence"][0]
        for row in results.nodes.values()
        if row.get("kind") == "file" and row.get("evidence")
    ][:4]
    if file_evidence:
        assets.append({
            "id": _stable_id("A413-", {
                "name": "source and configuration integrity", "kind": "source"}),
            "name": "source and configuration integrity", "kind": "source",
            "evidence_state": "proven", "evidence": file_evidence,
        })
    for category in sorted({row["category"] for row in findings}):
        name, kind = category_assets.get(
            category, ("application security properties", "application"))
        evidence = [
            row["evidence"][0] for row in findings
            if row["category"] == category and row["evidence"]
        ][:4]
        assets.append({
            "id": _stable_id("A413-", {"name": name, "kind": kind}),
            "name": name, "kind": kind,
            "evidence_state": "inferred", "evidence": evidence,
        })
    if results.entrypoints:
        assets.append({
            "id": _stable_id("A413-", {"name": "public API behavior", "kind": "api"}),
            "name": "public API behavior", "kind": "api",
            "evidence_state": "inferred",
            "evidence": [
                row["evidence"][0] for row in results.entrypoints if row["evidence"]
            ][:4],
        })
    if results.services:
        assets.append({
            "id": _stable_id("A413-", {
                "name": "service availability and identity", "kind": "service"}),
            "name": "service availability and identity", "kind": "service",
            "evidence_state": "inferred",
            "evidence": [
                row["evidence"][0] for row in results.services if row["evidence"]
            ][:4],
        })
    boundaries: list[dict[str, Any]] = []
    if results.entrypoints:
        boundaries.append({
            "id": "TB413-external-to-application",
            "from": "external client", "to": "application route",
            "evidence_state": "inferred",
            "evidence": [
                row["evidence"][0] for row in results.entrypoints if row["evidence"]
            ][:4],
        })
    if any(row["category"] in {"sql-injection", "authorization"} for row in results.sinks):
        boundaries.append({
            "id": "TB413-application-to-data-store",
            "from": "application", "to": "data store",
            "evidence_state": "inferred",
            "evidence": [
                row["evidence"][0] for row in results.sinks
                if row["category"] in {"sql-injection", "authorization"}
                and row["evidence"]
            ][:4],
        })
    if any(row["category"] == "ssrf" for row in results.sinks):
        boundaries.append({
            "id": "TB413-application-to-external-network",
            "from": "application", "to": "outbound network",
            "evidence_state": "inferred",
            "evidence": [
                row["evidence"][0] for row in results.sinks
                if row["category"] == "ssrf" and row["evidence"]
            ][:4],
        })
    if results.services:
        boundaries.append({
            "id": "TB413-service-to-service",
            "from": "application service", "to": "peer service",
            "evidence_state": "inferred",
            "evidence": [
                row["evidence"][0] for row in results.services if row["evidence"]
            ][:4],
        })
    return {
        "assets": sorted(assets, key=lambda row: row["id"]),
        "trust_boundaries": sorted(boundaries, key=lambda row: row["id"]),
        "entry_points": [
            {
                "node": row["node"], "path": row["path"], "line": row["line"],
                "route": row["route"], "methods": row["methods"],
                "authentication_evidence": row["auth_evidence"],
                "authentication_state": (
                    "proven-present" if row["auth_evidence"] else "unverified"),
                "evidence_state": "proven",
            }
            for row in sorted(results.entrypoints, key=lambda item: (
                item["path"], item["line"], item["route"]))
        ],
    }


def _assurance() -> dict[str, Any]:
    return {
        "analysis_mode": "bounded-static-evidence-only",
        "target_code_executed": False,
        "target_modules_imported": False,
        "processes_started": False,
        "network_accessed": False,
        "target_files_written": False,
        "remediation_applied": False,
        "exploit_payloads_generated": False,
        "symlinks_followed": False,
        "claim_states": {
            "proven": "direct syntax, snapshot, or configuration evidence was observed",
            "inferred": "a bounded static relationship was derived from direct evidence",
            "unverified": "runtime or deployment evidence was not collected",
        },
    }


def _execution() -> dict[str, bool]:
    """Machine-checkable execution side-effect contract for integrations."""
    return {
        "target_code_executed": False,
        "target_modules_imported": False,
        "processes_started": False,
        "network_accessed": False,
        "target_files_written": False,
        "remediation_applied": False,
        "exploit_payloads_generated": False,
        "symlinks_followed": False,
    }


def _finalize(body: dict[str, Any]) -> dict[str, Any]:
    result = dict(body)
    if len(_canonical(result)) > MAX_REPORT_BYTES:
        # Fail closed with a small, schema-complete report rather than handing a
        # worker an oversized JSON object or throwing away the execution
        # contract.
        result = {
            "schema": SCHEMA,
            "version": VERSION,
            "status": "failed",
            "root": _safe_text(body.get("root", ""), 4_096),
            "summary": {
                "findings": 0, "attack_paths": 0, "entry_points": 0,
                "graph_nodes": 0, "graph_edges": 0,
                "evidence_states": {
                    "proven": 0, "inferred": 0, "unverified": 0},
            },
            "findings": [],
            "graph": {"nodes": [], "edges": []},
            "attack_paths": [],
            "threat_model": {
                "assets": [], "trust_boundaries": [], "entry_points": []},
            "coverage": {
                "complete": False,
                "inventory": body.get("coverage", {}).get("inventory", {}),
                "gaps": [_gap(
                    "report-output-budget", ".", str(MAX_REPORT_BYTES))],
                "errors": ["report exceeded the hard serialized output budget"],
            },
            "limits": body.get("limits", {"configured": {}, "hit": []}),
            "execution": _execution(),
            "assurance": _assurance(),
        }
    result["report_sha256"] = _sha(result)
    return result


def _failed(root: str, limits: Limits, reason: str) -> dict[str, Any]:
    return _finalize({
        "schema": SCHEMA,
        "version": VERSION,
        "status": "failed",
        "root": _safe_text(root.replace("\\", "/"), 4_096),
        "summary": {
            "findings": 0, "attack_paths": 0, "entry_points": 0,
            "graph_nodes": 0, "graph_edges": 0,
            "evidence_states": {"proven": 0, "inferred": 0, "unverified": 0},
        },
        "findings": [],
        "graph": {"nodes": [], "edges": []},
        "attack_paths": [],
        "threat_model": {"assets": [], "trust_boundaries": [], "entry_points": []},
        "coverage": {
            "complete": False,
            "inventory": {
                "scope_kind": "unknown", "files_considered": 0, "files_loaded": 0,
                "total_bytes": 0, "decoded_with_replacement": 0,
                "snapshot_sha256": _sha([]),
            },
            "gaps": [_gap("analysis-failed", ".", reason)],
            "errors": [_safe_text(reason, 512)],
        },
        "limits": {"configured": limits.public(), "hit": []},
        "execution": _execution(),
        "assurance": _assurance(),
    })


def analyze(
        root: str | os.PathLike[str], *, snapshot_or_documents: Any = None,
        limits: Limits | None = None,
) -> dict[str, Any]:
    """Return a deterministic defensive report.

    ``snapshot_or_documents`` may be an Attestor immutable snapshot, a mapping of
    portable paths to text/bytes, or a sequence of ``{"path", "content"}``
    records.  When supplied, target filesystem discovery is skipped entirely.
    """
    policy = Limits() if limits is None else limits
    if not isinstance(policy, Limits):
        raise AttackSurface413Error("limits must be a Limits instance")
    if snapshot_or_documents is None:
        try:
            requested = Path(os.fspath(root)).expanduser()
        except (TypeError, ValueError, OSError):
            return _failed(str(root), policy, "analysis root is invalid")
        try:
            metadata = requested.lstat()
            if _link_or_reparse(metadata):
                return _failed(
                    str(requested), policy,
                    "analysis root may not be a symbolic link or reparse point")
            resolved = requested.resolve(strict=True)
        except OSError:
            return _failed(str(requested), policy, "analysis root is not readable")
        if not (resolved.is_dir() or resolved.is_file()):
            return _failed(
                str(resolved), policy,
                "analysis root is not a regular file or directory")
        sources, snapshot_gaps, snapshot_hits, inventory = _snapshot(resolved, policy)
        root_label = str(resolved)
    else:
        try:
            sources, snapshot_gaps, snapshot_hits, inventory = (
                _sources_from_documents(snapshot_or_documents, policy))
        except AttackSurface413Error as exc:
            return _failed(str(root), policy, str(exc))
        root_label = str(root)
    results = _Results(policy)
    ast_budget = [policy.max_ast_nodes]
    _discover_services(sources, results)
    _discover_api_contracts(sources, results)
    for source in sources:
        if source.language == "python":
            _analyze_python(source, results, ast_budget)
        elif source.language in {"javascript", "typescript"}:
            _analyze_javascript(source, results)
            results.add_gap(
                "lexical-language-adapter", source.path,
                "JavaScript/TypeScript evidence is not compiler-grade")
        _config_findings(source, results)
    _build_graph(sources, results)
    paths = _attack_paths(results)
    threat_model = _threat_model(results)

    all_gaps = [*snapshot_gaps, *results.gaps]
    if results.hits & {"max_graph_nodes", "max_graph_edges"}:
        all_gaps.append(_gap(
            "graph-output-truncated", ".",
            ",".join(sorted(results.hits & {"max_graph_nodes", "max_graph_edges"}))))
    if "max_findings" in results.hits:
        all_gaps.append(_gap("finding-output-truncated", ".", str(policy.max_findings)))
    if "max_attack_paths" in results.hits:
        all_gaps.append(_gap("attack-path-output-truncated", ".",
                             str(policy.max_attack_paths)))
    all_gaps = sorted(all_gaps, key=_canonical)
    if len(all_gaps) > policy.max_gaps:
        results.hits.add("max_gaps")
        all_gaps = all_gaps[:policy.max_gaps]

    findings = sorted(results.findings.values(), key=lambda row: (
        _SEVERITY_ORDER.get(row["severity"], 9), row["path"], row["line"],
        row["rule"], row["id"]))
    # Fold reachability back onto the findings before they are serialized, then
    # order by review grade first. Severity still breaks ties, but a reachable
    # medium outranks an unreachable high: which one an attacker can actually
    # touch is the more useful question when the queue is long.
    _apply_reachability_triage(results, paths, findings)
    findings.sort(key=lambda row: (
        row["triage"]["rank"], _SEVERITY_ORDER.get(row["severity"], 9),
        row["path"], row["line"], row["rule"], row["id"]))
    nodes = sorted(results.nodes.values(), key=lambda row: row["id"])
    edges = sorted(results.edges.values(), key=lambda row: row["id"])
    state_counts = Counter(
        row["evidence_state"] for row in [*findings, *nodes, *edges, *paths]
        if row.get("evidence_state") in {"proven", "inferred", "unverified"})
    limit_hits = sorted(set(snapshot_hits) | results.hits)
    if findings:
        status = "partial-findings" if all_gaps else "findings"
    else:
        status = "partial" if all_gaps else "clean"
    body = {
        "schema": SCHEMA,
        "version": VERSION,
        "status": status,
        "root": _safe_text(root_label.replace("\\", "/"), 4_096),
        "summary": {
            "findings": len(findings),
            "severity": {
                severity: sum(1 for row in findings if row["severity"] == severity)
                for severity in ("critical", "high", "medium", "low", "info")
            },
            "attack_paths": len(paths),
            "entry_points": len(results.entrypoints),
            "graph_nodes": len(nodes),
            "graph_edges": len(edges),
            "evidence_states": {
                state: state_counts.get(state, 0)
                for state in ("proven", "inferred", "unverified")
            },
            "highest_exploitability_score": max(
                (row["exploitability"]["score"] for row in findings), default=0),
            "triage": _triage_summary(findings),
        },
        "findings": findings,
        "graph": {
            "nodes": nodes,
            "edges": edges,
            "semantics": (
                "Edges marked inferred are bounded static reachability hypotheses; "
                "they are not runtime call traces."
            ),
        },
        "attack_paths": paths,
        "threat_model": threat_model,
        "coverage": {
            "complete": not all_gaps,
            "inventory": inventory,
            "gaps": all_gaps,
            "errors": [],
            "adapters": {
                "python": "stdlib-ast-bounded-static-dataflow",
                "javascript": "bounded-lexical-static-evidence",
                "typescript": "bounded-lexical-static-evidence",
                "configuration": "bounded-explicit-pattern-evidence",
            },
        },
        "limits": {
            "configured": policy.public(),
            "hard_ceiling": {
                "max_files": MAX_FILES_HARD,
                "max_file_bytes": MAX_FILE_BYTES_HARD,
                "max_total_bytes": MAX_TOTAL_BYTES_HARD,
                "max_ast_nodes": MAX_AST_NODES_HARD,
                "max_graph_nodes": MAX_GRAPH_NODES_HARD,
                "max_graph_edges": MAX_GRAPH_EDGES_HARD,
                "max_findings": MAX_FINDINGS_HARD,
                "max_attack_paths": MAX_ATTACK_PATHS_HARD,
                "max_gaps": MAX_GAPS_HARD,
                "max_directory_entries": MAX_DIRECTORY_ENTRIES_HARD,
            },
            "hit": limit_hits,
        },
        "execution": _execution(),
        "assurance": _assurance(),
    }
    return _finalize(body)


def verify_report(report: Any) -> tuple[bool, list[str]]:
    """Strictly verify an attack-surface report and its content digest."""
    errors: list[str] = []

    def error(message: str) -> None:
        if len(errors) < 100:
            errors.append(message)

    if not isinstance(report, Mapping):
        return False, ["report must be an object"]
    required = {
        "schema", "version", "status", "root", "summary", "findings", "graph",
        "attack_paths", "threat_model", "coverage", "limits", "execution",
        "assurance", "report_sha256",
    }
    missing = sorted(required - set(report))
    if missing:
        error("missing fields: " + ",".join(missing))
    unexpected = sorted(set(report) - required, key=lambda value: str(value))
    if unexpected:
        error("unexpected fields: " + ",".join(map(str, unexpected[:10])))
    if report.get("schema") != SCHEMA:
        error("schema mismatch")
    if report.get("version") != VERSION:
        error("version mismatch")
    if report.get("status") not in {
            "clean", "partial", "findings", "partial-findings", "failed"}:
        error("invalid status")
    digest = report.get("report_sha256")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        error("report_sha256 must be lowercase SHA-256")
    try:
        encoded = _canonical(report)
        if len(encoded) > MAX_REPORT_BYTES + 1_024:
            error("report exceeds serialized output budget")
        body = dict(report)
        body.pop("report_sha256", None)
        expected = _sha(body)
        if digest != expected:
            error("report digest mismatch")
    except AttackSurface413Error:
        error("report is not canonical bounded JSON")

    # A valid digest alone is not enough if a producer can sign ambiguous or
    # terminal-active strings.  Bound the entire JSON tree and reject raw
    # controls even when a malicious producer recomputes the digest.
    pending: list[tuple[Any, int]] = [(report, 0)]
    visited = 0
    while pending:
        value, depth = pending.pop()
        visited += 1
        if visited > 500_000:
            error("report JSON item budget exceeded")
            break
        if depth > 64:
            error("report JSON nesting budget exceeded")
            break
        if isinstance(value, str):
            if len(value) > 16_384:
                error("report string budget exceeded")
                break
            if any(
                ord(char) < 0x20
                or 0x7F <= ord(char) <= 0x9F
                or ord(char) in _BIDI_CONTROLS
                for char in value
            ):
                error("report contains an unescaped terminal or bidi control")
                break
        elif isinstance(value, Mapping):
            pending.extend((key, depth + 1) for key in value)
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)

    findings = report.get("findings")
    graph = report.get("graph")
    paths = report.get("attack_paths")
    threat = report.get("threat_model")
    coverage = report.get("coverage")
    execution = report.get("execution")
    summary = report.get("summary")
    limits = report.get("limits")
    if not isinstance(report.get("root"), str):
        error("root must be text")
    if not isinstance(summary, Mapping):
        error("summary must be an object")
        summary = {}
    if not isinstance(limits, Mapping):
        error("limits must be an object")
        limits = {}
    configured = limits.get("configured")
    if not isinstance(configured, Mapping):
        error("limits.configured must be an object")
    else:
        ceilings = {
            "max_files": MAX_FILES_HARD,
            "max_file_bytes": MAX_FILE_BYTES_HARD,
            "max_total_bytes": MAX_TOTAL_BYTES_HARD,
            "max_ast_nodes": MAX_AST_NODES_HARD,
            "max_graph_nodes": MAX_GRAPH_NODES_HARD,
            "max_graph_edges": MAX_GRAPH_EDGES_HARD,
            "max_findings": MAX_FINDINGS_HARD,
            "max_attack_paths": MAX_ATTACK_PATHS_HARD,
            "max_gaps": MAX_GAPS_HARD,
            "max_directory_entries": MAX_DIRECTORY_ENTRIES_HARD,
        }
        if set(configured) != set(ceilings):
            error("limits.configured has an invalid shape")
        for name, ceiling in ceilings.items():
            value = configured.get(name)
            if type(value) is not int or not 1 <= value <= ceiling:
                error(f"limits.configured.{name} is invalid")
    hits = limits.get("hit")
    if not isinstance(hits, list) or not all(isinstance(item, str) for item in hits):
        error("limits.hit must be a list of labels")
    if not isinstance(findings, list):
        error("findings must be a list")
        findings = []
    if not isinstance(graph, Mapping):
        error("graph must be an object")
        graph = {}
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    if not isinstance(nodes, list) or len(nodes) > MAX_GRAPH_NODES_HARD:
        error("graph nodes violate the hard budget")
        nodes = []
    if not isinstance(edges, list) or len(edges) > MAX_GRAPH_EDGES_HARD:
        error("graph edges violate the hard budget")
        edges = []
    if len(findings) > MAX_FINDINGS_HARD:
        error("findings violate the hard budget")
    if not isinstance(paths, list) or len(paths) > MAX_ATTACK_PATHS_HARD:
        error("attack paths violate the hard budget")
        paths = []
    if not isinstance(threat, Mapping) or not all(
            isinstance(threat.get(key), list)
            for key in ("assets", "trust_boundaries", "entry_points")):
        error("threat_model has an invalid shape")
    if not isinstance(coverage, Mapping) or not isinstance(
            coverage.get("gaps", []), list):
        error("coverage has an invalid shape")
    elif len(coverage.get("gaps", [])) > MAX_GAPS_HARD:
        error("coverage gaps violate the hard budget")

    node_ids: set[str] = set()
    for node in nodes:
        if not isinstance(node, Mapping):
            error("graph node must be an object")
            continue
        identifier = node.get("id")
        if not isinstance(identifier, str) or not identifier.startswith("N413-"):
            error("graph node has an invalid id")
        elif identifier in node_ids:
            error("graph node ids must be unique")
        else:
            node_ids.add(identifier)
        if node.get("evidence_state") not in {"proven", "inferred", "unverified"}:
            error("graph node has an invalid evidence_state")
    edge_ids: set[str] = set()
    for edge in edges:
        if not isinstance(edge, Mapping):
            error("graph edge must be an object")
            continue
        identifier = edge.get("id")
        if not isinstance(identifier, str) or not identifier.startswith("E413-"):
            error("graph edge has an invalid id")
        elif identifier in edge_ids:
            error("graph edge ids must be unique")
        else:
            edge_ids.add(identifier)
        if edge.get("source") not in node_ids or edge.get("target") not in node_ids:
            error("graph edge references an unknown node")
        if edge.get("evidence_state") not in {"proven", "inferred", "unverified"}:
            error("graph edge has an invalid evidence_state")
    finding_ids: set[str] = set()
    for finding in findings:
        if not isinstance(finding, Mapping):
            error("finding must be an object")
            continue
        identifier = finding.get("id")
        if not isinstance(identifier, str) or not identifier.startswith("AS413-"):
            error("finding has an invalid id")
        elif identifier in finding_ids:
            error("finding ids must be unique")
        else:
            finding_ids.add(identifier)
        if finding.get("evidence_state") not in {"proven", "inferred", "unverified"}:
            error("finding has an invalid evidence_state")
        exploitability = finding.get("exploitability")
        if not isinstance(exploitability, Mapping):
            error("finding exploitability must be an object")
        else:
            score = exploitability.get("score")
            if type(score) is not int or not 0 <= score <= 100:
                error("finding exploitability score is invalid")
            if exploitability.get("runtime_exploitability") != "unverified":
                error("runtime exploitability must remain unverified")
        triage = finding.get("triage")
        if not isinstance(triage, Mapping):
            error("finding triage must be an object")
        else:
            grade = triage.get("grade")
            if grade not in _TRIAGE_RANK:
                error("finding triage grade is invalid")
            elif triage.get("rank") != _TRIAGE_RANK[grade]:
                error("finding triage rank does not match its grade")
            # A triage grade orders review; it must never be readable as a
            # runtime claim, so the disclaimer is enforced rather than trusted.
            if triage.get("runtime_exploitability") != "unverified":
                error("triage runtime exploitability must remain unverified")
            if triage.get("evidence_state") != "inferred":
                error("triage evidence_state must be inferred")
            for name in ("reaching_path_count", "shortest_path_hops",
                         "entry_points_discovered"):
                value = triage.get(name)
                if type(value) is not int or value < 0:
                    error(f"finding triage.{name} is invalid")
            # A finding graded reachable must actually have a path, and one
            # graded unreachable must not -- otherwise the grade is decoration.
            reaching = triage.get("reaching_path_count")
            if grade in {_TRIAGE_REACHABLE_OPEN, _TRIAGE_REACHABLE_AUTH} and reaching == 0:
                error("finding is graded reachable with no reaching path")
            if grade in {_TRIAGE_NO_PATH, _TRIAGE_UNKNOWN} and reaching:
                error("finding is graded unreachable but has a reaching path")
            if grade == _TRIAGE_UNKNOWN and triage.get("entry_points_discovered"):
                error("reachability-unknown requires that no entry point was found")
            if grade == _TRIAGE_NO_PATH and not triage.get("entry_points_discovered"):
                error("no-static-path requires at least one discovered entry point")
    attack_path_ids: set[str] = set()
    for path in paths:
        if not isinstance(path, Mapping):
            error("attack path must be an object")
            continue
        identifier = path.get("id")
        if not isinstance(identifier, str) or not identifier.startswith("AP413-"):
            error("attack path has an invalid id")
        elif identifier in attack_path_ids:
            error("attack path ids must be unique")
        else:
            attack_path_ids.add(identifier)
        if path.get("evidence_state") != "inferred":
            error("attack paths must be labeled inferred")
        if path.get("runtime_exploitability") != "unverified":
            error("attack path runtime exploitability must remain unverified")
        path_nodes = path.get("nodes")
        path_edges = path.get("edges")
        if not isinstance(path_nodes, list):
            error("attack path nodes must be a list")
            path_nodes = []
        if not isinstance(path_edges, list):
            error("attack path edges must be a list")
            path_edges = []
        if any(identifier not in node_ids for identifier in path_nodes):
            error("attack path references an unknown node")
        if any(identifier not in edge_ids for identifier in path_edges):
            error("attack path references an unknown edge")
        finding_id = path.get("finding_id")
        if finding_id and finding_id not in finding_ids:
            error("attack path references an unknown finding")

    expected_execution = _execution()
    if not isinstance(execution, Mapping):
        error("execution must be an object")
    elif dict(execution) != expected_execution:
        error("execution contract is not the required no-side-effect contract")
    assurance = report.get("assurance")
    if not isinstance(assurance, Mapping):
        error("assurance must be an object")
    else:
        for key, expected_value in expected_execution.items():
            if assurance.get(key) is not expected_value:
                error(f"assurance.{key} violates the static contract")

    count_checks = {
        "findings": len(findings),
        "attack_paths": len(paths),
        "graph_nodes": len(nodes),
        "graph_edges": len(edges),
    }
    for name, expected_count in count_checks.items():
        if summary.get(name) != expected_count:
            error(f"summary.{name} does not match report contents")
    # Recompute the triage roll-up rather than trusting it. A headline count
    # that can drift from the findings it summarizes is worse than none.
    summary_triage = summary.get("triage")
    if not isinstance(summary_triage, Mapping):
        error("summary.triage must be an object")
    else:
        expected_triage = _triage_summary(
            [row for row in findings if isinstance(row, Mapping)])
        if summary_triage.get("by_grade") != expected_triage["by_grade"]:
            error("summary.triage.by_grade does not match the findings")
        if summary_triage.get("review_first") != expected_triage["review_first"]:
            error("summary.triage.review_first does not match the findings")
    if report.get("status") in {"clean", "partial"} and findings:
        error("non-finding status may not contain findings")
    if report.get("status") in {"findings", "partial-findings"} and not findings:
        error("finding status must contain a finding")

    return not errors, errors


scan = analyze


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run Attestor's bounded defensive attack-surface analysis.")
    parser.add_argument("root", help="local source file or repository directory")
    arguments = parser.parse_args(argv)
    print(json.dumps(analyze(arguments.root), sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through the CLI
    raise SystemExit(_main())


__all__ = [
    "VERSION", "SCHEMA", "Limits", "AttackSurface413Error", "analyze", "scan",
    "verify_report",
]
