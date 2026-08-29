#!/usr/bin/env python3
"""Attestor 4.0 bounded, offline defensive cybersecurity fabric.

The fabric inspects immutable, size-bounded snapshots of local text files.  It
never imports or executes target code, resolves dependencies, contacts a
network service, probes a host, or applies remediation.  Existing Attestor engines
are reused only through pure in-memory scanners or an isolated bounded lockfile
snapshot, preventing them from independently ingesting an untrusted tree.
"""
from __future__ import annotations

import ast
import hashlib
import heapq
import json
import os
import re
import stat
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import secret_guard
import secmax
import security_intelligence
import security_posture
import supply_chain35


VERSION = "4.0.0"
SCHEMA = "attestor-security-fabric/4.0"

MAX_FILES_HARD = 5_000
MAX_FILE_BYTES_HARD = 2 * 1024 * 1024
MAX_TOTAL_BYTES_HARD = 32 * 1024 * 1024
MAX_FINDINGS_HARD = 5_000
MAX_SURFACE_HARD = 1_500
MAX_ATTACK_PATHS_HARD = 250
MAX_SKIPPED = 250
MAX_GAPS = 500
MAX_EVIDENCE = 6
MAX_LINE_CHARS = 16 * 1024
MAX_RAW_FINDINGS = 10_000
MAX_ROWS_PER_SCANNER = 512
MAX_AST_NODES_PER_FILE = 100_000

SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", ".venv", "venv", "node_modules", "vendor",
    "dist", "build", "target", ".terraform", ".next", ".gradle", "bin",
    "obj", "coverage", "htmlcov",
}
TEXT_SUFFIXES = set(security_intelligence.TEXT_SUFFIXES)
TEXT_NAMES = set(security_intelligence.TEXT_NAMES) | {
    "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
    "openapi.yaml", "openapi.yml", "swagger.yaml", "swagger.yml",
}
SEVERITY_WEIGHT = {"CRITICAL": 10.0, "HIGH": 8.0, "MEDIUM": 5.0,
                   "LOW": 2.5, "INFO": 1.0}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class SecurityFabric40Error(ValueError):
    """Raised for invalid caller-controlled configuration."""


@dataclass(frozen=True)
class Limits:
    max_files: int = 2_000
    max_file_bytes: int = 1024 * 1024
    max_total_bytes: int = 16 * 1024 * 1024
    max_findings: int = 3_000
    max_attack_surface: int = 1_000
    max_attack_paths: int = 100

    def __post_init__(self) -> None:
        hard = {
            "max_files": MAX_FILES_HARD,
            "max_file_bytes": MAX_FILE_BYTES_HARD,
            "max_total_bytes": MAX_TOTAL_BYTES_HARD,
            "max_findings": MAX_FINDINGS_HARD,
            "max_attack_surface": MAX_SURFACE_HARD,
            "max_attack_paths": MAX_ATTACK_PATHS_HARD,
        }
        for name, ceiling in hard.items():
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= ceiling:
                raise SecurityFabric40Error(
                    "%s must be an integer between 1 and %d" % (name, ceiling))

    def public(self) -> dict[str, int]:
        return dict(sorted(asdict(self).items()))


@dataclass(frozen=True)
class SourceSnapshot:
    path: Path
    relative: str
    raw: bytes
    text: str
    sha256: str
    decoded_with_replacement: bool = False


class _CappedRows(list[dict[str, Any]]):
    """List-shaped scanner sink that refuses resource-amplified output."""

    def __init__(self, limit: int) -> None:
        super().__init__()
        self.limit = max(1, int(limit))
        self.truncated = False

    def append(self, row: dict[str, Any]) -> None:
        if len(self) < self.limit:
            super().append(row)
        else:
            self.truncated = True


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _relative(base: Path, path: Path) -> str:
    resolved = path.resolve(strict=True)
    try:
        return resolved.relative_to(base).as_posix()
    except ValueError as exc:
        raise SecurityFabric40Error("candidate escaped the analysis root") from exc


def _eligible(path: Path) -> bool:
    return path.suffix.lower() in TEXT_SUFFIXES or path.name.lower() in TEXT_NAMES


def _linklike(path: Path) -> bool:
    """Recognize POSIX links and Windows reparse points without following them."""
    if path.is_symlink():
        return True
    metadata = path.lstat()
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(attributes & reparse)


def _record_skip(skipped: list[dict[str, Any]], *, path: str, reason: str,
                 **metadata: Any) -> None:
    if len(skipped) < MAX_SKIPPED:
        skipped.append({"path": path.replace("\\", "/"), "reason": reason, **metadata})


def _discover(base: Path, limits: Limits) -> tuple[
        list[SourceSnapshot], dict[str, Any], list[str], list[str], list[str]]:
    snapshots: list[SourceSnapshot] = []
    skipped: list[dict[str, Any]] = []
    gaps: set[str] = set()
    errors: list[str] = []
    considered = 0
    consumed = 0
    skip_count = 0
    limit_hits: set[str] = set()
    stop = False
    scope_root = base.parent if base.is_file() else base
    if base.is_file() and not _eligible(base):
        return [], {
            "scope_kind": "file", "files_considered": 0, "files_loaded": 0,
            "bytes_consumed": 0, "decoded_with_replacement": 0,
            "skipped": [{"path": base.name, "reason": "unsupported-file-type"}],
            "skipped_count": 1, "skipped_list_truncated": False,
        }, [], ["requested file type is outside the bounded static text allowlist"], []
    traversal = ([(str(scope_root), [], [base.name])] if base.is_file() else
                 os.walk(scope_root, topdown=True, followlinks=False))

    for current, directories, filenames in traversal:
        kept = []
        for name in sorted(directories, key=lambda value: (value.casefold(), value)):
            child = Path(current) / name
            if name.casefold() in SKIP_DIRS:
                continue
            try:
                if _linklike(child):
                    skip_count += 1
                    _record_skip(skipped, path=child.relative_to(scope_root).as_posix(),
                                 reason="symlink-directory-not-followed")
                    gaps.add("symbolic links were excluded from coverage")
                    continue
            except OSError:
                skip_count += 1
                _record_skip(skipped, path=str(child), reason="directory-inspection-error")
                gaps.add("one or more directories could not be inspected")
                continue
            kept.append(name)
        directories[:] = kept

        for name in sorted(filenames, key=lambda value: (value.casefold(), value)):
            path = Path(current) / name
            if not _eligible(path):
                continue
            if considered >= limits.max_files:
                limit_hits.add("max_files")
                gaps.add("repository input truncated at max_files")
                _record_skip(skipped, path=".", reason="max_files reached",
                             limit=limits.max_files)
                stop = True
                break
            considered += 1
            try:
                if _linklike(path):
                    skip_count += 1
                    _record_skip(skipped, path=path.relative_to(scope_root).as_posix(),
                                 reason="symlink-file-not-followed")
                    gaps.add("symbolic links were excluded from coverage")
                    continue
                resolved = path.resolve(strict=True)
                relative = _relative(scope_root, resolved)
                metadata = resolved.stat()
                if not stat.S_ISREG(metadata.st_mode):
                    skip_count += 1
                    _record_skip(skipped, path=relative, reason="non-regular-file")
                    continue
                if metadata.st_size > limits.max_file_bytes:
                    skip_count += 1
                    limit_hits.add("max_file_bytes")
                    gaps.add("one or more files were omitted at max_file_bytes")
                    _record_skip(skipped, path=relative, reason="max_file_bytes exceeded",
                                 bytes=metadata.st_size, limit=limits.max_file_bytes)
                    continue
                remaining = limits.max_total_bytes - consumed
                if metadata.st_size > remaining:
                    limit_hits.add("max_total_bytes")
                    gaps.add("repository input truncated at max_total_bytes")
                    _record_skip(skipped, path=relative, reason="max_total_bytes reached",
                                 bytes_consumed=consumed, candidate_bytes=metadata.st_size,
                                 limit=limits.max_total_bytes)
                    stop = True
                    break

                flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(resolved, flags)
                try:
                    opened = os.fstat(descriptor)
                    if not stat.S_ISREG(opened.st_mode):
                        raise OSError("opened input is not a regular file")
                    budget = min(limits.max_file_bytes, remaining)
                    with os.fdopen(descriptor, "rb", closefd=False) as stream:
                        raw = stream.read(budget + 1)
                finally:
                    os.close(descriptor)
                if len(raw) > remaining:
                    limit_hits.add("max_total_bytes")
                    gaps.add("repository input truncated at max_total_bytes")
                    _record_skip(skipped, path=relative, reason="max_total_bytes reached",
                                 bytes_consumed=consumed,
                                 candidate_bytes_at_least=len(raw),
                                 limit=limits.max_total_bytes)
                    stop = True
                    break
                if len(raw) > limits.max_file_bytes:
                    consumed += len(raw)
                    skip_count += 1
                    limit_hits.add("max_file_bytes")
                    gaps.add("one or more files changed beyond max_file_bytes during read")
                    _record_skip(skipped, path=relative, reason="max_file_bytes exceeded",
                                 bytes=len(raw), limit=limits.max_file_bytes)
                    continue
                consumed += len(raw)
                if b"\x00" in raw[:8192]:
                    skip_count += 1
                    _record_skip(skipped, path=relative, reason="binary-content")
                    continue
                replacement = False
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    text = raw.decode("utf-8", errors="replace")
                    replacement = True
                    gaps.add("one or more files required UTF-8 replacement decoding")
                snapshots.append(SourceSnapshot(
                    resolved, relative, raw, text.replace("\r\n", "\n").replace("\r", "\n"),
                    hashlib.sha256(raw).hexdigest(), replacement))
            except (OSError, SecurityFabric40Error) as exc:
                skip_count += 1
                label = path.relative_to(scope_root).as_posix() if path.is_absolute() else str(path)
                _record_skip(skipped, path=label, reason="read-or-containment-error",
                             error=type(exc).__name__)
                errors.append("%s: %s" % (label, type(exc).__name__))
                gaps.add("one or more files could not be read safely")
        if stop:
            break

    coverage = {
        "scope_kind": "file" if base.is_file() else "directory",
        "files_considered": considered,
        "files_loaded": len(snapshots),
        "bytes_consumed": consumed,
        "decoded_with_replacement": sum(row.decoded_with_replacement for row in snapshots),
        "skipped": sorted(skipped, key=lambda row: (row["path"], row["reason"])),
        "skipped_count": skip_count,
        "skipped_list_truncated": skip_count > len(skipped),
    }
    return snapshots, coverage, sorted(limit_hits), sorted(gaps), errors


def _finding(path: str, line: int, rule: str, severity: str, category: str,
             cwe: str, message: str, remediation: str, confidence: float,
             source: str = "security-fabric40") -> dict[str, Any]:
    return {
        "path": path, "line": max(1, int(line)), "rule": rule,
        "severity": severity, "category": category, "cwe": cwe,
        "message": message, "remediation": remediation, "fix": remediation,
        "confidence": round(max(0.0, min(float(confidence), 1.0)), 2),
        "source": source,
    }


def _dotted(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _dotted(node.value)
        return (left + "." if left else "") + node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


_SOURCE_CALLS = {
    "input", "builtins.input", "request.get_json", "flask.request.get_json",
    "request.args.get", "request.form.get", "request.values.get",
    "request.headers.get", "request.cookies.get", "sys.stdin.read",
    "sys.stdin.readline", "socket.recv",
}
_SOURCE_PREFIXES = ("request.args", "request.form", "request.values", "request.json",
                    "request.data", "request.headers", "request.cookies", "sys.argv")
_SANITIZERS = {"int", "float", "uuid.UUID", "secure_filename", "os.path.basename"}


def _tainted(node: ast.AST | None, names: set[str]) -> bool:
    if node is None or isinstance(node, ast.Constant):
        return False
    if isinstance(node, ast.Name):
        return node.id in names
    dotted = _dotted(node)
    if isinstance(node, ast.Call):
        if dotted in _SANITIZERS or dotted.rsplit(".", 1)[-1] in _SANITIZERS:
            return False
        if dotted in _SOURCE_CALLS or any(dotted.startswith(prefix) for prefix in _SOURCE_PREFIXES):
            return True
    if isinstance(node, (ast.Attribute, ast.Subscript)) and any(
            dotted.startswith(prefix) for prefix in _SOURCE_PREFIXES):
        return True
    return any(_tainted(child, names) for child in ast.iter_child_nodes(node))


def _targets(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        return set().union(*(_targets(item) for item in node.elts)) if node.elts else set()
    return set()


def _keyword_constant(call: ast.Call, name: str, value: object) -> bool:
    return any(keyword.arg == name and isinstance(keyword.value, ast.Constant)
               and keyword.value.value is value for keyword in call.keywords)


def _python_checks(snapshot: SourceSnapshot, gaps: set[str], *,
                   max_rows: int = MAX_ROWS_PER_SCANNER) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(snapshot.text, filename=snapshot.relative, type_comments=True)
    except (SyntaxError, ValueError, TypeError):
        gaps.add("Python semantic security checks skipped files with parse errors")
        return []
    findings = _CappedRows(max_rows)
    functions = [node for node in ast.walk(tree)
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    scopes: Sequence[ast.AST] = functions or (tree,)

    for scope in scopes:
        tainted: set[str] = set()
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            route = any(_dotted(item.func if isinstance(item, ast.Call) else item).rsplit(".", 1)[-1]
                        in {"route", "get", "post", "put", "patch", "delete", "websocket"}
                        for item in scope.decorator_list)
            if route:
                tainted.update(arg.arg for arg in
                               list(scope.args.posonlyargs) + list(scope.args.args) +
                               list(scope.args.kwonlyargs))
        nodes = []
        for index, item in enumerate(ast.walk(scope)):
            if index >= MAX_AST_NODES_PER_FILE:
                gaps.add("%s: Python semantic checks truncated at the AST-node boundary" %
                         snapshot.relative)
                break
            nodes.append(item)
        for _ in range(4):
            changed = False
            for node in nodes:
                targets: set[str] = set()
                value: ast.AST | None = None
                if isinstance(node, ast.Assign):
                    targets = set().union(*(_targets(item) for item in node.targets))
                    value = node.value
                elif isinstance(node, ast.AnnAssign):
                    targets = _targets(node.target); value = node.value
                elif isinstance(node, ast.NamedExpr):
                    targets = _targets(node.target); value = node.value
                if targets and _tainted(value, tainted) and not targets <= tainted:
                    tainted.update(targets); changed = True
            if not changed:
                break

        for node in nodes:
            if isinstance(node, ast.If) and _tainted(node.test, tainted):
                identifiers = {item.id.lower() for item in ast.walk(node.test)
                               if isinstance(item, ast.Name)}
                if any(term in name for name in identifiers for term in
                       ("role", "admin", "permission", "authorize", "owner")):
                    findings.append(_finding(
                        snapshot.relative, node.lineno, "fabric40-client-controlled-authorization",
                        "HIGH", "auth/authorization", "CWE-639",
                        "an authorization decision depends on request-controlled identity or role data",
                        "Derive authorization attributes from the authenticated server-side identity and enforce object-level policy.",
                        0.91))
            if not isinstance(node, ast.Call):
                continue
            name = _dotted(node.func)
            short = name.rsplit(".", 1)[-1]
            first = node.args[0] if node.args else None
            first_tainted = _tainted(first, tainted)
            specification: tuple[str, str, str, str, str, float] | None = None
            if first_tainted and (name in {"eval", "exec", "builtins.eval", "builtins.exec"}):
                specification = ("fabric40-code-injection", "CRITICAL", "injection/code", "CWE-95",
                                 "request-controlled data reaches dynamic code execution",
                                 0.98)
            elif first_tainted and name in {"os.system", "os.popen"}:
                specification = ("fabric40-command-injection", "CRITICAL", "injection/command", "CWE-78",
                                 "request-controlled data reaches a command shell",
                                 0.98)
            elif first_tainted and name.startswith("subprocess.") and _keyword_constant(node, "shell", True):
                specification = ("fabric40-shell-command-injection", "CRITICAL", "injection/command", "CWE-78",
                                 "request-controlled data reaches subprocess execution with shell=True",
                                 0.99)
            elif first_tainted and short in {"execute", "executemany"}:
                specification = ("fabric40-sql-injection", "CRITICAL", "injection/sql", "CWE-89",
                                 "request-controlled data reaches the SQL statement argument",
                                 0.96)
            elif first_tainted and (name.startswith(("requests.", "httpx.")) or
                                    name == "urllib.request.urlopen"):
                specification = ("fabric40-ssrf", "HIGH", "web/ssrf", "CWE-918",
                                 "request-controlled data selects an outbound request destination",
                                 0.96)
            elif first_tainted and name in {"pickle.loads", "pickle.load", "marshal.loads", "yaml.load"}:
                specification = ("fabric40-unsafe-deserialization", "CRITICAL", "deserialization", "CWE-502",
                                 "request-controlled data reaches an executable deserializer",
                                 0.98)
            elif first_tainted and (name in {"open", "builtins.open", "pathlib.Path"} or
                                    short in {"send_file", "send_from_directory"}):
                specification = ("fabric40-path-traversal", "HIGH", "file/path-traversal", "CWE-22",
                                 "request-controlled data reaches a filesystem path operation",
                                 0.94)
            elif first_tainted and short == "render_template_string":
                specification = ("fabric40-template-injection", "CRITICAL", "injection/template", "CWE-1336",
                                 "request-controlled data reaches dynamic template compilation",
                                 0.97)
            elif first_tainted and short == "redirect":
                specification = ("fabric40-open-redirect", "MEDIUM", "web/redirect", "CWE-601",
                                 "request-controlled data selects a redirect destination",
                                 0.90)
            if specification:
                rule, severity, category, cwe, message, confidence = specification
                remediation = {
                    "CWE-89": "Use a constant query with bound parameters and allowlist dynamic identifiers.",
                    "CWE-78": "Use a fixed executable and an argument vector with shell=False.",
                    "CWE-918": "Resolve and validate scheme, host, port, redirects, and destination IP against an allowlist.",
                    "CWE-502": "Use a non-executable data format with a strict schema.",
                    "CWE-22": "Resolve beneath an approved root and reject absolute paths and traversal segments.",
                }.get(cwe, "Remove dynamic interpretation and replace it with an allowlisted structured operation.")
                findings.append(_finding(snapshot.relative, node.lineno, rule, severity,
                                         category, cwe, message, remediation, confidence))

            if short == "set_cookie":
                cookie_name = node.args[0].value.lower() if node.args and isinstance(
                    node.args[0], ast.Constant) and isinstance(node.args[0].value, str) else ""
                auth_cookie = any(word in cookie_name for word in ("session", "auth", "token", "sid"))
                keywords = {item.arg: item.value for item in node.keywords if item.arg}
                missing = [flag for flag in ("secure", "httponly") if flag not in keywords]
                disabled = [flag for flag, value in keywords.items() if flag in {"secure", "httponly"}
                            and isinstance(value, ast.Constant) and value.value is False]
                if auth_cookie and (missing or disabled or "samesite" not in keywords):
                    findings.append(_finding(
                        snapshot.relative, node.lineno, "fabric40-session-cookie-hardening",
                        "HIGH", "auth/session", "CWE-614",
                        "an authentication/session cookie lacks an explicit complete security-attribute policy",
                        "Set Secure, HttpOnly, and a purpose-appropriate SameSite policy; rotate the session after authentication.",
                        0.93))
            if name.startswith(("requests.", "httpx.")) and _keyword_constant(node, "verify", False):
                findings.append(_finding(
                    snapshot.relative, node.lineno, "fabric40-tls-verification-disabled",
                    "HIGH", "crypto/transport", "CWE-295",
                    "outbound TLS certificate verification is explicitly disabled",
                    "Enable certificate and hostname verification and use a narrowly scoped trusted CA bundle when required.",
                    0.99))

        for node in nodes:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = set().union(*(_targets(item) for item in targets))
            target_label = " ".join(names).lower()
            calls = ({_dotted(item.func) for item in ast.walk(value)
                      if isinstance(item, ast.Call)} if value is not None else set())
            if any(word in target_label for word in ("token", "session", "nonce", "reset", "secret")) and any(
                    call.startswith("random.") for call in calls):
                findings.append(_finding(
                    snapshot.relative, node.lineno, "fabric40-insecure-security-token-randomness",
                    "HIGH", "crypto/randomness", "CWE-338",
                    "a security-sensitive token or nonce is generated with a non-cryptographic PRNG",
                    "Generate security tokens with secrets.token_urlsafe/token_bytes or an operating-system CSPRNG.",
                    0.95))
            if any(word in target_label for word in ("password", "passwd", "signature")) and any(
                    call in {"hashlib.md5", "hashlib.sha1"} for call in calls):
                findings.append(_finding(
                    snapshot.relative, node.lineno, "fabric40-weak-security-hash",
                    "HIGH", "crypto/password", "CWE-916",
                    "a password or security value is processed with MD5 or SHA-1",
                    "Use Argon2id, scrypt, bcrypt, or PBKDF2 for passwords and a current collision-resistant hash for signatures.",
                    0.94))
    if findings.truncated:
        gaps.add("%s: Python security findings truncated at the per-scanner boundary" %
                 snapshot.relative)
    return list(findings)


_GENERIC_PATTERNS: tuple[tuple[re.Pattern[str], tuple[str, str, str, str, str, str, float]], ...] = (
    (re.compile(r"(?i)\b(?:eval|exec)\s*\([^\n]{0,300}\b(?:req(?:uest)?\.(?:query|body|params)|input\s*\()"),
     ("fabric40-generic-code-injection", "CRITICAL", "injection/code", "CWE-95",
      "request-derived data appears in dynamic code execution",
      "Replace dynamic evaluation with an allowlisted structured operation.", 0.88)),
    (re.compile(r"(?i)\b(?:child_process\.)?exec\s*\([^\n]{0,300}\breq\.(?:query|body|params)"),
     ("fabric40-generic-command-injection", "CRITICAL", "injection/command", "CWE-78",
      "request-derived data appears in command execution",
      "Use a fixed executable and argument vector without a shell.", 0.91)),
    (re.compile(r"(?i)\b(?:fetch|axios\.(?:get|post)|urlopen)\s*\([^\n]{0,300}\breq(?:uest)?\.(?:query|body|params)"),
     ("fabric40-generic-ssrf", "HIGH", "web/ssrf", "CWE-918",
      "request-derived data appears to select an outbound URL",
      "Allowlist destinations and validate redirects plus resolved destination addresses.", 0.88)),
    (re.compile(r"(?i)\b(?:unserialize|deserialize|ObjectInputStream)\b[^\n]{0,300}\breq(?:uest)?\.(?:query|body|params)"),
     ("fabric40-generic-unsafe-deserialization", "CRITICAL", "deserialization", "CWE-502",
      "request-derived data appears to reach an executable deserializer",
      "Use a non-executable format and enforce a strict schema.", 0.88)),
    (re.compile(r"(?i)\b(?:sendFile|readFile|createReadStream)\s*\([^\n]{0,300}\breq\.(?:query|body|params)"),
     ("fabric40-generic-path-traversal", "HIGH", "file/path-traversal", "CWE-22",
      "request-derived data appears to select a filesystem path",
      "Resolve beneath an approved root and reject absolute or traversal paths.", 0.88)),
)


def _generic_code_checks(snapshot: SourceSnapshot, gaps: set[str], *,
                         max_rows: int = MAX_ROWS_PER_SCANNER) -> list[dict[str, Any]]:
    findings = _CappedRows(max_rows)
    for pattern, spec in _GENERIC_PATTERNS:
        for index, match in enumerate(pattern.finditer(snapshot.text)):
            if index >= 100 or len(findings) >= findings.limit:
                findings.truncated = True
                break
            rule, severity, category, cwe, message, remediation, confidence = spec
            findings.append(_finding(snapshot.relative, _line(snapshot.text, match.start()),
                                     rule, severity, category, cwe, message,
                                     remediation, confidence))
    if findings.truncated:
        gaps.add("%s: lexical security findings truncated at the per-scanner boundary" %
                 snapshot.relative)
    return list(findings)


def _configuration_checks(snapshot: SourceSnapshot, gaps: set[str], *,
                          max_rows: int = MAX_ROWS_PER_SCANNER) -> list[dict[str, Any]]:
    text = snapshot.text
    lower = text.lower()
    name = snapshot.path.name.lower()
    path = snapshot.relative.lower()
    rows = _CappedRows(max_rows)
    if name.startswith(("dockerfile", "containerfile")):
        users = re.findall(r"(?mi)^\s*USER\s+(\S+)", text)
        if not users:
            rows.append(_finding(
                snapshot.relative, 1, "fabric40-container-user-not-declared", "MEDIUM",
                "container/least-privilege", "CWE-250",
                "the final container runtime user is not explicitly declared",
                "Create a dedicated non-root account and set USER in the final image stage.", 0.90))
        if re.search(r"(?mi)^\s*COPY\s+(?:--\S+\s+)*\.\s+\.\s*$", text):
            rows.append(_finding(
                snapshot.relative, _line(text, re.search(r"(?mi)^\s*COPY\s+(?:--\S+\s+)*\.\s+\.\s*$", text).start()),
                "fabric40-container-broad-context-copy", "MEDIUM", "container/data-exposure",
                "CWE-200", "the entire build context is copied into the image",
                "Use a restrictive .dockerignore and copy only explicit required artifacts.", 0.88))
    kubernetes = ("k8s" in path or "kubernetes" in path or
                  re.search(r"(?mi)^\s*kind\s*:\s*(?:Pod|Deployment|DaemonSet|StatefulSet|Job|CronJob)\s*$", text))
    if kubernetes:
        checks = (
            (r"(?mi)^\s*runAsNonRoot\s*:\s*false\s*$", "fabric40-k8s-root-allowed", "HIGH",
             "Kubernetes explicitly permits a root runtime identity",
             "Set runAsNonRoot=true and a non-zero runAsUser/group.", "CWE-250"),
            (r"(?mi)^\s*readOnlyRootFilesystem\s*:\s*false\s*$", "fabric40-k8s-writable-rootfs", "MEDIUM",
             "Kubernetes explicitly permits a writable container root filesystem",
             "Set readOnlyRootFilesystem=true and mount narrowly scoped writable volumes.", "CWE-732"),
            (r"(?mi)^\s*seccompProfile\s*:\s*\n\s*type\s*:\s*Unconfined\s*$", "fabric40-k8s-seccomp-unconfined", "HIGH",
             "Kubernetes disables the seccomp syscall profile",
             "Use RuntimeDefault or a reviewed Localhost seccomp profile.", "CWE-250"),
            (r"(?mis)^\s*capabilities\s*:.{0,300}?^\s*-\s*ALL\s*$", "fabric40-k8s-add-all-capabilities", "CRITICAL",
             "Kubernetes grants every Linux capability",
             "Drop ALL capabilities and add back only explicitly justified capabilities.", "CWE-250"),
        )
        for pattern, rule, severity, message, remediation, cwe in checks:
            for match in re.finditer(pattern, text):
                rows.append(_finding(snapshot.relative, _line(text, match.start()), rule,
                                     severity, "container/isolation", cwe, message,
                                     remediation, 0.97))
        if "resources:" not in lower or "limits:" not in lower:
            gaps.add("%s: Kubernetes resource-limit policy requires deployment review" % snapshot.relative)
    if snapshot.path.suffix.lower() in {".tf", ".tfvars", ".hcl"}:
        for match in re.finditer(r"(?i)\b(?:encrypted|encryption_enabled|storage_encrypted)\s*=\s*false", text):
            rows.append(_finding(
                snapshot.relative, _line(text, match.start()), "fabric40-cloud-encryption-disabled",
                "HIGH", "cloud/data-protection", "CWE-311",
                "cloud storage or database encryption is explicitly disabled",
                "Enable provider-managed encryption or a least-privilege customer-managed key and test key rotation.",
                0.98))
    if rows.truncated:
        gaps.add("%s: configuration findings truncated at the per-scanner boundary" %
                 snapshot.relative)
    return list(rows)


def _api_header_privacy_checks(snapshot: SourceSnapshot, gaps: set[str], *,
                               max_rows: int = MAX_ROWS_PER_SCANNER) -> tuple[
        list[dict[str, Any]], list[dict[str, Any]]]:
    text = snapshot.text
    lower = text.lower()
    rows = _CappedRows(max_rows)
    controls: list[dict[str, Any]] = []
    for header in ("strict-transport-security", "content-security-policy", "x-content-type-options",
                   "x-frame-options", "referrer-policy"):
        if header in lower:
            controls.append({"kind": "security-header-marker", "control": header,
                             "path": snapshot.relative, "line": _line(text, lower.index(header)),
                             "state": "observed-not-runtime-verified"})
    for match in re.finditer(r"(?i)strict-transport-security[^\n]{0,200}\bmax-age\s*=\s*0\b", text):
        rows.append(_finding(
            snapshot.relative, _line(text, match.start()), "fabric40-hsts-disabled",
            "HIGH", "web/security-headers", "CWE-319",
            "HTTP Strict Transport Security is configured with max-age=0",
            "Set a reviewed positive max-age after HTTPS coverage is complete; consider includeSubDomains and preload deliberately.",
            0.98))
    if snapshot.path.name.lower() == "nginx.conf" and re.search(r"(?mi)^\s*server\s*\{", text):
        missing = [header for header in ("strict-transport-security", "x-content-type-options", "referrer-policy")
                   if header not in lower]
        if missing:
            rows.append(_finding(
                snapshot.relative, 1, "fabric40-nginx-security-headers-incomplete",
                "MEDIUM", "web/security-headers", "CWE-693",
                "the Nginx server configuration does not declare: " + ", ".join(missing),
                "Define and test a response-header policy at the final public response boundary.", 0.86))

    contract_format = snapshot.path.suffix.lower() in {".json", ".yaml", ".yml"}
    openapi = contract_format and (
        snapshot.path.name.lower().startswith(("openapi", "swagger")) or
        '"openapi"' in lower or re.search(r"(?mi)^\s*openapi\s*:", text))
    if openapi:
        if "securityschemes" not in lower:
            rows.append(_finding(
                snapshot.relative, 1, "fabric40-openapi-security-scheme-missing",
                "MEDIUM", "api/authentication", "CWE-306",
                "the API contract does not declare a reusable authentication security scheme",
                "Declare the supported authentication scheme and apply explicit operation-level security requirements.",
                0.88))
        for match in re.finditer(r"(?mi)^\s*security\s*:\s*\[\s*\]\s*$", text):
            rows.append(_finding(
                snapshot.relative, _line(text, match.start()), "fabric40-openapi-operation-auth-disabled",
                "HIGH", "api/authorization", "CWE-306",
                "an API contract explicitly disables security requirements",
                "Require authentication by default and document narrowly reviewed public operations explicitly.",
                0.94))
        if not any(word in lower for word in ("429", "rate limit", "ratelimit", "throttl")):
            gaps.add("%s: API abuse/rate-limit enforcement was not evidenced in the contract" % snapshot.relative)
    for match in re.finditer(
            r"(?i)(?:\.update\s*\(\s*(?:req\.body|request\.(?:json|data))|\*\*\s*request\.get_json\s*\()", text):
        rows.append(_finding(
            snapshot.relative, _line(text, match.start()), "fabric40-api-mass-assignment",
            "HIGH", "api/object-binding", "CWE-915",
            "request data is passed directly to a broad object update or constructor",
            "Map an allowlisted request schema to explicit writable fields and enforce object-level authorization.",
            0.90))
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw[:MAX_LINE_CHARS]
        lowered = line.lower()
        if not re.search(r"\b(?:print|console\.log|log(?:ger)?\.(?:debug|info|warn|error))\s*\(", lowered):
            continue
        if any(term in lowered for term in ("request.body", "request.json", "req.body", "authorization",
                                             "password", "passwd", "token", "session", "ssn", "credit_card")) and not any(
                term in lowered for term in ("redact", "mask", "sanitize", "fingerprint")):
            rows.append(_finding(
                snapshot.relative, line_no, "fabric40-sensitive-data-logging",
                "HIGH", "privacy/logging", "CWE-532",
                "a logging call appears to include request, credential, session, or regulated-data fields",
                "Log an allowlisted event schema with sensitive values removed; enforce retention and access controls.",
                0.88))
    if rows.truncated:
        gaps.add("%s: API/header/privacy findings truncated at the per-scanner boundary" %
                 snapshot.relative)
    return list(rows), controls


def _adapt_secmax(item: secmax.Finding, relative: str) -> dict[str, Any]:
    return _finding(relative, item.line, item.rule, item.severity,
                    str(item.category).lower().replace(" ", "-"), "",
                    item.detail, item.fix, item.confidence, source="secmax")


def _normalize(row: Mapping[str, Any], snapshots: Mapping[str, SourceSnapshot],
               route_files: set[str]) -> dict[str, Any] | None:
    path = str(row.get("path", "")).replace("\\", "/")
    if path not in snapshots:
        return None
    snapshot = snapshots[path]
    severity = str(row.get("severity", "MEDIUM")).upper()
    if severity not in SEVERITY_WEIGHT:
        severity = "MEDIUM"
    line = max(1, int(row.get("line", 1) or 1))
    confidence = round(max(0.0, min(float(row.get("confidence", 0.75)), 1.0)), 2)
    category = str(row.get("category") or "security/static")[:160]
    cwe = str(row.get("cwe") or "")[:32]
    message = str(row.get("message") or row.get("detail") or "static security evidence")[:1000]
    remediation = str(row.get("remediation") or row.get("fix") or
                      "Review the evidence and implement a project-specific defensive correction.")[:1500]
    secret_related = ("secret" in category.lower() or "credential" in category.lower()
                      or bool(row.get("secret_material_redacted")))
    exposure = 1.12 if path in route_files else 1.0 if any(
        word in category.lower() for word in ("cloud", "container", "ci-cd", "api", "web")) else 0.88
    risk = round(min(10.0, SEVERITY_WEIGHT[severity] * confidence * exposure), 1)
    priority = "P0" if risk >= 9 else "P1" if risk >= 7 else "P2" if risk >= 4 else "P3"
    evidence = {
        "kind": "bounded-static-evidence", "path": path, "line": line,
        "description": message, "secret_material_redacted": secret_related,
    }
    if secret_related:
        # A whole-file digest can collapse into a credential digest for a
        # single-value file.  Omit it for secret evidence rather than creating
        # a secondary offline oracle.
        evidence["source_identity_redacted"] = True
    else:
        evidence["source_sha256"] = snapshot.sha256
    normalized = {
        "path": path, "line": line, "rule": str(row.get("rule") or "security-evidence")[:200],
        "severity": severity, "confidence": confidence, "risk_score": risk,
        "priority": priority, "category": category, "cwe": cwe,
        "message": message, "remediation": remediation,
        "remediation_metadata": {
            "automatic_apply": False, "review_required": True,
            "verification": "Add a focused negative regression test and rerun the relevant security gate.",
        },
        "source": str(row.get("source") or "security-fabric40")[:100],
        "evidence": [evidence],
    }
    for key in ("owasp", "owasp_2021", "owasp_2025", "asvs", "nist_ssdf", "stride"):
        if key in row:
            normalized[key] = row[key]
    normalized["fingerprint"] = security_posture.finding_fingerprint(normalized)
    normalized["id"] = "SF40-" + normalized["fingerprint"][:20]
    return normalized


def _supply_chain(snapshots: Sequence[SourceSnapshot], gaps: set[str]) -> tuple[
        dict[str, Any], list[dict[str, Any]], bool]:
    by_directory: dict[str, set[str]] = {}
    snapshot_by_location: dict[tuple[str, str], SourceSnapshot] = {}
    for row in snapshots:
        directory = str(Path(row.relative).parent).replace("\\", "/")
        by_directory.setdefault(directory, set()).add(row.path.name.lower())
        snapshot_by_location[(directory, row.path.name.lower())] = row
    coverage = []
    findings = []
    for directory, names in sorted(by_directory.items()):
        for manifest, expected in sorted(security_intelligence.LOCK_EXPECTATIONS.items()):
            if manifest not in names:
                continue
            present = sorted(set(expected) & names)
            manifest_path = (Path(directory) / manifest).as_posix()
            lock_required = True
            if manifest == "package.json":
                package = snapshot_by_location.get((directory, manifest))
                try:
                    package_json = json.loads(package.text) if package is not None else None
                except json.JSONDecodeError:
                    package_json = None
                if type(package_json) is dict:
                    dependency_keys = ("dependencies", "devDependencies", "peerDependencies",
                                       "optionalDependencies", "bundledDependencies")
                    lock_required = any(bool(package_json.get(key)) for key in dependency_keys)
            coverage.append({"manifest": manifest_path,
                             "status": "present" if present else
                                       "not-required-no-dependencies" if not lock_required else
                                       "not-observed",
                             "lockfiles": [(Path(directory) / name).as_posix() for name in present],
                             "expected_any_of": list(expected),
                             "lock_required": lock_required})
            if not present and lock_required:
                findings.append(_finding(
                    manifest_path, 1, "fabric40-lockfile-not-observed", "MEDIUM",
                    "supply-chain/reproducibility", "CWE-829",
                    "a dependency manifest has no recognized lockfile in the bounded readable snapshot",
                    "Generate the ecosystem lockfile deterministically, review it, and enforce frozen/locked installs in CI.",
                    0.86))
    lockfiles = []
    for row in sorted(snapshots, key=lambda item: item.relative):
        if row.path.name.lower() in security_intelligence.LOCKFILES:
            lockfiles.append({"path": row.relative, "bytes": len(row.raw),
                              "sha256": row.sha256, "state": "bounded-local-snapshot"})

    supported = [row for row in snapshots if row.path.name in
                 {"package-lock.json", "Cargo.lock", "poetry.lock"}]
    graph_summary: dict[str, Any] = {
        "engine_schema": supply_chain35.SCHEMA, "status": "unavailable",
        "manifests": [], "nodes": 0, "edges": 0, "gaps": [],
    }
    temporary_written = False
    if supported:
        try:
            with tempfile.TemporaryDirectory(prefix="attestor40-lock-snapshot-") as folder:
                temporary_written = True
                isolated = Path(folder)
                for row in supported:
                    destination = isolated / row.relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(row.raw)
                graph = supply_chain35.analyze_dependency_graph(isolated)
            graph_summary = {
                "engine_schema": graph.get("schema", supply_chain35.SCHEMA),
                "status": graph.get("status", "unavailable"),
                "manifests": list(graph.get("manifests", []))[:512],
                "nodes": len(graph.get("nodes", [])),
                "edges": len(graph.get("edges", [])),
                "gaps": list(graph.get("gaps", []))[:200],
                "graph_sha256": graph.get("graph_sha256", ""),
            }
            if graph_summary["gaps"]:
                gaps.add("exact lockfile dependency graph reported partial coverage")
        except (OSError, ValueError, TypeError, RuntimeError) as exc:
            graph_summary["status"] = "failed-safe"
            graph_summary["gaps"] = ["isolated graph analysis failed: " + type(exc).__name__]
            gaps.add("exact lockfile dependency graph was unavailable")
    else:
        gaps.add("exact dependency graph supports package-lock v2/v3, Cargo.lock, and poetry.lock only")
    report = {
        "lockfile_integrity": lockfiles,
        "manifest_lock_coverage": coverage,
        "exact_graph": graph_summary,
        "sbom": {"generated": False,
                 "reason": "lockfile integrity and exact local graph evidence were produced; no advisory or package resolution was attempted"},
        "execution": {"network": False, "dependencies_installed": False,
                      "build_scripts": False, "target_code": False,
                      "temporary_bounded_snapshot": temporary_written},
    }
    return report, findings, temporary_written


def _threat_model(findings: Sequence[dict[str, Any]], components: list[dict[str, Any]],
                  limits: Limits) -> dict[str, Any]:
    components.sort(key=lambda row: (row.get("kind", ""), row.get("path", ""),
                                     int(row.get("line", 1))))
    observed_surface_total = len(components)
    surface_truncated = observed_surface_total > limits.max_attack_surface
    components = components[:limits.max_attack_surface]
    for index, row in enumerate(components, start=1):
        row["id"] = "AS40-%04d" % index
    boundaries = security_intelligence._trust_boundaries(components)
    assets = [{"name": "source and configuration integrity", "evidence": [
        {"path": row["path"], "line": row.get("line", 1)} for row in components[:10]]}]
    kinds = {row.get("kind") for row in components}
    if "identity-control" in kinds or "web-or-api-route" in kinds:
        assets.append({"name": "identities, sessions, and authorization decisions",
                       "evidence": [{"path": row["path"], "line": row.get("line", 1)}
                                    for row in components if row.get("kind") in
                                    {"identity-control", "web-or-api-route"}][:10]})
    if "dependency-manifest" in kinds or "ci-cd-workflow" in kinds:
        assets.append({"name": "software supply-chain integrity",
                       "evidence": [{"path": row["path"], "line": row.get("line", 1)}
                                    for row in components if row.get("kind") in
                                    {"dependency-manifest", "ci-cd-workflow"}][:10]})
    templates = {
        "injection": ["untrusted input", "application parser/handler", "dynamic interpreter or sink"],
        "ssrf": ["untrusted URL input", "outbound HTTP client", "internal or external service"],
        "deserialization": ["untrusted serialized bytes", "deserializer", "application process"],
        "path": ["untrusted path input", "filesystem API", "workspace or host file"],
        "auth": ["external identity/request", "authentication or authorization decision", "protected operation/data"],
        "cloud": ["untrusted principal/network", "cloud control plane policy", "resource or data"],
        "container": ["build/deployment input", "container runtime boundary", "host or workload identity"],
        "supply": ["third-party source", "dependency/build pipeline", "released artifact/runtime"],
        "privacy": ["sensitive request/data", "logging pipeline", "log readers and retention systems"],
    }
    path_candidates: list[tuple[dict[str, Any], str]] = []
    for row in findings:
        category = row["category"].lower()
        key = next((name for name in templates if name in category), None)
        if key is None or row["risk_score"] < 4:
            continue
        path_candidates.append((row, key))
    paths = []
    for row, key in path_candidates[:limits.max_attack_paths]:
        paths.append({
            "id": "AP40-%04d" % (len(paths) + 1), "state": "static-hypothesis",
            "basis": "bounded static evidence; runtime exploitability was not tested",
            "nodes": templates[key], "finding_id": row["id"],
            "risk_score": row["risk_score"], "evidence": row["evidence"][:2],
        })
    return {
        "method": "STRIDE-informed evidence model",
        "assets": assets, "attack_surface": {"components": components,
                                               "total": len(components),
                                               "total_observed": observed_surface_total,
                                               "truncated": surface_truncated},
        "trust_boundaries": boundaries, "attack_paths": paths,
        "attack_path_candidates": len(path_candidates),
        "attack_paths_truncated": len(path_candidates) > limits.max_attack_paths,
    }


def _assurance(*, temporary_written: bool = False) -> dict[str, Any]:
    return {
        "defensive_static_only": True,
        "target_code_executed": False,
        "network_accessed": False,
        "network_probing": False,
        "external_processes_spawned": False,
        "dependencies_installed": False,
        "target_files_written": False,
        "temporary_snapshot_files_written": temporary_written,
        "automatic_remediation_applied": False,
        "raw_secret_material_in_report": False,
        "symlinks_followed": False,
        "root_containment_enforced": True,
    }


def _failed(root: str, limits: Limits, reason: str) -> dict[str, Any]:
    body = {
        "schema": SCHEMA, "version": VERSION, "root": root, "status": "failed",
        "summary": {"findings": 0, "risk_score": 0, "risk_label": "unknown"},
        "findings": [], "threat_model": {"assets": [], "attack_surface": {"components": [], "total": 0},
                                             "trust_boundaries": [], "attack_paths": []},
        "supply_chain": {}, "security_controls": [],
        "limits": {"configured": limits.public(), "hit": []},
        "coverage": {"gaps": [reason], "errors": [reason]},
        "remediation_plan": [], "assurance": _assurance(),
    }
    body["report_sha256"] = _sha(body)
    return body


def analyze(root: str | os.PathLike[str], *, limits: Limits | None = None) -> dict[str, Any]:
    """Analyze a local repository with deterministic, bounded static checks."""
    policy = Limits() if limits is None else limits
    if not isinstance(policy, Limits):
        raise SecurityFabric40Error("limits must be a Limits instance")
    requested = Path(root).expanduser()
    try:
        if _linklike(requested):
            return _failed(str(requested), policy,
                           "analysis root may not be a symbolic link or reparse point")
        base = requested.resolve(strict=True)
    except OSError:
        return _failed(str(requested), policy, "workspace is not a readable directory")
    if not base.is_dir() and not base.is_file():
        return _failed(str(base), policy, "workspace is not a readable file or directory")

    snapshots, discovery, limit_hits, discovery_gaps, errors = _discover(base, policy)
    snapshot_map = {row.relative: row for row in snapshots}
    ranked_findings: list[
        tuple[tuple[float, float, float, str], int, str, dict[str, Any]]
    ] = []
    components: list[dict[str, Any]] = []
    route_files: set[str] = set()
    controls: list[dict[str, Any]] = []
    controls_truncated = False
    gaps = set(discovery_gaps)
    if base.is_file():
        gaps.add("single-file scope excludes sibling source, policy, and lockfile evidence")
    engine_counts = {"security-intelligence": 0, "secret-guard": 0,
                     "secmax": 0, "security-fabric40": 0}
    raw_limit = min(MAX_RAW_FINDINGS, max(32, policy.max_findings * 3))
    raw_truncated = False
    raw_seen = 0

    def retain(rows: Iterable[dict[str, Any]], engine: str) -> None:
        """Retain a bounded global top-K instead of the first K observations."""
        nonlocal raw_seen, raw_truncated
        for scanner_index, row in enumerate(rows):
            if scanner_index >= MAX_ROWS_PER_SCANNER:
                raw_truncated = True
                return
            if type(row) is not dict:
                continue
            normalized = _normalize(row, snapshot_map, route_files)
            if normalized is None:
                continue
            raw_seen += 1
            priority = (
                float(SEVERITY_WEIGHT.get(
                    str(normalized.get("severity", "MEDIUM")), 0)),
                float(normalized.get("risk_score", 0)),
                float(normalized.get("confidence", 0)),
                str(normalized.get("fingerprint", "")),
            )
            entry = (priority, raw_seen, engine, normalized)
            if len(ranked_findings) < raw_limit:
                heapq.heappush(ranked_findings, entry)
            elif priority > ranked_findings[0][0]:
                heapq.heapreplace(ranked_findings, entry)
            if raw_seen > raw_limit:
                raw_truncated = True

    contextual_scanners = (
        lambda snapshot: security_intelligence._scan_ci(
            snapshot.text, snapshot.relative),
        lambda snapshot: security_intelligence._scan_container(
            snapshot.text, snapshot.relative, snapshot.path.name),
        lambda snapshot: security_intelligence._scan_iac_cloud(
            snapshot.text, snapshot.relative, snapshot.path.suffix.lower()),
        lambda snapshot: security_intelligence._scan_web_api(
            snapshot.text, snapshot.relative),
        lambda snapshot: security_intelligence._scan_mobile(
            snapshot.text, snapshot.relative, snapshot.path.name),
        lambda snapshot: security_intelligence._scan_crypto_auth(
            snapshot.text, snapshot.relative),
        lambda snapshot: security_intelligence._scan_dependency_file(
            snapshot.text, snapshot.relative, snapshot.path.name),
    )

    for snapshot in snapshots:
        security_intelligence._surface_file(
            snapshot.path, snapshot.relative, snapshot.text, components, route_files)
        secret_rows = secret_guard.scan_text(
            snapshot.text, snapshot.relative,
            max_findings=min(secret_guard.MAX_FINDINGS, MAX_ROWS_PER_SCANNER))
        retain(secret_rows, "secret-guard")
        for scanner in contextual_scanners:
            try:
                retain(scanner(snapshot), "security-intelligence")
            except (ValueError, TypeError, RuntimeError, RecursionError) as exc:
                gaps.add("%s: inherited static scanner failed safely (%s)" %
                         (snapshot.relative, type(exc).__name__))
        retain((_adapt_secmax(row, snapshot.relative) for row in
                secmax._scan_entropy(snapshot.text, snapshot.relative)), "secmax")
        retain((_adapt_secmax(row, snapshot.relative) for row in
                secmax._scan_web_api(snapshot.text, snapshot.relative)), "secmax")
        retain((_adapt_secmax(row, snapshot.relative) for row in
                secmax._scan_crypto_iac_supply(
                    snapshot.text, Path(snapshot.relative))), "secmax")

        if snapshot.path.suffix.lower() in {".py", ".pyw"}:
            retain(_python_checks(
                snapshot, gaps, max_rows=MAX_ROWS_PER_SCANNER),
                   "security-fabric40")
        retain(_generic_code_checks(
            snapshot, gaps, max_rows=MAX_ROWS_PER_SCANNER),
            "security-fabric40")
        retain(_configuration_checks(
            snapshot, gaps, max_rows=MAX_ROWS_PER_SCANNER),
            "security-fabric40")
        api_rows, observed_controls = _api_header_privacy_checks(
            snapshot, gaps, max_rows=MAX_ROWS_PER_SCANNER)
        retain(api_rows, "security-fabric40")
        for control in observed_controls:
            if len(controls) < policy.max_attack_surface:
                controls.append(control)
            else:
                controls_truncated = True

    supply_report, supply_findings, temporary_written = _supply_chain(snapshots, gaps)
    retain(supply_findings, "security-fabric40")
    selected = sorted(
        ranked_findings, key=lambda entry: (entry[0], entry[1]), reverse=True)
    raw_findings = [entry[3] for entry in selected]
    for _, _, engine, _ in selected:
        engine_counts[engine] += 1
    if raw_truncated:
        limit_hits.append("max_findings")
        gaps.add(
            "raw finding collection used bounded global severity-ranked top-K selection")

    if route_files:
        gaps.add("runtime authentication, authorization, CSRF, and rate-limit enforcement were not executed")
    gaps.add("dynamic infrastructure policy, deployed headers, and cloud control-plane state were not queried")
    gaps.add("vulnerability advisories were not queried; lockfile evidence is not a vulnerability verdict")
    gaps.add("non-Python source-to-sink relationships use bounded lexical evidence unless an inherited parser proves more")

    normalized = security_posture._deduplicate(raw_findings)
    normalized.sort(key=lambda row: (
        SEVERITY_ORDER[row["severity"]], -row["risk_score"],
        -row["confidence"], row["path"].casefold(), row["line"], row["rule"]))
    if len(normalized) > policy.max_findings:
        normalized = normalized[:policy.max_findings]
        limit_hits.append("max_findings")
        gaps.add("finding output truncated at max_findings")
    # Rebuild identities after inherited deduplication merged evidence.
    for row in normalized:
        row["evidence"] = row.get("evidence", [])[:MAX_EVIDENCE]
        row["fingerprint"] = security_posture.finding_fingerprint(row)
        row["id"] = "SF40-" + row["fingerprint"][:20]
    normalized.sort(key=lambda row: (
        SEVERITY_ORDER[row["severity"]], -row["risk_score"], -row["confidence"],
        row["path"].casefold(), row["line"], row["rule"]))
    score, label = security_posture._risk(normalized)
    threat = _threat_model(normalized, components, policy)
    if threat["attack_surface"].get("truncated"):
        limit_hits.append("max_attack_surface")
        gaps.add("attack-surface output truncated at max_attack_surface")
    if threat.get("attack_paths_truncated"):
        limit_hits.append("max_attack_paths")
        gaps.add("attack-path output truncated at max_attack_paths")
    if len(components) >= security_intelligence.MAX_COMPONENTS:
        limit_hits.append("max_attack_surface")
        gaps.add("attack-surface collection reached the inherited component capacity")
    if controls_truncated:
        limit_hits.append("max_attack_surface")
        gaps.add("observed security-control evidence truncated at max_attack_surface")
    if not snapshots:
        gaps.add("no analyzable files were loaded from the requested scope")
    limit_hits = sorted(set(limit_hits))
    status = "partial" if limit_hits or errors or not snapshots else \
        "findings" if normalized else "clean"

    severity = {name: 0 for name in SEVERITY_WEIGHT}
    categories: dict[str, int] = {}
    for row in normalized:
        severity[row["severity"]] += 1
        categories[row["category"]] = categories.get(row["category"], 0) + 1
    remediation_plan = [{
        "finding_id": row["id"], "priority": row["priority"], "path": row["path"],
        "line": row["line"], "rule": row["rule"], "guidance": row["remediation"],
        "automatic_apply": False, "review_required": True,
    } for row in normalized[:100]]

    body: dict[str, Any] = {
        "schema": SCHEMA, "version": VERSION, "root": str(base), "status": status,
        "summary": {
            "findings": len(normalized), "risk_score": score, "risk_label": label,
            "severity": severity,
            "categories": dict(sorted(categories.items(), key=lambda item: (-item[1], item[0]))),
            "top_priorities": [row["id"] for row in normalized[:10]],
        },
        "findings": normalized, "threat_model": threat,
        "supply_chain": supply_report,
        "security_controls": sorted(controls, key=lambda row: (
            row["path"], row["line"], row["control"])),
        "limits": {"configured": policy.public(), "hard_ceiling": {
            "max_files": MAX_FILES_HARD, "max_file_bytes": MAX_FILE_BYTES_HARD,
            "max_total_bytes": MAX_TOTAL_BYTES_HARD, "max_findings": MAX_FINDINGS_HARD,
            "max_attack_surface": MAX_SURFACE_HARD,
            "max_attack_paths": MAX_ATTACK_PATHS_HARD,
        }, "hit": limit_hits},
        "coverage": {
            **discovery,
            "gaps": sorted(gaps)[:MAX_GAPS],
            "gaps_truncated": len(gaps) > MAX_GAPS,
            "errors": sorted(errors),
            "engines": {
                "security-intelligence": {"mode": "bounded-in-memory-scanners",
                                          "raw_findings": engine_counts["security-intelligence"],
                                          "count_state": "retained-before-deduplication"},
                "secret-guard": {"mode": "bounded-in-memory-redacted",
                                 "raw_findings": engine_counts["secret-guard"],
                                 "count_state": "retained-before-deduplication"},
                "secmax": {"mode": "selected-pure-in-memory-scanners",
                           "raw_findings": engine_counts["secmax"],
                           "count_state": "retained-before-deduplication"},
                "security-posture": {"mode": "pure-fingerprint-dedup-risk-helpers"},
                "supply-chain35": {"mode": "isolated-bounded-lock-snapshot",
                                   "status": supply_report["exact_graph"]["status"]},
            },
            "raw_finding_boundary": {"limit": raw_limit,
                                     "retained": len(raw_findings),
                                     "truncated": raw_truncated},
        },
        "remediation_plan": remediation_plan,
        "remediation_plan_state": {"included": len(remediation_plan),
                                   "total_findings": len(normalized),
                                   "truncated": len(normalized) > len(remediation_plan)},
        "assurance": _assurance(temporary_written=temporary_written),
        "assurance_notes": [
            "Findings are defensive static evidence, not proof of exploitability.",
            "A clean result is not proof of absence; review coverage gaps and configured limits.",
            "No remediation was applied. Every proposed change requires human review and regression verification.",
            "Secret findings are value-redacted; raw source text is never included in this report.",
            "Dependency integrity evidence is local-only and does not invent advisory or reachability status.",
        ],
    }
    body["report_sha256"] = _sha(body)
    return body


scan = analyze


__all__ = ["VERSION", "SCHEMA", "Limits", "SecurityFabric40Error", "analyze", "scan"]
