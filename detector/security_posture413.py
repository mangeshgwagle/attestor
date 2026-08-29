#!/usr/bin/env python3
"""Attestor 4.1.3 bounded, evidence-labelled defensive security posture analysis.

This module is deliberately passive.  It reads caller-selected local artifacts
or accepts their bytes as data; it never runs target code, contacts a registry,
invokes version-control tooling, installs a package, changes a workspace, or
attempts exploitation.  Binary inspection is limited to metadata, entropy, and
bounded printable strings.  Secret values are detected in memory but are never
included, hashed, prefixed, or suffixed in the returned report.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import stat
import tomllib
import unicodedata
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import quote


VERSION = "4.1.3"
SCHEMA = "attestor.security-posture/4.1.3"
SBOM_SCHEMA = "attestor.security-sbom/4.1.3"

# All limits are intentionally public so a caller can display the exact audit
# boundary.  Limits are enforced before parsing, not merely after reporting.
MAX_ARTIFACTS = 4_096
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_BINARY_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_INPUT_BYTES = 64 * 1024 * 1024
MAX_LINE_CHARS = 32_768
MAX_LINES_PER_FILE = 100_000
MAX_FINDINGS = 8_000
MAX_GAPS = 2_000
MAX_COMPONENTS = 8_000
MAX_HISTORY_EVENTS = 4_096
MAX_PROVENANCE_RECORDS = 4_096
MAX_METADATA_BYTES = 4 * 1024 * 1024
MAX_BINARY_STRINGS = 20_000
MAX_OUTPUT_BYTES = 24 * 1024 * 1024
# Workspace discovery has independent traversal budgets.  Directory entries
# count whether or not their file type is eventually selected for analysis.
MAX_DIRECTORY_ENTRIES = 100_000
MAX_ENTRIES_PER_DIRECTORY = 20_000
MAX_DIRECTORY_DEPTH = 64
MAX_DIRECTORIES = 20_000

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_EVIDENCE_STATES = frozenset({"proven", "inferred", "unavailable"})
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_DRIVE = re.compile(r"[A-Za-z]:")
_BIDI = frozenset({
    0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D,
    0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x206A, 0x206B,
    0x206C, 0x206D, 0x206E, 0x206F,
})
_SKIP_DIRECTORIES = frozenset({
    ".git", ".hg", ".svn", "node_modules", "vendor", ".venv", "venv",
    "target", "dist", "build", "__pycache__", ".attestor-cache",
})
_TEXT_SUFFIXES = frozenset({
    ".c", ".cc", ".cfg", ".conf", ".cpp", ".cs", ".dockerfile", ".env",
    ".go", ".gradle", ".h", ".hpp", ".html", ".ini", ".java", ".js",
    ".json", ".jsx", ".kt", ".kts", ".lock", ".md", ".mjs", ".php",
    ".properties", ".ps1", ".py", ".rb", ".rs", ".sh", ".sql", ".tf",
    ".tfvars", ".toml", ".ts", ".tsx", ".txt", ".xml", ".yaml", ".yml",
})
_BINARY_SUFFIXES = frozenset({
    ".bin", ".com", ".dll", ".dylib", ".elf", ".exe", ".msi", ".so", ".sys",
})
_SCRIPT_SUFFIXES = frozenset({
    ".bat", ".cmd", ".js", ".mjs", ".ps1", ".py", ".rb", ".sh", ".vbs",
})
_SPECIAL_NAMES = frozenset({
    "dockerfile", "containerfile", "package.json", "package-lock.json",
    "cargo.toml", "cargo.lock", "go.mod", "go.sum", "pom.xml",
    "composer.json", "composer.lock", "pyproject.toml", "poetry.lock",
    "requirements.txt", "requirements.in", "pipfile", "pipfile.lock",
})
_POPULAR_PACKAGES: dict[str, frozenset[str]] = {
    "npm": frozenset({
        "axios", "chalk", "commander", "express", "lodash", "moment",
        "react", "typescript", "webpack",
    }),
    "pypi": frozenset({
        "django", "fastapi", "flask", "numpy", "pandas", "pillow",
        "pytest", "requests", "setuptools",
    }),
    "cargo": frozenset({"anyhow", "clap", "rand", "regex", "serde", "tokio"}),
}

# These patterns identify secret *shape*.  Matches never leave this module.
_SECRET_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("secret-private-key", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("secret-aws-access-key", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("secret-github-token", "high",
     re.compile(r"\b(?:gh[opusr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b")),
    ("secret-slack-token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,255}\b")),
    ("secret-jwt", "high",
     re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
    r"password|passwd|private[_-]?key|secret)\b\s*[:=]\s*"
    r"(?:[\"'](?P<quoted>[^\"'\r\n]{8,512})[\"']|(?P<bare>[^\s#;,]{8,512}))"
)
_PLACEHOLDER = re.compile(
    r"(?i)^(?:change[-_ ]?me|dummy|example|fake|none|null|placeholder|redacted|"
    r"sample|test|todo|your[-_ ].*|\$\{[^}]+\}|<[^>]+>)$"
)


class SecurityPostureError(ValueError):
    """Raised when an input cannot be handled inside the security boundary."""


@dataclass(frozen=True)
class Artifact:
    """A caller-supplied, non-executable artifact snapshot."""

    path: str
    content: str | bytes
    executable: bool = False
    media_type: str = ""


@dataclass(frozen=True)
class _ArtifactView:
    path: str
    data: bytes
    text: str | None
    executable: bool
    media_type: str
    kind: str


@dataclass(frozen=True)
class _Component:
    ecosystem: str
    name: str
    version: str
    scope: str
    source: str
    evidence_state: str


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise SecurityPostureError("value is not canonically serializable") from exc


def _sha(value: Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _looks_like_secret(value: str) -> bool:
    if any(pattern.search(value) for _rule, _severity, pattern in _SECRET_PATTERNS):
        return True
    for match in _SECRET_ASSIGNMENT.finditer(value):
        candidate = match.group("quoted") or match.group("bare") or ""
        if not _PLACEHOLDER.fullmatch(candidate):
            return True
    return False


def _safe_text(value: Any, maximum: int = 1_024, *, redact_secrets: bool = True) -> str:
    """Return bounded text that is safe for terminals and security reports."""
    raw = str(value if value is not None else "")
    if redact_secrets and _looks_like_secret(raw):
        return "[redacted]"
    output: list[str] = []
    size = 0
    for character in unicodedata.normalize("NFC", raw):
        codepoint = ord(character)
        if character in "\t\r\n":
            rendered = " "
        elif codepoint < 32 or 0x7F <= codepoint <= 0x9F:
            rendered = "\\x%02x" % codepoint
        elif 0xD800 <= codepoint <= 0xDFFF:
            rendered = "\\u%04x" % codepoint
        elif codepoint in _BIDI:
            rendered = "\\u%04x" % codepoint
        else:
            rendered = character
        if size + len(rendered) > maximum:
            break
        output.append(rendered)
        size += len(rendered)
    return "".join(output)


def _clean_path(value: Any) -> str:
    raw = unicodedata.normalize("NFC", str(value if value is not None else "")).replace("\\", "/")
    if not raw or len(raw) > 2_048 or raw.startswith("/") or _DRIVE.match(raw):
        raise SecurityPostureError("artifact path must be a bounded relative path")
    parts = PurePosixPath(raw).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise SecurityPostureError("artifact path contains an unsafe segment")
    clean = _safe_text("/".join(parts), 1_024)
    return clean or "[redacted-path]"


def _decode_text(data: bytes) -> str | None:
    if not data:
        return ""
    try:
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = data.decode("utf-16")
        else:
            text = data.decode("utf-8")
    except (UnicodeError, LookupError):
        return None
    # NUL-rich data is binary even if it technically decodes as UTF-8.
    if text.count("\x00") > max(1, len(text) // 200):
        return None
    return text


def _artifact_kind(path: str, data: bytes, text: str | None) -> str:
    lower = path.casefold()
    name = PurePosixPath(lower).name
    if name.startswith(("dockerfile", "containerfile")) or lower.endswith(".dockerfile"):
        return "docker"
    if lower.startswith(".github/workflows/") and lower.endswith((".yaml", ".yml")):
        return "github-actions"
    if lower.endswith((".tf", ".tfvars")):
        return "terraform"
    if lower.endswith((".yaml", ".yml")) and text and re.search(
            r"(?m)^\s*(?:apiVersion|kind)\s*:", text):
        return "kubernetes"
    if name in _SPECIAL_NAMES or name.startswith("requirements"):
        return "manifest"
    if text is None:
        return "binary"
    if PurePosixPath(lower).suffix in _SCRIPT_SUFFIXES or text.startswith("#!"):
        return "script"
    return "text"


def _coerce_artifacts(artifacts: Iterable[Artifact | Mapping[str, Any]]) -> tuple[list[_ArtifactView], int]:
    rows: list[_ArtifactView] = []
    total = 0
    seen: set[str] = set()
    iterator = iter(artifacts)
    for index, original in enumerate(iterator):
        if index >= MAX_ARTIFACTS:
            raise SecurityPostureError("artifact count exceeds boundary")
        if isinstance(original, Artifact):
            path, content = original.path, original.content
            executable, media_type = original.executable, original.media_type
        elif type(original) is dict:
            if set(original) - {"path", "content", "executable", "media_type"}:
                raise SecurityPostureError("artifact object contains unsupported fields")
            if "path" not in original or "content" not in original:
                raise SecurityPostureError("artifact object is missing path/content")
            path, content = original["path"], original["content"]
            executable = original.get("executable", False)
            media_type = original.get("media_type", "")
        else:
            raise SecurityPostureError("artifact must be an Artifact or exact object")
        if (
            not isinstance(path, str) or type(executable) is not bool
            or not isinstance(media_type, str)
        ):
            raise SecurityPostureError("artifact metadata has an invalid type")
        clean_path = _clean_path(path)
        identity = clean_path.casefold()
        if identity in seen:
            raise SecurityPostureError("artifact paths collide after normalization")
        seen.add(identity)
        if isinstance(content, str):
            try:
                data = content.encode("utf-8")
            except UnicodeError as exc:
                raise SecurityPostureError("artifact text is not valid Unicode") from exc
            text: str | None = content
        elif isinstance(content, bytes):
            data = content
            text = _decode_text(data)
        else:
            raise SecurityPostureError("artifact content must be text or bytes")
        per_file_limit = MAX_BINARY_FILE_BYTES if text is None else MAX_FILE_BYTES
        if len(data) > per_file_limit:
            raise SecurityPostureError("artifact exceeds per-file byte boundary")
        total += len(data)
        if total > MAX_TOTAL_INPUT_BYTES:
            raise SecurityPostureError("artifact input exceeds total byte boundary")
        clean_media = _safe_text(media_type, 128)
        rows.append(_ArtifactView(
            clean_path, data, text, executable, clean_media,
            _artifact_kind(clean_path, data, text),
        ))
    rows.sort(key=lambda row: (row.path.casefold(), row.path))
    return rows, total


class _GapSink:
    def __init__(self) -> None:
        self._rows: dict[tuple[str, str, str], dict[str, str]] = {}
        self.truncated = False

    def add(self, capability: str, reason: str, path: str = "") -> None:
        if len(self._rows) >= MAX_GAPS:
            self.truncated = True
            return
        row = {
            "capability": _safe_text(capability, 96),
            "reason": _safe_text(reason, 512),
            "path": _safe_text(path, 1_024),
            "evidence_state": "unavailable",
        }
        key = (row["capability"], row["reason"], row["path"])
        self._rows[key] = row

    def rows(self) -> list[dict[str, str]]:
        rows = sorted(
            self._rows.values(),
            key=lambda row: (row["capability"], row["path"].casefold(), row["reason"]),
        )
        if self.truncated and len(rows) < MAX_GAPS:
            rows.append({
                "capability": "reporting",
                "reason": "additional analysis gaps were withheld by the output boundary",
                "path": "",
                "evidence_state": "unavailable",
            })
        return rows[:MAX_GAPS]


class _FindingSink:
    def __init__(self) -> None:
        self._rows: dict[tuple[str, str, int], dict[str, Any]] = {}
        self.truncated = False

    def emit(
        self, rule_id: str, severity: str, category: str, path: str, line: int,
        message: str, remediation: str, evidence_state: str,
        source_kind: str,
    ) -> None:
        if severity not in _SEVERITY_ORDER or evidence_state not in _EVIDENCE_STATES:
            raise SecurityPostureError("internal finding contract is invalid")
        clean_path = _safe_text(path, 1_024)
        clean_line = max(1, min(2_147_483_647, int(line)))
        key = (rule_id, clean_path.casefold(), clean_line)
        if key in self._rows:
            return
        if len(self._rows) >= MAX_FINDINGS:
            self.truncated = True
            return
        stable = {
            "rule_id": rule_id,
            "severity": severity,
            "category": category,
            "path": clean_path,
            "line": clean_line,
            "message": message,
            "remediation": remediation,
            "evidence_state": evidence_state,
            "source_kind": source_kind,
        }
        stable["finding_id"] = "sec413-" + _sha([
            rule_id, clean_path.casefold(), clean_line, source_kind,
        ])[:24]
        self._rows[key] = stable

    def rows(self) -> list[dict[str, Any]]:
        return sorted(
            self._rows.values(),
            key=lambda row: (
                -_SEVERITY_ORDER[row["severity"]], row["path"].casefold(),
                row["line"], row["rule_id"],
            ),
        )


def _iter_lines(artifact: _ArtifactView, gaps: _GapSink) -> Iterable[tuple[int, str]]:
    if artifact.text is None:
        return
    for number, raw in enumerate(artifact.text.splitlines(), 1):
        if number > MAX_LINES_PER_FILE:
            gaps.add("static-text", "line count boundary reached", artifact.path)
            break
        if len(raw) > MAX_LINE_CHARS:
            gaps.add("static-text", "a line was truncated by the character boundary", artifact.path)
            raw = raw[:MAX_LINE_CHARS]
        yield number, raw


_REGEX_PATTERN_DECLARATION = re.compile(
    r"^\s*\(?\s*(?:r|u|b|br|rb)?[\"']\(\?[A-Za-z-]+[):]",
    re.IGNORECASE,
)


def _is_regex_pattern_declaration(line: str) -> bool:
    """Distinguish a detector regex literal from executable behavior text."""
    return _REGEX_PATTERN_DECLARATION.match(line) is not None


def _scan_docker(artifact: _ArtifactView, sink: _FindingSink, gaps: _GapSink) -> None:
    saw_user = False
    for line_number, line in _iter_lines(artifact, gaps):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"(?i)^USER\s+", stripped):
            saw_user = True
            if re.match(r"(?i)^USER\s+(?:0|root)(?:\s|$)", stripped):
                sink.emit(
                    "IAC-DOCKER-ROOT-USER", "high", "container", artifact.path, line_number,
                    "The container explicitly selects a privileged user.",
                    "Run the final image as a dedicated non-privileged numeric user.",
                    "proven", "static-text",
                )
        match = re.match(r"(?i)^FROM\s+(?:--platform=\S+\s+)?(\S+)", stripped)
        if match:
            image = match.group(1)
            if "@sha256:" not in image and (
                    ":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")):
                sink.emit(
                    "IAC-DOCKER-UNPINNED-BASE", "medium", "supply-chain", artifact.path,
                    line_number, "The base image is not pinned to an immutable digest.",
                    "Pin the reviewed base image by digest and update it through a controlled process.",
                    "proven", "static-text",
                )
        if re.search(r"(?i)^\s*ADD\s+https?://", stripped):
            sink.emit(
                "IAC-DOCKER-REMOTE-ADD", "high", "container", artifact.path, line_number,
                "The build imports remote content without local integrity evidence.",
                "Fetch a versioned artifact in a verified build step and validate its digest.",
                "proven", "static-text",
            )
        if re.search(r"(?i)\bchmod\s+(?:-R\s+)?777\b", stripped):
            sink.emit(
                "IAC-DOCKER-WORLD-WRITABLE", "high", "container", artifact.path, line_number,
                "The image build grants world-writable permissions.",
                "Grant only the owner/group permissions required at runtime.",
                "proven", "static-text",
            )
    if not saw_user:
        sink.emit(
            "IAC-DOCKER-DEFAULT-ROOT", "medium", "container", artifact.path, 1,
            "No final non-privileged container user was observed.",
            "Add a USER instruction for a dedicated non-privileged runtime identity.",
            "inferred", "static-text",
        )


def _scan_kubernetes(artifact: _ArtifactView, sink: _FindingSink, gaps: _GapSink) -> None:
    patterns = (
        (r"(?i)^\s*privileged\s*:\s*true\b", "IAC-K8S-PRIVILEGED", "critical",
         "A workload enables privileged container execution.",
         "Remove privileged mode and grant only explicitly required capabilities."),
        (r"(?i)^\s*allowPrivilegeEscalation\s*:\s*true\b", "IAC-K8S-PRIVESC", "high",
         "A workload permits process privilege escalation.",
         "Set allowPrivilegeEscalation to false and use a restrictive security context."),
        (r"(?i)^\s*(?:hostNetwork|hostPID|hostIPC)\s*:\s*true\b", "IAC-K8S-HOST-NAMESPACE", "high",
         "A workload joins a host namespace.",
         "Disable host namespace sharing unless a documented isolation exception requires it."),
        (r"(?i)^\s*hostPath\s*:", "IAC-K8S-HOSTPATH", "high",
         "A pod mounts a path from the host.",
         "Use a scoped volume type or restrict the permitted host path and mount mode."),
        (r"(?i)^\s*runAsUser\s*:\s*0\b", "IAC-K8S-ROOT-UID", "high",
         "A workload selects the root user ID.",
         "Use a non-zero user ID and enforce runAsNonRoot."),
        (r"(?i)^\s*readOnlyRootFilesystem\s*:\s*false\b", "IAC-K8S-WRITABLE-ROOTFS", "medium",
         "A container explicitly keeps a writable root filesystem.",
         "Use a read-only root filesystem and scoped writable volumes."),
        (r"(?i)^\s*automountServiceAccountToken\s*:\s*true\b", "IAC-K8S-SA-TOKEN", "medium",
         "A workload explicitly mounts a service-account token.",
         "Disable automatic token mounting or bind the least-privileged service account."),
        (r"(?i)^\s*-\s*ALL\s*(?:#.*)?$", "IAC-K8S-ALL-CAPABILITIES", "critical",
         "A security-context list includes all Linux capabilities.",
         "Drop all capabilities and add back only individually justified capabilities."),
    )
    for line_number, line in _iter_lines(artifact, gaps):
        for pattern, rule, severity, message, remediation in patterns:
            if re.search(pattern, line):
                sink.emit(
                    rule, severity, "kubernetes", artifact.path, line_number,
                    message, remediation, "proven", "static-text",
                )
        match = re.search(r"(?i)^\s*(?:-\s*)?image\s*:\s*[\"']?([^\"'\s#]+)", line)
        if match:
            image = match.group(1)
            if "@sha256:" not in image and (
                    ":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")):
                sink.emit(
                    "IAC-K8S-UNPINNED-IMAGE", "medium", "supply-chain", artifact.path,
                    line_number, "A workload image is not pinned to an immutable digest.",
                    "Deploy a reviewed image digest and preserve provenance for that digest.",
                    "proven", "static-text",
                )


def _scan_terraform(artifact: _ArtifactView, sink: _FindingSink, gaps: _GapSink) -> None:
    patterns = (
        (r"(?i)\b(?:cidr_blocks|source_ranges?)\s*=\s*\[[^\]]*[\"']0\.0\.0\.0/0[\"']",
         "IAC-TF-PUBLIC-IPV4", "high",
         "An infrastructure rule permits traffic from every IPv4 address.",
         "Restrict the source range and document any intentionally public listener."),
        (r"(?i)\b(?:ipv6_cidr_blocks|source_ranges?)\s*=\s*\[[^\]]*[\"']::/0[\"']",
         "IAC-TF-PUBLIC-IPV6", "high",
         "An infrastructure rule permits traffic from every IPv6 address.",
         "Restrict the source range and document any intentionally public listener."),
        (r"(?i)\bacl\s*=\s*[\"']public-(?:read|read-write)[\"']",
         "IAC-TF-PUBLIC-ACL", "critical",
         "An object-storage resource uses a public access-control setting.",
         "Use private access controls and a narrowly scoped resource policy."),
        (r"(?i)\bpublicly_accessible\s*=\s*true\b",
         "IAC-TF-PUBLIC-DATABASE", "high",
         "A managed data service is configured as publicly accessible.",
         "Place the service on private networks and require an authenticated access path."),
        (r"(?i)\b(?:encrypted|enable_encryption|storage_encrypted)\s*=\s*false\b",
         "IAC-TF-ENCRYPTION-DISABLED", "high",
         "An infrastructure resource explicitly disables encryption.",
         "Enable encryption with a managed key and document key ownership."),
        (r"(?i)\b(?:actions?|Action)\s*=\s*(?:[\"']\*[\"']|\[\s*[\"']\*[\"']\s*\])",
         "IAC-TF-IAM-WILDCARD-ACTION", "critical",
         "An infrastructure policy grants every action.",
         "Replace the wildcard with the smallest reviewed action set."),
        (r"(?i)\b(?:resources?|Resource)\s*=\s*(?:[\"']\*[\"']|\[\s*[\"']\*[\"']\s*\])",
         "IAC-TF-IAM-WILDCARD-RESOURCE", "high",
         "An infrastructure policy applies to every resource.",
         "Scope the statement to exact resource identifiers and required conditions."),
    )
    for line_number, line in _iter_lines(artifact, gaps):
        for pattern, rule, severity, message, remediation in patterns:
            if re.search(pattern, line):
                sink.emit(
                    rule, severity, "terraform", artifact.path, line_number,
                    message, remediation, "proven", "static-text",
                )


def _scan_github_actions(artifact: _ArtifactView, sink: _FindingSink, gaps: _GapSink) -> None:
    event_context = False
    for line_number, line in _iter_lines(artifact, gaps):
        if re.search(r"(?i)^\s*pull_request_target\s*:", line):
            event_context = True
            sink.emit(
                "CI-PR-TARGET", "medium", "ci-cd", artifact.path, line_number,
                "The workflow runs in the privileged pull-request-target context.",
                "Keep untrusted changes out of privileged steps and grant minimal token permissions.",
                "proven", "static-text",
            )
        match = re.search(r"(?i)^\s*-\s*uses\s*:\s*[\"']?([^\"'\s#]+)", line)
        if match:
            reference = match.group(1)
            if not reference.startswith("./") and "@" in reference:
                revision = reference.rsplit("@", 1)[-1]
                if not re.fullmatch(r"[0-9a-fA-F]{40,64}", revision):
                    sink.emit(
                        "CI-ACTION-MUTABLE-REF", "medium", "supply-chain", artifact.path,
                        line_number, "A third-party workflow action uses a mutable reference.",
                        "Pin the reviewed action to a full immutable commit digest.",
                        "proven", "static-text",
                    )
        if re.search(r"(?i)^\s*permissions\s*:\s*write-all\b", line):
            sink.emit(
                "CI-TOKEN-WRITE-ALL", "high", "ci-cd", artifact.path, line_number,
                "The workflow grants write access to every token permission.",
                "Set a deny-by-default permission block and enable only required operations.",
                "proven", "static-text",
            )
        if re.search(r"(?i)^\s*(?:contents|packages|actions|id-token)\s*:\s*write\b", line):
            sink.emit(
                "CI-TOKEN-WRITE-PERMISSION", "medium", "ci-cd", artifact.path, line_number,
                "The workflow grants a sensitive write permission.",
                "Confirm the job requires this permission and scope it to the smallest job.",
                "proven", "static-text",
            )
        if re.search(r"(?i)\brun\s*:.*\$\{\{\s*github\.event\.", line):
            sink.emit(
                "CI-UNTRUSTED-EXPRESSION-IN-SHELL", "high", "ci-cd", artifact.path,
                line_number, "Untrusted event data is interpolated directly into a shell step.",
                "Pass the value through a quoted environment variable and validate its format.",
                "proven", "static-text",
            )
        if event_context and re.search(
                r"(?i)^\s*(?:ref|repository)\s*:\s*\$\{\{\s*github\.event\.pull_request\.", line):
            sink.emit(
                "CI-PR-TARGET-UNTRUSTED-CHECKOUT", "critical", "ci-cd", artifact.path,
                line_number, "A privileged workflow appears to select untrusted pull-request code.",
                "Do not execute untrusted pull-request content in a privileged workflow context.",
                "inferred", "static-text",
            )


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SecurityPostureError("JSON contains duplicate object keys")
        result[key] = value
    return result


def _load_json(text: str, label: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise SecurityPostureError(label + " is not valid bounded JSON") from exc


def _scan_iam_json(
    artifact: _ArtifactView, sink: _FindingSink, gaps: _GapSink,
) -> None:
    if artifact.text is None:
        return
    lower_name = artifact.path.casefold()
    if not (
        lower_name.endswith(".json")
        and any(word in lower_name for word in ("iam", "policy", "role", "permission"))
    ):
        return
    try:
        document = _load_json(artifact.text, artifact.path)
    except SecurityPostureError:
        gaps.add("iam-policy", "candidate policy JSON could not be parsed", artifact.path)
        return
    pending: list[Any] = [document]
    visited = 0
    while pending:
        current = pending.pop()
        visited += 1
        if visited > 100_000:
            gaps.add("iam-policy", "policy object traversal boundary reached", artifact.path)
            return
        if isinstance(current, list):
            pending.extend(current)
            continue
        if type(current) is not dict:
            continue
        pending.extend(current.values())
        effect = current.get("Effect")
        action = current.get("Action")
        resource = current.get("Resource")
        actions = [action] if isinstance(action, str) else action if type(action) is list else []
        resources = [resource] if isinstance(resource, str) else resource if type(resource) is list else []
        actions = [value for value in actions if isinstance(value, str)]
        resources = [value for value in resources if isinstance(value, str)]
        if str(effect).casefold() != "allow":
            continue
        if "*" in actions:
            sink.emit(
                "IAM-WILDCARD-ACTION", "critical", "identity", artifact.path, 1,
                "An allow statement grants every action.",
                "Replace the wildcard with the smallest reviewed action set.",
                "proven", "parsed-structure",
            )
        if "*" in resources:
            sink.emit(
                "IAM-WILDCARD-RESOURCE", "high", "identity", artifact.path, 1,
                "An allow statement applies to every resource.",
                "Scope the statement to exact resource identifiers and required conditions.",
                "proven", "parsed-structure",
            )
        if any(value.casefold() == "iam:passrole" for value in actions) and "*" in resources:
            sink.emit(
                "IAM-PASSROLE-WILDCARD", "critical", "identity", artifact.path, 1,
                "Role-passing permission is granted for every resource.",
                "Restrict role passing to reviewed roles and constrain the destination service.",
                "proven", "parsed-structure",
            )


def _scan_secret_text(
    artifact: _ArtifactView, sink: _FindingSink, gaps: _GapSink,
) -> int:
    count = 0
    for line_number, line in _iter_lines(artifact, gaps):
        for rule_id, severity, pattern in _SECRET_PATTERNS:
            if pattern.search(line):
                sink.emit(
                    rule_id, severity, "secret", artifact.path, line_number,
                    "Secret-shaped material was observed; its value is withheld.",
                    "Revoke or rotate the credential, remove it from history, and use a secret store.",
                    "proven", "static-text-redacted",
                )
                count += 1
        for match in _SECRET_ASSIGNMENT.finditer(line):
            candidate = match.group("quoted") or match.group("bare") or ""
            if _PLACEHOLDER.fullmatch(candidate):
                continue
            unique = len(set(candidate))
            if len(candidate) >= 12 and unique >= 6:
                sink.emit(
                    "secret-assignment", "high", "secret", artifact.path, line_number,
                    "A credential-like assignment was observed; its value is withheld.",
                    "Move the value to an approved secret store and rotate it if it was committed.",
                    "inferred", "static-text-redacted",
                )
                count += 1
    return count


def _scan_crypto_tls(
    artifact: _ArtifactView, sink: _FindingSink, gaps: _GapSink,
) -> None:
    rules = (
        (r"(?i)\b(?:hashlib\.)?(?:md5|sha1)\s*\(", "CRYPTO-WEAK-DIGEST", "medium",
         "A legacy digest algorithm is used.",
         "Use a modern password KDF, MAC, or collision-resistant digest appropriate to the purpose."),
        (r"(?i)\b(?:DES|RC4|ARC4|MODE_ECB)\b", "CRYPTO-LEGACY-CIPHER", "high",
         "A legacy cipher or insecure block mode is referenced.",
         "Use an authenticated encryption construction with a unique nonce."),
        (r"(?i)\bverify\s*=\s*False\b|\brejectUnauthorized\s*:\s*false\b",
         "TLS-CERTIFICATE-VERIFY-DISABLED", "critical",
         "Peer-certificate verification is disabled.",
         "Enable certificate and hostname verification using the intended trust roots."),
        (r"(?i)\bCERT_NONE\b|\bcheck_hostname\s*=\s*False\b",
         "TLS-HOST-VERIFY-DISABLED", "high",
         "TLS peer identity checks are disabled.",
         "Require certificate-chain and hostname verification."),
        (r"(?i)\b(?:PROTOCOL_TLSv1|TLSv1(?:_1)?)\b",
         "TLS-LEGACY-PROTOCOL", "high",
         "A legacy TLS protocol version is explicitly selected.",
         "Require a currently supported TLS minimum and prefer platform-secure defaults."),
        (r"(?i)\b(?:curl\s+[^;\r\n]*\s-k(?:\s|$)|wget\s+[^;\r\n]*--no-check-certificate)",
         "TLS-CLI-VERIFY-DISABLED", "high",
         "A command-line transfer disables certificate verification.",
         "Remove the bypass and configure the correct trust root."),
        (r"(?i)\b(?:iv|nonce)\s*=\s*(?:(?:br?|rb)?[\"'][^\"']{4,}[\"']|[0-9]+)",
         "CRYPTO-STATIC-NONCE-INDICATOR", "medium",
         "A nonce or initialization vector appears to be assigned statically.",
         "Generate a unique nonce according to the selected authenticated cipher contract."),
    )
    for line_number, line in _iter_lines(artifact, gaps):
        if _is_regex_pattern_declaration(line):
            continue
        for pattern, rule, severity, message, remediation in rules:
            if re.search(pattern, line):
                sink.emit(
                    rule, severity, "crypto", artifact.path, line_number,
                    message, remediation, "inferred", "static-text",
                )
        if (
            re.search(r"(?i)\brandom\.(?:choice|choices|randint|random)\s*\(", line)
            and re.search(r"(?i)\b(?:auth|csrf|nonce|password|secret|session|token)\b", line)
        ):
            sink.emit(
                "CRYPTO-NONCRYPTO-RANDOM", "high", "crypto", artifact.path, line_number,
                "A general-purpose random generator appears to create security-sensitive material.",
                "Use the platform cryptographic random generator or a secrets API.",
                "inferred", "static-text",
            )


def _scan_script_indicators(
    artifact: _ArtifactView, sink: _FindingSink, gaps: _GapSink,
) -> None:
    if artifact.kind not in {"script", "docker", "github-actions", "text"}:
        return
    rules = (
        (r"(?i)\b(?:frombase64string|base64\s+(?:--decode|-d))\b.*\b(?:invoke|iex|sh|bash)\b",
         "SCRIPT-DECODE-EXECUTE", "high",
         "A script appears to decode data immediately before execution.",
         "Replace opaque runtime decoding with reviewed, versioned source."),
        (r"(?i)\b(?:curl|wget)\b[^|;\r\n]{0,400}\|\s*(?:ba)?sh\b",
         "SCRIPT-DOWNLOAD-EXECUTE", "critical",
         "A script appears to stream remotely obtained data into a command interpreter.",
         "Download a pinned artifact separately, verify its digest, and execute only reviewed content."),
        (r"(?i)\b(?:schtasks|runonce|launchagents|/etc/cron(?:\.d|tab)?)\b",
         "SCRIPT-PERSISTENCE-INDICATOR", "high",
         "A script references an operating-system persistence location or scheduler.",
         "Confirm the persistence behavior is required, documented, and least privileged."),
        (r"(?i)\b(?:set-mppreference|disableantispyware|disablebehaviormonitoring)\b",
         "SCRIPT-SECURITY-CONTROL-DISABLE", "critical",
         "A script appears to modify endpoint security controls.",
         "Remove the control bypass and route any required exception through security policy."),
        (r"(?i)\b(?:history\s+-c|clear-history|unset\s+HISTFILE)\b",
         "SCRIPT-AUDIT-ERASURE", "high",
         "A script appears to erase command-history evidence.",
         "Preserve audit evidence and remove history-erasure behavior."),
    )
    for line_number, line in _iter_lines(artifact, gaps):
        if _is_regex_pattern_declaration(line):
            continue
        for pattern, rule, severity, message, remediation in rules:
            if re.search(pattern, line):
                sink.emit(
                    rule, severity, "backdoor-indicator", artifact.path, line_number,
                    message, remediation, "inferred", "static-text",
                )


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)


def _binary_magic(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "pe"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith((b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")):
        return "mach-o"
    return "unknown"


def _bounded_strings(data: bytes) -> list[str]:
    rows: list[str] = []
    for match in re.finditer(rb"[\x20-\x7e]{6,256}", data):
        rows.append(match.group(0).decode("ascii", "strict"))
        if len(rows) >= MAX_BINARY_STRINGS:
            break
    return rows


def _scan_binary(
    artifact: _ArtifactView, sink: _FindingSink, gaps: _GapSink,
) -> dict[str, Any] | None:
    if artifact.text is not None and not (
            artifact.executable or PurePosixPath(artifact.path.casefold()).suffix in _BINARY_SUFFIXES):
        return None
    magic = _binary_magic(artifact.data)
    extension = PurePosixPath(artifact.path.casefold()).suffix
    executable = artifact.executable or magic != "unknown" or extension in _BINARY_SUFFIXES
    sample = artifact.data[: min(len(artifact.data), 1024 * 1024)]
    entropy = round(_entropy(sample), 3)
    if magic != "unknown" and extension not in _BINARY_SUFFIXES:
        sink.emit(
            "BINARY-EXECUTABLE-EXTENSION-MISMATCH", "high", "binary", artifact.path, 1,
            "Executable file metadata does not match the apparent filename extension.",
            "Quarantine the artifact and verify its origin, signature, and expected format.",
            "proven", "binary-metadata",
        )
    if executable and len(sample) >= 4_096 and entropy >= 7.4:
        sink.emit(
            "BINARY-HIGH-ENTROPY-EXECUTABLE", "medium", "binary", artifact.path, 1,
            "An executable artifact has unusually high byte entropy.",
            "Verify provenance and inspect the artifact with an approved isolated binary-analysis service.",
            "inferred", "binary-metadata",
        )
    strings = _bounded_strings(sample)
    joined = "\n".join(strings)
    binary_rules = (
        (r"(?i)(?:FromBase64String|EncodedCommand)", "BINARY-ENCODED-COMMAND-INDICATOR", "high",
         "Printable metadata references encoded command handling."),
        (r"(?i)(?:CurrentVersion\\Run|RunOnce|/etc/cron)", "BINARY-PERSISTENCE-INDICATOR", "high",
         "Printable metadata references a persistence location."),
        (r"(?i)(?:DisableAntiSpyware|DisableBehaviorMonitoring)", "BINARY-SECURITY-DISABLE-INDICATOR",
         "critical", "Printable metadata references disabling endpoint security controls."),
    )
    for pattern, rule, severity, message in binary_rules:
        if re.search(pattern, joined):
            sink.emit(
                rule, severity, "backdoor-indicator", artifact.path, 1, message,
                "Verify provenance and inspect the artifact in an approved isolated environment.",
                "inferred", "bounded-printable-strings",
            )
    return {
        "path": artifact.path,
        "size": len(artifact.data),
        "format": magic,
        "executable": bool(executable),
        "sample_entropy": entropy,
        "strings_considered": len(strings),
        "analysis": "metadata-and-bounded-printable-strings-only",
        "evidence_state": "proven",
    }


def _parse_requirement(value: str) -> tuple[str, str] | None:
    cleaned = value.strip()
    if not cleaned or cleaned.startswith(("#", "-", "git+", "http:", "https:", "file:")):
        return None
    cleaned = cleaned.split(";", 1)[0].strip()
    match = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]{0,199})(?:\[[^\]]+\])?\s*(.*)", cleaned)
    if not match:
        return None
    return match.group(1).casefold().replace("_", "-"), match.group(2).strip()


def _component_key(ecosystem: str, name: str) -> tuple[str, str]:
    normalized = name.casefold()
    if ecosystem == "pypi":
        normalized = re.sub(r"[-_.]+", "-", normalized)
    return ecosystem, normalized


def _component(
    ecosystem: str, name: Any, version: Any, scope: str, source: str,
    evidence_state: str = "proven",
) -> _Component | None:
    clean_name = _safe_text(str(name).strip(), 256)
    clean_version = _safe_text(str(version).strip(), 256)
    if (
        not clean_name or clean_name == "[redacted]" or
        not re.fullmatch(r"[A-Za-z0-9@][A-Za-z0-9@/._+:-]{0,255}", clean_name)
    ):
        return None
    return _Component(
        ecosystem, clean_name, clean_version, scope, _safe_text(source, 1_024),
        evidence_state,
    )


def _add_declared(
    target: dict[tuple[str, str], tuple[str, str]], ecosystem: str,
    name: Any, specifier: Any, source: str,
) -> None:
    item = _component(ecosystem, name, specifier, "declared", source)
    if item is not None:
        target[_component_key(ecosystem, item.name)] = (item.version, item.source)


def _add_locked(
    target: dict[tuple[str, str], tuple[str, str]], ecosystem: str,
    name: Any, version: Any, source: str,
) -> None:
    item = _component(ecosystem, name, version, "locked", source)
    if item is not None:
        target[_component_key(ecosystem, item.name)] = (item.version, item.source)


def _parse_manifests(
    artifacts: Sequence[_ArtifactView], gaps: _GapSink,
) -> tuple[list[_Component], dict[tuple[str, str], tuple[str, str]],
           dict[tuple[str, str], tuple[str, str]], set[str]]:
    components: dict[tuple[str, str, str, str], _Component] = {}
    declared: dict[tuple[str, str], tuple[str, str]] = {}
    locked: dict[tuple[str, str], tuple[str, str]] = {}
    lock_ecosystems: set[str] = set()

    def remember(item: _Component | None) -> None:
        if item is not None and len(components) < MAX_COMPONENTS:
            components[(item.ecosystem, item.name.casefold(), item.version, item.scope)] = item

    for artifact in artifacts:
        if artifact.text is None:
            continue
        name = PurePosixPath(artifact.path.casefold()).name
        text = artifact.text
        try:
            if name == "package.json":
                value = _load_json(text, artifact.path)
                if type(value) is not dict:
                    raise SecurityPostureError("package manifest root is not an object")
                for field, scope in (
                    ("dependencies", "runtime"), ("optionalDependencies", "optional"),
                    ("peerDependencies", "peer"), ("devDependencies", "development"),
                ):
                    rows = value.get(field, {})
                    if type(rows) is not dict:
                        gaps.add("sbom", field + " is not an object", artifact.path)
                        continue
                    for dependency, specifier in sorted(rows.items()):
                        if not isinstance(specifier, str):
                            gaps.add("sbom", "dependency specifier is not text", artifact.path)
                            continue
                        _add_declared(declared, "npm", dependency, specifier, artifact.path)
                        remember(_component("npm", dependency, specifier, scope, artifact.path))
            elif name == "package-lock.json":
                value = _load_json(text, artifact.path)
                if type(value) is not dict:
                    raise SecurityPostureError("package lock root is not an object")
                lock_ecosystems.add("npm")
                packages = value.get("packages")
                if type(packages) is dict:
                    for package_path, row in sorted(packages.items()):
                        if not package_path or type(row) is not dict:
                            continue
                        dep_name = row.get("name") or str(package_path).rsplit("node_modules/", 1)[-1]
                        dep_version = row.get("version", "")
                        _add_locked(locked, "npm", dep_name, dep_version, artifact.path)
                        remember(_component("npm", dep_name, dep_version, "locked", artifact.path))
                else:
                    rows = value.get("dependencies", {})
                    if type(rows) is dict:
                        for dep_name, row in sorted(rows.items()):
                            if type(row) is dict:
                                dep_version = row.get("version", "")
                                _add_locked(locked, "npm", dep_name, dep_version, artifact.path)
                                remember(_component("npm", dep_name, dep_version, "locked", artifact.path))
            elif name.startswith("requirements") and name.endswith((".txt", ".in")):
                is_lock = name.endswith(".txt")
                if is_lock:
                    lock_ecosystems.add("pypi")
                for number, line in _iter_lines(artifact, gaps):
                    parsed = _parse_requirement(line)
                    if parsed is None:
                        continue
                    dep_name, specifier = parsed
                    if is_lock and specifier.startswith("==") and len(specifier) > 2:
                        _add_locked(locked, "pypi", dep_name, specifier[2:], artifact.path)
                        remember(_component("pypi", dep_name, specifier[2:], "locked", artifact.path))
                    else:
                        _add_declared(declared, "pypi", dep_name, specifier, artifact.path)
                        remember(_component("pypi", dep_name, specifier, "runtime", artifact.path))
            elif name == "pyproject.toml":
                value = tomllib.loads(text)
                project = value.get("project", {}) if type(value) is dict else {}
                rows = project.get("dependencies", []) if type(project) is dict else []
                if type(rows) is list:
                    for row in rows:
                        if isinstance(row, str):
                            parsed = _parse_requirement(row)
                            if parsed:
                                _add_declared(declared, "pypi", parsed[0], parsed[1], artifact.path)
                                remember(_component("pypi", parsed[0], parsed[1], "runtime", artifact.path))
                poetry = value.get("tool", {}).get("poetry", {}) if type(value) is dict else {}
                poetry_rows = poetry.get("dependencies", {}) if type(poetry) is dict else {}
                if type(poetry_rows) is dict:
                    for dep_name, specifier in sorted(poetry_rows.items()):
                        if dep_name.casefold() == "python":
                            continue
                        if isinstance(specifier, dict):
                            specifier = specifier.get("version", "")
                        _add_declared(declared, "pypi", dep_name, specifier, artifact.path)
                        remember(_component("pypi", dep_name, specifier, "runtime", artifact.path))
            elif name == "cargo.toml":
                value = tomllib.loads(text)
                for field, scope in (
                    ("dependencies", "runtime"), ("dev-dependencies", "development"),
                    ("build-dependencies", "build"),
                ):
                    rows = value.get(field, {}) if type(value) is dict else {}
                    if type(rows) is dict:
                        for dep_name, specifier in sorted(rows.items()):
                            if isinstance(specifier, dict):
                                specifier = specifier.get("version", "")
                            _add_declared(declared, "cargo", dep_name, specifier, artifact.path)
                            remember(_component("cargo", dep_name, specifier, scope, artifact.path))
            elif name == "cargo.lock":
                value = tomllib.loads(text)
                lock_ecosystems.add("cargo")
                rows = value.get("package", []) if type(value) is dict else []
                if type(rows) is list:
                    for row in rows:
                        if type(row) is dict:
                            _add_locked(locked, "cargo", row.get("name", ""), row.get("version", ""),
                                        artifact.path)
                            remember(_component("cargo", row.get("name", ""), row.get("version", ""),
                                                "locked", artifact.path))
            elif name == "go.mod":
                in_block = False
                for _number, line in _iter_lines(artifact, gaps):
                    stripped = line.strip()
                    if stripped == "require (":
                        in_block = True
                        continue
                    if in_block and stripped == ")":
                        in_block = False
                        continue
                    match = re.match(r"(?:require\s+)?([^\s]+)\s+(v[^\s]+)", stripped)
                    if match and (in_block or stripped.startswith("require ")):
                        _add_declared(declared, "golang", match.group(1), match.group(2), artifact.path)
                        remember(_component("golang", match.group(1), match.group(2),
                                            "runtime", artifact.path))
            elif name == "go.sum":
                lock_ecosystems.add("golang")
                for _number, line in _iter_lines(artifact, gaps):
                    fields = line.split()
                    if len(fields) >= 2:
                        version = fields[1].removesuffix("/go.mod")
                        _add_locked(locked, "golang", fields[0], version, artifact.path)
                        remember(_component("golang", fields[0], version, "locked", artifact.path))
            elif name == "pom.xml":
                if "<!DOCTYPE" in text.upper():
                    raise SecurityPostureError("XML document type declarations are not accepted")
                root = ET.fromstring(text)
                for node in root.iter():
                    if node.tag.rsplit("}", 1)[-1] != "dependency":
                        continue
                    fields = {child.tag.rsplit("}", 1)[-1]: (child.text or "").strip()
                              for child in list(node)}
                    dep_name = ":".join(filter(None, (fields.get("groupId"), fields.get("artifactId"))))
                    if dep_name:
                        _add_declared(declared, "maven", dep_name, fields.get("version", ""), artifact.path)
                        remember(_component("maven", dep_name, fields.get("version", ""),
                                            fields.get("scope", "runtime"), artifact.path))
        except (SecurityPostureError, tomllib.TOMLDecodeError, ET.ParseError, RecursionError):
            gaps.add("sbom", "a supported manifest could not be parsed", artifact.path)

    if len(components) >= MAX_COMPONENTS:
        gaps.add("sbom", "component count boundary reached")
    return (
        sorted(components.values(), key=lambda row: (
            row.ecosystem, row.name.casefold(), row.version, row.scope, row.source,
        ))[:MAX_COMPONENTS],
        declared,
        locked,
        lock_ecosystems,
    )


def _edit_distance_at_most_one(left: str, right: str) -> bool:
    if left == right:
        return False
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        return sum(a != b for a, b in zip(left, right)) == 1
    short, long = (left, right) if len(left) < len(right) else (right, left)
    index_short = index_long = differences = 0
    while index_short < len(short) and index_long < len(long):
        if short[index_short] == long[index_long]:
            index_short += 1
            index_long += 1
        else:
            differences += 1
            index_long += 1
            if differences > 1:
                return False
    return True


def _scan_supply_indicators(
    declared: Mapping[tuple[str, str], tuple[str, str]],
    locked: Mapping[tuple[str, str], tuple[str, str]],
    lock_ecosystems: set[str],
    private_namespaces: Sequence[str],
    sink: _FindingSink,
    gaps: _GapSink,
) -> dict[str, Any]:
    ecosystems = sorted({key[0] for key in declared})
    missing = 0
    mismatched = 0
    for key, (specifier, source) in sorted(declared.items()):
        ecosystem, name = key
        if ecosystem not in lock_ecosystems:
            continue
        locked_row = locked.get(key)
        if locked_row is None:
            missing += 1
            sink.emit(
                "SC-LOCK-MISSING-DEPENDENCY", "high", "supply-chain", source, 1,
                "A declared dependency is absent from the corresponding parsed lock data.",
                "Regenerate the lockfile in a trusted environment and review the resulting change.",
                "proven", "parsed-structure",
            )
        else:
            exact = ""
            if ecosystem == "pypi" and specifier.startswith("=="):
                exact = specifier[2:]
            elif re.fullmatch(r"v?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?", specifier):
                exact = specifier
            if exact and exact != locked_row[0]:
                mismatched += 1
                sink.emit(
                    "SC-LOCK-VERSION-DRIFT", "high", "supply-chain", source, 1,
                    "An exact declared dependency version differs from parsed lock data.",
                    "Regenerate and review the lockfile, then verify build reproducibility.",
                    "proven", "parsed-structure",
                )
        if ecosystem in _POPULAR_PACKAGES and len(name) <= 64:
            for popular in _POPULAR_PACKAGES[ecosystem]:
                if _edit_distance_at_most_one(name, popular):
                    sink.emit(
                        "SC-TYPOSQUAT-SIMILAR-NAME", "medium", "supply-chain", source, 1,
                        "A dependency name is one edit away from a widely used package name.",
                        "Confirm the publisher, intended spelling, registry, and package provenance.",
                        "inferred", "parsed-structure",
                    )
                    break
        if ecosystem == "npm" and not name.startswith("@"):
            for namespace in private_namespaces:
                if name.startswith(namespace):
                    sink.emit(
                        "SC-UNSCOPED-PRIVATE-NAME", "high", "supply-chain", source, 1,
                        "A dependency matching a private naming convention is unscoped.",
                        "Use a registry scope and enforce the private registry mapping in trusted configuration.",
                        "inferred", "parsed-structure",
                    )
                    break
        if re.search(r"(?i)(?:git\+|https?://)", specifier) and not re.search(
                r"(?:#[0-9a-f]{40,64}|@sha256:[0-9a-f]{64})", specifier):
            sink.emit(
                "SC-UNPINNED-DIRECT-SOURCE", "high", "supply-chain", source, 1,
                "A direct dependency source is not pinned to immutable integrity evidence.",
                "Pin the source to an immutable revision and preserve verified provenance.",
                "proven", "parsed-structure",
            )
    for ecosystem in ecosystems:
        if ecosystem not in lock_ecosystems:
            gaps.add(
                "lockfile-drift",
                "no supported lock evidence was supplied for declared " + ecosystem + " dependencies",
            )
    if not ecosystems:
        gaps.add("lockfile-drift", "no supported dependency declaration was observed")
    state = (
        "unavailable" if ecosystems and not (set(ecosystems) & lock_ecosystems)
        else "partial" if any(ecosystem not in lock_ecosystems for ecosystem in ecosystems)
        else "complete" if ecosystems else "unavailable"
    )
    return {
        "state": state,
        "declared_count": len(declared),
        "locked_count": len(locked),
        "missing_count": missing,
        "version_mismatch_count": mismatched,
        "evidence_state": "proven" if state == "complete" else "unavailable",
    }


def _purl(component: _Component) -> str:
    ecosystem = {
        "pypi": "pypi", "npm": "npm", "cargo": "cargo",
        "golang": "golang", "maven": "maven",
    }.get(component.ecosystem, component.ecosystem)
    name = quote(component.name, safe="@/:")
    suffix = "@" + quote(component.version, safe=".+:~^<>=*") if component.version else ""
    return "pkg:" + ecosystem + "/" + name + suffix


def _build_sbom(components: Sequence[_Component]) -> dict[str, Any]:
    internal: list[dict[str, Any]] = []
    spdx_packages: list[dict[str, Any]] = []
    cdx_components: list[dict[str, Any]] = []
    for index, component in enumerate(components, 1):
        ref = "component-" + _sha([
            component.ecosystem, component.name.casefold(), component.version,
            component.scope, component.source,
        ])[:24]
        purl = _purl(component)
        internal.append({
            "bom_ref": ref,
            "ecosystem": component.ecosystem,
            "name": component.name,
            "version": component.version,
            "scope": component.scope,
            "source": component.source,
            "purl": purl,
            "evidence_state": component.evidence_state,
        })
        spdx_packages.append({
            "SPDXID": "SPDXRef-Package-" + str(index),
            "name": component.name,
            "versionInfo": component.version or "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }],
        })
        cdx_components.append({
            "bom-ref": ref,
            "type": "library",
            "group": "",
            "name": component.name,
            "version": component.version,
            "scope": "excluded" if component.scope == "development" else "required",
            "purl": purl,
        })
    namespace = "urn:uuid:attestor-" + _sha(internal)[:32]
    return {
        "schema": SBOM_SCHEMA,
        "component_count": len(internal),
        "components": internal,
        "spdx": {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "Attestor bounded workspace inventory",
            "documentNamespace": namespace,
            "packages": spdx_packages,
        },
        "cyclonedx": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": namespace,
            "version": 1,
            "components": cdx_components,
        },
        "generation": {
            "network_resolution": False,
            "package_execution": False,
            "identity_source": "bounded local manifest data",
        },
    }


def _validate_metadata_collection(
    rows: Iterable[Mapping[str, Any]], maximum: int, label: str,
) -> list[Mapping[str, Any]]:
    output: list[Mapping[str, Any]] = []
    for index, row in enumerate(rows):
        if index >= maximum:
            raise SecurityPostureError(label + " record count exceeds boundary")
        if type(row) is not dict:
            raise SecurityPostureError(label + " record must be an exact object")
        output.append(row)
    if len(_canonical(output)) > MAX_METADATA_BYTES:
        raise SecurityPostureError(label + " metadata exceeds byte boundary")
    return output


def _history_report(
    history_evidence: Iterable[Mapping[str, Any]],
    sink: _FindingSink,
    gaps: _GapSink,
) -> dict[str, Any]:
    records = _validate_metadata_collection(
        history_evidence, MAX_HISTORY_EVENTS, "secret-history",
    )
    allowed = {
        "path", "line", "rule_id", "severity", "removed",
        "rotation_verified", "revocation_verified",
    }
    output: list[dict[str, Any]] = []
    for row in records:
        if set(row) != allowed:
            raise SecurityPostureError(
                "secret-history records must contain metadata only; raw values are forbidden"
            )
        if (
            not isinstance(row["path"], str) or type(row["line"]) is not int
            or not 1 <= row["line"] <= 2_147_483_647
            or not isinstance(row["rule_id"], str)
            or row["severity"] not in _SEVERITY_ORDER
            or any(type(row[field]) is not bool for field in (
                "removed", "rotation_verified", "revocation_verified"
            ))
        ):
            raise SecurityPostureError("secret-history record metadata is invalid")
        path = _clean_path(row["path"])
        rule_id = _safe_text(row["rule_id"], 96)
        output.append({
            "path": path,
            "line": row["line"],
            "rule_id": rule_id,
            "severity": row["severity"],
            "removed": row["removed"],
            "rotation_verified": row["rotation_verified"],
            "revocation_verified": row["revocation_verified"],
            "raw_value_present": False,
            "value_hash_present": False,
            "evidence_state": "inferred",
        })
        if not row["removed"]:
            sink.emit(
                "SECRET-HISTORY-NOT-REMOVED", "high", "secret", path, row["line"],
                "Supplied history metadata says secret-shaped material remains in history.",
                "Remove the value from history through an approved process and coordinate rotation.",
                "inferred", "caller-supplied-history-metadata",
            )
        if not row["rotation_verified"] or not row["revocation_verified"]:
            sink.emit(
                "SECRET-LIFECYCLE-INCOMPLETE", "high", "secret", path, row["line"],
                "Rotation or revocation is not verified by the supplied lifecycle metadata.",
                "Revoke and rotate the credential, then preserve non-secret completion evidence.",
                "inferred", "caller-supplied-history-metadata",
            )
    if not output:
        gaps.add(
            "git-secret-history",
            "Git-history evidence was not supplied; version-control tooling was not invoked",
        )
    output.sort(key=lambda row: (row["path"].casefold(), row["line"], row["rule_id"]))
    return {
        "state": "available" if output else "unavailable",
        "event_count": len(output),
        "events": output,
        "raw_values": False,
        "value_hashes": False,
        "git_invoked": False,
        "evidence_state": "inferred" if output else "unavailable",
    }


def _provenance_report(
    rows: Iterable[Mapping[str, Any]],
    artifact_by_path: Mapping[str, _ArtifactView],
    gaps: _GapSink,
) -> dict[str, Any]:
    records = _validate_metadata_collection(
        rows, MAX_PROVENANCE_RECORDS, "provenance",
    )
    allowed = {
        "subject_path", "subject_sha256", "signature_verified",
        "provenance_verified", "signer", "source",
    }
    output: list[dict[str, Any]] = []
    for row in records:
        if set(row) != allowed:
            raise SecurityPostureError("provenance record shape is invalid")
        digest = row["subject_sha256"]
        signature = row["signature_verified"]
        provenance = row["provenance_verified"]
        if (
            not isinstance(row["subject_path"], str)
            or not isinstance(digest, str) or not _HEX64.fullmatch(digest)
            or (signature is not None and type(signature) is not bool)
            or (provenance is not None and type(provenance) is not bool)
            or not isinstance(row["signer"], str)
            or not isinstance(row["source"], str)
        ):
            raise SecurityPostureError("provenance record fields are invalid")
        path = _clean_path(row["subject_path"])
        artifact = artifact_by_path.get(path.casefold())
        digest_matches = artifact is not None and hmac.compare_digest(
            hashlib.sha256(artifact.data).hexdigest(), digest,
        )
        if artifact is None:
            state = "unavailable"
            evidence = "unavailable"
            gaps.add("signature-provenance", "provenance subject was not in the artifact snapshot", path)
        elif not digest_matches:
            state = "digest-mismatch"
            evidence = "proven"
            gaps.add("signature-provenance", "supplied subject digest does not match snapshot bytes", path)
        elif signature is True and provenance is True:
            state = "reported-verified"
            evidence = "inferred"
        elif signature is False or provenance is False:
            state = "reported-unverified"
            evidence = "inferred"
            gaps.add("signature-provenance", "supplied verification state is negative", path)
        else:
            state = "unavailable"
            evidence = "unavailable"
            gaps.add("signature-provenance", "signature or provenance state was not supplied", path)
        output.append({
            "subject_path": path,
            "subject_sha256": digest,
            "digest_matches_snapshot": bool(digest_matches),
            "state": state,
            "signature_verified": signature,
            "provenance_verified": provenance,
            "signer": _safe_text(row["signer"], 256),
            "source": _safe_text(row["source"], 256),
            "evidence_state": evidence,
        })
    if not output:
        gaps.add(
            "signature-provenance",
            "no caller-supplied signature or build-provenance evidence was available",
        )
    output.sort(key=lambda row: (row["subject_path"].casefold(), row["subject_sha256"]))
    states = {row["state"] for row in output}
    aggregate = (
        "unavailable" if not output or states == {"unavailable"}
        else "verified" if states == {"reported-verified"}
        else "partial"
    )
    return {
        "state": aggregate,
        "records": output,
        "record_count": len(output),
        "verification_performed_by_attestor": False,
        "evidence_state": "inferred" if output else "unavailable",
    }


def _summary(findings: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    severity = {name: 0 for name in _SEVERITY_ORDER}
    category: dict[str, int] = {}
    evidence = {name: 0 for name in sorted(_EVIDENCE_STATES)}
    for row in findings:
        severity[row["severity"]] += 1
        category[row["category"]] = category.get(row["category"], 0) + 1
        evidence[row["evidence_state"]] += 1
    return {
        "finding_count": len(findings),
        "by_severity": severity,
        "by_category": dict(sorted(category.items())),
        "by_evidence_state": evidence,
    }


def _finding_section(
    findings: Sequence[Mapping[str, Any]], categories: set[str], *,
    mode: str, rule_prefixes: tuple[str, ...] = (),
) -> dict[str, Any]:
    selected = [
        row for row in findings
        if row["category"] in categories
        or (rule_prefixes and row["rule_id"].startswith(rule_prefixes))
    ]
    rules: dict[str, int] = {}
    for row in selected:
        rules[row["rule_id"]] = rules.get(row["rule_id"], 0) + 1
    return {
        "mode": mode,
        "finding_count": len(selected),
        "by_rule": dict(sorted(rules.items())),
        "finding_ids": [row["finding_id"] for row in selected],
        "evidence_state": (
            "proven" if selected and all(row["evidence_state"] == "proven" for row in selected)
            else "inferred" if selected else "unavailable"
        ),
    }


def _contains_unsafe_controls(value: Any) -> bool:
    pending = [value]
    visited = 0
    while pending:
        current = pending.pop()
        visited += 1
        if visited > 1_000_000:
            return True
        if isinstance(current, str):
            if any(
                ord(character) < 32
                or 0x7F <= ord(character) <= 0x9F
                or ord(character) in _BIDI
                for character in current
            ):
                return True
        elif type(current) is dict:
            pending.extend(current.keys())
            pending.extend(current.values())
        elif type(current) is list:
            pending.extend(current)
    return False


def _contains_raw_secret(value: Any) -> bool:
    pending = [value]
    visited = 0
    while pending:
        current = pending.pop()
        visited += 1
        if visited > 1_000_000:
            return True
        if isinstance(current, str):
            if _looks_like_secret(current):
                return True
        elif type(current) is dict:
            pending.extend(current.keys())
            pending.extend(current.values())
        elif type(current) is list:
            pending.extend(current)
    return False


def scan_security_posture(
    artifacts: Iterable[Artifact | Mapping[str, Any]], *,
    history_evidence: Iterable[Mapping[str, Any]] = (),
    provenance_evidence: Iterable[Mapping[str, Any]] = (),
    private_namespaces: Iterable[str] = (),
    collection_gaps: Iterable[Mapping[str, str]] = (),
) -> dict[str, Any]:
    """Analyze a bounded immutable artifact snapshot and return a signed-shape report.

    ``history_evidence`` is metadata supplied by the caller.  Raw secret fields
    are rejected, and this function never obtains repository history itself.
    ``provenance_evidence`` records a caller's verification result; Attestor checks
    the subject digest against snapshot bytes but does not overstate the caller's
    signature assertion as independently proven.
    """
    views, input_bytes = _coerce_artifacts(artifacts)
    namespaces: list[str] = []
    for index, value in enumerate(private_namespaces):
        if index >= 128 or not isinstance(value, str):
            raise SecurityPostureError("private namespace boundary is invalid")
        clean = _safe_text(value.strip().casefold(), 64)
        if not clean or clean == "[redacted]":
            raise SecurityPostureError("private namespace is invalid")
        namespaces.append(clean)
    namespaces = sorted(set(namespaces))

    gaps = _GapSink()
    for index, row in enumerate(collection_gaps):
        if index >= MAX_GAPS or type(row) is not dict:
            raise SecurityPostureError("collection gap boundary is invalid")
        if set(row) != {"capability", "reason", "path"}:
            raise SecurityPostureError("collection gap shape is invalid")
        if any(not isinstance(row[field], str) for field in ("capability", "reason", "path")):
            raise SecurityPostureError("collection gap fields must be text")
        gaps.add(row["capability"], row["reason"], row["path"])
    sink = _FindingSink()
    binary_inventory: list[dict[str, Any]] = []
    current_secret_matches = 0
    for artifact in views:
        if artifact.kind == "docker":
            _scan_docker(artifact, sink, gaps)
        elif artifact.kind == "kubernetes":
            _scan_kubernetes(artifact, sink, gaps)
        elif artifact.kind == "terraform":
            _scan_terraform(artifact, sink, gaps)
        elif artifact.kind == "github-actions":
            _scan_github_actions(artifact, sink, gaps)
        _scan_iam_json(artifact, sink, gaps)
        if artifact.text is not None:
            current_secret_matches += _scan_secret_text(artifact, sink, gaps)
            _scan_crypto_tls(artifact, sink, gaps)
            _scan_script_indicators(artifact, sink, gaps)
        binary = _scan_binary(artifact, sink, gaps)
        if binary is not None:
            binary_inventory.append(binary)

    components, declared, locked, lock_ecosystems = _parse_manifests(views, gaps)
    lock_report = _scan_supply_indicators(
        declared, locked, lock_ecosystems, namespaces, sink, gaps,
    )
    sbom = _build_sbom(components)
    history = _history_report(history_evidence, sink, gaps)
    artifact_by_path = {row.path.casefold(): row for row in views}
    provenance = _provenance_report(provenance_evidence, artifact_by_path, gaps)
    if sink.truncated:
        gaps.add("findings", "finding count boundary reached; additional findings were withheld")

    findings = sink.rows()
    gap_rows = gaps.rows()
    artifact_kinds: dict[str, int] = {}
    for artifact in views:
        artifact_kinds[artifact.kind] = artifact_kinds.get(artifact.kind, 0) + 1
    cloud_iac = _finding_section(
        findings, {"container", "kubernetes", "terraform", "ci-cd", "identity"},
        mode="bounded-static-configuration", rule_prefixes=("IAC-", "CI-", "IAM-"),
    )
    cloud_iac["artifacts_considered"] = sum(
        artifact_kinds.get(kind, 0)
        for kind in ("docker", "kubernetes", "terraform", "github-actions")
    )
    crypto = _finding_section(findings, {"crypto"}, mode="bounded-static-text")
    binary_inventory.sort(key=lambda row: (row["path"].casefold(), row["path"]))
    binary = {
        "mode": "metadata-and-bounded-printable-strings-only",
        "artifact_count": len(binary_inventory),
        "artifacts": binary_inventory,
        "finding_count": sum(
            1 for row in findings if row["category"] in {"binary", "backdoor-indicator"}
        ),
        "target_code_executed": False,
    }
    coverage = {
        "artifact_kinds": dict(sorted(artifact_kinds.items())),
        "artifacts_considered": len(views),
        "input_bytes_considered": input_bytes,
        "gap_count": len(gap_rows),
        "complete": not gap_rows,
        "evidence_state": "proven" if not gap_rows else "unavailable",
    }
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "version": VERSION,
        "status": "partial" if gap_rows else "complete",
        "summary": _summary(findings),
        "findings": findings,
        "cloud_iac": cloud_iac,
        "sbom": sbom,
        "supply_chain": {
            "lockfile_drift": lock_report,
            "dependency_confusion_analysis": {
                "mode": "offline-indicators-only",
                "registry_queried": False,
                "private_namespace_count": len(namespaces),
                "evidence_state": "inferred",
            },
        },
        "provenance": provenance,
        "secret_lifecycle": {
            "current_snapshot_match_count": current_secret_matches,
            "raw_values": False,
            "value_hashes": False,
            "prefixes_or_suffixes": False,
        },
        "secret_history": history,
        "crypto": crypto,
        "binary": binary,
        "coverage": coverage,
        "gaps": gap_rows,
        "scope": {
            "artifact_count": len(views),
            "input_bytes": input_bytes,
            "limits": {
                "max_artifacts": MAX_ARTIFACTS,
                "max_file_bytes": MAX_FILE_BYTES,
                "max_binary_file_bytes": MAX_BINARY_FILE_BYTES,
                "max_total_input_bytes": MAX_TOTAL_INPUT_BYTES,
                "max_findings": MAX_FINDINGS,
                "max_components": MAX_COMPONENTS,
                "max_output_bytes": MAX_OUTPUT_BYTES,
                "max_directory_entries": MAX_DIRECTORY_ENTRIES,
                "max_entries_per_directory": MAX_ENTRIES_PER_DIRECTORY,
                "max_directory_depth": MAX_DIRECTORY_DEPTH,
                "max_directories": MAX_DIRECTORIES,
            },
        },
        "privacy": {
            "raw_secret_values": False,
            "secret_hashes": False,
            "secret_prefixes_or_suffixes": False,
            "terminal_controls_escaped": True,
        },
        "execution": {
            "target_code_executed": False,
            "network_accessed": False,
            "files_written": False,
            "git_invoked": False,
            "binary_mode": "metadata-and-bounded-printable-strings-only",
        },
    }
    body = _canonical(report)
    if len(body) > MAX_OUTPUT_BYTES:
        raise SecurityPostureError("report exceeds output byte boundary")
    report["report_sha256"] = hashlib.sha256(body).hexdigest()
    if not verify_report(report):
        raise SecurityPostureError("internal report verification failed")
    return report


def _interesting_file(path: Path) -> bool:
    name = path.name.casefold()
    suffix = path.suffix.casefold()
    return (
        name in _SPECIAL_NAMES or name.startswith(("dockerfile", "containerfile", "requirements"))
        or suffix in _TEXT_SUFFIXES or suffix in _BINARY_SUFFIXES
        or ".github" in {part.casefold() for part in path.parts}
    )


def _is_reparse_metadata(metadata: os.stat_result) -> bool:
    """Recognize POSIX links and every Windows reparse-point class."""
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse)


def _is_linklike(path: Path) -> bool:
    """Treat symbolic links, junctions, and opaque reparse points as links."""
    try:
        return _is_reparse_metadata(os.lstat(path))
    except OSError:
        return True


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return int(metadata.st_dev), int(metadata.st_ino)


def _metadata_token(
    metadata: os.stat_result, *, include_content_fields: bool,
) -> tuple[int, ...]:
    token = [
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000))),
    ]
    if include_content_fields:
        token.append(int(metadata.st_size))
    return tuple(token)


def _resolved_without_link(base: Path, candidate: Path) -> bool:
    """Require canonical containment and refuse a reparse in any child spelling."""
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(base)
    except (OSError, ValueError):
        return False
    return os.path.normcase(str(resolved)) == os.path.normcase(
        str(candidate.absolute()))


def _read_fd_pass(descriptor: int, maximum: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    remaining = maximum + 1
    chunks: list[bytes] = []
    while remaining:
        chunk = os.read(descriptor, min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_verified_regular_file(
    path: Path, initial: os.stat_result, base_device: int, limit: int,
) -> tuple[bytes | None, str]:
    """Read twice through one descriptor and verify identity/content stability."""
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    flags |= int(getattr(os, "O_NOINHERIT", 0))
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                _is_reparse_metadata(opened)
                or not stat.S_ISREG(opened.st_mode)
                or int(opened.st_dev) != base_device
                or not all(_identity(initial))
                or _identity(opened) != _identity(initial)
            ):
                return None, (
                    "opened file crossed a link, device, identity, or "
                    "regular-file boundary")
            if _metadata_token(
                    opened, include_content_fields=True) != _metadata_token(
                        initial, include_content_fields=True):
                return None, "file metadata changed before content verification"
            if opened.st_size > limit:
                return None, "file exceeded the applicable byte boundary"

            first = _read_fd_pass(descriptor, limit)
            middle = os.fstat(descriptor)
            second = _read_fd_pass(descriptor, limit)
            final = os.fstat(descriptor)
            if len(first) > limit or len(second) > limit:
                return None, "file grew beyond the read boundary"
            stable = _metadata_token(opened, include_content_fields=True)
            if (
                _metadata_token(middle, include_content_fields=True) != stable
                or _metadata_token(final, include_content_fields=True) != stable
                or len(first) != int(opened.st_size)
            ):
                return None, "file metadata changed while content was read"
            if not hmac.compare_digest(first, second):
                return None, "file content changed between verification reads"
            path_after = os.lstat(path)
            if (
                _is_reparse_metadata(path_after)
                or _metadata_token(
                    path_after, include_content_fields=True) != stable
            ):
                return None, (
                    "file path or metadata changed after content verification")
            return first, ""
        finally:
            # A close failure is part of the same fail-closed read operation;
            # the outer handler converts it into unavailable evidence.
            os.close(descriptor)
    except (OSError, OverflowError):
        return None, "file metadata or content became unavailable"


class _CollectionGapSink:
    """Deterministic bounded gaps with a reserved overflow disclosure."""

    def __init__(self) -> None:
        self._rows: dict[tuple[str, str], dict[str, str]] = {}
        self._withheld = 0

    def add(self, reason: str, path: str = "") -> None:
        row = {
            "capability": "workspace-collection",
            "reason": _safe_text(reason, 512),
            "path": _safe_text(path, 1_024),
        }
        key = (row["reason"], row["path"])
        if key in self._rows:
            return
        capacity = max(0, MAX_GAPS - 1)
        if len(self._rows) < capacity:
            self._rows[key] = row
        else:
            self._withheld += 1

    def rows(self) -> list[dict[str, str]]:
        rows = sorted(
            self._rows.values(),
            key=lambda row: (row["path"].casefold(), row["path"], row["reason"]),
        )
        if self._withheld and MAX_GAPS > 0:
            rows.append({
                "capability": "workspace-collection",
                "reason": _safe_text(
                    f"{self._withheld} additional distinct collection gaps were "
                    "withheld by the gap output boundary",
                    512,
                ),
                "path": "",
            })
        return rows[:MAX_GAPS]


def collect_workspace_artifacts(
    root: str | os.PathLike[str],
) -> tuple[list[Artifact], list[dict[str, str]]]:
    """Read a deterministic, bounded snapshot without following filesystem links."""
    try:
        supplied = Path(os.fspath(root)).expanduser()
        supplied_metadata = os.lstat(supplied)
    except (TypeError, ValueError, OSError) as exc:
        raise SecurityPostureError("workspace root is unavailable") from exc
    if _is_reparse_metadata(supplied_metadata):
        raise SecurityPostureError("workspace root must not be a link or junction")
    if not stat.S_ISDIR(supplied_metadata.st_mode):
        raise SecurityPostureError("workspace root must be a directory")
    try:
        base = supplied.resolve(strict=True)
        base_metadata = os.lstat(base)
    except OSError as exc:
        raise SecurityPostureError("workspace root metadata is unavailable") from exc
    if (
        _is_reparse_metadata(base_metadata)
        or not stat.S_ISDIR(base_metadata.st_mode)
        or not all(_identity(base_metadata))
        or _identity(base_metadata) != _identity(supplied_metadata)
    ):
        raise SecurityPostureError("workspace root identity is not stable")
    base_device = int(base_metadata.st_dev)

    artifacts: list[Artifact] = []
    gaps = _CollectionGapSink()
    total = 0
    entries_seen = 0
    directories_scheduled = 1
    stack: list[tuple[Path, str, int]] = [(base, "", 0)]
    visited_directories: list[tuple[Path, str, tuple[int, ...]]] = []
    artifact_identities: set[str] = set()
    stop_all = False

    while stack and not stop_all:
        here, here_relative, depth = stack.pop()
        try:
            before = os.lstat(here)
        except OSError:
            gaps.add("directory metadata was unavailable", here_relative)
            continue
        if (
            _is_reparse_metadata(before)
            or not stat.S_ISDIR(before.st_mode)
            or int(before.st_dev) != base_device
            or not all(_identity(before))
            or not _resolved_without_link(base, here)
        ):
            gaps.add(
                "directory crossed a link, device, containment, or type boundary",
                here_relative,
            )
            continue

        remaining = MAX_DIRECTORY_ENTRIES - entries_seen
        if remaining <= 0:
            gaps.add("total directory-entry inspection boundary reached", here_relative)
            break
        # Reserve one entry from the remaining global budget as an overflow
        # sentinel.  If it is observed, this whole directory is discarded, so
        # the chosen subset never depends on OS enumeration order.
        usable = max(0, remaining - 1)
        local_capacity = min(MAX_ENTRIES_PER_DIRECTORY, usable)
        names: list[str] = []
        overflow = False
        listing_error = False
        try:
            with os.scandir(here) as iterator:
                for entry in iterator:
                    entries_seen += 1
                    if len(names) >= local_capacity:
                        overflow = True
                        break
                    names.append(entry.name)
        except OSError:
            listing_error = True
        if listing_error:
            gaps.add("directory entries became unavailable", here_relative)
            continue
        if overflow:
            if local_capacity == MAX_ENTRIES_PER_DIRECTORY:
                gaps.add(
                    "per-directory entry inspection boundary reached; directory omitted",
                    here_relative,
                )
            else:
                gaps.add(
                    "total directory-entry inspection boundary reached; directory omitted",
                    here_relative,
                )
                stop_all = True
            continue
        try:
            after_listing = os.lstat(here)
        except OSError:
            gaps.add("directory metadata became unavailable after listing", here_relative)
            continue
        directory_token = _metadata_token(before, include_content_fields=False)
        if (
            _is_reparse_metadata(after_listing)
            or _metadata_token(after_listing, include_content_fields=False)
            != directory_token
        ):
            gaps.add("directory changed while entries were listed", here_relative)
            continue
        visited_directories.append((here, here_relative, directory_token))

        names.sort(key=lambda value: (
            unicodedata.normalize("NFC", value).casefold(),
            unicodedata.normalize("NFC", value),
            value,
        ))
        children: list[tuple[Path, str, int]] = []
        for name in names:
            path = here / name
            relative_raw = f"{here_relative}/{name}" if here_relative else name
            relative = _safe_text(relative_raw.replace("\\", "/"), 1_024)
            if not relative or len(unicodedata.normalize("NFC", relative_raw)) > 1_024:
                gaps.add("path exceeded the portable collection boundary", relative)
                continue
            try:
                metadata = os.lstat(path)
            except OSError:
                gaps.add("entry metadata was unavailable", relative)
                continue
            if _is_reparse_metadata(metadata):
                gaps.add("linked, junction, or reparse entry was not followed", relative)
                continue
            if int(metadata.st_dev) != base_device:
                gaps.add("cross-device entry was not followed", relative)
                continue
            if not all(_identity(metadata)):
                gaps.add("entry identity metadata was unavailable", relative)
                continue
            if stat.S_ISDIR(metadata.st_mode):
                if name.casefold() in _SKIP_DIRECTORIES:
                    gaps.add("policy-excluded directory was not inspected", relative)
                    continue
                if depth + 1 > MAX_DIRECTORY_DEPTH:
                    gaps.add("maximum directory depth boundary reached", relative)
                    continue
                if directories_scheduled >= MAX_DIRECTORIES:
                    gaps.add("directory count boundary reached", relative)
                    continue
                if not _resolved_without_link(base, path):
                    gaps.add("directory containment boundary was not satisfied", relative)
                    continue
                directories_scheduled += 1
                children.append((path, relative, depth + 1))
                continue
            if not stat.S_ISREG(metadata.st_mode):
                gaps.add("non-regular entry was not read", relative)
                continue
            if not _interesting_file(path):
                gaps.add(
                    "file type was outside the bounded workspace collection allowlist",
                    relative,
                )
                continue
            if not _resolved_without_link(base, path):
                gaps.add("file containment boundary was not satisfied", relative)
                continue
            identity = unicodedata.normalize("NFC", relative).casefold()
            if identity in artifact_identities:
                gaps.add("artifact path collided after portable normalization", relative)
                continue
            if len(artifacts) >= MAX_ARTIFACTS:
                gaps.add("artifact count boundary reached", relative)
                stop_all = True
                break
            text_candidate = (
                path.suffix.casefold() in _TEXT_SUFFIXES
                or path.name.casefold() in _SPECIAL_NAMES
            )
            limit = MAX_FILE_BYTES if text_candidate else MAX_BINARY_FILE_BYTES
            if metadata.st_size > limit:
                gaps.add("file exceeded the applicable byte boundary", relative)
                continue
            if total + int(metadata.st_size) > MAX_TOTAL_INPUT_BYTES:
                gaps.add("total input byte boundary reached", relative)
                stop_all = True
                break
            data, problem = _read_verified_regular_file(
                path, metadata, base_device, limit)
            if data is None:
                gaps.add(problem, relative)
                continue
            if total + len(data) > MAX_TOTAL_INPUT_BYTES:
                gaps.add("total input byte boundary reached after verified read", relative)
                stop_all = True
                break
            total += len(data)
            artifact_identities.add(identity)
            executable = bool(
                metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
            artifacts.append(Artifact(
                relative, data, executable,
                "application/octet-stream" if _decode_text(data) is None else "text/plain",
            ))
        for child in reversed(children):
            stack.append(child)

    # A directory modified after its listing makes coverage partial even when
    # every collected file remained individually stable.
    for directory, relative, token in visited_directories:
        try:
            current = os.lstat(directory)
        except OSError:
            gaps.add("directory became unavailable before snapshot completion", relative)
            continue
        if (
            _is_reparse_metadata(current)
            or _metadata_token(current, include_content_fields=False) != token
        ):
            gaps.add("directory changed before snapshot completion", relative)

    artifacts.sort(key=lambda row: (
        unicodedata.normalize("NFC", row.path).casefold(), row.path))
    return artifacts, gaps.rows()


def scan_workspace(
    root: str | os.PathLike[str], *,
    history_evidence: Iterable[Mapping[str, Any]] = (),
    provenance_evidence: Iterable[Mapping[str, Any]] = (),
    private_namespaces: Iterable[str] = (),
) -> dict[str, Any]:
    artifacts, gaps = collect_workspace_artifacts(root)
    return scan_security_posture(
        artifacts,
        history_evidence=history_evidence,
        provenance_evidence=provenance_evidence,
        private_namespaces=private_namespaces,
        collection_gaps=gaps,
    )


def analyze(
    root: str | os.PathLike[str], *, staged_diff: str = "",
    history_export: str = "",
) -> dict[str, Any]:
    """Compatibility entry point for Attestor's 4.1.3 security orchestration.

    The optional staged diff is scanned as caller-supplied text and is never
    applied. ``history_export`` must be a JSON array of the metadata-only
    records accepted by :func:`scan_security_posture`; unstructured history
    containing source lines or secret values is intentionally rejected.
    """
    if not isinstance(staged_diff, str) or not isinstance(history_export, str):
        raise SecurityPostureError("staged diff and history export must be text")
    if len(staged_diff.encode("utf-8")) > MAX_FILE_BYTES:
        raise SecurityPostureError("staged diff exceeds byte boundary")
    if len(history_export.encode("utf-8")) > MAX_METADATA_BYTES:
        raise SecurityPostureError("history export exceeds metadata byte boundary")
    artifacts, gaps = collect_workspace_artifacts(root)
    if staged_diff:
        artifacts.append(Artifact(
            "__attestor_supplied__/staged.diff", staged_diff, False, "text/x-diff",
        ))
    history: Iterable[Mapping[str, Any]] = ()
    if history_export:
        parsed = _load_json(history_export, "history export")
        if type(parsed) is dict and set(parsed) == {"events"}:
            parsed = parsed["events"]
        if type(parsed) is not list:
            raise SecurityPostureError("history export must be a metadata event array")
        history = parsed
    return scan_security_posture(
        artifacts, history_evidence=history, collection_gaps=gaps,
    )


def verify_report(report: Any) -> bool:
    """Verify the exact report contract, budgets, privacy flags, and digest."""
    try:
        expected = {
            "schema", "version", "status", "summary", "findings", "sbom",
            "cloud_iac", "supply_chain", "provenance", "secret_lifecycle",
            "secret_history", "crypto", "binary", "coverage", "gaps", "scope",
            "privacy", "execution", "report_sha256",
        }
        if (
            type(report) is not dict or set(report) != expected
            or report.get("schema") != SCHEMA or report.get("version") != VERSION
            or report.get("status") not in {"complete", "partial"}
            or type(report.get("findings")) is not list
            or len(report["findings"]) > MAX_FINDINGS
            or type(report.get("gaps")) is not list or len(report["gaps"]) > MAX_GAPS
            or report["status"] != ("partial" if report["gaps"] else "complete")
            or type(report.get("binary")) is not dict
            or type(report["binary"].get("artifacts")) is not list
            or len(report["binary"]["artifacts"]) > MAX_ARTIFACTS
            or report.get("privacy") != {
                "raw_secret_values": False,
                "secret_hashes": False,
                "secret_prefixes_or_suffixes": False,
                "terminal_controls_escaped": True,
            }
            or report.get("execution") != {
                "target_code_executed": False,
                "network_accessed": False,
                "files_written": False,
                "git_invoked": False,
                "binary_mode": "metadata-and-bounded-printable-strings-only",
            }
        ):
            return False
        for gap in report["gaps"]:
            if (
                type(gap) is not dict
                or set(gap) != {"capability", "reason", "path", "evidence_state"}
                or gap.get("evidence_state") != "unavailable"
                or any(not isinstance(gap.get(field), str)
                       for field in ("capability", "reason", "path"))
                or len(gap["capability"]) > 96 or len(gap["reason"]) > 512
                or len(gap["path"]) > 1_024
            ):
                return False
        for row in report["findings"]:
            keys = {
                "rule_id", "severity", "category", "path", "line", "message",
                "remediation", "evidence_state", "source_kind", "finding_id",
            }
            if (
                type(row) is not dict or set(row) != keys
                or row["severity"] not in _SEVERITY_ORDER
                or row["evidence_state"] not in _EVIDENCE_STATES
                or type(row["line"]) is not int
                or not 1 <= row["line"] <= 2_147_483_647
                or any(not isinstance(row[field], str) for field in keys - {"line"})
            ):
                return False
            expected_id = "sec413-" + _sha([
                row["rule_id"], row["path"].casefold(), row["line"], row["source_kind"],
            ])[:24]
            if not hmac.compare_digest(row["finding_id"], expected_id):
                return False
        if report.get("summary") != _summary(report["findings"]):
            return False
        scope = report.get("scope")
        exact_limits = {
            "max_artifacts": MAX_ARTIFACTS,
            "max_file_bytes": MAX_FILE_BYTES,
            "max_binary_file_bytes": MAX_BINARY_FILE_BYTES,
            "max_total_input_bytes": MAX_TOTAL_INPUT_BYTES,
            "max_findings": MAX_FINDINGS,
            "max_components": MAX_COMPONENTS,
            "max_output_bytes": MAX_OUTPUT_BYTES,
            "max_directory_entries": MAX_DIRECTORY_ENTRIES,
            "max_entries_per_directory": MAX_ENTRIES_PER_DIRECTORY,
            "max_directory_depth": MAX_DIRECTORY_DEPTH,
            "max_directories": MAX_DIRECTORIES,
        }
        if (
            type(scope) is not dict
            or set(scope) != {"artifact_count", "input_bytes", "limits"}
            or type(scope["artifact_count"]) is not int
            or not 0 <= scope["artifact_count"] <= MAX_ARTIFACTS
            or type(scope["input_bytes"]) is not int
            or not 0 <= scope["input_bytes"] <= MAX_TOTAL_INPUT_BYTES
            or scope["limits"] != exact_limits
        ):
            return False
        coverage = report.get("coverage")
        if (
            type(coverage) is not dict
            or set(coverage) != {
                "artifact_kinds", "artifacts_considered", "input_bytes_considered",
                "gap_count", "complete", "evidence_state",
            }
            or type(coverage["artifact_kinds"]) is not dict
            or any(not isinstance(key, str) or type(count) is not int or count < 0
                   for key, count in coverage["artifact_kinds"].items())
            or sum(coverage["artifact_kinds"].values()) != scope["artifact_count"]
            or coverage["artifacts_considered"] != scope["artifact_count"]
            or coverage["input_bytes_considered"] != scope["input_bytes"]
            or coverage["gap_count"] != len(report["gaps"])
            or coverage["complete"] is not (not report["gaps"])
            or coverage["evidence_state"] != (
                "proven" if not report["gaps"] else "unavailable"
            )
        ):
            return False
        expected_cloud = _finding_section(
            report["findings"],
            {"container", "kubernetes", "terraform", "ci-cd", "identity"},
            mode="bounded-static-configuration",
            rule_prefixes=("IAC-", "CI-", "IAM-"),
        )
        expected_cloud["artifacts_considered"] = sum(
            coverage["artifact_kinds"].get(kind, 0)
            for kind in ("docker", "kubernetes", "terraform", "github-actions")
        )
        if report.get("cloud_iac") != expected_cloud:
            return False
        if report.get("crypto") != _finding_section(
            report["findings"], {"crypto"}, mode="bounded-static-text",
        ):
            return False
        sbom = report.get("sbom")
        if (
            type(sbom) is not dict or sbom.get("schema") != SBOM_SCHEMA
            or set(sbom) != {
                "schema", "component_count", "components", "spdx",
                "cyclonedx", "generation",
            }
            or type(sbom.get("components")) is not list
            or len(sbom["components"]) > MAX_COMPONENTS
            or sbom.get("component_count") != len(sbom["components"])
            or type(sbom.get("spdx")) is not dict
            or type(sbom.get("cyclonedx")) is not dict
            or len(sbom["spdx"].get("packages", [])) != len(sbom["components"])
            or len(sbom["cyclonedx"].get("components", [])) != len(sbom["components"])
        ):
            return False
        reconstructed: list[_Component] = []
        for component in sbom["components"]:
            if (
                type(component) is not dict
                or set(component) != {
                    "bom_ref", "ecosystem", "name", "version", "scope",
                    "source", "purl", "evidence_state",
                }
                or component.get("evidence_state") not in _EVIDENCE_STATES
                or any(not isinstance(component.get(field), str) for field in (
                    "bom_ref", "ecosystem", "name", "version", "scope",
                    "source", "purl",
                ))
            ):
                return False
            reconstructed.append(_Component(
                component["ecosystem"], component["name"], component["version"],
                component["scope"], component["source"], component["evidence_state"],
            ))
        if _build_sbom(reconstructed) != sbom:
            return False
        supply = report.get("supply_chain")
        if (
            type(supply) is not dict
            or set(supply) != {"lockfile_drift", "dependency_confusion_analysis"}
            or type(supply["lockfile_drift"]) is not dict
            or set(supply["lockfile_drift"]) != {
                "state", "declared_count", "locked_count", "missing_count",
                "version_mismatch_count", "evidence_state",
            }
            or supply["lockfile_drift"]["state"] not in {
                "complete", "partial", "unavailable",
            }
            or supply["lockfile_drift"]["evidence_state"] not in _EVIDENCE_STATES
            or any(
                type(supply["lockfile_drift"][field]) is not int
                or supply["lockfile_drift"][field] < 0
                for field in (
                    "declared_count", "locked_count", "missing_count",
                    "version_mismatch_count",
                )
            )
            or supply["dependency_confusion_analysis"] != {
                "mode": "offline-indicators-only",
                "registry_queried": False,
                "private_namespace_count":
                    supply["dependency_confusion_analysis"].get("private_namespace_count"),
                "evidence_state": "inferred",
            }
            or type(supply["dependency_confusion_analysis"]["private_namespace_count"]) is not int
            or not 0 <= supply["dependency_confusion_analysis"]["private_namespace_count"] <= 128
        ):
            return False
        provenance = report.get("provenance")
        if (
            type(provenance) is not dict
            or set(provenance) != {
                "state", "records", "record_count",
                "verification_performed_by_attestor", "evidence_state",
            }
            or provenance["state"] not in {"unavailable", "verified", "partial"}
            or type(provenance["records"]) is not list
            or len(provenance["records"]) > MAX_PROVENANCE_RECORDS
            or provenance["record_count"] != len(provenance["records"])
            or provenance["verification_performed_by_attestor"] is not False
            or provenance["evidence_state"] not in {"inferred", "unavailable"}
        ):
            return False
        for record in provenance["records"]:
            if (
                type(record) is not dict
                or set(record) != {
                    "subject_path", "subject_sha256", "digest_matches_snapshot",
                    "state", "signature_verified", "provenance_verified", "signer",
                    "source", "evidence_state",
                }
                or not isinstance(record["subject_path"], str)
                or not isinstance(record["subject_sha256"], str)
                or not _HEX64.fullmatch(record["subject_sha256"])
                or type(record["digest_matches_snapshot"]) is not bool
                or record["state"] not in {
                    "unavailable", "digest-mismatch", "reported-verified",
                    "reported-unverified",
                }
                or (
                    record["signature_verified"] is not None
                    and type(record["signature_verified"]) is not bool
                )
                or (
                    record["provenance_verified"] is not None
                    and type(record["provenance_verified"]) is not bool
                )
                or not isinstance(record["signer"], str)
                or not isinstance(record["source"], str)
                or record["evidence_state"] not in _EVIDENCE_STATES
            ):
                return False
        lifecycle = report.get("secret_lifecycle")
        if (
            type(lifecycle) is not dict
            or set(lifecycle) != {
                "current_snapshot_match_count", "raw_values", "value_hashes",
                "prefixes_or_suffixes",
            }
            or type(lifecycle["current_snapshot_match_count"]) is not int
            or lifecycle["current_snapshot_match_count"] < 0
            or lifecycle["raw_values"] is not False
            or lifecycle["value_hashes"] is not False
            or lifecycle["prefixes_or_suffixes"] is not False
        ):
            return False
        history = report.get("secret_history")
        if (
            type(history) is not dict
            or set(history) != {
                "state", "event_count", "events", "raw_values", "value_hashes",
                "git_invoked", "evidence_state",
            }
            or history["state"] not in {"available", "unavailable"}
            or type(history.get("events")) is not list
            or history.get("event_count") != len(history["events"])
            or history.get("raw_values") is not False
            or history.get("value_hashes") is not False
            or history.get("git_invoked") is not False
            or len(history.get("events", [])) > MAX_HISTORY_EVENTS
            or history.get("evidence_state") not in {"inferred", "unavailable"}
        ):
            return False
        for event in history["events"]:
            if (
                type(event) is not dict
                or set(event) != {
                    "path", "line", "rule_id", "severity", "removed",
                    "rotation_verified", "revocation_verified",
                    "raw_value_present", "value_hash_present", "evidence_state",
                }
                or not isinstance(event["path"], str)
                or type(event["line"]) is not int
                or not 1 <= event["line"] <= 2_147_483_647
                or not isinstance(event["rule_id"], str)
                or event["severity"] not in _SEVERITY_ORDER
                or any(type(event[field]) is not bool for field in (
                    "removed", "rotation_verified", "revocation_verified",
                ))
                or event["raw_value_present"] is not False
                or event["value_hash_present"] is not False
                or event["evidence_state"] != "inferred"
            ):
                return False
        binary = report.get("binary")
        if (
            set(binary) != {
                "mode", "artifact_count", "artifacts", "finding_count",
                "target_code_executed",
            }
            or binary["mode"] != "metadata-and-bounded-printable-strings-only"
            or binary["artifact_count"] != len(binary["artifacts"])
            or binary["finding_count"] != sum(
                1 for row in report["findings"]
                if row["category"] in {"binary", "backdoor-indicator"}
            )
            or binary["target_code_executed"] is not False
        ):
            return False
        for artifact in binary["artifacts"]:
            if (
                type(artifact) is not dict
                or set(artifact) != {
                    "path", "size", "format", "executable", "sample_entropy",
                    "strings_considered", "analysis", "evidence_state",
                }
                or not isinstance(artifact["path"], str)
                or type(artifact["size"]) is not int
                or not 0 <= artifact["size"] <= MAX_BINARY_FILE_BYTES
                or artifact["format"] not in {"pe", "elf", "mach-o", "unknown"}
                or type(artifact["executable"]) is not bool
                or type(artifact["sample_entropy"]) not in {int, float}
                or not 0.0 <= artifact["sample_entropy"] <= 8.0
                or type(artifact["strings_considered"]) is not int
                or not 0 <= artifact["strings_considered"] <= MAX_BINARY_STRINGS
                or artifact["analysis"] != "metadata-and-bounded-printable-strings-only"
                or artifact["evidence_state"] != "proven"
            ):
                return False
        if _contains_unsafe_controls(report) or _contains_raw_secret(report):
            return False
        digest = report.get("report_sha256")
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            return False
        body = {key: value for key, value in report.items() if key != "report_sha256"}
        canonical = _canonical(body)
        return bool(
            len(canonical) <= MAX_OUTPUT_BYTES
            and hmac.compare_digest(digest, hashlib.sha256(canonical).hexdigest())
        )
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, SecurityPostureError):
        return False


__all__ = [
    "Artifact", "SecurityPostureError", "VERSION", "SCHEMA", "SBOM_SCHEMA",
    "scan_security_posture", "collect_workspace_artifacts", "scan_workspace",
    "analyze", "verify_report",
]
