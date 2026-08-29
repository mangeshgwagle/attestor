#!/usr/bin/env python3
"""Bounded secret-lifecycle inspection for Attestor 4.1.3.

Inputs are caller-supplied local material.  Findings never contain a secret,
secret prefix/suffix, reversible encoding, or a hash of secret material.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import io
import json
import math
import os
import re
import subprocess
import sys
import tarfile
import zipfile
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


VERSION = "4.1.3"
SCHEMA = "attestor.secret-lifecycle/4.1"
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_FINDINGS = 10_000
MAX_EXPORT_BYTES = 32 * 1024 * 1024
MAX_INPUT_ARTIFACTS = 1_000
_TEXT_SUFFIXES = frozenset({
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs", ".cs",
    ".c", ".h", ".cpp", ".hpp", ".rb", ".php", ".sh", ".ps1", ".yaml",
    ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".env", ".xml",
    ".properties", ".txt", ".md", ".sql", ".gradle", ".lock",
})
_SKIP = frozenset({".git", ".hg", ".svn", "node_modules", ".venv", "venv",
                   "target", "dist", "build", "__pycache__"})
_PLACEHOLDERS = re.compile(r"(?i)^(?:example|sample|dummy|test|changeme|replace[_-]?me|"
                           r"redacted|your[_-].*|x+|\*+|<[^>]+>)$")
_PATTERNS = (
    ("private-key", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("aws-access-key", "high", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("github-token", "high", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,255}\b")),
    ("gitlab-token", "high", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,255}\b")),
    ("stripe-live-key", "high", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,255}\b")),
    ("jwt", "medium", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
)
_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|client[_-]?secret|auth)\b"
    r"\s*(?:=|:|=>)\s*(?:"
    r"(?P<quote>['\"])(?P<quoted>[^'\"\r\n]{12,512})(?P=quote)|"
    r"(?P<bare>[^\s'\",;}{()\[\]]{12,512})(?=\s*(?:$|#|[,;}]))"
    r")"
)
_OPAQUE_COMPONENT = re.compile(r"[A-Za-z0-9_+=.-]{20,}")
_SOURCE_KIND = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")


class SecretLifecycleError(ValueError):
    pass


@dataclass(frozen=True)
class SecretFinding:
    rule_id: str
    severity: str
    source_kind: str
    path: str
    line: int
    evidence: str
    value_exposed: bool = False
    value_hashed: bool = False


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value))
                for count in counts.values())


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _location(path: str) -> str:
    """Bound a location without allowing a credential-shaped filename to leak."""
    value = re.sub(r"[\x00-\x1f\x7f]", "?", str(path))
    for _rule_id, _severity, pattern in _PATTERNS:
        value = pattern.sub("<redacted-secret>", value)

    def redact_component(match: re.Match[str]) -> str:
        candidate = match.group(0)
        # Long opaque path components are not necessary evidence.  Withhold
        # instead of hashing or exposing a prefix/suffix.
        if _entropy(candidate) >= 3.5:
            return "<redacted-opaque-component>"
        return candidate

    value = _OPAQUE_COMPONENT.sub(redact_component, value)
    pieces = re.split(r"([/\\])", value)
    for index, piece in enumerate(pieces):
        if (piece not in {"/", "\\"} and "<redacted-" not in piece and
                len(piece) >= 16 and not any(char.isspace() for char in piece) and
                _entropy(piece) >= 3.5):
            pieces[index] = "<redacted-opaque-component>"
    return "".join(pieces)[:1_024]


def _source(value: str) -> str:
    return value if isinstance(value, str) and _SOURCE_KIND.fullmatch(value) else "caller-supplied"


def _bounded_export(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise SecretLifecycleError(label + " must be text")
    if len(value.encode("utf-8", "replace")) > MAX_EXPORT_BYTES:
        raise SecretLifecycleError(label + " exceeds byte boundary")
    return value


def scan_text(text: str, *, source_kind: str, path: str,
              line_offset: int = 0) -> list[SecretFinding]:
    if not isinstance(text, str):
        raise SecretLifecycleError("scan input must be text")
    if len(text.encode("utf-8", "replace")) > MAX_FILE_BYTES:
        raise SecretLifecycleError("scan input exceeds byte boundary")
    findings: list[SecretFinding] = []
    safe_source = _source(source_kind)
    safe_path = _location(path)
    for line_number, line in enumerate(text.splitlines(), 1 + line_offset):
        for rule_id, severity, pattern in _PATTERNS:
            if pattern.search(line):
                findings.append(SecretFinding(rule_id, severity, safe_source,
                                               safe_path, line_number,
                                               "secret-shaped material matched; value withheld"))
        for match in _ASSIGNMENT.finditer(line):
            candidate = match.group("quoted") or match.group("bare") or ""
            if (_PLACEHOLDERS.fullmatch(candidate) or
                    (len(set(candidate)) < 5) or _entropy(candidate) < 3.0):
                continue
            findings.append(SecretFinding("generic-high-entropy-secret", "high", safe_source,
                                           safe_path, line_number,
                                           "credential assignment matched; value withheld"))
        if len(findings) >= MAX_FINDINGS:
            break
    # De-duplicate without using secret material in the key.
    unique = {(item.rule_id, item.source_kind, item.path, item.line): item for item in findings}
    return sorted(unique.values(), key=lambda item: (item.path, item.line, item.rule_id))


def scan_staged_diff(diff: str) -> list[SecretFinding]:
    """Scan only added lines from a caller-supplied staged unified diff."""
    diff = _bounded_export(diff, "staged diff")
    current = "<staged-diff>"; target_line = 0; findings: list[SecretFinding] = []
    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            current = raw[4:].removeprefix("b/")[:1_024]
        elif raw.startswith("@@"):
            match = re.search(r"\+(\d+)", raw)
            target_line = int(match.group(1)) - 1 if match else target_line
        elif raw.startswith("+") and not raw.startswith("+++"):
            target_line += 1
            findings.extend(scan_text(raw[1:], source_kind="staged-diff", path=current,
                                      line_offset=target_line - 1))
        elif not raw.startswith("-"):
            target_line += 1
        if len(findings) >= MAX_FINDINGS: break
    return findings[:MAX_FINDINGS]


def scan_history_export(export: str) -> list[SecretFinding]:
    """Scan a supplied patch/history export without invoking Git."""
    export = _bounded_export(export, "history export")
    return [SecretFinding(item.rule_id, item.severity, "git-history-export", item.path,
                          item.line, item.evidence)
            for item in scan_staged_diff(export)]


def _decode(data: bytes) -> str | None:
    if b"\x00" in data[:8_192]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeError:
        return None


def scan_notebook_bytes(data: bytes, path: str) -> list[SecretFinding]:
    if len(data) > MAX_FILE_BYTES:
        raise SecretLifecycleError("notebook exceeds byte boundary")
    try:
        notebook = json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SecretLifecycleError("notebook cannot be parsed") from exc
    findings: list[SecretFinding] = []
    cells = notebook.get("cells") if type(notebook) is dict else None
    if type(cells) is not list:
        raise SecretLifecycleError("notebook has no cells array")
    for index, cell in enumerate(cells[:10_000]):
        if type(cell) is not dict: continue
        source = cell.get("source", "")
        source_text = ("".join(item for item in source if isinstance(item, str))
                       if type(source) is list else source if isinstance(source, str) else "")
        findings.extend(scan_text(source_text, source_kind="notebook-cell",
                                  path=f"{path}#cell/{index}"))
        for output_index, output in enumerate(cell.get("outputs", [])):
            if type(output) is not dict: continue
            pieces: list[str] = []
            for key in ("text", "data", "ename", "evalue", "traceback"):
                value = output.get(key)
                if isinstance(value, str): pieces.append(value)
                elif type(value) is list: pieces.extend(str(item) for item in value)
                elif type(value) is dict:
                    try: pieces.append(json.dumps(value, sort_keys=True))
                    except (TypeError, ValueError, RecursionError): continue
            findings.extend(scan_text("\n".join(pieces), source_kind="notebook-output",
                                      path=f"{path}#cell/{index}/output/{output_index}"))
        if len(findings) >= MAX_FINDINGS: break
    return findings[:MAX_FINDINGS]


def _safe_member(name: str) -> bool:
    pure = PurePosixPath(name.replace("\\", "/"))
    return bool(name and not pure.is_absolute() and ".." not in pure.parts and
                not re.match(r"^[A-Za-z]:", name))


def scan_archive(path: str | os.PathLike[str], *, source_kind: str = "safe-archive") -> tuple[list[SecretFinding], list[str]]:
    supplied = Path(path).expanduser()
    if supplied.is_symlink():
        raise SecretLifecycleError("archive is linked, non-regular, or exceeds boundary")
    archive = supplied.resolve(strict=True)
    if not archive.is_file() or archive.stat().st_size > MAX_FILE_BYTES:
        raise SecretLifecycleError("archive is linked, non-regular, or exceeds boundary")
    findings: list[SecretFinding] = []; gaps: list[str] = []; total = 0; members = 0

    def count_member() -> None:
        nonlocal members
        members += 1
        if members > MAX_ARCHIVE_MEMBERS:
            raise SecretLifecycleError("expanded archive exceeds member/byte boundary")

    def inspect(name: str, data: bytes) -> None:
        nonlocal total
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise SecretLifecycleError("expanded archive exceeds member/byte boundary")
        if not _safe_member(name):
            gaps.append("unsafe archive member rejected")
            return
        virtual = _location(archive.name + "!/" + name)
        if name.lower().endswith(".ipynb"):
            try: findings.extend(scan_notebook_bytes(data, virtual))
            except SecretLifecycleError: gaps.append(_location(virtual) + ": invalid notebook")
        else:
            text = _decode(data)
            if text is not None:
                findings.extend(scan_text(text, source_kind=source_kind, path=virtual))

    try:
        if zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as handle:
                entries = handle.infolist()
                if len(entries) > MAX_ARCHIVE_MEMBERS:
                    raise SecretLifecycleError(
                        "expanded archive exceeds member/byte boundary")
                for info in entries:
                    count_member()
                    if not _safe_member(info.filename):
                        gaps.append("unsafe archive member rejected"); continue
                    mode = (info.external_attr >> 16) & 0o170000
                    if info.is_dir(): continue
                    if mode == 0o120000 or info.flag_bits & 1:
                        gaps.append("linked/encrypted ZIP member rejected"); continue
                    if info.file_size > MAX_FILE_BYTES or (info.compress_size and info.file_size / info.compress_size > 200):
                        gaps.append("ZIP member exceeded size/ratio boundary"); continue
                    with handle.open(info, "r") as stream:
                        data = stream.read(MAX_FILE_BYTES + 1)
                    if len(data) > MAX_FILE_BYTES:
                        gaps.append("ZIP member exceeded read boundary"); continue
                    inspect(info.filename, data)
        elif tarfile.is_tarfile(archive):
            with tarfile.open(archive, mode="r:*") as handle:
                for info in handle:
                    count_member()
                    if not _safe_member(info.name):
                        gaps.append("unsafe archive member rejected"); continue
                    if not info.isfile():
                        if info.issym() or info.islnk(): gaps.append("linked TAR member rejected")
                        continue
                    if info.size > MAX_FILE_BYTES:
                        gaps.append("TAR member exceeded size boundary"); continue
                    stream = handle.extractfile(info)
                    if stream is not None:
                        data = stream.read(MAX_FILE_BYTES + 1)
                        if len(data) > MAX_FILE_BYTES:
                            gaps.append("TAR member exceeded read boundary"); continue
                        inspect(info.name, data)
        else:
            raise SecretLifecycleError("unsupported archive format")
    except (OSError, zipfile.BadZipFile, tarfile.TarError, RuntimeError) as exc:
        raise SecretLifecycleError("archive cannot be inspected safely") from exc
    return findings[:MAX_FINDINGS], sorted(set(gaps))


def scan_oci_layer_tar(path: str | os.PathLike[str]) -> tuple[list[SecretFinding], list[str]]:
    """Inspect a caller-supplied OCI layer tar; whiteouts and links are never followed."""
    supplied = Path(path).expanduser()
    if supplied.is_symlink():
        raise SecretLifecycleError("OCI layer must be a regular local tar")
    target = supplied.resolve(strict=True)
    if (not target.is_file() or not tarfile.is_tarfile(target) or
            zipfile.is_zipfile(target)):
        raise SecretLifecycleError("OCI layer must be a regular local tar")
    findings, gaps = scan_archive(target, source_kind="oci-layer")
    return findings, gaps


def scan_workspace(root: str | os.PathLike[str]) -> dict[str, Any]:
    supplied = Path(root).expanduser()
    if supplied.is_symlink(): raise SecretLifecycleError("workspace must be a real directory")
    base = supplied.resolve(strict=True)
    if not base.is_dir(): raise SecretLifecycleError("workspace must be a directory")
    findings: list[SecretFinding] = []; gaps: list[str] = []; files = 0; total = 0
    stop = False
    for current, directories, names in os.walk(base, topdown=True, followlinks=False):
        here = Path(current)
        directories[:] = sorted(
            (name for name in directories
             if name not in _SKIP and not (here / name).is_symlink()),
            key=str.casefold)
        for name in sorted(names, key=str.casefold):
            path = here / name
            try:
                relative = path.relative_to(base)
                if path.is_symlink() or not path.is_file(): continue
                files += 1
                if files > 100_000: raise SecretLifecycleError("workspace file boundary exceeded")
                size = path.stat().st_size; total += size
                if size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                    gaps.append(_location(relative.as_posix()) + ": byte boundary exceeded"); continue
                data = path.read_bytes()
                if path.suffix.lower() == ".ipynb":
                    findings.extend(scan_notebook_bytes(data, relative.as_posix()))
                elif path.suffix.lower() in _TEXT_SUFFIXES or path.name.lower().startswith(".env"):
                    text = _decode(data)
                    if text is not None:
                        findings.extend(scan_text(text, source_kind="workspace",
                                                  path=relative.as_posix()))
            except (OSError, SecretLifecycleError) as exc:
                gaps.append(_location(str(path)) + ": " + str(exc))
            if len(findings) >= MAX_FINDINGS:
                stop = True; break
        if stop: break
    return _report(findings, gaps, {"workspace": _location(str(base)),
                                    "files_considered": files})


def _report(findings: Iterable[SecretFinding], gaps: Iterable[str], scope: dict[str, Any]) -> dict[str, Any]:
    rows = [asdict(item) for item in findings][:MAX_FINDINGS]
    gap_rows = [_location(item) for item in gaps]
    report = {"schema": SCHEMA, "version": VERSION,
              "status": "partial" if gap_rows else "complete",
              "findings": rows, "finding_count": len(rows),
              "gaps": sorted(set(gap_rows))[:1_000],
              "scope": scope, "privacy": {"raw_values": False, "secret_hashes": False,
                                          "prefixes_or_suffixes": False},
              "execution": {"target_code": False, "network": False, "git_invoked": False}}
    report["report_sha256"] = hashlib.sha256(_canonical(report)).hexdigest()
    return report


def _contains_raw_secret(value: Any) -> bool:
    """Conservatively reject recognizable secret material anywhere in a report."""
    pending = [value]
    visited = 0
    while pending:
        current = pending.pop()
        visited += 1
        if visited > 250_000:
            return True
        if isinstance(current, str):
            if any(pattern.search(current) for _rule, _severity, pattern in _PATTERNS):
                return True
            for match in _ASSIGNMENT.finditer(current):
                candidate = match.group("quoted") or match.group("bare") or ""
                if (not _PLACEHOLDERS.fullmatch(candidate) and
                        len(set(candidate)) >= 5 and _entropy(candidate) >= 3.0):
                    return True
        elif type(current) is dict:
            pending.extend(current.keys()); pending.extend(current.values())
        elif type(current) in {list, tuple}:
            pending.extend(current)
    return False


def verify_report(report: Any) -> bool:
    """Verify report integrity and the non-disclosure contract."""
    try:
        expected_keys = {"schema", "version", "status", "findings", "finding_count",
                         "gaps", "scope", "privacy", "execution", "report_sha256"}
        allowed_rules = {rule: severity for rule, severity, _pattern in _PATTERNS}
        allowed_rules["generic-high-entropy-secret"] = "high"
        allowed_evidence = {
            "secret-shaped material matched; value withheld",
            "credential assignment matched; value withheld",
        }
        if (type(report) is not dict or report.get("schema") != SCHEMA or
                set(report) != expected_keys or
                report.get("version") != VERSION or
                report.get("status") not in {"complete", "partial"} or
                type(report.get("findings")) is not list or
                len(report["findings"]) > MAX_FINDINGS or
                report.get("finding_count") != len(report["findings"]) or
                type(report.get("gaps")) is not list or len(report["gaps"]) > 1_000 or
                any(not isinstance(gap, str) or len(gap) > 1_024 for gap in report["gaps"]) or
                report.get("status") != ("partial" if report["gaps"] else "complete") or
                type(report.get("scope")) is not dict or
                report.get("privacy") != {"raw_values": False, "secret_hashes": False,
                                          "prefixes_or_suffixes": False} or
                report.get("execution") != {"target_code": False, "network": False,
                                             "git_invoked": False}):
            return False
        for row in report["findings"]:
            if (type(row) is not dict or set(row) != {
                    "rule_id", "severity", "source_kind", "path", "line", "evidence",
                    "value_exposed", "value_hashed"} or
                    row.get("rule_id") not in allowed_rules or
                    row.get("severity") != allowed_rules.get(row.get("rule_id")) or
                    not isinstance(row.get("source_kind"), str) or
                    _source(row["source_kind"]) != row["source_kind"] or
                    not isinstance(row.get("path"), str) or len(row["path"]) > 1_024 or
                    type(row.get("line")) is not int or not 1 <= row["line"] <= 2_147_483_647 or
                    row.get("evidence") not in allowed_evidence or
                    row.get("value_exposed") is not False or
                    row.get("value_hashed") is not False):
                return False
        if _contains_raw_secret(report):
            return False
        digest = report.get("report_sha256")
        body = {key: value for key, value in report.items() if key != "report_sha256"}
        canonical = _canonical(body)
        return bool(len(canonical) <= MAX_TOTAL_BYTES and isinstance(digest, str) and
                    re.fullmatch(r"[0-9a-f]{64}", digest) and
                    hmac.compare_digest(digest, hashlib.sha256(canonical).hexdigest()))
    except (TypeError, ValueError, OverflowError, RecursionError):
        return False


def scan_lifecycle(*, root: str | os.PathLike[str] | None = None,
                   staged_diff: str = "", history_export: str = "",
                   archives: Iterable[str | os.PathLike[str]] = (),
                   oci_layers: Iterable[str | os.PathLike[str]] = ()) -> dict[str, Any]:
    findings: list[SecretFinding] = []; gaps: list[str] = []; sources = []
    if root is not None:
        workspace = scan_workspace(root); sources.append("workspace")
        findings.extend(SecretFinding(**row) for row in workspace["findings"]); gaps.extend(workspace["gaps"])
    if staged_diff:
        sources.append("staged-diff"); findings.extend(scan_staged_diff(staged_diff))
    if history_export:
        sources.append("git-history-export"); findings.extend(scan_history_export(history_export))
    for index, archive in enumerate(archives):
        if index >= MAX_INPUT_ARTIFACTS:
            raise SecretLifecycleError("archive input count exceeds boundary")
        sources.append("archive"); found, missed = scan_archive(archive); findings.extend(found); gaps.extend(missed)
    for index, layer in enumerate(oci_layers):
        if index >= MAX_INPUT_ARTIFACTS:
            raise SecretLifecycleError("OCI layer input count exceeds boundary")
        sources.append("oci-layer"); found, missed = scan_oci_layer_tar(layer); findings.extend(found); gaps.extend(missed)
    unique = {(item.rule_id, item.source_kind, item.path, item.line): item for item in findings}
    return _report(sorted(unique.values(), key=lambda item: (item.path, item.line, item.rule_id)),
                   gaps, {"sources": sorted(set(sources))})


def scan_hostile_file_out_of_process(path: str | os.PathLike[str], timeout: float = 10.0) -> dict[str, Any]:
    """Scan an untrusted local artifact in an isolated Python child process.

    The worker uses isolated-mode Python, a minimal environment, no shell, a
    bounded timeout/output, and only Attestor's parser code.  It never imports or
    executes the target artifact.
    """
    supplied = Path(path).expanduser()
    if supplied.is_symlink():
        raise SecretLifecycleError("out-of-process scanner refuses linked artifacts")
    target = supplied.resolve(strict=True)
    if not target.is_file() or target.stat().st_size > MAX_FILE_BYTES:
        raise SecretLifecycleError("out-of-process artifact exceeds the file boundary")
    environment = {key: value for key, value in os.environ.items()
                   if key in {"SystemRoot", "WINDIR", "TEMP", "TMP", "PATH", "PATHEXT"}}
    try:
        result = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()),
                                 "--worker", str(target)], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, shell=False,
                                timeout=max(0.1, min(float(timeout), 30.0)),
                                env=environment, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise SecretLifecycleError("out-of-process scanner failed") from exc
    if result.returncode != 0 or len(result.stdout) > 8 * 1024 * 1024:
        raise SecretLifecycleError("out-of-process scanner rejected the artifact")
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SecretLifecycleError("out-of-process scanner returned invalid evidence") from exc
    if not verify_report(report):
        raise SecretLifecycleError("out-of-process scanner returned invalid evidence")
    return report


def _worker(path: Path) -> dict[str, Any]:
    if path.suffix.lower() == ".ipynb":
        findings = scan_notebook_bytes(path.read_bytes(), path.name); gaps = []
    elif zipfile.is_zipfile(path) or tarfile.is_tarfile(path):
        findings, gaps = scan_archive(path)
    else:
        data = path.read_bytes()
        if len(data) > MAX_FILE_BYTES: raise SecretLifecycleError("file exceeds byte boundary")
        text = _decode(data); findings = scan_text(text or "", source_kind="hostile-file", path=path.name); gaps = []
    return _report(findings, gaps, {"out_of_process": True, "file": _location(path.name)})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--worker")
    args = parser.parse_args(argv)
    if not args.worker: return 2
    try:
        print(json.dumps(_worker(Path(args.worker)), sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, SecretLifecycleError):
        return 3


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["SecretLifecycleError", "scan_archive", "scan_history_export",
           "scan_hostile_file_out_of_process", "scan_lifecycle", "scan_notebook_bytes",
           "scan_oci_layer_tar", "scan_staged_diff", "scan_text", "scan_workspace",
           "verify_report"]
