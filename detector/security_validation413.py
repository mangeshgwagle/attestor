#!/usr/bin/env python3
"""Permission, verification, regression, and evidence controls for Attestor 4.1.3.

This module is deliberately defensive.  It can describe container-isolated
validation work, bind a one-use authorization to an exact project/plan/patch,
track proof gates, and create bounded fuzz/property/differential plans.  It
does not silently execute a target, grant itself permission, enable network
access, or apply source changes.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
from typing import Any, Callable, Iterable, Mapping, Sequence


SCHEMA = "attestor-security-validation/4.1"
VERSION = "4.1.3"
AUTH_SCHEMA = "attestor-one-use-authorization/4.1"
PIPELINE_SCHEMA = "attestor-verified-repair/4.1"
MEMORY_SCHEMA = "attestor-security-regression-memory/4.1"
LEDGER_SCHEMA = "attestor-evidence-claim-ledger/4.1"
COMMAND_CENTER_SCHEMA = "attestor-security-command-center/4.1"

MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_FILES = 20_000
MAX_ENTRIES = 80_000
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_COMMANDS = 32
MAX_ARGUMENTS = 128
MAX_ARGUMENT_BYTES = 4_096
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 1_800
MAX_FUZZ_PLANS = 256
MAX_REGRESSION_RUNS = 128
MAX_CLAIMS = 4_000
MAX_FINDINGS = 20_000
SHA256_RE = re.compile(r"[0-9a-f]{64}")
IMAGE_RE = re.compile(
    r"[a-z0-9][a-z0-9._/-]{0,190}@sha256:[0-9a-f]{64}", re.ASCII)
SAFE_EXECUTABLES = frozenset({
    "python", "python3", "pytest", "node", "npm", "npx", "pnpm", "yarn",
    "dotnet", "java", "mvn", "mvnw", "gradle", "gradlew", "go", "cargo",
    "rustc", "make", "cmake", "ctest", "gcc", "clang", "php", "ruby",
})
CLAIM_STATES = frozenset({"proven", "inferred", "unverified", "unavailable"})
GATE_ORDER = ("static-scan", "build", "test", "security-rescan")
AUTH_PURPOSES = frozenset({
    "sandbox-execution", "repair-apply", "case-minimization",
})
_BIDI = frozenset(chr(value) for value in (
    0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2066, 0x2067, 0x2068, 0x2069,
))
_WINDOWS_DEVICES = frozenset({
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
})


class ValidationError(ValueError):
    """A validation or authorization boundary failed closed."""


def _preflight_json(value: Any) -> None:
    """Reject oversized/deep JSON shapes before ``json.dumps`` allocates them."""
    pending: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    estimated = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > 300_000 or depth > 128:
            raise ValidationError("value exceeds the JSON structure boundary")
        if isinstance(current, str):
            if len(current) > MAX_JSON_BYTES:
                raise ValidationError("value exceeds the JSON boundary")
            estimated += len(current.encode("utf-8"))
        elif current is None or type(current) is bool:
            estimated += 5
        elif type(current) is int:
            estimated += max(
                1, (abs(current).bit_length() * 30_103) // 100_000 + 2)
        elif type(current) is float:
            if not math.isfinite(current):
                raise ValidationError("value contains a non-finite number")
            estimated += 32
        elif type(current) in {list, tuple}:
            if len(current) > MAX_ENTRIES:
                raise ValidationError("value exceeds the JSON collection boundary")
            estimated += len(current) + 2
            pending.extend((item, depth + 1) for item in current)
        elif type(current) is dict:
            if len(current) > MAX_ENTRIES:
                raise ValidationError("value exceeds the JSON collection boundary")
            estimated += len(current) + 2
            for key, item in current.items():
                if not isinstance(key, str):
                    raise ValidationError("JSON object keys must be text")
                if len(key) > MAX_JSON_BYTES:
                    raise ValidationError("JSON object key exceeds the boundary")
                estimated += len(key.encode("utf-8")) + 3
                pending.append((item, depth + 1))
        else:
            raise ValidationError("value contains a non-JSON type")
        if estimated > MAX_JSON_BYTES:
            raise ValidationError("value exceeds the JSON boundary")


def _canonical(value: Any) -> bytes:
    _preflight_json(value)
    try:
        raw = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ValidationError("value is not bounded deterministic JSON") from exc
    if len(raw) > MAX_JSON_BYTES:
        raise ValidationError("value exceeds the JSON boundary")
    return raw


def _sha(value: Any) -> str:
    raw = value if isinstance(value, bytes) else _canonical(value)
    return hashlib.sha256(raw).hexdigest()


def _report(body: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(body)
    value["report_sha256"] = _sha(value)
    return value


def verify_report(report: Any, *, schema: str = SCHEMA) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if type(report) is not dict:
        return False, ["report is not an exact object"]
    if report.get("schema") != schema or report.get("version") != VERSION:
        errors.append("report schema or version is invalid")
    claimed = report.get("report_sha256")
    if not isinstance(claimed, str) or not SHA256_RE.fullmatch(claimed):
        errors.append("report digest is invalid")
    else:
        body = {key: value for key, value in report.items()
                if key != "report_sha256"}
        try:
            actual = _sha(body)
        except ValidationError:
            errors.append("report is not bounded deterministic JSON")
        else:
            if not hmac.compare_digest(claimed, actual):
                errors.append("report digest does not match")
    if not errors:
        try:
            errors.extend(_validate_schema_shape(report, schema))
        except (KeyError, TypeError, ValueError, OverflowError,
                RecursionError, ValidationError):
            errors.append("report shape validation failed closed")
    return not errors, errors


def safe_text(value: Any, maximum: int = 1_000) -> str:
    """Return display-safe bounded text without raw terminal/bidi controls."""
    if type(maximum) is not int or maximum < 0:
        raise ValidationError("text boundary is invalid")
    output: list[str] = []
    used = 0
    for character in str(value or ""):
        code = ord(character)
        token = (f"\\u{code:04x}" if
                 code < 0x20 or 0x7F <= code <= 0x9F or character in _BIDI
                 else character)
        encoded = len(token.encode("utf-8"))
        if used + encoded > maximum:
            break
        output.append(token)
        used += encoded
    return "".join(output)


def _exact_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ValidationError(label + " must be a lowercase SHA-256 digest")
    return value


def _bounded_values(values: Iterable[Any], maximum: int, label: str) -> list[Any]:
    rows: list[Any] = []
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise ValidationError(label + " is not iterable") from exc
    for item in iterator:
        if len(rows) >= maximum:
            raise ValidationError(label + " exceeds the count boundary")
        rows.append(item)
    return rows


def _is_link_or_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return True
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(info.st_mode) or bool(
        int(getattr(info, "st_file_attributes", 0)) & reparse)


def _real_root(value: str | os.PathLike[str]) -> Path:
    supplied = Path(value).expanduser()
    try:
        lexical = supplied if supplied.is_absolute() else Path.cwd() / supplied
        current = Path(lexical.anchor)
        for part in lexical.parts[1:]:
            if part in {"", "."}:
                continue
            current = current.parent if part == ".." else current / part
            if _is_link_or_reparse(current):
                raise ValidationError("project root traverses a link or reparse point")
        root = lexical.resolve(strict=True)
    except ValidationError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ValidationError("project root is unavailable") from exc
    if not root.is_dir() or _is_link_or_reparse(root):
        raise ValidationError("project root must be a real directory")
    return root


def _safe_relative(path: str) -> bool:
    if not isinstance(path, str) or not path or path.startswith(("/", "\\")):
        return False
    if "\\" in path:
        return False
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return False
    for part in parts:
        if any(ord(character) < 32 or ord(character) == 127
               for character in part):
            return False
        if any(character in '<>:"|?*' for character in part):
            return False
        if part.endswith((" ", ".")):
            return False
        if part.split(".", 1)[0].rstrip(" .").upper() in _WINDOWS_DEVICES:
            return False
    return True


def tree_manifest(root: str | os.PathLike[str]) -> dict[str, Any]:
    """Hash a bounded regular-file tree and reject links and unsafe names."""
    base = _real_root(root)
    rows: list[dict[str, Any]] = []
    total = 0
    try:
        base_device = base.stat().st_dev
    except OSError as exc:
        raise ValidationError("project root metadata is unavailable") from exc
    seen: dict[str, str] = {}
    stack = [base]
    entries_seen = 0
    candidates: list[tuple[Path, str, os.stat_result]] = []
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as stream:
                entries = []
                for entry in stream:
                    entries_seen += 1
                    if entries_seen > MAX_ENTRIES:
                        raise ValidationError(
                            "project exceeds the traversal-entry boundary")
                    entries.append(entry)
        except ValidationError:
            raise
        except OSError as exc:
            raise ValidationError("project traversal failed") from exc
        entries.sort(key=lambda entry: entry.name.casefold())
        child_directories: list[Path] = []
        for entry in entries:
            item = Path(entry.path)
            relative = item.relative_to(base).as_posix()
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise ValidationError("project entry became unreadable") from exc
            reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
            if (stat.S_ISLNK(info.st_mode) or
                    int(getattr(info, "st_file_attributes", 0)) & reparse):
                raise ValidationError("project contains a link or reparse point")
            if info.st_dev and base_device and info.st_dev != base_device:
                raise ValidationError("project crosses a filesystem boundary")
            if not _safe_relative(relative):
                raise ValidationError("project contains an unsafe portable path")
            folded = relative.casefold()
            if folded in seen:
                raise ValidationError("project contains case-colliding paths")
            seen[folded] = relative
            if stat.S_ISDIR(info.st_mode):
                child_directories.append(item)
            elif stat.S_ISREG(info.st_mode):
                candidates.append((item, relative, info))
                if len(candidates) > MAX_FILES:
                    raise ValidationError("project exceeds the file-count boundary")
            else:
                raise ValidationError("project contains a non-regular entry")
        stack.extend(reversed(child_directories))
    candidates.sort(key=lambda row: row[1].casefold())
    for item, relative, observed in candidates:
        if len(rows) >= MAX_FILES:
            raise ValidationError("project exceeds the file-count boundary")
        try:
            if (not item.resolve(strict=True).is_relative_to(base) or
                    _is_link_or_reparse(item)):
                raise ValidationError("project file crossed the root boundary")
            before = item.stat()
            if before.st_dev != base_device:
                raise ValidationError("project file crosses a filesystem boundary")
            # Windows DirEntry.stat may expose zero device/inode values while
            # Path.stat returns the real file identity.  Compare portable
            # metadata here, then use the stronger before/after identity below.
            if ((stat.S_IFMT(before.st_mode), before.st_size, before.st_mtime_ns) !=
                    (stat.S_IFMT(observed.st_mode), observed.st_size,
                     observed.st_mtime_ns)):
                raise ValidationError("project changed before manifest capture")
            if before.st_size > MAX_FILE_BYTES:
                raise ValidationError("project file exceeds the byte boundary")
            digest = hashlib.sha256()
            size = 0
            flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
            flags |= int(getattr(os, "O_NOFOLLOW", 0))
            descriptor = os.open(item, flags)
            try:
                opened = os.fstat(descriptor)
                if (not stat.S_ISREG(opened.st_mode) or
                        (opened.st_dev, opened.st_ino) !=
                        (before.st_dev, before.st_ino)):
                    raise ValidationError(
                        "project file identity changed before reading")
                while True:
                    block = os.read(descriptor, 128 * 1024)
                    if not block:
                        break
                    size += len(block)
                    if size > MAX_FILE_BYTES or total + size > MAX_TOTAL_BYTES:
                        raise ValidationError("project exceeds the byte boundary")
                    digest.update(block)
            finally:
                os.close(descriptor)
            after = item.stat()
        except ValidationError:
            raise
        except OSError as exc:
            raise ValidationError("project file became unreadable") from exc
        identity_before = (before.st_dev, before.st_ino, before.st_size,
                           before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size,
                          after.st_mtime_ns)
        if identity_before != identity_after or size != before.st_size:
            raise ValidationError("project changed during manifest capture")
        total += size
        rows.append({"path": relative, "bytes": size,
                     "sha256": digest.hexdigest()})
    body = {
        "schema": "attestor-project-manifest/4.1",
        "version": VERSION,
        "root_identity_sha256": _sha(
            os.path.normcase(str(base)).encode("utf-8", "surrogatepass")),
        "files": rows,
        "file_count": len(rows),
        "bytes": total,
        "content_sha256": _sha({
            "files": rows, "file_count": len(rows), "bytes": total,
        }),
    }
    return _report(body)


def _validate_argv(command: Any) -> list[str]:
    if (not isinstance(command, Sequence) or isinstance(command, (str, bytes)) or
            not 1 <= len(command) <= MAX_ARGUMENTS):
        raise ValidationError("sandbox command must be a bounded argument list")
    argv: list[str] = []
    for argument in command:
        if not isinstance(argument, str):
            raise ValidationError("sandbox arguments must be text")
        encoded = argument.encode("utf-8")
        if not encoded or len(encoded) > MAX_ARGUMENT_BYTES:
            raise ValidationError("sandbox argument exceeds its byte boundary")
        if any(
                ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F
                or character in _BIDI for character in argument):
            raise ValidationError("sandbox argument contains a control token")
        argv.append(argument)
    if ("/" in argv[0] or "\\" in argv[0] or
            Path(argv[0]).name.casefold() != argv[0].casefold()):
        raise ValidationError("sandbox executable must be an allowlisted bare name")
    executable = Path(argv[0]).name.casefold()
    if executable.endswith(".exe"):
        executable = executable[:-4]
    if executable not in SAFE_EXECUTABLES:
        raise ValidationError("sandbox executable is not allowlisted")
    return argv


_KNOWN_REPORT_SCHEMAS = frozenset({
    SCHEMA, AUTH_SCHEMA, PIPELINE_SCHEMA, MEMORY_SCHEMA, LEDGER_SCHEMA,
    COMMAND_CENTER_SCHEMA, "attestor-project-manifest/4.1",
    "attestor-security-sandbox-plan/4.1",
    "attestor-authorization-consumption/4.1",
    "attestor-security-sandbox-authorization/4.1",
    "attestor-one-use-security-lab-result/4.1",
    "attestor-security-test-plans/4.1",
    "attestor-case-minimization-plan/4.1",
    "attestor-observed-case-minimization/4.1",
    "attestor-repair-apply-authorization/4.1",
    "attestor-security-regression-comparison/4.1",
})


def _validate_schema_shape(report: Mapping[str, Any], schema: str) -> list[str]:
    """Validate exact generated-report shapes after digest verification."""
    errors: list[str] = []
    if schema not in _KNOWN_REPORT_SCHEMAS:
        return ["report schema is not allowlisted"]

    def exact(keys: set[str]) -> bool:
        if set(report) != keys | {"report_sha256"}:
            errors.append("report object shape is invalid for its schema")
            return False
        return True

    if schema == "attestor-project-manifest/4.1":
        if not exact({
                "schema", "version", "root_identity_sha256", "content_sha256",
                "files", "file_count", "bytes"}):
            return errors
        files = report.get("files")
        if (not isinstance(files, list) or len(files) > MAX_FILES or
                report.get("file_count") != len(files) or
                type(report.get("bytes")) is not int or report["bytes"] < 0 or
                report["bytes"] > MAX_TOTAL_BYTES):
            return errors + ["project manifest boundaries are invalid"]
        previous = ""
        total = 0
        seen: set[str] = set()
        for row in files:
            if (type(row) is not dict or set(row) != {"path", "bytes", "sha256"} or
                    not _safe_relative(row.get("path")) or
                    type(row.get("bytes")) is not int or
                    not 0 <= row["bytes"] <= MAX_FILE_BYTES or
                    not isinstance(row.get("sha256"), str) or
                    not SHA256_RE.fullmatch(row["sha256"])):
                return errors + ["project manifest file row is invalid"]
            folded = row["path"].casefold()
            if folded in seen or folded < previous:
                return errors + ["project manifest paths are not unique and ordered"]
            seen.add(folded)
            previous = folded
            total += row["bytes"]
        if total != report["bytes"]:
            errors.append("project manifest byte total is inconsistent")
        for field in ("root_identity_sha256", "content_sha256"):
            if (not isinstance(report.get(field), str) or
                    not SHA256_RE.fullmatch(report[field])):
                errors.append("project manifest digest field is invalid")
        expected_content = _sha({
            "files": files, "file_count": len(files), "bytes": total,
        })
        if (isinstance(report.get("content_sha256"), str) and
                not hmac.compare_digest(report["content_sha256"], expected_content)):
            errors.append("project manifest content digest is inconsistent")
        return errors

    if schema == "attestor-security-sandbox-plan/4.1":
        if not exact({
                "schema", "version", "status", "project_manifest_sha256",
                "project_root_identity_sha256", "project_content_sha256",
                "patch_sha256", "commands", "container", "limits",
                "authorization", "execution", "project_manifest"}):
            return errors
        if report.get("status") != "planned-not-authorized":
            errors.append("sandbox plan status is not default deny")
        project = report.get("project_manifest")
        if type(project) is not dict:
            errors.append("sandbox project manifest is missing")
        else:
            valid, nested = verify_report(
                project, schema="attestor-project-manifest/4.1")
            if not valid:
                errors.append("sandbox project manifest is invalid: " + ", ".join(nested))
            elif (report.get("project_manifest_sha256") != project["report_sha256"] or
                    report.get("project_root_identity_sha256") !=
                    project["root_identity_sha256"] or
                    report.get("project_content_sha256") != project["content_sha256"]):
                errors.append("sandbox project bindings are inconsistent")
        for field in (
                "project_manifest_sha256", "project_root_identity_sha256",
                "project_content_sha256", "patch_sha256"):
            if (not isinstance(report.get(field), str) or
                    not SHA256_RE.fullmatch(report[field])):
                errors.append("sandbox digest binding is invalid")
        commands = report.get("commands")
        if not isinstance(commands, list) or not 1 <= len(commands) <= MAX_COMMANDS:
            errors.append("sandbox command collection is invalid")
        else:
            try:
                for command in commands:
                    _validate_argv(command)
            except ValidationError as exc:
                errors.append(str(exc))
        container = report.get("container")
        if (type(container) is not dict or set(container) != {
                "image", "ephemeral", "network", "capabilities",
                "no_new_privileges", "host_fallback", "workspace"} or
                not isinstance(container.get("image"), str) or
                not IMAGE_RE.fullmatch(container["image"]) or
                {key: container.get(key) for key in container if key != "image"} != {
                    "ephemeral": True, "network": "none",
                    "capabilities": "drop-all", "no_new_privileges": True,
                    "host_fallback": False, "workspace": "disposable-copy",
                }):
            errors.append("sandbox container boundary is invalid")
        limits = report.get("limits")
        if (type(limits) is not dict or set(limits) != {
                "timeout_seconds", "output_bytes", "memory_mib", "cpu_count",
                "pids"} or
                type(limits.get("timeout_seconds")) is not int or
                not 1 <= limits["timeout_seconds"] <= MAX_TIMEOUT_SECONDS or
                type(limits.get("output_bytes")) is not int or
                not 1 <= limits["output_bytes"] <= MAX_OUTPUT_BYTES or
                type(limits.get("memory_mib")) is not int or
                not 128 <= limits["memory_mib"] <= 32_768 or
                isinstance(limits.get("cpu_count"), bool) or
                not isinstance(limits.get("cpu_count"), (int, float)) or
                not math.isfinite(float(limits["cpu_count"])) or
                not 0.25 <= float(limits["cpu_count"]) <= 32 or
                type(limits.get("pids")) is not int or
                not 16 <= limits["pids"] <= 4_096):
            errors.append("sandbox resource limits are invalid")
        if report.get("authorization") != {
                "required": True, "purpose": "sandbox-execution",
                "one_use": True, "plan_bound": True, "patch_bound": True}:
            errors.append("sandbox authorization policy is invalid")
        if report.get("execution") != {
                "target_executed": False, "network_accessed": False,
                "files_written": False}:
            errors.append("sandbox plan improperly claims execution")
        return errors

    if schema == PIPELINE_SCHEMA:
        if not exact({
                "schema", "version", "status", "proof_state",
                "root_identity_sha256", "patch_sha256", "baseline_sha256",
                "gates", "next_gate", "approval", "applied"}):
            return errors
        for field in ("root_identity_sha256", "patch_sha256", "baseline_sha256"):
            if (not isinstance(report.get(field), str) or
                    not SHA256_RE.fullmatch(report[field])):
                errors.append("repair pipeline digest binding is invalid")
        gates = report.get("gates")
        if not isinstance(gates, list) or len(gates) > len(GATE_ORDER):
            return errors + ["repair pipeline gates are invalid"]
        previous = report.get("patch_sha256")
        for index, row in enumerate(gates):
            if (type(row) is not dict or set(row) != {
                    "gate", "status", "input_sha256", "output_sha256",
                    "executed", "network_accessed", "summary",
                    "evidence_sha256", "evidence_state"} or
                    row.get("gate") != GATE_ORDER[index] or
                    row.get("status") != "passed" or
                    row.get("executed") is not True or
                    row.get("network_accessed") is not False or
                    row.get("evidence_state") != "unverified" or
                    row.get("input_sha256") != previous or
                    not isinstance(row.get("output_sha256"), str) or
                    not SHA256_RE.fullmatch(row["output_sha256"]) or
                    not isinstance(row.get("evidence_sha256"), str) or
                    not SHA256_RE.fullmatch(row["evidence_sha256"]) or
                    not isinstance(row.get("summary"), str)):
                return errors + ["repair pipeline gate chain is invalid"]
            previous = row["output_sha256"]
        expected_status = (
            "candidate" if not gates else
            "evidence-chain-complete" if len(gates) == len(GATE_ORDER)
            else "verification-in-progress")
        expected_next = "" if len(gates) == len(GATE_ORDER) else GATE_ORDER[len(gates)]
        if (report.get("status") != expected_status or
                report.get("next_gate") != expected_next or
                report.get("proof_state") != "unverified" or
                report.get("approval") != {
                    "required": True, "one_use": True, "patch_bound": True,
                    "proof_bound": True} or report.get("applied") is not False):
            errors.append("repair pipeline state is inconsistent")
        return errors

    if schema == MEMORY_SCHEMA:
        if not exact({
                "schema", "version", "project_namespace",
                "root_identity_sha256", "runs", "stores_source",
                "stores_secret_values"}):
            return errors
        root_digest = report.get("root_identity_sha256")
        if (not isinstance(root_digest, str) or
                not SHA256_RE.fullmatch(root_digest) or
                report.get("project_namespace") != project_namespace(root_digest) or
                report.get("stores_source") is not False or
                report.get("stores_secret_values") is not False):
            errors.append("security memory namespace or privacy policy is invalid")
        runs = report.get("runs")
        if not isinstance(runs, list) or len(runs) > MAX_REGRESSION_RUNS:
            return errors + ["security memory run boundary is invalid"]
        prior_time = -1
        reports: set[str] = set()
        for run in runs:
            if (type(run) is not dict or set(run) != {
                    "report_sha256", "observed_at", "finding_fingerprints",
                    "finding_count"} or
                    not isinstance(run.get("report_sha256"), str) or
                    not SHA256_RE.fullmatch(run["report_sha256"]) or
                    run["report_sha256"] in reports or
                    type(run.get("observed_at")) is not int or
                    run["observed_at"] <= prior_time or
                    not isinstance(run.get("finding_fingerprints"), list) or
                    len(run["finding_fingerprints"]) > MAX_FINDINGS or
                    run.get("finding_count") != len(run["finding_fingerprints"]) or
                    run["finding_fingerprints"] != sorted(set(
                        run["finding_fingerprints"])) or
                    any(not isinstance(value, str) or
                        not SHA256_RE.fullmatch(value)
                        for value in run["finding_fingerprints"])):
                return errors + ["security memory run is invalid or replayed"]
            reports.add(run["report_sha256"])
            prior_time = run["observed_at"]
        return errors

    if schema == LEDGER_SCHEMA:
        if not exact({
                "schema", "version", "claims", "claim_count", "counts",
                "verified_evidence_sha256", "verified_evidence_count", "proof_policy",
                "unsupported_claims_promoted"}):
            return errors
        claims = report.get("claims")
        verified_evidence = report.get("verified_evidence_sha256")
        if (not isinstance(claims, list) or len(claims) > MAX_CLAIMS or
                report.get("claim_count") != len(claims) or
                report.get("unsupported_claims_promoted") is not False or
                not isinstance(verified_evidence, list) or
                len(verified_evidence) > MAX_FINDINGS or
                verified_evidence != sorted(set(verified_evidence)) or
                any(not isinstance(value, str) or
                    not SHA256_RE.fullmatch(value)
                    for value in verified_evidence) or
                type(report.get("verified_evidence_count")) is not int or
                report["verified_evidence_count"] != len(verified_evidence) or
                report.get("proof_policy") !=
                "proven requires membership in the explicit verified-evidence set"):
            return errors + ["claim ledger boundary is invalid"]
        verified_set = set(verified_evidence)
        counts = {state: 0 for state in sorted(CLAIM_STATES)}
        for claim in claims:
            if (type(claim) is not dict or set(claim) != {
                    "claim_id", "text", "state", "evidence", "limitation"} or
                    claim.get("state") not in CLAIM_STATES or
                    not isinstance(claim.get("text"), str) or
                    not isinstance(claim.get("limitation"), str) or
                    not isinstance(claim.get("evidence"), list) or
                    len(claim["evidence"]) > 128):
                return errors + ["claim ledger row is invalid"]
            for evidence in claim["evidence"]:
                if (type(evidence) is not dict or set(evidence) != {
                        "kind", "locator", "sha256"} or
                        not isinstance(evidence.get("kind"), str) or
                        not isinstance(evidence.get("locator"), str) or
                        not isinstance(evidence.get("sha256"), str) or
                        not SHA256_RE.fullmatch(evidence["sha256"])):
                    return errors + ["claim evidence row is invalid"]
            expected_id = _sha({
                "text": claim["text"], "state": claim["state"],
                "evidence": claim["evidence"],
                "limitation": claim["limitation"]})[:24]
            if claim.get("claim_id") != expected_id:
                errors.append("claim identity digest is inconsistent")
            if claim["state"] == "proven" and not claim["evidence"]:
                errors.append("proven claim lacks evidence")
            if claim["state"] == "proven" and any(
                    evidence["sha256"] not in verified_set
                    for evidence in claim["evidence"]):
                errors.append(
                    "proven claim is not bound to verified evidence")
            counts[claim["state"]] += 1
        if report.get("counts") != counts:
            errors.append("claim ledger counts are inconsistent")
        return errors

    if schema == "attestor-security-regression-comparison/4.1":
        if not exact({
                "schema", "version", "project_namespace", "status", "new",
                "resolved", "unchanged", "cross_project_comparison"}):
            return errors
        if (report.get("status") not in {"compared", "baseline-only"} or
                report.get("cross_project_comparison") is not False):
            errors.append("security regression comparison state is invalid")
        for field in ("new", "resolved", "unchanged"):
            values = report.get(field)
            if (not isinstance(values, list) or len(values) > MAX_FINDINGS or
                    values != sorted(set(values)) or
                    any(not isinstance(value, str) or
                        not SHA256_RE.fullmatch(value) for value in values)):
                errors.append("security regression comparison values are invalid")
        return errors

    if schema == COMMAND_CENTER_SCHEMA:
        if not exact({
                "schema", "version", "status", "metrics", "top_findings",
                "attack_paths", "coverage_gaps", "repair_status",
                "repair_proof_state", "regression_status", "source_reports",
                "automatic_apply", "permission_retained",
                "raw_secret_values_present"}):
            return errors
        metrics = report.get("metrics")
        if (type(metrics) is not dict or set(metrics) != {
                "findings", "severity", "attack_paths", "coverage_gaps",
                "claim_states"}):
            return errors + ["command-center metrics are invalid"]
        severity = metrics.get("severity")
        claims = metrics.get("claim_states")
        if (type(severity) is not dict or set(severity) != {
                "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} or
                any(type(value) is not int or value < 0
                    for value in severity.values()) or
                type(claims) is not dict or set(claims) != CLAIM_STATES or
                any(type(value) is not int or value < 0
                    for value in claims.values()) or
                any(type(metrics.get(field)) is not int or
                    not 0 <= metrics[field] <= max_value
                    for field, max_value in (
                        ("findings", MAX_FINDINGS),
                        ("attack_paths", 2_000),
                        ("coverage_gaps", 4_000)))):
            errors.append("command-center severity or claim counts are invalid")
        top = report.get("top_findings")
        paths = report.get("attack_paths")
        gaps = report.get("coverage_gaps")
        if (not isinstance(top, list) or len(top) > 100 or
                not isinstance(paths, list) or len(paths) > 200 or
                not isinstance(gaps, list) or len(gaps) > 1_000 or
                any(not isinstance(value, str) for value in gaps) or
                metrics.get("attack_paths") < len(paths) or
                metrics.get("coverage_gaps") < len(gaps) or
                metrics.get("findings") < len(top)):
            errors.append("command-center bounded collections are inconsistent")
        if isinstance(top, list):
            for row in top:
                if (type(row) is not dict or set(row) != {
                        "rule", "severity", "path", "line", "evidence_state"} or
                        not isinstance(row.get("rule"), str) or
                        row.get("severity") not in {
                            "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} or
                        not isinstance(row.get("path"), str) or
                        type(row.get("line")) is not int or
                        not 0 <= row["line"] <= 2_147_483_647 or
                        row.get("evidence_state") not in CLAIM_STATES):
                    errors.append("command-center top finding is invalid")
                    break
        if isinstance(paths, list):
            for row in paths:
                if (type(row) is not dict or set(row) != {
                        "id", "title", "exploitability", "evidence_state"} or
                        any(not isinstance(row.get(field), str)
                            for field in ("id", "title", "exploitability")) or
                        row.get("evidence_state") not in CLAIM_STATES):
                    errors.append("command-center attack path is invalid")
                    break
        if (report.get("automatic_apply") is not False or
                report.get("permission_retained") is not False or
                report.get("raw_secret_values_present") != "not-assessed" or
                type(report.get("source_reports")) is not dict or
                set(report["source_reports"]) != {
                    "repair_pipeline_integrity_verified",
                    "regression_integrity_verified",
                    "claim_ledger_integrity_verified"} or
                any(type(value) is not bool
                    for value in report["source_reports"].values())):
            errors.append("command-center authorization or provenance boundary is invalid")
        return errors

    # Remaining schemas are not consumed as authority by this module. Their
    # digest, schema/version, byte boundary, and exact known identity still
    # prevent an arbitrary schema from being accepted as one of Attestor's reports.
    if not isinstance(report.get("status", ""), str):
        errors.append("report status is invalid")
    return errors


def create_sandbox_plan(
        root: str | os.PathLike[str], commands: Sequence[Sequence[str]], *,
        patch_sha256: str, image: str, timeout_seconds: int = 600,
        output_bytes: int = MAX_OUTPUT_BYTES, memory_mib: int = 2_048,
        cpu_count: float = 2.0, pids_limit: int = 256) -> dict[str, Any]:
    """Create a non-executing, network-denied container validation plan."""
    project = tree_manifest(root)
    _exact_digest(patch_sha256, "patch digest")
    if not isinstance(commands, Sequence) or isinstance(commands, (str, bytes)):
        raise ValidationError("sandbox commands must be a sequence")
    if not 1 <= len(commands) <= MAX_COMMANDS:
        raise ValidationError("sandbox command count exceeds the boundary")
    checked = [_validate_argv(command) for command in commands]
    if not isinstance(image, str) or not IMAGE_RE.fullmatch(image):
        raise ValidationError("container image must be pinned by SHA-256")
    if (type(timeout_seconds) is not int or
            not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS):
        raise ValidationError("sandbox timeout is outside the boundary")
    if type(output_bytes) is not int or not 1 <= output_bytes <= MAX_OUTPUT_BYTES:
        raise ValidationError("sandbox output boundary is invalid")
    if type(memory_mib) is not int or not 128 <= memory_mib <= 32_768:
        raise ValidationError("sandbox memory boundary is invalid")
    if (isinstance(cpu_count, bool) or not isinstance(cpu_count, (int, float)) or
            not math.isfinite(float(cpu_count)) or not 0.25 <= float(cpu_count) <= 32):
        raise ValidationError("sandbox CPU boundary is invalid")
    if type(pids_limit) is not int or not 16 <= pids_limit <= 4_096:
        raise ValidationError("sandbox process boundary is invalid")
    body = {
        "schema": "attestor-security-sandbox-plan/4.1",
        "version": VERSION,
        "status": "planned-not-authorized",
        "project_manifest_sha256": project["report_sha256"],
        "project_root_identity_sha256": project["root_identity_sha256"],
        "project_content_sha256": project["content_sha256"],
        "patch_sha256": patch_sha256,
        "commands": checked,
        "container": {
            "image": image,
            "ephemeral": True,
            "network": "none",
            "capabilities": "drop-all",
            "no_new_privileges": True,
            "host_fallback": False,
            "workspace": "disposable-copy",
        },
        "limits": {
            "timeout_seconds": timeout_seconds,
            "output_bytes": output_bytes,
            "memory_mib": memory_mib,
            "cpu_count": float(cpu_count),
            "pids": pids_limit,
        },
        "authorization": {
            "required": True,
            "purpose": "sandbox-execution",
            "one_use": True,
            "plan_bound": True,
            "patch_bound": True,
        },
        "execution": {
            "target_executed": False,
            "network_accessed": False,
            "files_written": False,
        },
        "project_manifest": project,
    }
    return _report(body)


def container_invocations(
        plan: Mapping[str, Any], disposable_root: str | os.PathLike[str], *,
        runtime: str = "docker") -> list[list[str]]:
    """Return shell-free Docker/Podman invocations; this does not execute them."""
    ok, errors = verify_report(dict(plan), schema="attestor-security-sandbox-plan/4.1")
    if not ok:
        raise ValidationError("sandbox plan is invalid: " + ", ".join(errors))
    if runtime not in {"docker", "podman"}:
        raise ValidationError("container runtime is not allowlisted")
    root = _real_root(disposable_root)
    current = tree_manifest(root)
    if not hmac.compare_digest(
            str(plan.get("project_content_sha256", "")),
            current["content_sha256"]):
        raise ValidationError(
            "disposable workspace no longer matches the authorized plan content")
    rendered_root = str(root)
    if "," in rendered_root or any(
            ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F
            or character in _BIDI for character in rendered_root):
        raise ValidationError("disposable workspace path is unsafe for a mount argument")
    limits = plan.get("limits")
    container = plan.get("container")
    commands = plan.get("commands")
    if type(limits) is not dict or type(container) is not dict or type(commands) is not list:
        raise ValidationError("sandbox plan shape is invalid")
    image = container.get("image")
    if not isinstance(image, str) or not IMAGE_RE.fullmatch(image):
        raise ValidationError("sandbox image identity is invalid")
    rows: list[list[str]] = []
    for command in commands:
        argv = _validate_argv(command)
        rows.append([
            runtime, "run", "--rm", "--network=none", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--pids-limit",
            str(limits["pids"]), "--memory", f"{limits['memory_mib']}m",
            "--cpus", str(limits["cpu_count"]), "--mount",
            "type=bind,src=%s,dst=/workspace" % rendered_root,
            "--workdir", "/workspace", image, *argv,
        ])
    return rows


class ApprovalRegistry:
    """Issue and consume exact, expiring, one-use authorization envelopes."""

    def __init__(self, key: bytes, *, key_id: str = "local-session",
                 registry_id: str | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        if not isinstance(key, bytes) or not 32 <= len(key) <= 512:
            raise ValidationError("authorization key must contain 32 to 512 bytes")
        if not isinstance(key_id, str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", key_id):
            raise ValidationError("authorization key ID is invalid")
        if not callable(clock):
            raise ValidationError("authorization clock is invalid")
        identity = registry_id if registry_id is not None else secrets.token_hex(16)
        if not isinstance(identity, str) or not re.fullmatch(r"[0-9a-f]{32}", identity):
            raise ValidationError("authorization registry ID is invalid")
        self._key = key
        self._key_id = key_id
        self._registry_id = identity
        self._clock = clock
        self._used: set[str] = set()
        self._issued: set[str] = set()
        self._lock = threading.Lock()

    def issue(
            self, *, root_identity_sha256: str, patch_sha256: str,
            plan_sha256: str, purpose: str, confirmed: bool,
            ttl_seconds: int = 300, nonce: str | None = None) -> dict[str, Any]:
        if confirmed is not True:
            raise ValidationError("authorization requires an exact affirmative confirmation")
        root_digest = _exact_digest(root_identity_sha256, "root identity")
        patch_digest = _exact_digest(patch_sha256, "patch")
        plan_digest = _exact_digest(plan_sha256, "plan")
        if purpose not in AUTH_PURPOSES:
            raise ValidationError("authorization purpose is not allowlisted")
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 900:
            raise ValidationError("authorization lifetime is outside the boundary")
        token_nonce = nonce if nonce is not None else secrets.token_hex(24)
        if not isinstance(token_nonce, str) or not re.fullmatch(
                r"[0-9a-f]{48}", token_nonce):
            raise ValidationError("authorization nonce is invalid")
        clock_value = self._clock()
        if (isinstance(clock_value, bool) or
                not isinstance(clock_value, (int, float)) or
                not math.isfinite(float(clock_value)) or
                not 0 <= float(clock_value) <= 9_223_372_036_854_775_000):
            raise ValidationError("authorization clock returned an invalid time")
        issued = int(clock_value)
        payload = {
            "schema": AUTH_SCHEMA,
            "version": VERSION,
            "key_id": self._key_id,
            "registry_id": self._registry_id,
            "purpose": purpose,
            "root_identity_sha256": root_digest,
            "patch_sha256": patch_digest,
            "plan_sha256": plan_digest,
            "nonce": token_nonce,
            "issued_at": issued,
            "expires_at": issued + ttl_seconds,
            "one_use": True,
        }
        message = b"ATTESTOR-4.1.3-AUTHORIZATION\x00" + _canonical(payload)
        with self._lock:
            if token_nonce in self._issued or token_nonce in self._used:
                raise ValidationError(
                    "authorization nonce was already issued by this registry")
            self._issued.add(token_nonce)
        return {
            **payload,
            "hmac_sha256": hmac.new(
                self._key, message, hashlib.sha256).hexdigest(),
        }

    def consume(
            self, token: Mapping[str, Any], *, root_identity_sha256: str,
            patch_sha256: str, plan_sha256: str, purpose: str) -> dict[str, Any]:
        if type(token) is not dict or set(token) != {
                "schema", "version", "key_id", "registry_id", "purpose",
                "root_identity_sha256", "patch_sha256", "plan_sha256", "nonce",
                "issued_at", "expires_at", "one_use", "hmac_sha256"}:
            raise ValidationError("authorization envelope shape is invalid")
        expected = {
            "schema": AUTH_SCHEMA,
            "version": VERSION,
            "key_id": self._key_id,
            "registry_id": self._registry_id,
            "purpose": purpose,
            "root_identity_sha256": _exact_digest(
                root_identity_sha256, "root identity"),
            "patch_sha256": _exact_digest(patch_sha256, "patch"),
            "plan_sha256": _exact_digest(plan_sha256, "plan"),
            "nonce": token.get("nonce"),
            "issued_at": token.get("issued_at"),
            "expires_at": token.get("expires_at"),
            "one_use": True,
        }
        for key, value in expected.items():
            if token.get(key) != value:
                raise ValidationError("authorization is not bound to this operation")
        if (not isinstance(expected["nonce"], str) or
                not re.fullmatch(r"[0-9a-f]{48}", expected["nonce"])):
            raise ValidationError("authorization nonce is invalid")
        if (type(expected["issued_at"]) is not int or
                type(expected["expires_at"]) is not int or
                not expected["issued_at"] < expected["expires_at"] or
                expected["expires_at"] - expected["issued_at"] > 900):
            raise ValidationError("authorization time boundary is invalid")
        supplied = token.get("hmac_sha256")
        if not isinstance(supplied, str) or not SHA256_RE.fullmatch(supplied):
            raise ValidationError("authorization authenticator is invalid")
        message = b"ATTESTOR-4.1.3-AUTHORIZATION\x00" + _canonical(expected)
        actual = hmac.new(self._key, message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(supplied, actual):
            raise ValidationError("authorization authentication failed")
        if purpose not in AUTH_PURPOSES:
            raise ValidationError("authorization purpose is not allowlisted")
        clock_value = self._clock()
        if (isinstance(clock_value, bool) or
                not isinstance(clock_value, (int, float)) or
                not math.isfinite(float(clock_value))):
            raise ValidationError("authorization clock returned an invalid time")
        now = int(clock_value)
        if now < expected["issued_at"] - 5 or now >= expected["expires_at"]:
            raise ValidationError("authorization has expired or is not yet valid")
        nonce_value = str(expected["nonce"])
        with self._lock:
            if nonce_value not in self._issued:
                raise ValidationError(
                    "authorization was not issued by this live registry")
            if nonce_value in self._used:
                raise ValidationError("authorization has already been consumed")
            self._used.add(nonce_value)
        return _report({
            "schema": "attestor-authorization-consumption/4.1",
            "version": VERSION,
            "status": "authorized-once",
            "purpose": purpose,
            "root_identity_sha256": expected["root_identity_sha256"],
            "patch_sha256": expected["patch_sha256"],
            "plan_sha256": expected["plan_sha256"],
            "nonce_sha256": _sha(nonce_value.encode("ascii")),
            "consumed_at": now,
            "permission_retained": False,
        })


def authorize_sandbox(
        plan: Mapping[str, Any], registry: ApprovalRegistry,
        token: Mapping[str, Any], *,
        current_root: str | os.PathLike[str]) -> dict[str, Any]:
    ok, errors = verify_report(dict(plan), schema="attestor-security-sandbox-plan/4.1")
    if not ok:
        raise ValidationError("sandbox plan is invalid: " + ", ".join(errors))
    project = plan.get("project_manifest")
    if type(project) is not dict:
        raise ValidationError("sandbox project manifest is missing")
    current = tree_manifest(current_root)
    if (not hmac.compare_digest(
            current["root_identity_sha256"],
            str(plan.get("project_root_identity_sha256", ""))) or
            not hmac.compare_digest(
                current["content_sha256"],
                str(plan.get("project_content_sha256", "")))):
        raise ValidationError(
            "current workspace identity or content no longer matches the plan")
    consumption = registry.consume(
        token,
        root_identity_sha256=str(plan.get("project_root_identity_sha256", "")),
        patch_sha256=str(plan.get("patch_sha256", "")),
        plan_sha256=str(plan.get("report_sha256", "")),
        purpose="sandbox-execution",
    )
    return _report({
        "schema": "attestor-security-sandbox-authorization/4.1",
        "version": VERSION,
        "status": "authorized-once",
        "plan_sha256": plan["report_sha256"],
        "project_manifest_sha256": plan["project_manifest_sha256"],
        "current_manifest_sha256": current["report_sha256"],
        "workspace_revalidated": True,
        "authorization_consumption": consumption,
        "execution_started": False,
        "network_accessed": False,
    })


def execute_security_lab_once(
        lab: Any, plan: Any, registry: ApprovalRegistry,
        token: Mapping[str, Any]) -> dict[str, Any]:
    """Execute one existing Security Lab plan through a consumed approval.

    The authorization is bound to the exact workspace content and lab plan.
    The ordinary ``LabAuthorization`` object is created internally and is never
    returned, preventing callers from reusing it through this gateway.
    """
    import security_lab41

    if not isinstance(lab, security_lab41.SecurityLab):
        raise ValidationError("one-use lab gateway requires SecurityLab")
    if not isinstance(plan, security_lab41.LabPlan) or not lab.verify_plan(plan):
        raise ValidationError("security-lab plan is invalid")
    consumption = registry.consume(
        token,
        root_identity_sha256=plan.workspace_sha256,
        patch_sha256=plan.workspace_sha256,
        plan_sha256=plan.plan_sha256,
        purpose="sandbox-execution",
    )
    internal = security_lab41.LabAuthorization(
        granted=True,
        workspace_sha256=plan.workspace_sha256,
        experiments=(plan.experiment,),
        purpose="one-use Attestor 4.1.3 security validation",
        actor="one-use-authorization:" + consumption["nonce_sha256"][:16],
        plan_sha256=plan.plan_sha256,
    )
    result = lab.execute(plan, internal)
    return _report({
        "schema": "attestor-one-use-security-lab-result/4.1",
        "version": VERSION,
        "status": safe_text(result.get("status"), 120),
        "plan_sha256": plan.plan_sha256,
        "workspace_sha256": plan.workspace_sha256,
        "authorization_consumption": consumption,
        "lab_result": result,
        "permission_retained": False,
        "authorization_reusable": False,
    })


def generate_test_plans(
        entry_points: Iterable[Mapping[str, Any]],
        findings: Iterable[Mapping[str, Any]], *, maximum: int = 128) -> dict[str, Any]:
    """Generate bounded, non-payload fuzz/property/differential test plans."""
    if type(maximum) is not int or not 1 <= maximum <= MAX_FUZZ_PLANS:
        raise ValidationError("test-plan count boundary is invalid")
    entries = _bounded_values(entry_points, 4_000, "test-plan entry points")
    issues = _bounded_values(findings, MAX_FINDINGS, "test-plan findings")
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    truncated = False
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        entry_id = safe_text(entry.get("id") or entry.get("name"), 200)
        path = safe_text(entry.get("path"), 500)
        if not entry_id:
            continue
        for mode, oracle in (
                ("property", "declared invariants remain true"),
                ("boundary-fuzz", "no crash, timeout, or invariant violation"),
                ("differential", "old and candidate behavior differ only where declared"),
        ):
            key = (entry_id, mode)
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "plan_id": _sha({"entry": entry_id, "path": path, "mode": mode})[:24],
                "entry_point": entry_id,
                "path": path,
                "mode": mode,
                "generator": {
                    "kind": "typed-boundary-values",
                    "classes": ["empty", "minimum", "maximum", "unicode",
                                "duplicate-structure", "truncated-structure"],
                    "offensive_payloads": False,
                },
                "oracle": oracle,
                "execution": "requires separately authorized sandbox",
                "evidence_state": "inferred",
            })
            if len(rows) > maximum:
                truncated = True
                break
        if truncated:
            break
    rules = sorted({
        safe_text(row.get("rule") or row.get("rule_id"), 200)
        for row in issues if isinstance(row, Mapping)
        and (row.get("rule") or row.get("rule_id"))
    })
    body = {
        "schema": "attestor-security-test-plans/4.1",
        "version": VERSION,
        "status": "planned-not-executed",
        "plans": rows[:maximum],
        "plan_count": min(len(rows), maximum),
        "rules_considered": rules[:1_000],
        "coverage": {
            "complete": not truncated,
            "gaps": (["test plans were truncated by the count boundary"]
                     if truncated else []),
        },
        "execution": {
            "target_executed": False,
            "network_accessed": False,
            "files_written": False,
        },
    }
    return _report(body)


def create_minimization_plan(
        values: Sequence[Any], *, predicate_sha256: str,
        maximum_evaluations: int = 128) -> dict[str, Any]:
    if (not isinstance(values, Sequence) or isinstance(values, (str, bytes)) or
            len(values) > 10_000):
        raise ValidationError("observed case exceeds the element boundary")
    if type(maximum_evaluations) is not int or not 1 <= maximum_evaluations <= 1_024:
        raise ValidationError("minimization evaluation boundary is invalid")
    try:
        current = json.loads(_canonical(
            {"observed_values": list(values)}))["observed_values"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValidationError("observed case is not bounded JSON data") from exc
    return _report({
        "schema": "attestor-case-minimization-plan/4.1",
        "version": VERSION,
        "status": "planned-not-authorized",
        "case_sha256": _sha({"observed_values": current}),
        "predicate_sha256": _exact_digest(
            predicate_sha256, "failure predicate"),
        "maximum_evaluations": maximum_evaluations,
        "execution_started": False,
    })


def minimize_observed_case(
        values: Sequence[Any], still_fails: Callable[[Sequence[Any]], bool], *,
        registry: ApprovalRegistry, token: Mapping[str, Any],
        predicate_sha256: str, maximum_evaluations: int = 128) -> dict[str, Any]:
    """Bounded delta minimization over already-observed data.

    The callback may execute external logic, so a one-use authorization is
    consumed before the first evaluation. Attestor supplies no target executor.
    """
    if not isinstance(registry, ApprovalRegistry):
        raise ValidationError("case minimization requires an approval registry")
    if not callable(still_fails):
        raise ValidationError("failure predicate is invalid")
    try:
        current = json.loads(_canonical(
            {"observed_values": list(values)}))["observed_values"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValidationError("observed case is not bounded JSON data") from exc
    plan = create_minimization_plan(
        current, predicate_sha256=predicate_sha256,
        maximum_evaluations=maximum_evaluations,
    )
    case_sha256 = plan["case_sha256"]
    predicate_digest = plan["predicate_sha256"]
    plan_sha256 = plan["report_sha256"]
    consumption = registry.consume(
        token,
        root_identity_sha256=case_sha256,
        patch_sha256=predicate_digest,
        plan_sha256=plan_sha256,
        purpose="case-minimization",
    )
    evaluations = 0
    granularity = 2
    while len(current) >= 2 and evaluations < maximum_evaluations:
        chunk = max(1, math.ceil(len(current) / granularity))
        reduced = False
        for start in range(0, len(current), chunk):
            candidate = current[:start] + current[start + chunk:]
            evaluations += 1
            predicate_input = json.loads(_canonical(candidate))
            outcome = still_fails(predicate_input)
            if type(outcome) is not bool:
                raise ValidationError("failure predicate must return an exact boolean")
            if outcome is True:
                current = candidate
                granularity = max(2, granularity - 1)
                reduced = True
                break
            if evaluations >= maximum_evaluations:
                break
        if not reduced:
            if granularity >= len(current):
                break
            granularity = min(len(current), granularity * 2)
    return _report({
        "schema": "attestor-observed-case-minimization/4.1",
        "version": VERSION,
        "status": "completed" if evaluations < maximum_evaluations else "bounded",
        "original_elements": len(values),
        "minimized_elements": len(current),
        "evaluations": evaluations,
        "maximum_evaluations": maximum_evaluations,
        "minimized_case": current,
        "case_sha256": case_sha256,
        "predicate_sha256": predicate_digest,
        "plan_sha256": plan_sha256,
        "authorization_consumption": consumption,
        "permission_retained": False,
        "network_accessed_by_attestor": False,
    })


def new_repair_pipeline(
        *, root_identity_sha256: str, patch_sha256: str,
        baseline_sha256: str) -> dict[str, Any]:
    body = {
        "schema": PIPELINE_SCHEMA,
        "version": VERSION,
        "status": "candidate",
        "proof_state": "unverified",
        "root_identity_sha256": _exact_digest(
            root_identity_sha256, "root identity"),
        "patch_sha256": _exact_digest(patch_sha256, "patch"),
        "baseline_sha256": _exact_digest(baseline_sha256, "baseline"),
        "gates": [],
        "next_gate": GATE_ORDER[0],
        "approval": {
            "required": True,
            "one_use": True,
            "patch_bound": True,
            "proof_bound": True,
        },
        "applied": False,
    }
    return _report(body)


def record_repair_gate(
        pipeline: Mapping[str, Any], gate: str, evidence: Mapping[str, Any]
        ) -> dict[str, Any]:
    ok, errors = verify_report(dict(pipeline), schema=PIPELINE_SCHEMA)
    if not ok:
        raise ValidationError("repair pipeline is invalid: " + ", ".join(errors))
    gates = pipeline.get("gates")
    if type(gates) is not list or len(gates) >= len(GATE_ORDER):
        raise ValidationError("repair gate sequence is already complete")
    expected = GATE_ORDER[len(gates)]
    if gate != expected:
        raise ValidationError("repair gate is out of order")
    if type(evidence) is not dict or set(evidence) != {
            "status", "input_sha256", "output_sha256", "executed",
            "network_accessed", "summary"}:
        raise ValidationError("repair gate evidence shape is invalid")
    if evidence.get("status") != "passed":
        raise ValidationError("repair gate did not pass")
    input_digest = _exact_digest(evidence.get("input_sha256"), "gate input")
    output_digest = _exact_digest(evidence.get("output_sha256"), "gate output")
    if evidence.get("executed") is not True:
        raise ValidationError("repair gate lacks execution evidence")
    if not isinstance(evidence.get("summary"), str):
        raise ValidationError("repair gate summary must be bounded text")
    if type(evidence.get("network_accessed")) is not bool:
        raise ValidationError("repair gate network evidence is invalid")
    if evidence.get("network_accessed") is not False:
        raise ValidationError("repair proof gates must remain offline")
    previous = (pipeline["patch_sha256"] if not gates else
                gates[-1]["output_sha256"])
    if input_digest != previous:
        raise ValidationError("repair gate is not chained to prior evidence")
    row = {
        "gate": gate,
        "status": "passed",
        "input_sha256": input_digest,
        "output_sha256": output_digest,
        "executed": True,
        "network_accessed": evidence["network_accessed"],
        "summary": safe_text(evidence.get("summary"), 1_000),
        "evidence_sha256": _sha(evidence),
        "evidence_state": "unverified",
    }
    body = {key: value for key, value in pipeline.items()
            if key != "report_sha256"}
    body["gates"] = [*gates, row]
    body["status"] = ("evidence-chain-complete" if len(body["gates"]) == len(GATE_ORDER)
                      else "verification-in-progress")
    body["next_gate"] = ("" if len(body["gates"]) == len(GATE_ORDER)
                         else GATE_ORDER[len(body["gates"])])
    return _report(body)


def authorize_repair_apply(
        pipeline: Mapping[str, Any], registry: ApprovalRegistry,
        token: Mapping[str, Any]) -> dict[str, Any]:
    ok, errors = verify_report(dict(pipeline), schema=PIPELINE_SCHEMA)
    if not ok:
        raise ValidationError("repair pipeline is invalid: " + ", ".join(errors))
    gates = pipeline.get("gates")
    if (pipeline.get("status") != "evidence-chain-complete" or
            pipeline.get("proof_state") != "unverified" or
            type(gates) is not list or
            [row.get("gate") for row in gates if isinstance(row, Mapping)]
            != list(GATE_ORDER)):
        raise ValidationError("repair proof gates are incomplete")
    consumption = registry.consume(
        token,
        root_identity_sha256=str(pipeline.get("root_identity_sha256", "")),
        patch_sha256=str(pipeline.get("patch_sha256", "")),
        plan_sha256=str(pipeline.get("report_sha256", "")),
        purpose="repair-apply",
    )
    return _report({
        "schema": "attestor-repair-apply-authorization/4.1",
        "version": VERSION,
        "status": "authorized-once-with-unverified-evidence",
        "pipeline_sha256": pipeline["report_sha256"],
        "patch_sha256": pipeline["patch_sha256"],
        "proof_chain_sha256": _sha(gates),
        "proof_state": "unverified",
        "authorization_consumption": consumption,
        "source_changed": False,
        "permission_retained": False,
    })


def project_namespace(root_identity_sha256: str) -> str:
    digest = _exact_digest(root_identity_sha256, "root identity")
    return _sha(b"ATTESTOR-4.1.3-SECURITY-MEMORY\x00" + digest.encode("ascii"))


def new_regression_memory(root_identity_sha256: str) -> dict[str, Any]:
    body = {
        "schema": MEMORY_SCHEMA,
        "version": VERSION,
        "project_namespace": project_namespace(root_identity_sha256),
        "root_identity_sha256": _exact_digest(
            root_identity_sha256, "root identity"),
        "runs": [],
        "stores_source": False,
        "stores_secret_values": False,
    }
    return _report(body)


def record_security_run(
        memory: Mapping[str, Any], *, report_sha256: str,
        finding_fingerprints: Iterable[str], observed_at: int) -> dict[str, Any]:
    ok, errors = verify_report(dict(memory), schema=MEMORY_SCHEMA)
    if not ok:
        raise ValidationError("regression memory is invalid: " + ", ".join(errors))
    if type(observed_at) is not int or observed_at < 0:
        raise ValidationError("security run timestamp is invalid")
    supplied_fingerprints = _bounded_values(
        finding_fingerprints, MAX_FINDINGS, "finding fingerprints")
    fingerprints = sorted(set(supplied_fingerprints))
    if any(
            not isinstance(value, str) or not SHA256_RE.fullmatch(value)
            for value in fingerprints):
        raise ValidationError("finding fingerprints exceed the boundary")
    runs = memory.get("runs")
    if type(runs) is not list or len(runs) >= MAX_REGRESSION_RUNS:
        raise ValidationError("security regression run boundary is exhausted")
    normalized_report = _exact_digest(report_sha256, "security report")
    if runs and observed_at <= runs[-1].get("observed_at", -1):
        raise ValidationError(
            "security regression timestamps must increase monotonically")
    if any(
            isinstance(run, Mapping)
            and run.get("report_sha256") == normalized_report for run in runs):
        raise ValidationError("security report replay is not accepted")
    row = {
        "report_sha256": normalized_report,
        "observed_at": observed_at,
        "finding_fingerprints": fingerprints,
        "finding_count": len(fingerprints),
    }
    body = {key: value for key, value in memory.items()
            if key != "report_sha256"}
    body["runs"] = [*runs, row]
    return _report(body)


def compare_security_runs(memory: Mapping[str, Any]) -> dict[str, Any]:
    ok, errors = verify_report(dict(memory), schema=MEMORY_SCHEMA)
    if not ok:
        raise ValidationError("regression memory is invalid: " + ", ".join(errors))
    runs = memory.get("runs")
    if type(runs) is not list:
        raise ValidationError("regression run collection is invalid")
    previous = set(runs[-2]["finding_fingerprints"]) if len(runs) >= 2 else set()
    current = set(runs[-1]["finding_fingerprints"]) if runs else set()
    return _report({
        "schema": "attestor-security-regression-comparison/4.1",
        "version": VERSION,
        "project_namespace": memory["project_namespace"],
        "status": "compared" if len(runs) >= 2 else "baseline-only",
        "new": sorted(current - previous),
        "resolved": sorted(previous - current),
        "unchanged": sorted(current & previous),
        "cross_project_comparison": False,
    })


def claim_ledger(
        claims: Iterable[Mapping[str, Any]], *,
        verified_evidence_sha256: Iterable[str] = ()) -> dict[str, Any]:
    verified_rows = _bounded_values(
        verified_evidence_sha256, MAX_FINDINGS, "verified evidence digests")
    if any(
            not isinstance(value, str) or not SHA256_RE.fullmatch(value)
            for value in verified_rows):
        raise ValidationError("verified evidence digest is invalid")
    verified = set(verified_rows)
    verified_list = sorted(verified)
    rows: list[dict[str, Any]] = []
    for claim in claims:
        if len(rows) >= MAX_CLAIMS:
            raise ValidationError("claim ledger exceeds the count boundary")
        if not isinstance(claim, Mapping):
            raise ValidationError("claim ledger contains a non-object")
        state = claim.get("state")
        if state not in CLAIM_STATES:
            raise ValidationError("claim evidence state is invalid")
        evidence = claim.get("evidence")
        if not isinstance(evidence, list) or len(evidence) > 128:
            raise ValidationError("claim evidence exceeds the boundary")
        normalized_evidence: list[dict[str, str]] = []
        for item in evidence:
            if (type(item) is not dict or set(item) !=
                    {"kind", "locator", "sha256"}):
                raise ValidationError("claim evidence shape is invalid")
            normalized_evidence.append({
                "kind": safe_text(item["kind"], 120),
                "locator": safe_text(item["locator"], 500),
                "sha256": _exact_digest(item["sha256"], "claim evidence"),
            })
        if state == "proven" and not normalized_evidence:
            raise ValidationError("a proven claim requires exact evidence")
        if state == "proven" and any(
                item["sha256"] not in verified for item in normalized_evidence):
            raise ValidationError(
                "a proven claim requires independently verified evidence digests")
        claim_text = safe_text(claim.get("text"), 2_000)
        limitation = safe_text(claim.get("limitation"), 1_000)
        rows.append({
            "claim_id": _sha({
                "text": claim_text, "state": state,
                "evidence": normalized_evidence, "limitation": limitation,
            })[:24],
            "text": claim_text,
            "state": state,
            "evidence": normalized_evidence,
            "limitation": limitation,
        })
    counts = {state: sum(row["state"] == state for row in rows)
              for state in sorted(CLAIM_STATES)}
    return _report({
        "schema": LEDGER_SCHEMA,
        "version": VERSION,
        "claims": rows,
        "claim_count": len(rows),
        "counts": counts,
        "verified_evidence_sha256": verified_list,
        "verified_evidence_count": len(verified_list),
        "proof_policy": "proven requires membership in the explicit verified-evidence set",
        "unsupported_claims_promoted": False,
    })


def command_center(
        *, findings: Iterable[Mapping[str, Any]] = (),
        attack_paths: Iterable[Mapping[str, Any]] = (),
        coverage_gaps: Iterable[Any] = (),
        repair_pipeline: Mapping[str, Any] | None = None,
        regression: Mapping[str, Any] | None = None,
        ledger: Mapping[str, Any] | None = None) -> dict[str, Any]:
    finding_rows = _bounded_values(
        findings, MAX_FINDINGS, "command-center findings")
    path_rows = _bounded_values(
        attack_paths, 2_000, "command-center attack paths")
    gap_rows = _bounded_values(
        coverage_gaps, 4_000, "command-center coverage gaps")
    normalized_findings = [
        item for item in finding_rows if isinstance(item, Mapping)
    ]
    normalized_paths = [
        item for item in path_rows if isinstance(item, Mapping)
    ]
    severity = {name: 0 for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    top: list[dict[str, Any]] = []
    for item in normalized_findings:
        level = str(item.get("severity", "INFO")).upper()
        level = level if level in severity else "INFO"
        severity[level] += 1
        top.append({
            "rule": safe_text(item.get("rule") or item.get("rule_id"), 200),
            "severity": level,
            "path": safe_text(item.get("path"), 500),
            "line": (item.get("line") if type(item.get("line")) is int
                     and 0 <= item.get("line") <= 2_147_483_647 else 0),
            "evidence_state": (item.get("evidence_state")
                               if item.get("evidence_state") in CLAIM_STATES
                               else "unverified"),
        })
    top.sort(key=lambda row: (
        -{"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[
            row["severity"]],
        row["path"].casefold(), row["line"], row["rule"],
    ))
    top = top[:100]
    repair_ok = False
    if type(repair_pipeline) is dict:
        repair_ok = verify_report(
            repair_pipeline, schema=PIPELINE_SCHEMA)[0]
    repair_status = (
        safe_text(repair_pipeline.get("status"), 120)
        if repair_ok else "unverified-or-not-started"
    )
    repair_proof_state = (
        safe_text(repair_pipeline.get("proof_state"), 80)
        if repair_ok else "unavailable"
    )
    regression_ok = False
    if type(regression) is dict:
        regression_ok = verify_report(
            regression, schema="attestor-security-regression-comparison/4.1")[0]
    regression_status = (
        safe_text(regression.get("status"), 120)
        if regression_ok else "unverified-or-not-compared"
    )
    ledger_ok = False
    if type(ledger) is dict:
        ledger_ok = verify_report(ledger, schema=LEDGER_SCHEMA)[0]
    ledger_counts = (
        {state: int(ledger["counts"].get(state, 0))
         for state in sorted(CLAIM_STATES)}
        if ledger_ok else {state: 0 for state in sorted(CLAIM_STATES)}
    )
    normalized_gaps: list[str] = []
    for item in gap_rows[:1_000]:
        if isinstance(item, str):
            text = item
        elif isinstance(item, Mapping):
            text = item.get("message") or item.get("reason") or item.get("kind")
            if not isinstance(text, str):
                text = "structured coverage gap (detail unavailable)"
        elif isinstance(item, (int, float)) and not isinstance(item, bool):
            text = str(item)
        else:
            text = "coverage gap had an unsupported display shape"
        normalized_gaps.append(safe_text(text, 1_000))
    normalized_attack_paths = [{
        "id": safe_text(item.get("id") or item.get("path_id"), 160),
        "title": safe_text(item.get("title") or item.get("summary"), 500),
        "exploitability": safe_text(
            item.get("exploitability") or item.get("confidence"), 120),
        "evidence_state": (item.get("evidence_state")
                           if item.get("evidence_state") in CLAIM_STATES
                           else "unverified"),
    } for item in normalized_paths]
    exploitability_rank = {
        "critical": 5, "high": 4, "medium": 3, "low": 2, "unlikely": 1,
    }
    normalized_attack_paths.sort(key=lambda row: (
        -exploitability_rank.get(row["exploitability"].casefold(), 0),
        -{"proven": 3, "inferred": 2, "unverified": 1,
          "unavailable": 0}[row["evidence_state"]],
        row["title"].casefold(), row["id"],
    ))
    body = {
        "schema": COMMAND_CENTER_SCHEMA,
        "version": VERSION,
        "status": (
            "action-required" if normalized_findings
            else "incomplete-evidence" if gap_rows
            else "no-findings-within-bounded-evidence"
        ),
        "metrics": {
            "findings": len(normalized_findings),
            "severity": severity,
            "attack_paths": len(normalized_paths),
            "coverage_gaps": len(gap_rows),
            "claim_states": ledger_counts,
        },
        "top_findings": top,
        "attack_paths": normalized_attack_paths[:200],
        "coverage_gaps": normalized_gaps,
        "repair_status": repair_status,
        "repair_proof_state": repair_proof_state,
        "regression_status": regression_status,
        "source_reports": {
            "repair_pipeline_integrity_verified": repair_ok,
            "regression_integrity_verified": regression_ok,
            "claim_ledger_integrity_verified": ledger_ok,
        },
        "automatic_apply": False,
        "permission_retained": False,
        "raw_secret_values_present": "not-assessed",
    }
    return _report(body)


def capability_report() -> dict[str, Any]:
    """Describe the safe default without scanning or executing a target."""
    return _report({
        "schema": SCHEMA,
        "version": VERSION,
        "status": "available-default-deny",
        "capabilities": [
            "one-use plan-and-patch-bound authorization",
            "network-disabled disposable container plans",
            "bounded fuzz/property/differential plans",
            "verified repair proof state machine",
            "project-namespaced security regression memory",
            "evidence-state claim ledger",
            "security command-center view model",
        ],
        "defaults": {
            "target_execution": "denied",
            "network": "denied",
            "source_apply": "denied",
            "permission_retention": False,
            "host_execution_fallback": False,
        },
        "coverage": {
            "complete": False,
            "gaps": [
                "container runtime and pinned image must be supplied separately",
                "kernel isolation must be established by the selected runtime",
                "test oracles and target-specific properties require project evidence",
            ],
        },
        "execution": {
            "target_executed": False,
            "network_accessed": False,
            "files_written": False,
        },
    })


__all__ = [
    "ApprovalRegistry", "ValidationError", "authorize_repair_apply",
    "authorize_sandbox", "capability_report", "claim_ledger",
    "command_center", "compare_security_runs", "container_invocations",
    "create_minimization_plan", "create_sandbox_plan", "generate_test_plans",
    "minimize_observed_case",
    "new_regression_memory", "new_repair_pipeline", "project_namespace",
    "record_repair_gate", "record_security_run", "safe_text",
    "execute_security_lab_once", "tree_manifest",
    "verify_report",
]
