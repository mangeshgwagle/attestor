#!/usr/bin/env python3
"""Bounded child-process host for Attestor 4.1.3 static analyzers.

The worker isolates parser and regex failures from the public orchestrator.  It
accepts a small JSON request over stdin, dispatches only fixed internal actions,
emits one bounded JSON result, and never imports or executes target modules.
Wall-clock and output controls are enforced on every platform; POSIX children
also receive CPU/address-space/file-descriptor/file-size limits.  Windows lacks
a portable stdlib memory sandbox, so that gap is reported rather than hidden.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Mapping, Sequence


SCHEMA = "attestor-bounded-worker/4.1"
VERSION = "4.1.3"
MAX_REQUEST_BYTES = 512 * 1024
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_TIMEOUT = 180.0
MIN_MEMORY_BYTES = 64 * 1024 * 1024
MAX_MEMORY_BYTES = 1536 * 1024 * 1024
ACTIONS = frozenset({
    "attack-static-413",
    "coding-static",
    "posture-static-413",
    "security-static",
})
ACTION_PAYLOAD_KEYS = {
    "attack-static-413": frozenset({"root"}),
    "coding-static": frozenset({
        "root",
        "rule_packs",
        "rule_pack_key_base64",
        "require_signed_packs",
        "snapshot_limits",
        "max_graph_nodes",
    }),
    "posture-static-413": frozenset({
        "root", "staged_diff", "history_export",
    }),
    "security-static": frozenset({
        "root", "staged_diff", "history_export",
    }),
}


class WorkerError(ValueError):
    """The worker request or result violated a fixed boundary."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False,
                      default=str).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _is_link_or_reparse(info: os.stat_result) -> bool:
    """Recognize POSIX links and Windows reparse-backed path components."""
    attributes = int(getattr(info, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse)


def _lexical_root(value: Any) -> Path:
    """Validate *value* without resolving a link, then return an absolute root.

    ``Path.resolve`` cannot be the first check: by then a supplied link has
    disappeared from the spelling.  Walking the caller's lexical spelling also
    checks components that precede ``..`` before normalising the final path.
    The child repeats this check, so changing its working directory cannot
    silently retarget a relative API/CLI request.
    """
    if (not isinstance(value, str) or not value or len(value) > 32_768 or
            "\x00" in value):
        raise WorkerError("worker root is invalid")
    try:
        supplied = Path(value).expanduser()
        if supplied.drive and not supplied.is_absolute():
            raise WorkerError("worker root must not be drive-relative")
        spelling = supplied if supplied.is_absolute() else Path.cwd() / supplied
        current = Path(spelling.anchor)
        if not current.anchor:
            raise WorkerError("worker root is invalid")
        anchor_info = os.lstat(current)
        if _is_link_or_reparse(anchor_info):
            raise WorkerError("worker root contains a link or reparse point")
        if not stat.S_ISDIR(anchor_info.st_mode):
            raise WorkerError("worker root contains a non-directory component")
        for part in spelling.parts[1:]:
            if part in {"", "."}:
                continue
            if part == "..":
                current = current.parent
                continue
            current = current / part
            info = os.lstat(current)
            if _is_link_or_reparse(info):
                raise WorkerError("worker root contains a link or reparse point")
            if not stat.S_ISDIR(info.st_mode):
                raise WorkerError("worker root contains a non-directory component")
        lexical = Path(os.path.abspath(os.fspath(spelling)))
        resolved = lexical.resolve(strict=True)
        if resolved != lexical:
            raise WorkerError("worker root resolution traversed a link or reparse point")
        # Repeat the lexical walk to turn a concurrent link swap into a
        # refusal.  Downstream snapshot capture performs its own checks too.
        current = Path(lexical.anchor)
        for part in lexical.parts[1:]:
            current = current / part
            info = os.lstat(current)
            if _is_link_or_reparse(info):
                raise WorkerError("worker root contains a link or reparse point")
            if not stat.S_ISDIR(info.st_mode):
                raise WorkerError("worker root contains a non-directory component")
        root_info = os.lstat(resolved)
    except WorkerError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise WorkerError("worker root is unavailable") from exc
    if not stat.S_ISDIR(root_info.st_mode) or _is_link_or_reparse(root_info):
        raise WorkerError("worker root must be a real directory")
    return resolved


def _root(value: Any) -> Path:
    return _lexical_root(value)


def _request_payload(action: str, payload: Mapping[str, Any]) -> tuple[dict[str, Any], bytes]:
    """Create the exact bounded request sent to the isolated child."""
    if action not in ACTIONS or type(payload) is not dict:
        raise WorkerError("worker action or payload is unsupported")
    normalized = dict(payload)
    normalized["root"] = str(_lexical_root(normalized.get("root")))
    try:
        request = json.dumps(
            normalized, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise WorkerError("worker request is not strict JSON") from exc
    if len(request) > MAX_REQUEST_BYTES:
        raise WorkerError("worker request exceeds the byte boundary")
    unknown = set(normalized) - ACTION_PAYLOAD_KEYS[action]
    if unknown:
        raise WorkerError("worker payload contains unsupported fields")
    return normalized, request


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise WorkerError("worker JSON contains a duplicate object key")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise WorkerError("worker JSON contains a non-finite number: " + value)


def _coding(payload: Mapping[str, Any]) -> dict[str, Any]:
    import analysis_snapshot41
    import semantic_graph41
    import semantic_rule_sdk41

    root = _root(payload.get("root"))
    max_graph_nodes = payload.get(
        "max_graph_nodes", semantic_graph41.MAX_AST_NODES)
    if (type(max_graph_nodes) is not int or
            not 1 <= max_graph_nodes <= semantic_graph41.MAX_AST_NODES):
        raise WorkerError("max_graph_nodes is outside the compiled boundary")
    limits_raw = payload.get("snapshot_limits", {})
    if type(limits_raw) is not dict:
        raise WorkerError("snapshot_limits must be an object")
    allowed = {key: limits_raw[key] for key in (
        "max_files", "max_file_bytes", "max_total_bytes", "max_path_chars")
               if key in limits_raw}
    snapshot = analysis_snapshot41.capture(root, analysis_snapshot41.SnapshotLimits(**allowed))
    graph = semantic_graph41.build(
        snapshot, max_nodes=max_graph_nodes)
    graph_rows = graph.get("graph") if type(graph) is dict else None
    if (type(graph_rows) is not dict or
            any(type(rows) is not list for rows in graph_rows.values())):
        raise WorkerError("semantic graph returned an invalid graph shape")
    graph_node_count = sum(len(rows) for rows in graph_rows.values())
    if graph_node_count > max_graph_nodes:
        raise WorkerError("semantic graph exceeded the selected profile boundary")
    correctness: dict[str, Any]
    try:
        import deep_correctness41
    except ImportError:
        correctness = {
            "schema": "attestor.deep-correctness/4.1", "version": VERSION,
            "status": "unavailable", "findings": [],
            "coverage": {"complete": False,
                         "gaps": ["deep-correctness adapter is unavailable"]},
        }
    else:
        analyzer = getattr(deep_correctness41, "analyze", None)
        if not callable(analyzer):
            raise WorkerError("deep-correctness adapter has no analyze entry point")
        correctness = analyzer(snapshot)
    raw_packs = payload.get("rule_packs", [])
    if type(raw_packs) is not list or len(raw_packs) > 32:
        raise WorkerError("semantic rule packs exceed the request boundary")
    encoded_key = payload.get("rule_pack_key_base64", "")
    if not isinstance(encoded_key, str) or len(encoded_key) > 1_024:
        raise WorkerError("semantic rule-pack key exceeds the request boundary")
    try:
        pack_key = base64.b64decode(encoded_key, validate=True) if encoded_key else None
    except ValueError as exc:
        raise WorkerError("semantic rule-pack key encoding is invalid") from exc
    if pack_key is not None and not 16 <= len(pack_key) <= 512:
        raise WorkerError("semantic rule-pack key length is invalid")
    require_signed = payload.get("require_signed_packs", False)
    if type(require_signed) is not bool:
        raise WorkerError("require_signed_packs must be boolean")
    rule_reports = []
    for pack in raw_packs:
        if type(pack) is not dict:
            raise WorkerError("semantic rule pack must be an object")
        # Validation/authentication happens inside evaluate; untrusted packs do
        # not become Python modules or executable callbacks.
        rule_reports.append(semantic_rule_sdk41.evaluate(
            pack, snapshot, graph=graph, key=pack_key,
            require_signature=require_signed))
    body = {
        "schema": "attestor-coding-fabric/4.1", "version": VERSION,
        "snapshot": snapshot.report(), "semantic_graph": graph,
        "deep_correctness": correctness, "semantic_rule_reports": rule_reports,
        "shared_snapshot_sha256": snapshot.snapshot_sha256,
        "resource_limits": {
            "max_graph_nodes": max_graph_nodes,
            "observed_graph_nodes": graph_node_count,
        },
        "execution": {"target_code_executed": False,
                      "target_modules_imported": False, "network_accessed": False,
                      "filesystem_writes": False},
    }
    body["report_sha256"] = _sha(body)
    return body


def _security(payload: Mapping[str, Any]) -> dict[str, Any]:
    import secret_lifecycle41
    import supply_chain_trust41

    root = _root(payload.get("root"))
    graph = supply_chain_trust41.analyze_dependency_graph(root)
    staged = payload.get("staged_diff", "")
    history = payload.get("history_export", "")
    if not isinstance(staged, str) or len(staged.encode("utf-8")) > 128 * 1024:
        raise WorkerError("staged diff evidence exceeds the worker boundary")
    if not isinstance(history, str) or len(history.encode("utf-8")) > 128 * 1024:
        raise WorkerError("history export evidence exceeds the worker boundary")
    secrets = secret_lifecycle41.scan_lifecycle(
        root=root, staged_diff=staged, history_export=history)
    body = {
        "schema": "attestor-security-static-fabric/4.1", "version": VERSION,
        "supply_chain_trust": graph, "secret_lifecycle": secrets,
        "execution": {"target_code_executed": False, "network_accessed": False,
                      "git_invoked": False, "filesystem_writes": False},
    }
    body["report_sha256"] = _sha(body)
    return body


def _attack(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Run the 4.1.3 attack-surface analyzer inside the fixed worker boundary."""
    import attack_surface413

    root = _root(payload.get("root"))
    report = attack_surface413.analyze(root)
    valid, errors = attack_surface413.verify_report(report)
    if not valid:
        raise WorkerError(
            "attack-surface analyzer returned invalid evidence: " +
            ", ".join(errors[:3]))
    return report


def _posture(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Run cloud/IaC, supply-chain, crypto, and binary posture adapters."""
    import security_posture413

    root = _root(payload.get("root"))
    staged = payload.get("staged_diff", "")
    history = payload.get("history_export", "")
    if not isinstance(staged, str) or len(staged.encode("utf-8")) > 128 * 1024:
        raise WorkerError("staged diff evidence exceeds the worker boundary")
    if not isinstance(history, str) or len(history.encode("utf-8")) > 128 * 1024:
        raise WorkerError("history export evidence exceeds the worker boundary")
    report = security_posture413.analyze(
        root, staged_diff=staged, history_export=history)
    if not security_posture413.verify_report(report):
        raise WorkerError("security-posture analyzer returned invalid evidence")
    return report


def dispatch(action: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    if action not in ACTIONS or type(payload) is not dict:
        raise WorkerError("worker action or payload is unsupported")
    if set(payload) - ACTION_PAYLOAD_KEYS[action]:
        raise WorkerError("worker payload contains unsupported fields")
    handlers = {
        "attack-static-413": _attack,
        "coding-static": _coding,
        "posture-static-413": _posture,
        "security-static": _security,
    }
    return handlers[action](payload)


def _apply_child_limits(
        timeout: float, output: int, max_memory_bytes: int) -> None:
    """Apply POSIX limits in the isolated child, avoiding unsafe preexec hooks."""
    if os.name == "nt":
        return
    import resource

    def install(kind: int, soft: int, hard: int) -> None:
        _old_soft, old_hard = resource.getrlimit(kind)
        bounded_hard = hard if old_hard == resource.RLIM_INFINITY else min(hard, old_hard)
        bounded_soft = min(soft, bounded_hard)
        resource.setrlimit(kind, (bounded_soft, bounded_hard))

    cpu = max(1, int(math.ceil(timeout)))
    install(resource.RLIMIT_CPU, cpu, cpu + 1)
    install(resource.RLIMIT_AS, max_memory_bytes, max_memory_bytes)
    install(resource.RLIMIT_FSIZE, output, output)
    install(resource.RLIMIT_NOFILE, 64, 64)


def run(action: str, payload: Mapping[str, Any], *, timeout: float = 90.0,
        max_output_bytes: int = MAX_OUTPUT_BYTES,
        max_memory_bytes: int = MAX_MEMORY_BYTES) -> dict[str, Any]:
    """Run an allowlisted analyzer and return a bounded evidence wrapper."""
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or
            not math.isfinite(float(timeout)) or not 0.1 <= float(timeout) <= MAX_TIMEOUT):
        raise WorkerError("worker timeout is outside the boundary")
    if (isinstance(max_output_bytes, bool) or not isinstance(max_output_bytes, int) or
            not 1_024 <= max_output_bytes <= MAX_OUTPUT_BYTES):
        raise WorkerError("worker output limit is outside the boundary")
    if (isinstance(max_memory_bytes, bool) or
            not isinstance(max_memory_bytes, int) or
            not MIN_MEMORY_BYTES <= max_memory_bytes <= MAX_MEMORY_BYTES):
        raise WorkerError("worker memory limit is outside the boundary")
    _normalized, request = _request_payload(action, payload)
    environment = {key: value for key, value in os.environ.items()
                   if key in {"SystemRoot", "WINDIR", "TEMP", "TMP", "PATH", "PATHEXT",
                              "HOME", "USERPROFILE"} and isinstance(value, str)}
    environment.update({"PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1",
                        "NO_COLOR": "1", "ATTESTOR_NETWORK": "disabled"})
    command = [sys.executable, "-I", "-B", "-X", "utf8", str(Path(__file__).resolve()),
               "--worker", action, "--worker-timeout", str(float(timeout)),
               "--worker-output", str(int(max_output_bytes)),
               "--worker-memory", str(int(max_memory_bytes))]
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    process: subprocess.Popen[bytes] | None = None
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    threads: list[threading.Thread] = []

    def stop_child() -> None:
        if process is None:
            return
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            if process.poll() is None:
                process.kill()
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            process.wait(timeout=5.0)

    def finish_io() -> None:
        for thread in threads:
            thread.join(timeout=2.0)
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    with contextlib.suppress(OSError, ValueError):
                        stream.close()

    try:
        process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, shell=False, env=environment,
            cwd=str(Path(__file__).resolve().parent), creationflags=creationflags)
        deadline = time.monotonic() + float(timeout)

        def drain(stream, destination: bytearray, limit: int) -> None:
            try:
                while True:
                    remaining = limit + 1 - len(destination)
                    if remaining <= 0:
                        overflow.set()
                        stop_child()
                        return
                    chunk = os.read(stream.fileno(), min(65_536, remaining))
                    if not chunk:
                        return
                    destination.extend(chunk)
                    if len(destination) > limit:
                        overflow.set()
                        stop_child()
                        return
            except (OSError, ValueError):
                return

        def feed() -> None:
            active = process
            if active is None or active.stdin is None:
                stop_child()
                return
            try:
                descriptor = active.stdin.fileno()
                offset = 0
                while offset < len(request):
                    written = os.write(descriptor, request[offset:])
                    if written <= 0:
                        return
                    offset += written
            except (BrokenPipeError, OSError, ValueError):
                return
            finally:
                with contextlib.suppress(OSError, ValueError):
                    active.stdin.close()

        if process.stdout is None or process.stderr is None:
            stop_child()
            finish_io()
            return _wrapper(
                action, "failed", None, request, timeout=float(timeout),
                output_bytes=len(stdout), error="process-pipe-boundary",
                max_output_bytes=int(max_output_bytes),
                max_memory_bytes=int(max_memory_bytes))
        threads = [
            threading.Thread(target=drain, args=(process.stdout, stdout, int(max_output_bytes)),
                             daemon=True, name="attestor41-worker-stdout"),
            threading.Thread(target=drain, args=(process.stderr, stderr, 64 * 1024),
                             daemon=True, name="attestor41-worker-stderr"),
            threading.Thread(target=feed, daemon=True, name="attestor41-worker-stdin"),
        ]
        for thread in threads:
            thread.start()
        try:
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            stop_child()
            finish_io()
            return _wrapper(action, "timed-out", None, request, timeout=float(timeout),
                            output_bytes=len(stdout), error="wall-clock-boundary",
                            max_output_bytes=int(max_output_bytes),
                            max_memory_bytes=int(max_memory_bytes))
        finish_io()
    except subprocess.TimeoutExpired:
        stop_child()
        finish_io()
        return _wrapper(action, "timed-out", None, request, timeout=float(timeout),
                        output_bytes=len(stdout), error="wall-clock-boundary",
                        max_output_bytes=int(max_output_bytes),
                        max_memory_bytes=int(max_memory_bytes))
    except (OSError, subprocess.SubprocessError) as exc:
        stop_child()
        finish_io()
        return _wrapper(action, "failed", None, request, timeout=float(timeout),
                        output_bytes=len(stdout), error="process-boundary-" + type(exc).__name__,
                        max_output_bytes=int(max_output_bytes),
                        max_memory_bytes=int(max_memory_bytes))
    if overflow.is_set() or len(stdout) > max_output_bytes or len(stderr) > 64 * 1024:
        return _wrapper(action, "refused", None, request, timeout=float(timeout),
                        output_bytes=len(stdout), error="output-boundary",
                        max_output_bytes=int(max_output_bytes),
                        max_memory_bytes=int(max_memory_bytes))
    if process is None:
        return _wrapper(
            action, "failed", None, request, timeout=float(timeout),
            output_bytes=len(stdout), error="process-boundary-missing",
            max_output_bytes=int(max_output_bytes),
            max_memory_bytes=int(max_memory_bytes))
    if process.returncode == 3:
        return _wrapper(action, "refused", None, request, timeout=float(timeout),
                        output_bytes=len(stdout), error="output-boundary",
                        max_output_bytes=int(max_output_bytes),
                        max_memory_bytes=int(max_memory_bytes))
    if process.returncode == 2:
        return _wrapper(action, "refused", None, request, timeout=float(timeout),
                        output_bytes=len(stdout), error="request-boundary",
                        max_output_bytes=int(max_output_bytes),
                        max_memory_bytes=int(max_memory_bytes))
    if process.returncode != 0:
        child_error = ""
        try:
            failure = json.loads(bytes(stdout).decode("utf-8", "strict"),
                                 object_pairs_hook=_strict_object,
                                 parse_constant=_reject_constant)
            candidate = failure.get("error") if type(failure) is dict else ""
            if isinstance(candidate, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", candidate):
                child_error = "worker-error-" + candidate
        except (UnicodeError, json.JSONDecodeError, WorkerError):
            child_error = ""
        return _wrapper(action, "failed", None, request, timeout=float(timeout),
                        output_bytes=len(stdout),
                        error=child_error or "worker-exit-%d" % process.returncode,
                        max_output_bytes=int(max_output_bytes),
                        max_memory_bytes=int(max_memory_bytes))
    try:
        result = json.loads(bytes(stdout).decode("utf-8", "strict"),
                            object_pairs_hook=_strict_object,
                            parse_constant=_reject_constant)
    except (UnicodeError, json.JSONDecodeError, WorkerError):
        return _wrapper(action, "failed", None, request, timeout=float(timeout),
                        output_bytes=len(stdout), error="invalid-json",
                        max_output_bytes=int(max_output_bytes),
                        max_memory_bytes=int(max_memory_bytes))
    if type(result) is not dict:
        return _wrapper(action, "failed", None, request, timeout=float(timeout),
                        output_bytes=len(stdout), error="invalid-result-shape",
                        max_output_bytes=int(max_output_bytes),
                        max_memory_bytes=int(max_memory_bytes))
    return _wrapper(action, "completed", result, request, timeout=float(timeout),
                    output_bytes=len(stdout), error="",
                    max_output_bytes=int(max_output_bytes),
                    max_memory_bytes=int(max_memory_bytes))


def _wrapper(action: str, status: str, result: Mapping[str, Any] | None,
             request: bytes, *, timeout: float, output_bytes: int, error: str,
             max_output_bytes: int, max_memory_bytes: int) -> dict[str, Any]:
    body = {
        "schema": SCHEMA, "version": VERSION, "status": status, "action": action,
        "request_sha256": _sha(request), "result": dict(result) if result is not None else None,
        "result_sha256": _sha(result) if result is not None else "",
        "error": error,
        "boundary": {"wall_clock_seconds": timeout, "output_bytes": output_bytes,
                     "max_output_bytes": max_output_bytes,
                     "max_memory_bytes": max_memory_bytes,
                     "max_stderr_bytes": 64 * 1024,
                     "max_request_bytes": MAX_REQUEST_BYTES,
                     "memory_limit": "rlimit-as" if os.name != "nt" else "unavailable-stdlib-windows",
                     "cpu_limit": "rlimit-cpu" if os.name != "nt" else "wall-clock-only",
                     "network_kernel_blocked": False,
                     "network_contract": "allowlisted-offline-analyzers",
                     "shell": False, "isolated_python": True,
                     "preexec_fn_used": False,
                     "target_code_executed": False},
    }
    body["report_sha256"] = _sha(body)
    return body


def verify_report(report: Mapping[str, Any]) -> tuple[bool, list[str]]:
    errors = []
    if type(report) is not dict or report.get("schema") != SCHEMA or report.get("version") != VERSION:
        return False, ["worker schema or version is invalid"]
    status = report.get("status")
    if status not in {"completed", "timed-out", "failed", "refused"}:
        errors.append("worker status is invalid")
    if report.get("action") not in ACTIONS:
        errors.append("worker action is invalid")
    body = {key: value for key, value in report.items() if key != "report_sha256"}
    if report.get("report_sha256") != _sha(body):
        errors.append("worker report digest mismatch")
    result = report.get("result")
    if status == "completed":
        if type(result) is not dict:
            errors.append("completed worker result is missing")
        elif report.get("result_sha256") != _sha(result):
            errors.append("worker result digest mismatch")
        if report.get("error") != "":
            errors.append("completed worker has a contradictory error")
    else:
        if result is not None or report.get("result_sha256") != "":
            errors.append("failed worker has a contradictory result")
        if not isinstance(report.get("error"), str) or not report.get("error"):
            errors.append("failed worker error is missing")
    request_digest = report.get("request_sha256")
    if not isinstance(request_digest, str) or re.fullmatch(r"[0-9a-f]{64}", request_digest) is None:
        errors.append("worker request digest is invalid")
    boundary = report.get("boundary") if isinstance(report.get("boundary"), Mapping) else {}
    if (boundary.get("shell") is not False or
            boundary.get("target_code_executed") is not False or
            boundary.get("preexec_fn_used") is not False):
        errors.append("worker execution boundary is contradictory")
    output_bytes = boundary.get("output_bytes")
    output_limit = boundary.get("max_output_bytes")
    if (isinstance(output_bytes, bool) or not isinstance(output_bytes, int) or output_bytes < 0 or
            isinstance(output_limit, bool) or not isinstance(output_limit, int) or
            not 1_024 <= output_limit <= MAX_OUTPUT_BYTES or output_bytes > output_limit + 1):
        errors.append("worker output boundary is invalid")
    wall_clock = boundary.get("wall_clock_seconds")
    if (isinstance(wall_clock, bool) or not isinstance(wall_clock, (int, float)) or
            not math.isfinite(float(wall_clock)) or not 0.1 <= float(wall_clock) <= MAX_TIMEOUT):
        errors.append("worker wall-clock boundary is invalid")
    memory_limit = boundary.get("max_memory_bytes")
    if (isinstance(memory_limit, bool) or not isinstance(memory_limit, int) or
            not MIN_MEMORY_BYTES <= memory_limit <= MAX_MEMORY_BYTES):
        errors.append("worker memory boundary is invalid")
    if (boundary.get("max_request_bytes") != MAX_REQUEST_BYTES or
            boundary.get("max_stderr_bytes") != 64 * 1024):
        errors.append("worker fixed byte boundary is invalid")
    return not errors, errors


def _worker_main(
        action: str, timeout: float, max_output_bytes: int,
        max_memory_bytes: int) -> int:
    try:
        _apply_child_limits(timeout, max_output_bytes, max_memory_bytes)
    except Exception as exc:
        # This occurs before any target data is parsed.  A completed result is
        # therefore proof that the advertised POSIX child limits were applied.
        encoded = _canonical({"schema": SCHEMA, "version": VERSION,
                              "status": "failed", "error": type(exc).__name__})
        if len(encoded) <= max_output_bytes:
            sys.stdout.buffer.write(encoded)
        return 1
    # ``-I`` intentionally removes ambient/current-directory imports.  Restore
    # only this signed release's detector directory, never the target root.
    detector_root = str(Path(__file__).resolve().parent)
    if detector_root not in sys.path:
        sys.path.insert(0, detector_root)
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        return 2
    try:
        payload = json.loads(raw.decode("utf-8", "strict"),
                             object_pairs_hook=_strict_object,
                             parse_constant=_reject_constant)
        result = dispatch(action, payload)
        encoded = _canonical(result)
    except Exception as exc:  # internal boundary: expose type, never target path/content
        encoded = _canonical({"schema": SCHEMA, "version": VERSION,
                              "status": "failed", "error": type(exc).__name__})
        if len(encoded) <= max_output_bytes:
            sys.stdout.buffer.write(encoded)
        return 1
    if len(encoded) > max_output_bytes:
        return 3
    sys.stdout.buffer.write(encoded)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", choices=sorted(ACTIONS))
    parser.add_argument("--root")
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--worker-timeout", type=float, default=90.0,
                        help=argparse.SUPPRESS)
    parser.add_argument("--worker-output", type=int, default=MAX_OUTPUT_BYTES,
                        help=argparse.SUPPRESS)
    parser.add_argument("--worker-memory", type=int, default=MAX_MEMORY_BYTES,
                        help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.worker:
        if not 0.1 <= args.worker_timeout <= MAX_TIMEOUT:
            return 2
        if not 1_024 <= args.worker_output <= MAX_OUTPUT_BYTES:
            return 2
        if not MIN_MEMORY_BYTES <= args.worker_memory <= MAX_MEMORY_BYTES:
            return 2
        return _worker_main(
            args.worker, args.worker_timeout, args.worker_output,
            args.worker_memory)
    if not args.root:
        parser.error("--root is required outside worker mode")
    report = run("coding-static", {"root": args.root}, timeout=args.timeout)
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    return 0 if report["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
