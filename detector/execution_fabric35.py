#!/usr/bin/env python3
"""Fail-closed container execution for Attestor 3.5 verification jobs.

The fabric has deliberately fewer features than a general process runner.  It
never invokes a shell, never executes target code on the host, never enables a
network, and never retries a rejected hardening option with a weaker command.
Only a rootless Linux Docker/Podman capability is eligible today.  Windows
container capability is reported, but is not treated as equivalent because the
Linux capability/drop and read-only controls cannot be proven there.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Sequence


SCHEMA = "attestor-execution-fabric/3.5"
ZERO_HASH = "0" * 64
_IMAGE_RE = re.compile(
    r"(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*@sha256:[0-9a-f]{64}\Z"
)
_ENV_RE = re.compile(r"[A-Z_][A-Z0-9_]{0,63}\Z")
_SENSITIVE_NAME_RE = re.compile(
    r"(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH)", re.I
)
_TEXT_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)"
    r"\s*([:=])\s*([^\s,;]+)"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{6,}")
_RUNTIME_CONTROL_ENV = frozenset({
    "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
    "CONTAINER_HOST", "CONTAINER_CONNECTION", "PODMAN_HOST",
})


class FabricError(ValueError):
    """A request violates the non-negotiable execution boundary."""


def _ambient_runtime_selectors() -> tuple[str, ...]:
    """Return ambient variables that could redirect a runtime client.

    Capability detection is not a permanent security decision: an environment
    can change after a fabric object is constructed.  Callers therefore check
    this again immediately before every execution.
    """
    return tuple(sorted(name for name in _RUNTIME_CONTROL_ENV
                        if str(os.environ.get(name, "")).strip()))


@dataclass(frozen=True)
class RuntimeCapability:
    name: str
    executable: str
    available: bool
    rootless: bool
    os_type: str
    hardened_linux: bool
    windows_isolation: bool
    reason: str

    @property
    def eligible(self) -> bool:
        return bool(self.available and self.rootless and self.hardened_linux)


@dataclass(frozen=True)
class FabricCapabilities:
    runtimes: tuple[RuntimeCapability, ...]
    windows_isolation_available: bool

    def by_name(self, name: str) -> RuntimeCapability | None:
        wanted = name.strip().lower()
        return next((item for item in self.runtimes if item.name == wanted), None)

    @property
    def eligible(self) -> tuple[RuntimeCapability, ...]:
        return tuple(item for item in self.runtimes if item.eligible)


@dataclass(frozen=True)
class ExecutionAuthorization:
    """An explicit, auditable decision to run untrusted verification code."""

    granted: bool = False
    purpose: str = ""
    actor: str = ""

    def valid(self) -> bool:
        return bool(
            self.granted
            and isinstance(self.purpose, str)
            and isinstance(self.actor, str)
            and 4 <= len(self.purpose.strip()) <= 512
            and len(self.actor.strip()) <= 128
            and "\x00" not in self.purpose
            and "\x00" not in self.actor
        )


@dataclass(frozen=True)
class ExecutionPolicy:
    timeout_seconds: float = 30.0
    kill_grace_seconds: float = 2.0
    max_output_bytes: int = 1_048_576
    pids_limit: int = 128
    cpus: float = 1.0
    memory_bytes: int = 512 * 1024 * 1024
    tmpfs_bytes: int = 64 * 1024 * 1024
    max_workspace_files: int = 50_000
    max_workspace_bytes: int = 1024 * 1024 * 1024
    max_workspace_file_bytes: int = 128 * 1024 * 1024
    user: str = "65534:65534"

    def __post_init__(self) -> None:
        if not 0.1 <= float(self.timeout_seconds) <= 600:
            raise FabricError("timeout must be between 0.1 and 600 seconds")
        if not 0.1 <= float(self.kill_grace_seconds) <= 10:
            raise FabricError("kill grace must be between 0.1 and 10 seconds")
        if not 1_024 <= int(self.max_output_bytes) <= 16 * 1024 * 1024:
            raise FabricError("output boundary is outside the supported range")
        if not 16 <= int(self.pids_limit) <= 1_024:
            raise FabricError("pid boundary is outside the supported range")
        if not 0.1 <= float(self.cpus) <= 8:
            raise FabricError("cpu boundary is outside the supported range")
        if not 32 * 1024 * 1024 <= int(self.memory_bytes) <= 8 * 1024 * 1024 * 1024:
            raise FabricError("memory boundary is outside the supported range")
        if not 1 * 1024 * 1024 <= int(self.tmpfs_bytes) <= 1024 * 1024 * 1024:
            raise FabricError("tmpfs boundary is outside the supported range")
        if not 1 <= int(self.max_workspace_files) <= 500_000:
            raise FabricError("workspace file boundary is outside the supported range")
        if not 1_024 <= int(self.max_workspace_file_bytes) <= 512 * 1024 * 1024:
            raise FabricError("workspace per-file boundary is outside the supported range")
        if not int(self.max_workspace_file_bytes) <= int(self.max_workspace_bytes) <= 8 * 1024**3:
            raise FabricError("workspace byte boundary is outside the supported range")
        if not re.fullmatch(r"[0-9]{1,10}:[0-9]{1,10}", self.user):
            raise FabricError("container user must be a numeric uid:gid")


@dataclass(frozen=True)
class ExecutionRequest:
    image: str
    command: tuple[str, ...]
    workspace: str | os.PathLike[str]
    runtime: str = ""
    environment: Mapping[str, str] = field(default_factory=dict)
    label: str = "verification"

    def __post_init__(self) -> None:
        object.__setattr__(self, "command", tuple(self.command))
        object.__setattr__(self, "environment", MappingProxyType(dict(self.environment)))


@dataclass(frozen=True)
class ExecutionResult:
    status: str
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool
    runtime: str
    request_sha256: str
    argv_sha256: str
    transcript: tuple[dict[str, Any], ...]
    reason: str = ""

    @property
    def completed(self) -> bool:
        return self.status == "completed" and not self.timed_out

    @property
    def ok(self) -> bool:
        return self.completed and self.returncode == 0


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8", "replace")


def _sha(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8", "replace")
    return hashlib.sha256(value).hexdigest()


def _redact_text(value: str, exact: Iterable[str] = ()) -> str:
    result = value
    for secret in sorted({item for item in exact if item}, key=len, reverse=True):
        result = result.replace(secret, "[REDACTED]")
    result = _TEXT_SECRET_RE.sub(lambda match: "%s%s[REDACTED]" % (
        match.group(1), match.group(2)), result)
    return _BEARER_RE.sub("Bearer [REDACTED]", result)


def _redact_tree(value: Any, exact: Iterable[str] = ()) -> Any:
    if isinstance(value, str):
        return _redact_text(value, exact)
    if isinstance(value, Mapping):
        return {str(key): ("[REDACTED]" if _SENSITIVE_NAME_RE.search(str(key))
                           else _redact_tree(item, exact))
                for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_tree(item, exact) for item in value]
    return value


class SignedTranscript:
    """Append-only HMAC-authenticated SHA-256 event chain."""

    def __init__(self, signing_key: bytes, clock_ns: Callable[[], int] = time.time_ns):
        if not isinstance(signing_key, bytes) or len(signing_key) < 32:
            raise FabricError("transcript signing key must contain at least 32 bytes")
        self._key = signing_key
        self._clock_ns = clock_ns
        self._entries: list[dict[str, Any]] = []

    def append(self, event: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{1,63}", event):
            raise FabricError("invalid transcript event")
        body = {
            "schema": SCHEMA,
            "sequence": len(self._entries),
            "timestamp_ns": int(self._clock_ns()),
            "event": event,
            "payload": _redact_tree(dict(payload)),
            "previous_hash": self._entries[-1]["event_hash"] if self._entries else ZERO_HASH,
        }
        event_hash = _sha(_canonical(body))
        entry = {
            **body,
            "event_hash": event_hash,
            "signature": hmac.new(self._key, event_hash.encode("ascii"),
                                  hashlib.sha256).hexdigest(),
        }
        self._entries.append(entry)
        return dict(entry)

    def export(self) -> tuple[dict[str, Any], ...]:
        return tuple(json.loads(json.dumps(item)) for item in self._entries)

    @staticmethod
    def verify(entries: Sequence[Mapping[str, Any]], signing_key: bytes) -> bool:
        previous = ZERO_HASH
        for sequence, raw in enumerate(entries):
            try:
                body = {
                    "schema": raw["schema"], "sequence": raw["sequence"],
                    "timestamp_ns": raw["timestamp_ns"], "event": raw["event"],
                    "payload": raw["payload"], "previous_hash": raw["previous_hash"],
                }
                if body["schema"] != SCHEMA or body["sequence"] != sequence:
                    return False
                if body["previous_hash"] != previous:
                    return False
                digest = _sha(_canonical(body))
                if not hmac.compare_digest(str(raw["event_hash"]), digest):
                    return False
                expected = hmac.new(signing_key, digest.encode("ascii"),
                                    hashlib.sha256).hexdigest()
                if not hmac.compare_digest(str(raw["signature"]), expected):
                    return False
                previous = digest
            except (KeyError, TypeError, ValueError):
                return False
        return True


def _probe(argv: Sequence[str], timeout: float = 3.0) -> subprocess.CompletedProcess[str]:
    # Never let ambient variables redirect a capability probe to a remote
    # daemon.  The local default socket is the only eligible endpoint.
    allowed = {"PATH", "PATHEXT", "SystemRoot", "WINDIR", "HOME",
               "USERPROFILE", "TEMP", "TMP"}
    environment = {key: value for key, value in os.environ.items()
                   if key in allowed and isinstance(value, str)}
    return subprocess.run(list(argv), stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, shell=False, timeout=timeout, check=False,
                          env=environment)


def _cleanup_container(executable: str, name: str, environment: Mapping[str, str],
                       timeout: float) -> bool:
    """Best-effort removal after killing a timed-out runtime client; no shell."""
    result = subprocess.run(
        [executable, "rm", "--force", name], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False,
        timeout=timeout, check=False, env=dict(environment),
    )
    return result.returncode == 0


def detect_capabilities(
    *,
    which: Callable[[str], str | None] = shutil.which,
    probe: Callable[[Sequence[str], float], Any] = _probe,
) -> FabricCapabilities:
    """Detect runtimes without starting a container or weakening any policy."""
    found: list[RuntimeCapability] = []
    windows_isolation = False
    remote_selectors = _ambient_runtime_selectors()
    for name in ("podman", "docker"):
        executable = which(name)
        if not executable:
            found.append(RuntimeCapability(name, "", False, False, "unknown", False,
                                           False, "executable not found"))
            continue
        if remote_selectors:
            found.append(RuntimeCapability(
                name, str(executable), False, False, "unknown", False, False,
                "ambient runtime endpoint selection is forbidden: " +
                ", ".join(remote_selectors)))
            continue
        rootless = False
        os_type = "unknown"
        reason = "runtime information was unavailable"
        try:
            if name == "podman":
                result = probe([executable, "info", "--format",
                                "{{.Host.Security.Rootless}}|{{.Host.Os}}"], 3.0)
                text = ((getattr(result, "stdout", "") or "") + "|" +
                        (getattr(result, "stderr", "") or "")).strip().lower()
                rootless = text.startswith("true|")
                os_type = "linux" if "linux" in text else (
                    "windows" if "windows" in text else "unknown")
            else:
                result = probe([executable, "info", "--format",
                                "{{.OSType}}|{{json .SecurityOptions}}"], 3.0)
                text = ((getattr(result, "stdout", "") or "") + "|" +
                        (getattr(result, "stderr", "") or "")).strip().lower()
                rootless = "rootless" in text
                os_type = "windows" if text.startswith("windows|") else (
                    "linux" if text.startswith("linux|") else "unknown")
            available = getattr(result, "returncode", 1) == 0
            if not available:
                reason = "runtime info command failed"
            elif os_type == "windows":
                windows_isolation = True
                reason = ("Windows isolation detected; required Linux cap-drop/read-only "
                          "controls are not claimed equivalent")
            elif not rootless:
                reason = "runtime is not proven rootless"
            elif os_type != "linux":
                reason = "runtime OS is not proven Linux"
            else:
                reason = "eligible rootless Linux runtime"
        except (OSError, subprocess.SubprocessError, TypeError, ValueError):
            available = False
            reason = "runtime capability probe failed"
        hardened = bool(available and rootless and os_type == "linux")
        found.append(RuntimeCapability(name, str(executable), available, rootless,
                                       os_type, hardened, os_type == "windows", reason))
    return FabricCapabilities(tuple(found), windows_isolation)


class _OutputBudget:
    def __init__(self, maximum: int):
        self.maximum = maximum
        self.used = 0
        self.truncated = False
        self.lock = threading.Lock()

    def take(self, chunk: bytes) -> bytes:
        with self.lock:
            remaining = max(0, self.maximum - self.used)
            accepted = chunk[:remaining]
            self.used += len(accepted)
            if len(accepted) != len(chunk):
                self.truncated = True
            return accepted


def _drain(stream: Any, sink: io.BytesIO, budget: _OutputBudget) -> None:
    try:
        while True:
            chunk = stream.read(16_384)
            if not chunk:
                break
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8", "replace")
            accepted = budget.take(chunk)
            if accepted:
                sink.write(accepted)
    except (OSError, ValueError):
        budget.truncated = True


class ExecutionFabric:
    """Rootless-container-only runner with a fail-closed authorization gate."""

    def __init__(
        self,
        capabilities: FabricCapabilities | None = None,
        policy: ExecutionPolicy | None = None,
        *,
        signing_key: bytes | None = None,
        process_factory: Callable[..., Any] = subprocess.Popen,
        cleanup_runner: Callable[[str, str, Mapping[str, str], float], bool] = _cleanup_container,
        clock_ns: Callable[[], int] = time.time_ns,
    ) -> None:
        self.capabilities = capabilities or detect_capabilities()
        self.policy = policy or ExecutionPolicy()
        self._signing_key = signing_key or secrets.token_bytes(32)
        self._process_factory = process_factory
        self._cleanup_runner = cleanup_runner
        self._clock_ns = clock_ns

    @property
    def transcript_verification_key(self) -> bytes:
        """Return a copy for the caller's evidence store; it is never serialized."""
        return bytes(self._signing_key)

    def verify_transcript(self, transcript: Sequence[Mapping[str, Any]]) -> bool:
        return SignedTranscript.verify(transcript, self._signing_key)

    def _runtime(self, requested: str) -> RuntimeCapability | None:
        if requested:
            # A named insecure/unavailable runtime is never silently replaced.
            capability = self.capabilities.by_name(requested)
            return capability if capability and capability.eligible else None
        return next(iter(self.capabilities.eligible), None)

    @staticmethod
    def _workspace(value: str | os.PathLike[str]) -> Path:
        raw = os.fspath(value)
        if any(mark in raw for mark in ("\x00", "\n", "\r", ",")):
            raise FabricError("workspace path contains a container-option delimiter")
        supplied = Path(raw).expanduser()
        if supplied.is_symlink():
            raise FabricError("workspace must be a real directory, not a link")
        path = supplied.resolve(strict=True)
        if not path.is_dir():
            raise FabricError("workspace must be a real directory, not a link")
        return path

    @staticmethod
    def _validate(request: ExecutionRequest) -> None:
        if not isinstance(request.image, str) or not _IMAGE_RE.fullmatch(request.image):
            raise FabricError("image must be a lowercase OCI name pinned by sha256 digest")
        if not isinstance(request.runtime, str):
            raise FabricError("runtime selector must be text")
        if not request.command or len(request.command) > 256:
            raise FabricError("command must contain between 1 and 256 argv items")
        for argument in request.command:
            if not isinstance(argument, str) or "\x00" in argument or len(argument) > 16_384:
                raise FabricError("command contains an invalid argv item")
        if (not isinstance(request.label, str) or
                not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", request.label)):
            raise FabricError("execution label is invalid")
        if len(request.environment) > 64:
            raise FabricError("too many environment variables")
        for key, value in request.environment.items():
            if not isinstance(key, str) or not _ENV_RE.fullmatch(key):
                raise FabricError("environment variable name is invalid")
            if _SENSITIVE_NAME_RE.search(key):
                raise FabricError("secrets are not accepted by verification containers")
            if key.startswith(("DOCKER_", "CONTAINER_", "PODMAN_")) or key in {
                    "PATH", "PATHEXT", "SystemRoot", "WINDIR"}:
                raise FabricError("runtime-control environment variables may not be overridden")
            if not isinstance(value, str) or "\x00" in value or len(value) > 8_192:
                raise FabricError("environment variable value is invalid")

    def _argv(self, runtime: RuntimeCapability, request: ExecutionRequest,
              workspace: Path, name: str, *, writable_workspace: bool = False) -> list[str]:
        memory = "%db" % self.policy.memory_bytes
        tmpfs = "rw,noexec,nosuid,nodev,size=%d" % self.policy.tmpfs_bytes
        argv = [
            runtime.executable, "run", "--rm", "--name", name,
            "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--pids-limit=%d" % self.policy.pids_limit,
            "--cpus=%s" % format(self.policy.cpus, ".3g"),
            "--memory=%s" % memory, "--memory-swap=%s" % memory,
            "--tmpfs=/tmp:%s" % tmpfs, "--tmpfs=/run:%s" % tmpfs,
            "--user=%s" % self.policy.user, "--workdir=/workspace",
            "--mount", "type=bind,src=%s,dst=/workspace,%s" % (
                workspace, "rw" if writable_workspace else "ro"),
        ]
        for key in sorted(request.environment):
            # Value travels in the child's sanitized environment, not process argv.
            argv.extend(["--env", key])
        argv.append(request.image)
        argv.extend(request.command)
        return argv

    @staticmethod
    def _host_environment(extra: Mapping[str, str]) -> dict[str, str]:
        allowed = {"PATH", "PATHEXT", "SystemRoot", "WINDIR", "HOME",
                   "USERPROFILE", "TEMP", "TMP"}
        result = {key: value for key, value in os.environ.items()
                  if key in allowed and isinstance(value, str)}
        result.update(extra)
        result.update({"CI": "1", "NO_COLOR": "1", "ATTESTOR_NETWORK": "disabled"})
        return result

    def _refused(self, transcript: SignedTranscript, request_hash: str,
                 reason: str) -> ExecutionResult:
        transcript.append("execution.refused", {"reason": reason,
                                                 "request_sha256": request_hash})
        return ExecutionResult("refused", None, "", "", False, False, "",
                               request_hash, "", transcript.export(), reason)

    @staticmethod
    def _request_hash(request: ExecutionRequest) -> str:
        command_summary = [item if isinstance(item, str) else
                           "<invalid:%s>" % type(item).__name__
                           for item in request.command]
        environment_names = [key if isinstance(key, str) else
                             "<invalid:%s>" % type(key).__name__
                             for key in request.environment]
        return _sha(_canonical({
            "image": request.image if isinstance(request.image, str) else
                     "<invalid:%s>" % type(request.image).__name__,
            "command_sha256": _sha(_canonical(command_summary)),
            "command_argc": len(request.command),
            "runtime": request.runtime if isinstance(request.runtime, str) else
                       "<invalid:%s>" % type(request.runtime).__name__,
            "environment_names": sorted(environment_names),
            "label": request.label if isinstance(request.label, str) else
                     "<invalid:%s>" % type(request.label).__name__,
        }))

    def _copy_workspace(self, source: Path, destination: Path) -> None:
        """Create a bounded link-free disposable copy for writable verification."""
        destination.mkdir(parents=True, exist_ok=False)
        files = 0
        total = 0
        for current, directories, names in os.walk(source, followlinks=False):
            here = Path(current)
            relative = here.relative_to(source)
            target_directory = destination / relative
            target_directory.mkdir(parents=True, exist_ok=True)
            for name in tuple(directories):
                child = here / name
                if child.is_symlink():
                    raise FabricError("disposable workspace refuses symbolic-link directories")
                (target_directory / name).mkdir(exist_ok=True)
            for name in names:
                item = here / name
                if item.is_symlink() or not item.is_file():
                    raise FabricError("disposable workspace requires regular link-free files")
                files += 1
                if files > self.policy.max_workspace_files:
                    raise FabricError("disposable workspace exceeds the file-count boundary")
                output = target_directory / name
                file_bytes = 0
                with item.open("rb") as source_file, output.open("xb") as output_file:
                    while True:
                        chunk = source_file.read(1024 * 1024)
                        if not chunk:
                            break
                        file_bytes += len(chunk)
                        total += len(chunk)
                        if file_bytes > self.policy.max_workspace_file_bytes:
                            raise FabricError("disposable workspace file exceeds the byte boundary")
                        if total > self.policy.max_workspace_bytes:
                            raise FabricError("disposable workspace exceeds the byte boundary")
                        output_file.write(chunk)
                shutil.copystat(item, output, follow_symlinks=False)

    def run(self, request: ExecutionRequest,
            authorization: ExecutionAuthorization | None = None) -> ExecutionResult:
        """Run against a read-only bind mount; the caller's workspace cannot be mutated."""
        return self._run(request, authorization, writable_workspace=False)

    def run_disposable(self, request: ExecutionRequest,
                       authorization: ExecutionAuthorization | None = None) -> ExecutionResult:
        """Run with writes confined to a bounded temporary copy that is always discarded."""
        transcript = SignedTranscript(self._signing_key, self._clock_ns)
        request_hash = self._request_hash(request)
        transcript.append("request.received", {"request_sha256": request_hash,
                                               "label": request.label
                                               if isinstance(request.label, str)
                                               else "invalid"})
        if (not isinstance(authorization, ExecutionAuthorization) or
                not authorization.valid()):
            return self._refused(transcript, request_hash,
                                 "explicit execution authorization is required")
        remote_selectors = _ambient_runtime_selectors()
        if remote_selectors:
            return self._refused(
                transcript, request_hash,
                "ambient runtime endpoint selection is forbidden: " +
                ", ".join(remote_selectors))
        try:
            self._validate(request)
            workspace = self._workspace(request.workspace)
            with tempfile.TemporaryDirectory(prefix="attestor35-fabric-") as temporary:
                disposable = Path(temporary) / "workspace"
                self._copy_workspace(workspace, disposable)
                isolated = ExecutionRequest(
                    image=request.image, command=request.command, workspace=disposable,
                    runtime=request.runtime, environment=request.environment, label=request.label)
                return self._run(isolated, authorization, writable_workspace=True)
        except (FabricError, OSError, TypeError) as exc:
            return self._refused(transcript, request_hash, str(exc))

    def _run(self, request: ExecutionRequest,
             authorization: ExecutionAuthorization | None,
             *, writable_workspace: bool) -> ExecutionResult:
        transcript = SignedTranscript(self._signing_key, self._clock_ns)
        request_hash = self._request_hash(request)
        transcript.append("request.received", {"request_sha256": request_hash,
                                               "label": request.label
                                               if isinstance(request.label, str)
                                               else "invalid"})
        if (not isinstance(authorization, ExecutionAuthorization) or
                not authorization.valid()):
            return self._refused(transcript, request_hash,
                                 "explicit execution authorization is required")
        remote_selectors = _ambient_runtime_selectors()
        if remote_selectors:
            return self._refused(
                transcript, request_hash,
                "ambient runtime endpoint selection is forbidden: " +
                ", ".join(remote_selectors))
        try:
            self._validate(request)
            workspace = self._workspace(request.workspace)
        except (FabricError, OSError, TypeError) as exc:
            return self._refused(transcript, request_hash, str(exc))
        runtime = self._runtime(request.runtime)
        if runtime is None:
            reason = ("requested runtime is unavailable or does not prove rootless Linux "
                      "hardening" if request.runtime else
                      "no eligible rootless Linux Docker/Podman runtime was detected")
            return self._refused(transcript, request_hash, reason)

        container_name = "attestor35-%s" % secrets.token_hex(8)
        argv = self._argv(runtime, request, workspace, container_name,
                          writable_workspace=writable_workspace)
        argv_hash = _sha(_canonical(argv))
        transcript.append("execution.authorized", {
            "request_sha256": request_hash,
            "authorization_purpose_sha256": _sha(authorization.purpose),
            "actor_sha256": _sha(authorization.actor) if authorization.actor else "",
            "runtime": runtime.name, "argv_sha256": argv_hash,
            "controls": ["rootless", "network-none", "read-only-root", "cap-drop-all",
                         "no-new-privileges", "resource-bounds", "tmpfs-noexec", "no-shell",
                         "pull-never", "local-daemon-environment",
                         ("disposable-workspace" if writable_workspace else
                          "read-only-workspace")],
        })
        stdout_buffer, stderr_buffer = io.BytesIO(), io.BytesIO()
        budget = _OutputBudget(self.policy.max_output_bytes)
        process = None
        timed_out = False
        reason = ""
        returncode: int | None = None
        try:
            process = self._process_factory(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, shell=False, close_fds=True,
                env=self._host_environment(request.environment),
            )
            readers = [
                threading.Thread(target=_drain, args=(process.stdout, stdout_buffer, budget),
                                 daemon=True),
                threading.Thread(target=_drain, args=(process.stderr, stderr_buffer, budget),
                                 daemon=True),
            ]
            for thread in readers:
                thread.start()
            try:
                returncode = process.wait(timeout=self.policy.timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                reason = "container execution exceeded the configured timeout"
                process.kill()
                try:
                    process.wait(timeout=self.policy.kill_grace_seconds)
                except subprocess.TimeoutExpired:
                    reason += "; process did not terminate within kill grace"
                try:
                    cleaned = self._cleanup_runner(
                        runtime.executable, container_name, self._host_environment({}),
                        self.policy.kill_grace_seconds)
                    transcript.append("execution.cleanup", {
                        "container_name_sha256": _sha(container_name),
                        "removed": bool(cleaned),
                    })
                    if not cleaned:
                        reason += "; timed-out container cleanup was not confirmed"
                except (OSError, subprocess.SubprocessError, ValueError):
                    reason += "; timed-out container cleanup failed"
            for thread in readers:
                thread.join(timeout=self.policy.kill_grace_seconds)
                if thread.is_alive():
                    budget.truncated = True
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            reason = "container runtime failed: %s" % type(exc).__name__
            if process is not None:
                try:
                    process.kill()
                except OSError as kill_exc:
                    reason += "; runtime client kill failed: %s" % type(kill_exc).__name__

        exact = tuple(request.environment.values())
        stdout = _redact_text(stdout_buffer.getvalue().decode("utf-8", "replace"), exact)
        stderr = _redact_text(stderr_buffer.getvalue().decode("utf-8", "replace"), exact)
        status = "timed-out" if timed_out else ("completed" if returncode is not None else "failed")
        transcript.append("execution.finished", {
            "status": status, "returncode": returncode, "timed_out": timed_out,
            "truncated": budget.truncated, "stdout_sha256": _sha(stdout),
            "stderr_sha256": _sha(stderr), "reason": reason,
        })
        return ExecutionResult(status, returncode, stdout, stderr, timed_out,
                               budget.truncated, runtime.name, request_hash, argv_hash,
                               transcript.export(), reason)


__all__ = [
    "ExecutionAuthorization", "ExecutionFabric", "ExecutionPolicy", "ExecutionRequest",
    "ExecutionResult", "FabricCapabilities", "FabricError", "RuntimeCapability",
    "SignedTranscript", "detect_capabilities",
]
