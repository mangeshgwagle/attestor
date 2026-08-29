#!/usr/bin/env python3
"""Deny-by-default, bounded runtime support for Attestor's verification lab.

This module is deliberately *not* described as a security sandbox.  Python's
standard library cannot create a strong network/process sandbox on every
supported operating system.  The lab therefore refuses execution by default,
uses an isolated project copy, applies OS resource limits where available, and
installs a Python startup guard for selected Python test commands.  Its
``availability`` report names the guarantees that are strong, best-effort, or
unavailable so callers never confuse a policy hook with kernel isolation.

Generated or target code needs a second, separate authorization in addition to
the general execution gate.  Attestor's remediation pipeline only uses the
``selected-tests`` purpose; it never executes the proposed source directly.
"""
from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import json
import math
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Sequence


DEFAULT_MAX_OUTPUT = 64 * 1024
DEFAULT_TIMEOUT = 20.0
MAX_TIMEOUT = 300.0
MAX_OUTPUT = 4 * 1024 * 1024
MAX_STAGE_BYTES = 512 * 1024 * 1024
MAX_STAGE_FILES = 50_000
IGNORED_DIRECTORIES = {
    ".git", ".hg", ".svn", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".tox", ".venv", "venv", "node_modules", "vendor", "dist", "build",
    "target", "__pycache__", ".attestor-backups",
}


@dataclass(frozen=True)
class RuntimePolicy:
    """Explicit execution policy.  Every execution capability defaults off."""

    allow_execution: bool = False
    allow_target_execution: bool = False
    allow_network: bool = False
    allow_child_processes: bool = False
    allow_unisolated_non_python: bool = False
    timeout_seconds: float = DEFAULT_TIMEOUT
    cpu_seconds: int = 10
    memory_bytes: int = 512 * 1024 * 1024
    max_output_bytes: int = DEFAULT_MAX_OUTPUT
    max_processes: int = 1
    deterministic_seed: int = 13_371
    allowed_executables: tuple[str, ...] = field(
        default_factory=lambda: (str(Path(sys.executable).resolve()),))

    @classmethod
    def selected_tests(cls, **overrides) -> "RuntimePolicy":
        """Return a network-denied policy after explicit test authorization."""
        values = dataclasses.asdict(cls())
        values.update(overrides)
        values["allow_execution"] = True
        values["allowed_executables"] = tuple(values["allowed_executables"])
        return cls(**values)

    def validated(self) -> "RuntimePolicy":
        if not 0.05 <= float(self.timeout_seconds) <= MAX_TIMEOUT:
            raise ValueError("timeout_seconds must be between 0.05 and 300")
        if not 1 <= int(self.cpu_seconds) <= 300:
            raise ValueError("cpu_seconds must be between 1 and 300")
        if not 16 * 1024 * 1024 <= int(self.memory_bytes) <= 16 * 1024**3:
            raise ValueError("memory_bytes must be between 16 MiB and 16 GiB")
        if not 1 <= int(self.max_output_bytes) <= MAX_OUTPUT:
            raise ValueError("max_output_bytes must be between 1 byte and 4 MiB")
        if not 1 <= int(self.max_processes) <= 128:
            raise ValueError("max_processes must be between 1 and 128")
        if not 0 <= int(self.deterministic_seed) <= 2**32 - 1:
            raise ValueError("deterministic_seed must be an unsigned 32-bit integer")
        if any(not isinstance(item, str) or not item for item in self.allowed_executables):
            raise ValueError("allowed_executables must contain non-empty paths")
        return self


@dataclass(frozen=True)
class Capability:
    name: str
    available: bool
    strength: str
    detail: str


@dataclass(frozen=True)
class LabAvailability:
    platform: str
    capabilities: tuple[Capability, ...]
    safe_for_untrusted_code: bool = False
    summary: str = (
        "Bounded verification helper only; no cross-platform stdlib security "
        "sandbox is available for hostile code."
    )


@dataclass(frozen=True)
class StageInfo:
    source: str
    root: str
    files: int
    bytes: int
    skipped: tuple[str, ...]
    manifest_sha256: str


@dataclass(frozen=True)
class RuntimeResult:
    purpose: str
    status: str
    command: tuple[str, ...] = ()
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    truncated: bool = False
    timed_out: bool = False
    elapsed_ms: int = 0
    network_policy: str = "not-applicable"
    process_policy: str = "not-applicable"
    resource_policy: str = "not-applicable"
    changed_paths: tuple[str, ...] = ()
    detail: str = ""

    @property
    def passed(self) -> bool:
        return self.status == "passed"


def availability() -> LabAvailability:
    posix_limits = os.name == "posix"
    python_guard = bool(sys.executable)
    return LabAvailability(
        platform="%s/%s" % (sys.platform, os.name),
        capabilities=(
            Capability("execution-default-deny", True, "policy",
                       "Execution needs an explicit allow flag and executable allowlist."),
            Capability("target-execution-separate-gate", True, "policy",
                       "Generated/target execution needs a second explicit authorization."),
            Capability("wall-clock-timeout", True, "process",
                       "The parent kills a command that exceeds its wall-clock budget."),
            Capability("bounded-captured-output", True, "process",
                       "Retained stdout/stderr are capped; excess bytes are discarded."),
            Capability("posix-cpu-memory-process-limits", posix_limits,
                       "kernel" if posix_limits else "unavailable",
                       "resource.setrlimit is used on POSIX; stdlib has no Windows Job Object adapter."),
            Capability("python-network-guard", python_guard, "language-hook",
                       "socket APIs are denied for normal Python startup; native code or deliberate bypasses are not contained."),
            Capability("kernel-network-isolation", False, "unavailable",
                       "No portable stdlib kernel network namespace/firewall sandbox is available."),
            Capability("python-child-process-guard", python_guard, "language-hook",
                       "subprocess/os launch helpers are denied during selected Python tests unless allowed."),
            Capability("hostile-code-containment", False, "unavailable",
                       "Use a hardened container/VM sandbox for adversarial binaries or generated code."),
        ),
    )


def _is_link(path: Path) -> bool:
    if path.is_symlink():
        return True
    checker = getattr(path, "is_junction", None)
    return bool(checker and checker())


def _manifest(root: Path, *, max_bytes: int = MAX_STAGE_BYTES,
              max_files: int = MAX_STAGE_FILES) -> tuple[str, dict[str, str]]:
    digest = hashlib.sha256()
    rows: dict[str, str] = {}
    total = 0
    count = 0
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(
            name for name in directories
            if name not in IGNORED_DIRECTORIES and not _is_link(current_path / name))
        for name in sorted(files):
            path = current_path / name
            if _is_link(path):
                continue
            relative = path.relative_to(root).as_posix()
            size = path.stat().st_size
            total += size
            count += 1
            if total > max_bytes:
                raise ValueError("runtime workspace exceeds %d bytes" % max_bytes)
            if count > max_files:
                raise ValueError("runtime workspace exceeds %d files" % max_files)
            file_digest = hashlib.sha256()
            with path.open("rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    file_digest.update(chunk)
            file_hash = file_digest.hexdigest()
            rows[relative] = file_hash
            digest.update(relative.encode("utf-8") + b"\0")
            digest.update(str(size).encode("ascii") + b"\0")
            digest.update(file_hash.encode("ascii") + b"\0")
    return digest.hexdigest(), rows


def _copy_stage(source: Path, destination: Path, *, max_bytes: int,
                max_files: int) -> StageInfo:
    destination.mkdir(parents=True, exist_ok=False)
    skipped: list[str] = []
    total = 0
    count = 0
    for current, directories, files in os.walk(source, followlinks=False):
        current_path = Path(current)
        relative_dir = current_path.relative_to(source)
        kept = []
        for name in sorted(directories):
            child = current_path / name
            relative = child.relative_to(source).as_posix()
            if name in IGNORED_DIRECTORIES:
                skipped.append(relative + "/ (ignored)")
            elif _is_link(child):
                skipped.append(relative + " (link)")
            else:
                kept.append(name)
        directories[:] = kept
        (destination / relative_dir).mkdir(parents=True, exist_ok=True)
        for name in sorted(files):
            item = current_path / name
            relative = item.relative_to(source)
            if _is_link(item):
                skipped.append(relative.as_posix() + " (link)")
                continue
            size = item.stat().st_size
            total += size
            count += 1
            if total > max_bytes:
                raise ValueError("stage exceeds %d bytes" % max_bytes)
            if count > max_files:
                raise ValueError("stage exceeds %d files" % max_files)
            output = destination / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, output)
    manifest, _ = _manifest(destination)
    return StageInfo(str(source), str(destination), count, total,
                     tuple(skipped), manifest)


@contextlib.contextmanager
def staged_project(project_root: str | os.PathLike[str], *,
                   max_bytes: int = MAX_STAGE_BYTES,
                   max_files: int = MAX_STAGE_FILES) -> Iterator[StageInfo]:
    """Yield metadata for a disposable, regular-files-only project copy."""
    source = Path(project_root).expanduser().resolve()
    if not source.is_dir() or _is_link(source):
        raise ValueError("project_root must be a real directory, not a link")
    source_manifest, _ = _manifest(source, max_bytes=max_bytes, max_files=max_files)
    with tempfile.TemporaryDirectory(prefix="attestor-runtime-lab-") as temporary:
        root = Path(temporary) / "project"
        info = _copy_stage(source, root, max_bytes=max_bytes, max_files=max_files)
        source_after, _ = _manifest(source, max_bytes=max_bytes, max_files=max_files)
        if source_after != source_manifest or info.manifest_sha256 != source_manifest:
            raise RuntimeError("project changed while its isolated runtime copy was created")
        yield info


class _BoundedReader(threading.Thread):
    def __init__(self, stream, limit: int):
        super().__init__(daemon=True)
        self.stream = stream
        self.limit = max(0, limit)
        self.data = bytearray()
        self.truncated = False

    def run(self) -> None:
        try:
            while True:
                chunk = self.stream.read(8192)
                if not chunk:
                    break
                remaining = self.limit - len(self.data)
                if remaining > 0:
                    self.data.extend(chunk[:remaining])
                if len(chunk) > max(0, remaining):
                    self.truncated = True
        finally:
            self.stream.close()


_PYTHON_GUARD = r'''"""Ephemeral Attestor runtime policy hook."""
import os

def _denied(*args, **kwargs):
    raise PermissionError("disabled by Attestor Runtime Lab policy")

if os.environ.get("ATTESTOR_NETWORK_DISABLED") == "1":
    import socket
    socket.socket = _denied
    socket.socketpair = _denied
    socket.create_connection = _denied
    socket.getaddrinfo = _denied

if os.environ.get("ATTESTOR_CHILD_PROCESSES_DISABLED") == "1":
    import subprocess
    subprocess.Popen = _denied
    subprocess.run = _denied
    subprocess.call = _denied
    subprocess.check_call = _denied
    subprocess.check_output = _denied
    os.system = _denied
    os.popen = _denied
    for _name in ("spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe"):
        if hasattr(os, _name):
            setattr(os, _name, _denied)
'''


def _minimal_environment(policy: RuntimePolicy, guard_directory: Path | None) -> dict[str, str]:
    allowed = {
        "PATH", "PATHEXT", "SystemRoot", "WINDIR", "COMSPEC", "TEMP", "TMP",
        "HOME", "USERPROFILE", "LANG", "LC_ALL",
    }
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment.update({
        "CI": "1", "NO_COLOR": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8", "PYTHONHASHSEED": str(policy.deterministic_seed),
        "ATTESTOR_DETERMINISTIC_SEED": str(policy.deterministic_seed),
        "ATTESTOR_NETWORK_DISABLED": "0" if policy.allow_network else "1",
        "ATTESTOR_CHILD_PROCESSES_DISABLED": "0" if policy.allow_child_processes else "1",
    })
    if guard_directory is not None:
        environment["PYTHONPATH"] = str(guard_directory)
    return environment


def _python_executable(path: str) -> bool:
    try:
        return Path(path).resolve() == Path(sys.executable).resolve()
    except OSError:
        return False


def _allowed_executable(executable: str, allowed: Sequence[str]) -> bool:
    candidate = shutil.which(executable) or executable
    try:
        resolved = Path(candidate).expanduser().resolve()
    except OSError:
        return False
    for item in allowed:
        possible = shutil.which(item) or item
        try:
            if resolved == Path(possible).expanduser().resolve():
                return True
        except OSError:
            continue
    return False


def _posix_preexec(policy: RuntimePolicy):
    if os.name != "posix":
        return None

    def configure() -> None:
        import resource
        cpu = max(1, min(int(policy.cpu_seconds), int(math.ceil(policy.timeout_seconds))))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        resource.setrlimit(resource.RLIMIT_AS, (int(policy.memory_bytes), int(policy.memory_bytes)))
        if hasattr(resource, "RLIMIT_NPROC"):
            resource.setrlimit(resource.RLIMIT_NPROC,
                               (int(policy.max_processes), int(policy.max_processes)))
        if hasattr(resource, "RLIMIT_CORE"):
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    return configure


def _kill_process(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except (OSError, ProcessLookupError):
        try:
            proc.kill()
        except OSError:
            return


def _changed(before: dict[str, str], after: dict[str, str]) -> tuple[str, ...]:
    return tuple(sorted(
        key for key in set(before) | set(after) if before.get(key) != after.get(key)))


def run_command(command: Sequence[str], cwd: str | os.PathLike[str], *,
                policy: RuntimePolicy | None = None, authorized: bool = False,
                purpose: str = "selected-tests") -> RuntimeResult:
    """Run an allowlisted command within explicit policy bounds.

    ``purpose='target-execution'`` is always rejected unless the policy's
    separate target gate is true.  With network denied, only normal Python
    startup is supported because that is the only portable enforcement hook
    available here.  Commands using ``-I``, ``-S``, or ``-E`` are refused since
    those options bypass the startup policy hook.
    """
    chosen = (policy or RuntimePolicy()).validated()
    if isinstance(command, (str, bytes)):
        raise TypeError("command must be an argv sequence, never a shell string")
    argv = tuple(command)
    if not argv or any(not isinstance(value, str) or "\x00" in value for value in argv):
        raise ValueError("command must contain valid string arguments")
    work = Path(cwd).expanduser().resolve()
    if not work.is_dir() or _is_link(work):
        raise ValueError("cwd must be a real directory")
    if purpose not in {"selected-tests", "property-probe", "fuzz-probe", "target-execution"}:
        raise ValueError("unknown execution purpose")
    if not authorized or not chosen.allow_execution:
        return RuntimeResult(purpose, "refused", argv, detail=(
            "execution is disabled; both authorized=True and policy.allow_execution=True are required"))
    if purpose == "target-execution" and not chosen.allow_target_execution:
        return RuntimeResult(purpose, "refused", argv,
                             detail=("target execution needs the second explicit gate: "
                                     "policy.allow_target_execution=True"))
    if not _allowed_executable(argv[0], chosen.allowed_executables):
        return RuntimeResult(purpose, "refused", argv,
                             detail="executable is not on the explicit allowlist")

    python_command = _python_executable(shutil.which(argv[0]) or argv[0])
    bypass_flags = {"-I", "-S", "-E"}.intersection(argv[1:])
    if not chosen.allow_network and (not python_command or bypass_flags):
        if not chosen.allow_unisolated_non_python:
            detail = ("network-denied execution requires normal Python startup so the "
                      "language guard loads; kernel network isolation is unavailable")
            return RuntimeResult(purpose, "refused", argv, network_policy="unavailable", detail=detail)

    before_manifest, before_files = _manifest(work)
    del before_manifest
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="attestor-runtime-policy-") as temporary:
        guard = Path(temporary)
        guard_directory: Path | None = None
        if python_command and (not chosen.allow_network or not chosen.allow_child_processes):
            (guard / "sitecustomize.py").write_text(_PYTHON_GUARD, encoding="utf-8")
            guard_directory = guard
        environment = _minimal_environment(chosen, guard_directory)
        kwargs = {
            "cwd": str(work), "env": environment, "shell": False,
            "stdin": subprocess.DEVNULL, "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE, "preexec_fn": _posix_preexec(chosen),
        }
        if os.name == "posix":
            kwargs["start_new_session"] = True
        elif hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        try:
            proc = subprocess.Popen(list(argv), **kwargs)
        except OSError as exc:
            return RuntimeResult(
                purpose, "failed", argv,
                elapsed_ms=int((time.perf_counter() - started) * 1000),
                detail="could not start command: %s" % exc)
        stdout_reader = _BoundedReader(proc.stdout, (chosen.max_output_bytes + 1) // 2)
        stderr_reader = _BoundedReader(proc.stderr, chosen.max_output_bytes // 2)
        stdout_reader.start()
        stderr_reader.start()
        timed_out = False
        try:
            returncode = proc.wait(timeout=float(chosen.timeout_seconds))
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process(proc)
            returncode = proc.wait()
        stdout_reader.join(timeout=5)
        stderr_reader.join(timeout=5)

    stdout = bytes(stdout_reader.data).decode("utf-8", "replace")
    stderr = bytes(stderr_reader.data).decode("utf-8", "replace")
    truncated = stdout_reader.truncated or stderr_reader.truncated
    if truncated:
        marker = "\n[output truncated by Attestor Runtime Lab]"
        if stdout_reader.truncated:
            stdout += marker
        if stderr_reader.truncated:
            stderr += marker
    try:
        _, after_files = _manifest(work)
    except (OSError, ValueError) as exc:
        after_files = before_files
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return RuntimeResult(
            purpose, "failed", argv, returncode, stdout, stderr, truncated,
            timed_out, elapsed_ms,
            "allowed" if chosen.allow_network else
            ("python-language-guard" if python_command else "unavailable"),
            "allowed" if chosen.allow_child_processes else
            ("python-language-guard" if python_command else "unavailable"),
            "posix-rlimit+wall-clock" if os.name == "posix" else "wall-clock-only",
            (), "could not safely inventory runtime changes: %s" % exc)
    changed_paths = _changed(before_files, after_files)
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    status = "failed" if timed_out or returncode else "passed"
    network_policy = (
        "allowed" if chosen.allow_network else
        ("python-language-guard" if python_command else "unavailable"))
    process_policy = (
        "allowed" if chosen.allow_child_processes else
        ("python-language-guard" if python_command else
         ("posix-rlimit" if os.name == "posix" else "unavailable")))
    resource_policy = "posix-rlimit+wall-clock" if os.name == "posix" else "wall-clock-only"
    detail = ("timed out after %.2f seconds" % chosen.timeout_seconds if timed_out
              else "exit code %d" % returncode)
    return RuntimeResult(
        purpose, status, argv, returncode, stdout, stderr, truncated, timed_out,
        elapsed_ms, network_policy, process_policy, resource_policy,
        changed_paths, detail)


def run_selected_tests(command: Sequence[str], cwd: str | os.PathLike[str], *,
                       authorized: bool = False,
                       policy: RuntimePolicy | None = None) -> RuntimeResult:
    """Convenience API that still preserves both explicit execution gates."""
    return run_command(command, cwd, policy=policy, authorized=authorized,
                       purpose="selected-tests")


def _as_dict(value):
    if dataclasses.is_dataclass(value):
        return {field.name: _as_dict(getattr(value, field.name))
                for field in dataclasses.fields(value)}
    if isinstance(value, (tuple, list)):
        return [_as_dict(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _as_dict(item) for key, item in value.items()}
    return value


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--availability", action="store_true")
    parser.add_argument("--cwd", default=".")
    parser.add_argument("--allow-execution", action="store_true")
    parser.add_argument("--allow-target-execution", action="store_true")
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--allow-child-processes", action="store_true")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--max-output", type=int, default=DEFAULT_MAX_OUTPUT)
    parser.add_argument("--seed", type=int, default=13_371)
    parser.add_argument("--purpose", choices=(
        "selected-tests", "property-probe", "fuzz-probe", "target-execution"),
        default="selected-tests")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.availability:
        print(json.dumps(_as_dict(availability()), indent=2, sort_keys=True))
        return 0
    if not args.command:
        parser.error("a command is required unless --availability is used")
    executable = shutil.which(args.command[0]) or args.command[0]
    policy = RuntimePolicy(
        allow_execution=args.allow_execution,
        allow_target_execution=args.allow_target_execution,
        allow_network=args.allow_network,
        allow_child_processes=args.allow_child_processes,
        timeout_seconds=args.timeout,
        max_output_bytes=args.max_output,
        deterministic_seed=args.seed,
        allowed_executables=(str(Path(executable).resolve()),),
    )
    result = run_command(args.command, args.cwd, policy=policy,
                         authorized=args.allow_execution, purpose=args.purpose)
    print(json.dumps(_as_dict(result), indent=2, sort_keys=True))
    return 0 if result.passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
