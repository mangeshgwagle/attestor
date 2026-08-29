#!/usr/bin/env python3
"""Restricted, bounded execution gate for candidate Python code.

Forge and Patch Forge do not invoke this gate unless their caller explicitly
opts into generated-code execution.  Direct API calls to ``verify``/``imports``
are themselves an explicit execution request; the command-line interface also
requires ``--execute``.

The restricted profile combines Python isolated mode, a minimal environment, a
temporary working directory, an audit hook that blocks network/process access
and filesystem access outside the temporary directory/Python runtime, bounded
output, timeout enforcement, process-tree termination, and OS resource limits
where available.  ``sandbox_status()`` reports the precise guarantees and the
remaining platform limitation instead of claiming this is a VM/container.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time


DEFAULT_TIMEOUT = 10
MAX_TIMEOUT = 60
DEFAULT_MAX_OUTPUT = 1_000_000
MAX_SOURCE_BYTES = 5_000_000
MAX_MEMORY_BYTES = 512 * 1024 * 1024
MAX_FILESYSTEM_GROWTH_BYTES = 50 * 1024 * 1024

_SAFE_ENV_KEYS = {
    "SystemDrive",
    "SystemRoot",
    "TEMP",
    "TMP",
    "WINDIR",
}


def sandbox_status(trusted_command: bool = False) -> dict:
    """Describe the active policy without overstating kernel isolation."""
    restricted_python = not trusted_command
    if os.name == "posix":
        kernel = "POSIX rlimits and a separate process session"
    elif os.name == "nt":
        kernel = "Windows Job Object when assignable, with task-tree fallback"
    else:
        kernel = "process-tree fallback only"
    return {
        "profile": "attestor-trusted-command-v1" if trusted_command else "attestor-python-restricted-v1",
        "python_isolated_mode": restricted_python,
        "third_party_site_disabled": restricted_python,
        "minimal_environment": True,
        "network_blocked": restricted_python,
        "child_processes_blocked": restricted_python,
        "filesystem_writes": "temporary directory only" if restricted_python else "not restricted",
        "filesystem_growth_limit_bytes": MAX_FILESYSTEM_GROWTH_BYTES,
        "filesystem_reads": ("temporary directory and Python runtime only"
                             if restricted_python else "not restricted"),
        "bounded_output": True,
        "max_source_bytes": MAX_SOURCE_BYTES,
        "process_tree_termination": True,
        "os_limits": kernel,
        "windows_job_object": "reported per verdict" if os.name == "nt" else "not applicable",
        "kernel_container": False,
        "limitation": ("defence in depth, not a VM/container boundary; use an external "
                       "container or disposable VM for hostile native code"),
    }


class Verdict:
    def __init__(self, ok: bool, detail: str = "", stdout: str = "", stderr: str = "",
                 status: str = "", sandbox: dict | None = None):
        self.ok = ok
        self.detail = detail
        self.stdout = stdout
        self.stderr = stderr
        self.status = status or ("passed" if ok else "failed")
        self.sandbox = dict(sandbox or sandbox_status())

    def __bool__(self) -> bool:
        return self.ok


def _child_env(temp_dir: str = "") -> dict:
    """Minimal environment for generated code; no keys, proxies, or user paths."""
    env = {key: value for key, value in os.environ.items() if key in _SAFE_ENV_KEYS}
    env.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
    })
    if temp_dir:
        env["TEMP"] = temp_dir
        env["TMP"] = temp_dir
        env["TMPDIR"] = temp_dir
    return env


def _bounded_timeout(timeout: int | float) -> float:
    try:
        value = float(timeout)
    except (TypeError, ValueError):
        value = float(DEFAULT_TIMEOUT)
    return max(0.1, min(value, float(MAX_TIMEOUT)))


def _bounded_output(max_output: int) -> int:
    try:
        value = int(max_output)
    except (TypeError, ValueError):
        value = DEFAULT_MAX_OUTPUT
    return max(1_024, min(value, 10_000_000))


def _posix_preexec(timeout: float, max_output: int):
    if os.name != "posix":
        return None

    def apply_limits():
        import resource

        limits = [
            ("RLIMIT_CORE", 0),
            ("RLIMIT_CPU", max(1, int(math.ceil(timeout)))),
            ("RLIMIT_FSIZE", max_output),
            ("RLIMIT_NOFILE", 64),
            ("RLIMIT_NPROC", 8),
            ("RLIMIT_AS", MAX_MEMORY_BYTES),
        ]
        for name, desired in limits:
            resource_id = getattr(resource, name, None)
            if resource_id is None:
                continue
            try:
                _soft, hard = resource.getrlimit(resource_id)
                if hard == resource.RLIM_INFINITY:
                    value = desired
                else:
                    value = min(desired, hard)
                resource.setrlimit(resource_id, (value, value))
            except (OSError, ValueError):
                continue

    return apply_limits


class _WindowsJob:
    """Best-effort one-process Windows Job Object with kill-on-close."""

    def __init__(self, proc):
        self.handle = None
        if os.name != "nt":
            return
        try:
            import ctypes
            from ctypes import wintypes

            class BasicLimits(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_longlong),
                    ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class IoCounters(ctypes.Structure):
                _fields_ = [(name, ctypes.c_ulonglong) for name in (
                    "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                    "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

            class ExtendedLimits(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", BasicLimits),
                    ("IoInfo", IoCounters),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
            kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            kernel32.SetInformationJobObject.argtypes = [
                wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
            kernel32.SetInformationJobObject.restype = wintypes.BOOL
            kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
            kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
            kernel32.TerminateJobObject.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            handle = kernel32.CreateJobObjectW(None, None)
            if not handle:
                return
            info = ExtendedLimits()
            info.BasicLimitInformation.LimitFlags = 0x00000008 | 0x00000100 | 0x00002000
            info.BasicLimitInformation.ActiveProcessLimit = 1
            info.ProcessMemoryLimit = MAX_MEMORY_BYTES
            ok = kernel32.SetInformationJobObject(
                handle, 9, ctypes.byref(info), ctypes.sizeof(info))
            if ok:
                ok = kernel32.AssignProcessToJobObject(handle, int(proc._handle))  # noqa: SLF001
            if not ok:
                kernel32.CloseHandle(handle)
                return
            self._kernel32 = kernel32
            self.handle = handle
        except (AttributeError, OSError, TypeError):
            self.handle = None

    def terminate(self):
        if self.handle is not None:
            try:
                self._kernel32.TerminateJobObject(self.handle, 1)
            except (AttributeError, OSError):
                pass

    def close(self):
        if self.handle is not None:
            try:
                self._kernel32.CloseHandle(self.handle)
            except (AttributeError, OSError):
                pass
            self.handle = None


def _terminate_tree(proc, job=None):
    if proc.poll() is not None:
        return
    if job is not None:
        job.terminate()
    if os.name == "posix":
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
    elif os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=2, check=False)
        except (OSError, subprocess.SubprocessError):
            proc.kill()
    else:
        proc.kill()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()


def _limit_verdict(signal_number: int, timeout_value: float, elapsed: float,
                   stdout: str, stderr: str, profile):
    """Name the limit that killed a child, when one of ours did.

    ``_posix_preexec`` hands the kernel the CPU and file-size ceilings, so on
    POSIX a runaway usually dies by signal rather than by the polling loop
    noticing. Returns ``None`` when the signal is not one of ours -- a genuine
    segfault is a failed candidate, not a contained one, and must not be
    dressed up as a clean timeout.
    """
    sigxcpu = getattr(signal, "SIGXCPU", None)
    sigxfsz = getattr(signal, "SIGXFSZ", None)
    sigkill = getattr(signal, "SIGKILL", None)

    if sigxcpu is not None and signal_number == sigxcpu:
        return Verdict(False, "timed out after %gs (CPU limit)" % timeout_value,
                       stdout, stderr, status="timed-out", sandbox=profile)
    if sigxfsz is not None and signal_number == sigxfsz:
        return Verdict(False, "filesystem write limit exceeded (file size)",
                       stdout, stderr, status="filesystem-limited",
                       sandbox=profile)
    if sigkill is not None and signal_number == sigkill:
        # SIGKILL has more than one author: the CPU ceiling escalates to it,
        # but so does the OOM killer and so does `_terminate_tree`. Only claim
        # a timeout when the child actually ran long enough for one; otherwise
        # say what is known and no more.
        if elapsed >= timeout_value * 0.9:
            return Verdict(False,
                           "timed out after %gs (killed at the limit)"
                           % timeout_value, stdout, stderr, status="timed-out",
                           sandbox=profile)
        return Verdict(False, "killed by the sandbox before it exited",
                       stdout, stderr, status="resource-limited",
                       sandbox=profile)
    return None


class _OutputCapture:
    """Drain both pipes while retaining at most one shared byte budget."""

    def __init__(self, limit: int):
        self.limit = limit
        self.total = 0
        self.parts = {"stdout": [], "stderr": []}
        self.exceeded = threading.Event()
        self.lock = threading.Lock()

    def drain(self, name: str, stream):
        try:
            while True:
                chunk = stream.read(8_192)
                if not chunk:
                    return
                with self.lock:
                    remaining = max(0, self.limit - self.total)
                    kept = chunk[:remaining]
                    if kept:
                        self.parts[name].append(kept)
                        self.total += len(kept)
                    if len(chunk) > remaining:
                        self.exceeded.set()
                        return
        except (OSError, ValueError):
            return

    def text(self, name: str) -> str:
        return b"".join(self.parts[name]).decode("utf-8", "replace")


def _directory_size(path: str, stop_after: int | None = None) -> int:
    """Best-effort non-symlink-following size used to stop disk-filling code."""
    total = 0
    try:
        for root, _dirs, files in os.walk(path, followlinks=False):
            for name in files:
                try:
                    total += os.stat(os.path.join(root, name), follow_symlinks=False).st_size
                except OSError:
                    continue
                if stop_after is not None and total > stop_after:
                    return total
    except OSError:
        return total
    return total


def _execute(argv: list[str], cwd: str, timeout: int | float, max_output: int,
             *, trusted_command: bool = False) -> Verdict:
    cwd = os.path.abspath(cwd)
    timeout_value = _bounded_timeout(timeout)
    output_limit = _bounded_output(max_output)
    profile = sandbox_status(trusted_command=trusted_command)
    profile["timeout_seconds"] = timeout_value
    profile["output_limit_bytes"] = output_limit
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
    started = time.monotonic()
    baseline_size = _directory_size(cwd)
    try:
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_child_env(cwd),
            close_fds=True,
            start_new_session=(os.name == "posix"),
            creationflags=creationflags,
            preexec_fn=_posix_preexec(timeout_value, output_limit),
            bufsize=0,
        )
    except OSError as exc:
        return Verdict(False, "could not start restricted process: " + str(exc),
                       status="launch-failed", sandbox=profile)

    job = _WindowsJob(proc)
    if os.name == "nt":
        profile["windows_job_assigned"] = job.handle is not None
    capture = _OutputCapture(output_limit)
    readers = [
        threading.Thread(target=capture.drain, args=("stdout", proc.stdout), daemon=True),
        threading.Thread(target=capture.drain, args=("stderr", proc.stderr), daemon=True),
    ]
    for reader in readers:
        reader.start()

    stop_reason = ""
    next_disk_check = started
    try:
        while proc.poll() is None:
            elapsed = time.monotonic() - started
            if capture.exceeded.is_set():
                stop_reason = "output limit exceeded (%d bytes)" % output_limit
                _terminate_tree(proc, job)
                break
            if time.monotonic() >= next_disk_check:
                disk_limit = baseline_size + MAX_FILESYSTEM_GROWTH_BYTES
                if _directory_size(cwd, stop_after=disk_limit) > disk_limit:
                    stop_reason = "filesystem write limit exceeded (%d bytes)" % MAX_FILESYSTEM_GROWTH_BYTES
                    _terminate_tree(proc, job)
                    break
                next_disk_check = time.monotonic() + 0.1
            if elapsed > timeout_value:
                stop_reason = "timed out after %gs (infinite loop?)" % timeout_value
                _terminate_tree(proc, job)
                break
            time.sleep(0.02)
        for reader in readers:
            reader.join(timeout=1)
        if not stop_reason and capture.exceeded.is_set():
            stop_reason = "output limit exceeded (%d bytes)" % output_limit
        disk_limit = baseline_size + MAX_FILESYSTEM_GROWTH_BYTES
        if not stop_reason and _directory_size(cwd, stop_after=disk_limit) > disk_limit:
            stop_reason = "filesystem write limit exceeded (%d bytes)" % MAX_FILESYSTEM_GROWTH_BYTES
    finally:
        # ``poll`` reaps a normally exited process, while the limit paths call
        # ``_terminate_tree``.  An explicit wait makes that ownership contract
        # unconditional and visible to both readers and static typestate tools.
        try:
            proc.wait(timeout=0)
        except subprocess.TimeoutExpired:
            _terminate_tree(proc, job)
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()
        job.close()

    stdout = capture.text("stdout")
    stderr = capture.text("stderr")
    if stop_reason:
        if stop_reason.startswith("output"):
            status = "output-limited"
        elif stop_reason.startswith("filesystem"):
            status = "filesystem-limited"
        else:
            status = "timed-out"
        return Verdict(False, stop_reason, stdout, stderr, status=status, sandbox=profile)
    # On POSIX the rlimits set in `_posix_preexec` are enforced by the kernel,
    # so a runaway is killed by signal before the wall-clock check above ever
    # runs: `poll` returns, the loop exits, and `stop_reason` is still empty.
    # The containment worked -- reporting it as a plain non-zero exit would
    # lose that, and anything keying on "timed-out" would miss it.
    if proc.returncode is not None and proc.returncode < 0:
        signalled = _limit_verdict(-proc.returncode, timeout_value,
                                   time.monotonic() - started, stdout, stderr,
                                   profile)
        if signalled is not None:
            return signalled
    if proc.returncode != 0:
        tail = (stderr or stdout or "").strip().splitlines()
        why = tail[-1] if tail else "exit %d" % proc.returncode
        status = "policy-blocked" if "sandbox denied" in (stderr + stdout) else "failed"
        return Verdict(False, why, stdout, stderr, status=status, sandbox=profile)
    return Verdict(True, "ran clean under " + profile["profile"], stdout, stderr,
                   status="passed", sandbox=profile)


_SANDBOX_BOOTSTRAP = r'''
import os as _os
import sys as _sys

_ROOT = _os.path.realpath(_os.path.dirname(__file__))
_READ_ROOTS = tuple({_os.path.realpath(_ROOT), _os.path.realpath(_sys.base_prefix),
                     _os.path.realpath(_sys.exec_prefix)})
_WRITE_FLAGS = (_os.O_WRONLY | _os.O_RDWR | _os.O_CREAT | _os.O_TRUNC | _os.O_APPEND)
_BLOCKED = {
    "ctypes.call_function", "ctypes.dlopen", "ctypes.dlsym", "ctypes.dlsym/handle",
    "os.exec", "os.fork", "os.forkpty", "os.kill", "os.posix_spawn", "os.spawn",
    "os.startfile", "os.system", "pty.spawn"
}
_BLOCKED_IMPORTS = {"_ctypes", "_posixsubprocess", "_winapi"}
_PATH_EVENTS = {
    "os.chdir": (0,), "os.chmod": (0,), "os.chown": (0,), "os.mkdir": (0,),
    "os.remove": (0,), "os.rename": (0, 1), "os.rmdir": (0,),
    "os.truncate": (0,), "os.utime": (0,)
}

def _inside(_path, _roots):
    if isinstance(_path, int):
        return True
    try:
        _real = _os.path.realpath(_os.path.abspath(_os.fspath(_path)))
    except (TypeError, ValueError, OSError):
        return False
    for _base in _roots:
        try:
            if _os.path.commonpath((_real, _base)) == _base:
                return True
        except ValueError:
            continue
    return False

def _audit(_event, _args):
    if _event == "import" and _args and str(_args[0]).split(".", 1)[0] in _BLOCKED_IMPORTS:
        raise PermissionError("sandbox denied import " + str(_args[0]))
    if (_event in _BLOCKED or _event.startswith("socket.") or
            _event.startswith("subprocess.") or _event.startswith("winreg.")):
        raise PermissionError("sandbox denied " + _event)
    if _event in {"os.link", "os.symlink"}:
        raise PermissionError("sandbox denied " + _event)
    if _event == "sqlite3.connect" and _args:
        _database = _args[0]
        if _database != ":memory:":
            if isinstance(_database, str) and _database.lower().startswith("file:"):
                raise PermissionError("sandbox denied sqlite file URI")
            if not _inside(_database, (_ROOT,)):
                raise PermissionError("sandbox denied sqlite database outside temporary directory")
    if _event == "open" and _args:
        _path = _args[0]
        _mode = _args[1] if len(_args) > 1 else "r"
        _flags = _args[2] if len(_args) > 2 and isinstance(_args[2], int) else 0
        _writing = (isinstance(_mode, str) and any(_ch in _mode for _ch in "wax+")) or bool(_flags & _WRITE_FLAGS)
        _roots = (_ROOT,) if _writing else _READ_ROOTS
        if not _inside(_path, _roots):
            raise PermissionError("sandbox denied open outside allowed roots")
    for _index in _PATH_EVENTS.get(_event, ()):
        if _index < len(_args) and not _inside(_args[_index], (_ROOT,)):
            raise PermissionError("sandbox denied " + _event + " outside temporary directory")

_sys.addaudithook(_audit)
_sys.path.insert(0, _ROOT)
'''


def _run(pyfile_dir: str, code: str, timeout: int, max_output: int = DEFAULT_MAX_OUTPUT) -> Verdict:
    """Run controlled bootstrap code in a restricted isolated interpreter."""
    runner = os.path.join(pyfile_dir, "_crucible_run.py")
    with open(runner, "w", encoding="utf-8") as fh:
        fh.write(_SANDBOX_BOOTSTRAP)
        fh.write("\n")
        fh.write(code)
    return _execute(
        [sys.executable, "-I", "-S", "-B", "-X", "utf8", runner],
        pyfile_dir, timeout, max_output,
        trusted_command=False)


def _with_module(source: str, extra: str, timeout: int,
                 max_output: int = DEFAULT_MAX_OUTPUT) -> Verdict:
    if len(source.encode("utf-8")) + len(extra.encode("utf-8")) > MAX_SOURCE_BYTES:
        return Verdict(False, "candidate and smoke test exceed the 5 MB execution limit",
                       status="input-limited")
    with tempfile.TemporaryDirectory(prefix="attestor-crucible-") as tmp:
        with open(os.path.join(tmp, "candidate.py"), "w", encoding="utf-8") as fh:
            fh.write(source)
        return _run(tmp, extra, timeout, max_output)


def imports(source: str, timeout: int = DEFAULT_TIMEOUT,
            max_output: int = DEFAULT_MAX_OUTPUT) -> Verdict:
    """Explicitly execute an isolated import of ``source``."""
    return _with_module(source, "import candidate\n", timeout, max_output)


def smoke(source: str, snippet: str, timeout: int = DEFAULT_TIMEOUT,
          max_output: int = DEFAULT_MAX_OUTPUT) -> Verdict:
    """Explicitly execute a smoke-test snippet against ``source``."""
    return _with_module(source, "from candidate import *\n" + snippet, timeout, max_output)


def run_main(source: str, timeout: int = DEFAULT_TIMEOUT,
             max_output: int = DEFAULT_MAX_OUTPUT) -> Verdict:
    """Explicitly execute the candidate module's ``__main__`` path."""
    code = "import runpy\nrunpy.run_path('candidate.py', run_name='__main__')\n"
    return _with_module(source, code, timeout, max_output)


def verify(source: str, snippet: str = "", timeout: int = DEFAULT_TIMEOUT,
           max_output: int = DEFAULT_MAX_OUTPUT) -> Verdict:
    """Explicitly run the full restricted dynamic gate."""
    loaded = imports(source, timeout, max_output)
    if not loaded:
        return Verdict(False, "does not import: " + loaded.detail, loaded.stdout, loaded.stderr,
                       loaded.status, loaded.sandbox)
    if snippet:
        checked = smoke(source, snippet, timeout, max_output)
        if not checked:
            return Verdict(False, "smoke test failed: " + checked.detail,
                           checked.stdout, checked.stderr, checked.status, checked.sandbox)
    return Verdict(True, "imports and runs under " + loaded.sandbox["profile"],
                   status="passed", sandbox=loaded.sandbox)


def run_trusted_command(argv: list[str], cwd: str, *, trusted: bool = False,
                        timeout: int = DEFAULT_TIMEOUT,
                        max_output: int = DEFAULT_MAX_OUTPUT) -> Verdict:
    """Run a caller-supplied regression command after an explicit trust opt-in.

    The process is still bounded and secret-free, but arbitrary commands do not
    receive Python's audit-hook restrictions. This distinction is exposed in the
    returned sandbox profile.
    """
    if not trusted:
        return Verdict(False,
                       "trusted command execution disabled; pass trusted=True explicitly",
                       status="disabled", sandbox=sandbox_status(trusted_command=True))
    if not argv or not all(isinstance(part, str) and part for part in argv):
        return Verdict(False, "regression command is empty", status="launch-failed",
                       sandbox=sandbox_status(trusted_command=True))
    return _execute(list(argv), cwd, timeout, max_output, trusted_command=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", nargs="?", help="the Python file to put through the crucible")
    ap.add_argument("--main", action="store_true", help="also run its __main__ block")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("--execute", action="store_true",
                    help="explicitly opt into executing this candidate")
    ap.add_argument("--sandbox-status", action="store_true",
                    help="print the active restriction profile")
    args = ap.parse_args(argv)

    if args.sandbox_status:
        print(json.dumps(sandbox_status(), indent=2, sort_keys=True))
        if not args.file:
            return 0
    if not args.file:
        print("a Python file is required", file=sys.stderr)
        return 2
    if not args.execute:
        print("execution disabled by default; inspect the file, then pass --execute to opt in",
              file=sys.stderr)
        return 3
    if not os.path.exists(args.file):
        print("no such file: " + args.file, file=sys.stderr)
        return 2
    with open(args.file, encoding="utf-8", errors="replace") as fh:
        source = fh.read()

    loaded = imports(source, args.timeout)
    print("sandbox : " + loaded.sandbox["profile"] + " (not a VM/container)")
    print("imports : " + ("OK" if loaded else "FAIL -- " + loaded.detail))
    code = 0 if loaded else 1
    if args.main and loaded:
        ran = run_main(source, args.timeout)
        print("__main__: " + ("OK" if ran else "FAIL -- " + ran.detail))
        code = 0 if ran else 1
    return code


if __name__ == "__main__":
    raise SystemExit(main())
