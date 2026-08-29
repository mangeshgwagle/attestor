#!/usr/bin/env python3
"""Transactional verification and application of proposed source patches.

PatchGuard never runs generated code by default.  It copies the project into a
temporary workspace, asks :mod:`scanengine` to scan and syntax-check both the
before and after trees, and rejects compiler failures or new static findings.
An optional test command is an argv vector (never a shell command), requires an
explicit authorization flag, receives a small environment, and has bounded
time and captured output.

Applying a candidate is a separate, explicit transaction.  The source must be
unchanged since verification, a durable backup is written first, and the target
is replaced atomically.  A failed post-apply check restores the backup.
"""
from __future__ import annotations

import argparse
import collections
import dataclasses
import difflib
import hashlib
import json
import os
import pprint
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping, Sequence

import scanengine


MAX_CANDIDATE_BYTES = 2 * 1024 * 1024
MAX_PROJECT_COPY_BYTES = 512 * 1024 * 1024
MAX_PROJECT_FILES = 50_000
DEFAULT_TEST_TIMEOUT = 30.0
DEFAULT_MAX_OUTPUT = 64 * 1024
COMPILED_LANGUAGES = {
    "python", "c", "cpp", "javascript", "typescript", "rust", "go",
    "java", "csharp", "haskell",
}
_SEVERITY_WEIGHT = {
    "CRITICAL": 100_000, "HIGH": 20_000, "MEDIUM": 3_000,
    "LOW": 300, "INFO": 10,
}


@dataclass(frozen=True)
class TestResult:
    command: tuple[str, ...] = ()
    status: str = "not-run"
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    truncated: bool = False
    timed_out: bool = False
    elapsed_ms: int = 0
    detail: str = "tests were not requested"

    @property
    def passed(self) -> bool:
        return self.status in {"not-run", "passed"}


@dataclass(frozen=True)
class ScanSummary:
    status: str
    files_scanned: int
    verification: str
    issues: tuple[scanengine.Issue, ...] = ()
    errors: tuple[str, ...] = ()


@dataclass
class CandidateReport:
    name: str
    project_root: str
    target: str
    accepted: bool
    reasons: tuple[str, ...]
    original_sha256: str
    candidate_sha256: str
    project_sha256: str
    diff: str
    changed_lines: int
    baseline: ScanSummary
    candidate: ScanSummary
    new_issues: tuple[scanengine.Issue, ...] = ()
    resolved_issues: tuple[scanengine.Issue, ...] = ()
    high_regressions: tuple[scanengine.Issue, ...] = ()
    new_failures: tuple[str, ...] = ()
    test: TestResult = field(default_factory=TestResult)
    score: int = 0
    skipped_links: tuple[str, ...] = ()
    verification_scope: str = "project"


@dataclass(frozen=True)
class RegressionArtifact:
    suggested_path: str
    content: str
    rules: tuple[str, ...]


@dataclass(frozen=True)
class ApplyResult:
    target: str
    backup: str
    applied: bool
    rolled_back: bool
    original_sha256: str
    candidate_sha256: str
    detail: str


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_link(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction and is_junction())


def _project_and_target(project_root: str | os.PathLike[str],
                        target: str | os.PathLike[str]) -> tuple[Path, Path, Path]:
    root = Path(project_root).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("project root is not a directory: %s" % root)
    relative = Path(target)
    if relative.is_absolute() or not relative.parts or any(
            part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("target must be a normalized project-relative path")
    # Colons can name alternate data streams on Windows and have no place in a
    # portable project-relative source path.
    if any(":" in part for part in relative.parts):
        raise ValueError("target path contains a forbidden colon")
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if _is_link(cursor):
            raise ValueError("target may not traverse a symlink or junction")
    resolved = (root / relative).resolve()
    try:
        normalized = resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("target escapes the project root") from exc
    if not resolved.is_file():
        raise ValueError("target is not a regular file: %s" % resolved)
    return root, normalized, resolved


def unified_diff(original: str, candidate: str, target: str) -> str:
    """Return a complete, deterministic unified diff for a replacement file."""
    name = Path(target).as_posix()
    return "".join(difflib.unified_diff(
        original.splitlines(keepends=True), candidate.splitlines(keepends=True),
        fromfile="a/" + name, tofile="b/" + name,
    ))


def _changed_lines(diff: str) -> int:
    return sum(1 for line in diff.splitlines()
               if line.startswith(("+", "-")) and not line.startswith(("+++", "---")))


def _copy_project(source: Path, destination: Path, *,
                  max_bytes: int = MAX_PROJECT_COPY_BYTES,
                  max_files: int = MAX_PROJECT_FILES) -> list[str]:
    """Copy regular files only; links are deliberately omitted from the sandbox."""
    destination.mkdir(parents=True, exist_ok=False)
    skipped: list[str] = []
    total = 0
    count = 0
    ignored = set(scanengine.SKIP_DIRS) | {".attestor-backups"}
    for current, directories, filenames in os.walk(source, followlinks=False):
        current_path = Path(current)
        relative_dir = current_path.relative_to(source)
        keep_dirs = []
        for name in directories:
            child = current_path / name
            rel = child.relative_to(source).as_posix()
            if name in ignored:
                skipped.append(rel + "/ (ignored)")
            elif _is_link(child):
                skipped.append(rel + " (link)")
            else:
                keep_dirs.append(name)
        directories[:] = keep_dirs
        (destination / relative_dir).mkdir(parents=True, exist_ok=True)
        for name in filenames:
            item = current_path / name
            relative = item.relative_to(source)
            if _is_link(item):
                skipped.append(relative.as_posix() + " (link)")
                continue
            try:
                size = item.stat().st_size
            except OSError as exc:
                raise RuntimeError("cannot inspect %s: %s" % (item, exc)) from exc
            total += size
            count += 1
            if total > max_bytes:
                raise ValueError("project copy exceeds %d bytes" % max_bytes)
            if count > max_files:
                raise ValueError("project copy exceeds %d files" % max_files)
            output = destination / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, output)
    return skipped


def _project_manifest(root: Path, *, max_bytes: int = MAX_PROJECT_COPY_BYTES,
                      max_files: int = MAX_PROJECT_FILES) -> str:
    """Hash the same regular-file project view that is copied for verification."""
    digest = hashlib.sha256()
    total = 0
    count = 0
    ignored = set(scanengine.SKIP_DIRS) | {".attestor-backups"}
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(
            name for name in directories
            if name not in ignored and not _is_link(current_path / name))
        for name in sorted(filenames):
            item = current_path / name
            if _is_link(item):
                continue
            relative = item.relative_to(root).as_posix()
            data = item.read_bytes()
            count += 1
            total += len(data)
            if count > max_files or total > max_bytes:
                raise ValueError("project manifest exceeds verification limits")
            digest.update(relative.encode("utf-8"))
            digest.update(b"\0")
            digest.update(str(len(data)).encode("ascii"))
            digest.update(b"\0")
            digest.update(data)
            digest.update(b"\0")
    return digest.hexdigest()


def _exact_file_manifest(root: Path, relative: Path, target: Path) -> str:
    """Bind one exact regular file without reading any sibling artifact."""
    resolved_root = root.resolve()
    resolved_target = target.resolve()
    try:
        normalized = resolved_target.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError("exact-file target escapes its verification root") from exc
    if (normalized != relative or not resolved_target.is_file() or
            _is_link(resolved_target)):
        raise ValueError("exact-file verification target is missing or unsafe")
    data = resolved_target.read_bytes()
    digest = hashlib.sha256()
    digest.update(relative.as_posix().encode("utf-8"))
    digest.update(b"\0")
    digest.update(str(len(data)).encode("ascii"))
    digest.update(b"\0")
    digest.update(data)
    digest.update(b"\0")
    return digest.hexdigest()


def _minimal_env() -> dict[str, str]:
    allowed = {
        "PATH", "PATHEXT", "SystemRoot", "WINDIR", "COMSPEC", "TEMP", "TMP",
        "HOME", "USERPROFILE",
    }
    env = {key: value for key, value in os.environ.items() if key in allowed}
    env.update({
        "CI": "1", "NO_COLOR": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
    })
    return env


class _PipeReader(threading.Thread):
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


def run_test_command(command: Sequence[str], cwd: str | os.PathLike[str], *,
                     authorized: bool = False,
                     timeout: float = DEFAULT_TEST_TIMEOUT,
                     max_output: int = DEFAULT_MAX_OUTPUT) -> TestResult:
    """Run an explicitly trusted argv vector without a shell.

    This is an execution guard, not a security sandbox.  The caller is required
    to make the trust decision explicitly.  Execution happens only inside the
    temporary project copy used by :func:`verify_candidate`.
    """
    if not authorized:
        raise PermissionError("test execution requires authorized=True/--run-tests")
    if isinstance(command, (str, bytes)):
        raise TypeError("test command must be an argv sequence, not a shell string")
    argv = tuple(command)
    if not argv or any(not isinstance(arg, str) or "\x00" in arg for arg in argv):
        raise ValueError("test command must contain valid string arguments")
    if not (0.05 <= float(timeout) <= 300.0):
        raise ValueError("test timeout must be between 0.05 and 300 seconds")
    if not (1 <= int(max_output) <= 4 * 1024 * 1024):
        raise ValueError("max output must be between 1 byte and 4 MiB")
    work = Path(cwd).resolve()
    if not work.is_dir():
        raise ValueError("test working directory does not exist")

    started = time.perf_counter()
    try:
        # Popen itself has no timeout parameter; the bounded wait/kill below is
        # the timeout gate, while reader threads cap retained output.
        popen = subprocess.Popen
        proc = popen(
            list(argv), cwd=str(work), env=_minimal_env(), shell=False,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except OSError as exc:
        return TestResult(argv, "failed", detail="could not start: %s" % exc,
                          elapsed_ms=int((time.perf_counter() - started) * 1000))
    stdout_reader = _PipeReader(proc.stdout, (max_output + 1) // 2)
    stderr_reader = _PipeReader(proc.stderr, max_output // 2)
    stdout_reader.start()
    stderr_reader.start()
    timed_out = False
    try:
        returncode = proc.wait(timeout=float(timeout))
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        returncode = proc.wait()
    stdout_reader.join(timeout=5)
    stderr_reader.join(timeout=5)
    stdout = bytes(stdout_reader.data).decode("utf-8", "replace")
    stderr = bytes(stderr_reader.data).decode("utf-8", "replace")
    truncated = stdout_reader.truncated or stderr_reader.truncated
    if truncated:
        marker = "\n[output truncated by PatchGuard]"
        if stdout_reader.truncated:
            stdout += marker
        if stderr_reader.truncated:
            stderr += marker
    elapsed = int((time.perf_counter() - started) * 1000)
    if timed_out:
        return TestResult(argv, "failed", returncode, stdout, stderr, truncated,
                          True, elapsed, "timed out after %.2f seconds" % timeout)
    status = "passed" if returncode == 0 else "failed"
    return TestResult(argv, status, returncode, stdout, stderr, truncated,
                      False, elapsed, "exit code %d" % returncode)


def _relative(path: str, root: Path) -> str:
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return Path(path).name


def _clean_detail(value: str, root: Path) -> str:
    text = str(value)
    for spelling in {str(root), root.as_posix()}:
        text = text.replace(spelling, "<PROJECT>")
    return text


def _rebase_issue(issue: scanengine.Issue, source_root: Path,
                  destination_root: Path) -> scanengine.Issue:
    relative = _relative(issue.path, source_root)
    message = _clean_detail(issue.message, source_root)
    fix = _clean_detail(issue.fix, source_root)
    return dataclasses.replace(
        issue, path=str(destination_root / Path(relative)), message=message, fix=fix,
    )


def _issue_base(issue: scanengine.Issue, root: Path) -> tuple[str, str, str]:
    return (_relative(issue.path, root), issue.rule, _clean_detail(issue.message, root))


def _issue_key(issue: scanengine.Issue, root: Path) -> tuple[str, str, str, str]:
    return _issue_base(issue, root) + (issue.severity.upper(),)


def _multiset_delta(left: Iterable[scanengine.Issue], left_root: Path,
                    right: Iterable[scanengine.Issue], right_root: Path,
                    report_root: Path) -> tuple[scanengine.Issue, ...]:
    """Return items present in ``left`` more often than in ``right``."""
    remaining = collections.Counter(_issue_key(item, right_root) for item in right)
    delta = []
    for item in left:
        key = _issue_key(item, left_root)
        if remaining[key]:
            remaining[key] -= 1
        else:
            delta.append(_rebase_issue(item, left_root, report_root))
    return tuple(delta)


def _failure_rows(result: scanengine.WorkspaceResult, root: Path) -> list[str]:
    rows = []
    for file_result in result.files:
        relative = _relative(file_result.path, root)
        for error in file_result.errors:
            rows.append("%s: scan: %s" % (relative, _clean_detail(error, root)))
        for check in file_result.tools:
            if check.status == "failed":
                rows.append("%s: %s: %s" % (
                    relative, check.name, _clean_detail(check.detail, root)))
    for error in result.errors:
        cleaned = _clean_detail(error, root)
        if cleaned not in rows and not any(cleaned in row for row in rows):
            rows.append("workspace: " + cleaned)
    return rows


def _counter_delta(left: Iterable[str], right: Iterable[str]) -> tuple[str, ...]:
    remaining = collections.Counter(right)
    out = []
    for value in left:
        if remaining[value]:
            remaining[value] -= 1
        else:
            out.append(value)
    return tuple(out)


def _scan_summary(result: scanengine.WorkspaceResult, source_root: Path,
                  report_root: Path, target: Path) -> ScanSummary:
    target_result = next((row for row in result.files
                          if _relative(row.path, source_root) == target.as_posix()), None)
    verification = target_result.verification if target_result else "missing"
    issues = tuple(_rebase_issue(item, source_root, report_root) for item in result.issues)
    errors = tuple(_clean_detail(item, source_root) for item in result.errors)
    return ScanSummary(result.status, result.files_scanned, verification, issues, errors)


def _severity_regressions(baseline: Iterable[scanengine.Issue], baseline_root: Path,
                          candidate: Iterable[scanengine.Issue], candidate_root: Path,
                          report_root: Path) -> tuple[scanengine.Issue, ...]:
    before: dict[tuple[str, str, str], list[int]] = collections.defaultdict(list)
    for item in baseline:
        before[_issue_base(item, baseline_root)].append(
            scanengine.SEVERITY_RANK.get(item.severity.upper(), 0))
    regressions = []
    for item in candidate:
        ranks = before.get(_issue_base(item, candidate_root), [])
        rank = scanengine.SEVERITY_RANK.get(item.severity.upper(), 0)
        if ranks and rank > max(ranks):
            regressions.append(_rebase_issue(item, candidate_root, report_root))
    return tuple(regressions)


def _score(report: CandidateReport) -> int:
    resolved = sum(_SEVERITY_WEIGHT.get(item.severity.upper(), 0)
                   for item in report.resolved_issues)
    introduced = sum(_SEVERITY_WEIGHT.get(item.severity.upper(), 0)
                     for item in report.new_issues)
    return (
        (1_000_000 if report.accepted else 0) + resolved - introduced
        + (2_000 if report.candidate.verification == "verified" else 0)
        + (1_000 if report.test.status == "passed" else 0)
        - report.changed_lines
    )


def verify_candidate(project_root: str | os.PathLike[str],
                     target: str | os.PathLike[str], candidate_source: str, *,
                     name: str = "candidate", test_command: Sequence[str] | None = None,
                     authorize_tests: bool = False,
                     test_timeout: float = DEFAULT_TEST_TIMEOUT,
                     max_test_output: int = DEFAULT_MAX_OUTPUT,
                     jobs: int = 1, deep: bool = False,
                     require_verified: bool = True,
                     exact_file_scope: bool = False) -> CandidateReport:
    """Verify one candidate in disposable, explicitly bounded before/after copies."""
    root, relative, source_path = _project_and_target(project_root, target)
    if not isinstance(candidate_source, str):
        raise TypeError("candidate source must be text")
    candidate_bytes = candidate_source.encode("utf-8")
    if len(candidate_bytes) > MAX_CANDIDATE_BYTES:
        raise ValueError("candidate exceeds %d UTF-8 bytes" % MAX_CANDIDATE_BYTES)
    if "\x00" in candidate_source:
        raise ValueError("candidate source contains a NUL byte")
    original_bytes = source_path.read_bytes()
    try:
        original_source = original_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("target is not valid UTF-8") from exc
    if test_command is not None and not authorize_tests:
        raise PermissionError("test command supplied without authorize_tests=True/--run-tests")
    if exact_file_scope and test_command is not None:
        raise PermissionError(
            "selected tests require a separately authorized project-scope verification")

    diff = unified_diff(original_source, candidate_source, relative.as_posix())
    original_sha = _sha(original_bytes)
    candidate_sha = _sha(candidate_bytes)
    test_result = TestResult()
    with tempfile.TemporaryDirectory(prefix="attestor-patchguard-") as temp:
        temp_root = Path(temp)
        before_root = temp_root / "before"
        after_root = temp_root / "after"
        if exact_file_scope:
            copied_target = before_root / relative
            copied_target.parent.mkdir(parents=True, exist_ok=False)
            shutil.copy2(source_path, copied_target)
            skipped: list[str] = []
            project_sha = _exact_file_manifest(
                before_root, relative, copied_target)
            if _exact_file_manifest(root, relative, source_path) != project_sha:
                raise RuntimeError(
                    "target changed while its exact-file verification copy was created")
        else:
            skipped = _copy_project(root, before_root)
            project_sha = _project_manifest(before_root)
            if _project_manifest(root) != project_sha:
                raise RuntimeError(
                    "project changed while its verification copy was created")
        if _sha((before_root / relative).read_bytes()) != original_sha:
            raise RuntimeError("target changed while its verification copy was created")
        shutil.copytree(before_root, after_root)
        candidate_path = after_root / relative
        candidate_path.write_text(candidate_source, encoding="utf-8", newline="")

        baseline_target = before_root / relative if exact_file_scope else before_root
        candidate_target = after_root / relative if exact_file_scope else after_root
        baseline_scan = scanengine.scan(
            [str(baseline_target)], jobs=jobs, deep=deep,
            tools=True, use_cache=False,
        )
        candidate_scan = scanengine.scan(
            [str(candidate_target)], jobs=jobs, deep=deep,
            tools=True, use_cache=False,
        )

        new_issues = _multiset_delta(
            candidate_scan.issues, after_root, baseline_scan.issues, before_root, root)
        resolved = _multiset_delta(
            baseline_scan.issues, before_root, candidate_scan.issues, after_root, root)
        severity_regressions = _severity_regressions(
            baseline_scan.issues, before_root, candidate_scan.issues, after_root, root)
        high_regressions = tuple({
            (item.path, item.line, item.rule, item.message): item
            for item in new_issues + severity_regressions
            if scanengine.SEVERITY_RANK.get(item.severity.upper(), 0)
            >= scanengine.SEVERITY_RANK["HIGH"]
        }.values())
        before_failures = _failure_rows(baseline_scan, before_root)
        after_failures = _failure_rows(candidate_scan, after_root)
        new_failures = _counter_delta(after_failures, before_failures)
        target_result = next((row for row in candidate_scan.files
                              if _relative(row.path, after_root) == relative.as_posix()), None)
        reasons = []
        if target_result is None:
            reasons.append("candidate target was not scanned")
        elif target_result.verification == "failed":
            reasons.append("candidate failed its syntax/compiler check")
        elif (require_verified and target_result.language in COMPILED_LANGUAGES
              and target_result.verification != "verified"):
            reasons.append("candidate could not be syntax/compiler verified")
        if new_failures:
            reasons.append("candidate introduced scan or compiler failures")
        if new_issues:
            reasons.append("candidate introduced new static findings")
        if high_regressions:
            reasons.append("candidate introduced or escalated HIGH/CRITICAL findings")

        if test_command is not None and not reasons:
            expected_hash = _sha(candidate_path.read_bytes())
            test_result = run_test_command(
                test_command, after_root, authorized=authorize_tests,
                timeout=test_timeout, max_output=max_test_output,
            )
            if not test_result.passed:
                reasons.append("authorized test command failed")
            if _sha(candidate_path.read_bytes()) != expected_hash:
                reasons.append("test command modified the candidate target")

        report = CandidateReport(
            name=str(name), project_root=str(root), target=relative.as_posix(),
            accepted=not reasons, reasons=tuple(reasons),
            original_sha256=original_sha, candidate_sha256=candidate_sha,
            project_sha256=project_sha,
            diff=diff, changed_lines=_changed_lines(diff),
            baseline=_scan_summary(baseline_scan, before_root, root, relative),
            candidate=_scan_summary(candidate_scan, after_root, root, relative),
            new_issues=new_issues, resolved_issues=resolved,
            high_regressions=high_regressions, new_failures=new_failures,
            test=test_result, skipped_links=tuple(skipped),
            verification_scope=(
                "exact-file" if exact_file_scope else "project"),
        )
    report.score = _score(report)
    return report


def rank_candidates(project_root: str | os.PathLike[str],
                    target: str | os.PathLike[str],
                    candidates: Mapping[str, str], **verify_options) -> list[CandidateReport]:
    """Verify and rank named candidates; accepted, safer, smaller patches win."""
    if not candidates:
        return []
    reports = [
        verify_candidate(project_root, target, source, name=name, **verify_options)
        for name, source in candidates.items()
    ]
    return sorted(reports, key=lambda item: (-item.score, item.name.lower()))


def generate_regression_test_artifact(
        report: CandidateReport,
        confirmed: Iterable[scanengine.Issue] | None = None) -> RegressionArtifact:
    """Create a unittest artifact that caps recurrence of confirmed findings.

    By default, resolved findings are considered confirmed.  Supplying
    ``confirmed`` lets a reviewer explicitly narrow that set; every supplied
    finding must have been resolved by this report.
    """
    resolved_keys = {
        (Path(item.path).resolve().relative_to(Path(report.project_root)).as_posix(),
         item.rule, item.message): item for item in report.resolved_issues
    }
    if confirmed is None:
        selected = list(report.resolved_issues)
    else:
        selected = list(confirmed)
        for item in selected:
            try:
                key = (Path(item.path).resolve().relative_to(Path(report.project_root)).as_posix(),
                       item.rule, item.message)
            except ValueError as exc:
                raise ValueError("confirmed finding is outside the verified project") from exc
            if key not in resolved_keys:
                raise ValueError("confirmed finding was not resolved by this candidate")
    if not selected:
        raise ValueError("there are no confirmed resolved findings for a regression artifact")

    candidate_counts = collections.Counter(
        (Path(item.path).resolve().relative_to(Path(report.project_root)).as_posix(),
         item.rule, item.message) for item in report.candidate.issues
    )
    caps = []
    for item in selected:
        relative = Path(item.path).resolve().relative_to(Path(report.project_root)).as_posix()
        key = (relative, item.rule, item.message)
        row = key + (candidate_counts[key],)
        if row not in caps:
            caps.append(row)
    caps.sort()
    content = '''#!/usr/bin/env python3
"""Generated by Attestor PatchGuard; keep confirmed findings from recurring."""
import collections
import os
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(os.environ.get(
    "ATTESTOR_PROJECT_ROOT", Path(__file__).resolve().parents[1])).resolve()
DETECTOR = PROJECT_ROOT / "detector"
if DETECTOR.is_dir() and str(DETECTOR) not in sys.path:
    sys.path.insert(0, str(DETECTOR))

import scanengine

CONFIRMED_CAPS = %s


class AttestorPatchRegression(unittest.TestCase):
    def test_confirmed_findings_do_not_recur(self):
        result = scanengine.scan(
            [str(PROJECT_ROOT)], jobs=1, tools=False, use_cache=False)
        self.assertNotEqual(result.status, "failed", result.errors)
        counts = collections.Counter()
        for issue in result.issues:
            try:
                relative = Path(issue.path).resolve().relative_to(PROJECT_ROOT).as_posix()
            except ValueError:
                continue
            message = issue.message.replace(str(PROJECT_ROOT), "<PROJECT>")
            message = message.replace(PROJECT_ROOT.as_posix(), "<PROJECT>")
            counts[(relative, issue.rule, message)] += 1
        for path, rule, message, maximum in CONFIRMED_CAPS:
            self.assertLessEqual(
                counts[(path, rule, message)], maximum,
                "confirmed %%s finding recurred in %%s" %% (rule, path))


if __name__ == "__main__":
    unittest.main()
''' % pprint.pformat(caps, width=100, sort_dicts=True)
    short_hash = report.candidate_sha256[:12]
    return RegressionArtifact(
        "tests/test_attestor_regression_%s.py" % short_hash, content,
        tuple(sorted({item.rule for item in selected})),
    )


def _atomic_write(path: Path, data: bytes, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".attestor-write-", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_regression_test_artifact(project_root: str | os.PathLike[str],
                                   artifact: RegressionArtifact, *,
                                   authorized: bool = False,
                                   overwrite: bool = False) -> Path:
    if not authorized:
        raise PermissionError("writing an artifact requires authorized=True")
    root = Path(project_root).resolve()
    relative = Path(artifact.suggested_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("artifact path must stay inside the project")
    output = (root / relative).resolve()
    try:
        output.relative_to(root)
    except ValueError as exc:
        raise ValueError("artifact path escapes the project") from exc
    if output.exists() and not overwrite:
        raise FileExistsError(output)
    _atomic_write(output, artifact.content.encode("utf-8"))
    return output


def _default_backup_root(project_root: Path) -> Path:
    return project_root.parent / (project_root.name + ".attestor-backups")


def _post_apply_check(path: Path, require_verified: bool = True) -> tuple[bool, str]:
    result = scanengine.scan(
        [str(path)], jobs=1, tools=True, use_cache=False,
    )
    if not result.files:
        return False, "post-apply scanner did not inspect the target"
    row = result.files[0]
    if result.status == "failed" or row.verification == "failed":
        return False, "post-apply syntax/compiler scan failed"
    if require_verified and row.language in COMPILED_LANGUAGES and row.verification != "verified":
        return False, "post-apply syntax/compiler check was unavailable"
    return True, "post-apply scan passed"


def apply_candidate(report: CandidateReport, candidate_source: str, *,
                    authorized: bool = False,
                    backup_root: str | os.PathLike[str] | None = None,
                    require_verified: bool = True) -> ApplyResult:
    """Atomically apply an accepted, non-stale report after explicit consent."""
    if not authorized:
        raise PermissionError("applying a candidate requires authorized=True/--apply")
    if not report.accepted:
        raise ValueError("a rejected candidate cannot be applied")
    root, relative, target = _project_and_target(report.project_root, report.target)
    if str(root) != str(Path(report.project_root).resolve()):
        raise ValueError("report project root no longer matches")
    candidate_bytes = candidate_source.encode("utf-8")
    if _sha(candidate_bytes) != report.candidate_sha256:
        raise ValueError("candidate content does not match the verified report")
    original_bytes = target.read_bytes()
    if _sha(original_bytes) != report.original_sha256:
        raise RuntimeError("target changed after verification; refusing stale apply")
    if report.verification_scope == "exact-file":
        current_scope_sha = _exact_file_manifest(root, relative, target)
    elif report.verification_scope == "project":
        current_scope_sha = _project_manifest(root)
    else:
        raise ValueError("report verification scope is unsupported")
    if current_scope_sha != report.project_sha256:
        raise RuntimeError(
            "verified scope changed after verification; refusing stale apply")

    backup_base = (Path(backup_root).expanduser().resolve() if backup_root
                   else _default_backup_root(root))
    backup_dir = backup_base / relative.parent
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    backup = backup_dir / (relative.name + ".%s.%s.bak" % (
        stamp, report.original_sha256[:12]))
    suffix = 1
    while backup.exists():
        backup = backup_dir / (relative.name + ".%s.%s.%d.bak" % (
            stamp, report.original_sha256[:12], suffix))
        suffix += 1
    mode = target.stat().st_mode
    _atomic_write(backup, original_bytes, mode)
    replaced = False
    try:
        _atomic_write(target, candidate_bytes, mode)
        replaced = True
        ok, detail = _post_apply_check(target, require_verified=require_verified)
        if not ok:
            _atomic_write(target, original_bytes, mode)
            return ApplyResult(
                str(target), str(backup), False, True, report.original_sha256,
                report.candidate_sha256, detail + "; restored backup",
            )
    except Exception:
        if replaced:
            _atomic_write(target, original_bytes, mode)
        raise
    return ApplyResult(
        str(target), str(backup), True, False, report.original_sha256,
        report.candidate_sha256, "applied atomically; post-apply scan passed",
    )


def rollback_apply(result: ApplyResult, *, authorized: bool = False) -> ApplyResult:
    """Restore a PatchGuard backup, refusing to overwrite later user changes."""
    if not authorized:
        raise PermissionError("rollback requires authorized=True")
    if not result.applied or result.rolled_back:
        raise ValueError("this result does not represent an active applied patch")
    target = Path(result.target)
    backup = Path(result.backup)
    if not backup.is_file() or _is_link(backup):
        raise ValueError("backup is missing or unsafe")
    if not target.is_file() or _is_link(target):
        raise ValueError("target is missing or unsafe")
    if _sha(target.read_bytes()) != result.candidate_sha256:
        raise RuntimeError("target changed after apply; refusing destructive rollback")
    original = backup.read_bytes()
    if _sha(original) != result.original_sha256:
        raise RuntimeError("backup integrity check failed")
    _atomic_write(target, original, target.stat().st_mode)
    return ApplyResult(
        str(target), str(backup), False, True, result.original_sha256,
        result.candidate_sha256, "backup restored atomically",
    )


def report_dict(report: CandidateReport) -> dict:
    return dataclasses.asdict(report)


def render(report: CandidateReport) -> str:
    lines = [
        "PatchGuard: %s" % report.name,
        "RESULT: %s" % ("ACCEPTED" if report.accepted else "REJECTED"),
        "Target: %s" % report.target,
        "Compiler/syntax: %s" % report.candidate.verification,
        "Findings: %d before, %d after, %d new, %d resolved" % (
            len(report.baseline.issues), len(report.candidate.issues),
            len(report.new_issues), len(report.resolved_issues)),
        "Tests: %s (%s)" % (report.test.status, report.test.detail),
        "Score: %d" % report.score,
    ]
    if report.reasons:
        lines.append("Reasons:")
        lines.extend("  - " + reason for reason in report.reasons)
    lines.extend(["", "Unified diff:", report.diff or "(no changes)"])
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", help="project root")
    parser.add_argument("target", help="project-relative file to replace")
    parser.add_argument("candidate", help="file containing the proposed replacement")
    parser.add_argument("--name", default="candidate")
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--run-tests", action="store_true",
                        help="explicitly authorize --test-command execution")
    parser.add_argument("--test-timeout", type=float, default=DEFAULT_TEST_TIMEOUT)
    parser.add_argument("--max-test-output", type=int, default=DEFAULT_MAX_OUTPUT)
    parser.add_argument("--apply", action="store_true",
                        help="explicitly apply an accepted patch (default is dry-run)")
    parser.add_argument("--backup-root", default="")
    parser.add_argument("--write-regression", action="store_true",
                        help="write a generated test for resolved findings")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--test-command", nargs=argparse.REMAINDER,
                        help="argv to run; this option and its args must be last")
    args = parser.parse_args(argv)

    if args.test_command and not args.run_tests:
        parser.error("--test-command executes code; pass --run-tests explicitly")
    try:
        candidate_source = Path(args.candidate).read_text(encoding="utf-8")
        report = verify_candidate(
            args.project, args.target, candidate_source, name=args.name,
            test_command=args.test_command or None, authorize_tests=args.run_tests,
            test_timeout=args.test_timeout, max_test_output=args.max_test_output,
            jobs=args.jobs, deep=args.deep,
        )
    except (PermissionError, OSError, TypeError, ValueError, RuntimeError) as exc:
        print("PatchGuard error: %s" % exc, file=sys.stderr)
        return 2

    print(json.dumps(report_dict(report), indent=2) if args.json else render(report))
    if not report.accepted:
        return 1
    if args.apply:
        try:
            applied = apply_candidate(
                report, candidate_source, authorized=True,
                backup_root=args.backup_root or None,
            )
        except (PermissionError, OSError, ValueError, RuntimeError) as exc:
            print("PatchGuard apply error: %s" % exc, file=sys.stderr)
            return 2
        print("Applied: %s\nBackup: %s" % (applied.target, applied.backup))
    else:
        print("DRY RUN: pass --apply to write the accepted candidate")
    if args.write_regression:
        try:
            artifact = generate_regression_test_artifact(report)
            output = write_regression_test_artifact(
                args.project, artifact, authorized=True,
            )
            print("Regression artifact: %s" % output)
        except (OSError, ValueError) as exc:
            print("PatchGuard artifact error: %s" % exc, file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
