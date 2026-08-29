#!/usr/bin/env python3
"""Read-only Git intelligence and content-addressed semantic cache for Attestor 3.5.

All Git commands use a fixed executable and argument vector with ``shell=False``.
Only diff, blame, and rev-parse are admitted.  Hooks, external diffs, pagers,
prompts, builds, tests, target code, mutation commands, and ``git bisect`` are
never invoked.  Introducing commits are *candidates inferred from blame*, not a
claim that Attestor reproduced the bug at those revisions.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Sequence


SCHEMA = "attestor-incremental-semantic-db/3.5"
SCHEMA_VERSION = 1
ANALYZER_ID = "polyglot-ir35/bounded-lexical-v1"
MAX_GIT_OUTPUT = 8 * 1024 * 1024
MAX_GIT_STDERR = 128 * 1024
MAX_CACHE_BYTES = 64 * 1024 * 1024
MAX_CACHE_ENTRIES = 100_000
DEFAULT_TIMEOUT = 15.0
GIT_EXECUTABLE = shutil.which("git") or "git"

_READ_ONLY_SUBCOMMANDS = {"diff", "blame", "rev-parse"}
_REVISION_RX = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@{}~^:+-]{0,199}\Z")
_HASH_RX = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_RX = re.compile(r"[0-9a-f]{40,64}\Z")
_CONTROL_RX = re.compile(r"[\x00-\x1f\x7f]")


class GitIntelligenceError(RuntimeError):
    """Base class for bounded Git intelligence failures."""


class GitTimeoutError(GitIntelligenceError):
    pass


class GitOutputLimitError(GitIntelligenceError):
    pass


class GitDataError(GitIntelligenceError):
    pass


class SemanticCacheError(ValueError):
    pass


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def _sha(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _execute_argv(argv: Sequence[str], cwd: Path, timeout: float,
                  max_output: int) -> CommandResult:
    """Execute a fixed argv while monitoring output files and wall-clock time.

    Temporary files keep child output out of process memory.  The child is
    killed as soon as either output boundary is observed.
    """
    if not isinstance(argv, (list, tuple)) or not argv or not all(
            isinstance(item, str) for item in argv):
        raise GitIntelligenceError("Git argv must be a non-empty text sequence")
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        raise GitIntelligenceError("Git timeout must be positive")
    env = os.environ.copy()
    env.update({
        "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat", "PAGER": "cat", "GIT_CONFIG_NOSYSTEM": "1",
        "LC_ALL": "C", "LANG": "C",
    })
    env.pop("GIT_EXTERNAL_DIFF", None)
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(
                list(argv), cwd=str(cwd), stdin=subprocess.DEVNULL,
                stdout=stdout_file, stderr=stderr_file, shell=False,
                close_fds=True, env=env,
            )
        except OSError as exc:
            raise GitIntelligenceError("Git could not be started: " + str(exc)[:240]) from exc
        deadline = time.monotonic() + float(timeout)
        reason = ""
        while process.poll() is None:
            if time.monotonic() >= deadline:
                reason = "timeout"
                break
            try:
                if os.fstat(stdout_file.fileno()).st_size > max_output or \
                        os.fstat(stderr_file.fileno()).st_size > MAX_GIT_STDERR:
                    reason = "output"
                    break
            except OSError:
                reason = "output"
                break
            time.sleep(0.01)
        if reason:
            process.kill()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        stdout_size = os.fstat(stdout_file.fileno()).st_size
        stderr_size = os.fstat(stderr_file.fileno()).st_size
        if reason == "timeout":
            raise GitTimeoutError("Git command exceeded its wall-clock timeout")
        if reason == "output" or stdout_size > max_output or stderr_size > MAX_GIT_STDERR:
            raise GitOutputLimitError("Git command exceeded its output boundary")
        stdout_file.seek(0)
        stderr_file.seek(0)
        return CommandResult(process.returncode, stdout_file.read(max_output + 1),
                             stderr_file.read(MAX_GIT_STDERR + 1))


Executor = Callable[[Sequence[str], Path, float, int], CommandResult]


def _safe_revision(value: str) -> str:
    if (not isinstance(value, str) or not _REVISION_RX.fullmatch(value) or
            value.startswith("-") or ".." in value or "@{" in value or ":" in value):
        raise GitDataError("revision is not a bounded Git revision name")
    return value


def _no_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise SemanticCacheError("semantic database contains duplicate JSON keys")
        value[key] = item
    return value


def _safe_relative_text(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or _CONTROL_RX.search(value):
        raise GitDataError("repository path is invalid")
    normalized = value.replace("\\", "/")
    pure = PurePosixPath(normalized)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise GitDataError("repository path escapes its root")
    if pure.parts and pure.parts[0].casefold() == ".git":
        raise GitDataError("Git metadata paths are outside analysis scope")
    return pure.as_posix()


def _safe_repo_path(root: Path, value: str | os.PathLike[str]) -> str:
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise GitDataError("repository path must be text or path-like") from exc
    if not isinstance(raw, str) or "\0" in raw:
        raise GitDataError("repository path is invalid")
    candidate = Path(raw)
    if candidate.is_absolute():
        try:
            relative = candidate.resolve(strict=False).relative_to(root).as_posix()
        except (OSError, ValueError) as exc:
            raise GitDataError("repository path escapes its root") from exc
    else:
        relative = raw.replace("\\", "/")
    return _safe_relative_text(relative)


def _safe_message(stderr: bytes) -> str:
    message = stderr.decode("utf-8", errors="replace")
    message = _CONTROL_RX.sub(" ", message)
    return " ".join(message.split())[:300]


class GitRepository:
    """A narrow, read-only facade over fixed Git commands."""

    def __init__(self, root: str | os.PathLike[str], *, timeout: float = DEFAULT_TIMEOUT,
                 max_output: int = MAX_GIT_OUTPUT, executor: Executor | None = None):
        try:
            self.root = Path(root).expanduser().resolve()
        except (OSError, RuntimeError, ValueError, TypeError) as exc:
            raise GitDataError("repository root is invalid") from exc
        if not self.root.is_dir():
            raise GitDataError("repository root is not a directory")
        if not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > 300:
            raise GitDataError("timeout must be between zero and 300 seconds")
        if not isinstance(max_output, int) or max_output < 1024 or max_output > 64 * 1024 * 1024:
            raise GitDataError("output boundary is outside the supported range")
        self.timeout = float(timeout)
        self.max_output = max_output
        self.executor = executor or _execute_argv

    def _run(self, arguments: Sequence[str]) -> bytes:
        if not isinstance(arguments, (list, tuple)) or not arguments:
            raise GitDataError("Git arguments are invalid")
        subcommand = arguments[0]
        if subcommand not in _READ_ONLY_SUBCOMMANDS:
            raise GitDataError("Git subcommand is not in the read-only allowlist")
        argv = [
            GIT_EXECUTABLE, "--no-pager", "-c", "core.pager=cat", "-c", "color.ui=false",
            "-c", "diff.external=", "-c", "core.fsmonitor=false",
            "-c", "core.quotePath=false", "-C", str(self.root), *arguments,
        ]
        result = self.executor(argv, self.root, self.timeout, self.max_output)
        if not isinstance(result, CommandResult):
            raise GitDataError("Git executor returned an invalid result")
        if len(result.stdout) > self.max_output or len(result.stderr) > MAX_GIT_STDERR:
            raise GitOutputLimitError("Git executor returned output beyond its boundary")
        if result.returncode != 0:
            message = _safe_message(result.stderr)
            raise GitIntelligenceError("Git read failed" + ((": " + message) if message else ""))
        return result.stdout

    def resolve_commit(self, revision: str = "HEAD") -> str:
        revision = _safe_revision(revision)
        raw = self._run(["rev-parse", "--verify", "--end-of-options", revision + "^{commit}"])
        try:
            commit = raw.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise GitDataError("Git returned a non-ASCII object id") from exc
        if not _COMMIT_RX.fullmatch(commit):
            raise GitDataError("Git returned an invalid commit object id")
        return commit

    def repository_scope_prefix(self) -> str:
        """Return this analysis root's canonical, repository-relative prefix.

        Git diff paths are always relative to the repository top level, even
        when ``git -C`` points at a nested directory.  Semantic database paths
        are relative to ``self.root``.  Exposing the bounded prefix lets impact
        analysis translate between those namespaces without widening its
        selected project scope.
        """
        raw = self._run(["rev-parse", "--path-format=absolute", "--show-toplevel"])
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GitDataError("Git top-level path is not valid UTF-8") from exc
        top_text = text.rstrip("\r\n")
        terminator = text[len(top_text):]
        if (not top_text or terminator not in {"\n", "\r\n"} or
                _CONTROL_RX.search(top_text)):
            raise GitDataError("Git returned a malformed top-level path")
        candidate = Path(top_text)
        if not candidate.is_absolute():
            raise GitDataError("Git returned a non-absolute top-level path")
        try:
            top = candidate.resolve(strict=True)
            relative = self.root.relative_to(top)
        except (OSError, ValueError) as exc:
            raise GitDataError("analysis root is outside the Git work tree") from exc
        if not top.is_dir():
            raise GitDataError("Git top level is not a readable directory")
        if not relative.parts:
            return ""
        return _safe_relative_text(PurePosixPath(*relative.parts).as_posix()) + "/"

    def diff(self, base: str, head: str = "HEAD", *, paths: Iterable[str] = (),
             context: int = 0) -> dict[str, Any]:
        base = _safe_revision(base)
        head = _safe_revision(head)
        if not isinstance(context, int) or not 0 <= context <= 20:
            raise GitDataError("diff context must be between zero and 20")
        safe_paths = sorted(set(_safe_repo_path(self.root, item) for item in paths))
        arguments = ["diff", "--no-ext-diff", "--no-color", "--no-textconv",
                     "--no-renames", "--unified=%d" % context, base, head]
        if safe_paths:
            arguments.extend(["--", *safe_paths])
        raw = self._run(arguments)
        try:
            patch = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GitDataError("Git diff is not valid UTF-8") from exc
        return {"base": base, "head": head, "paths": safe_paths, "patch": patch,
                "patch_sha256": _sha(raw), "bytes": len(raw), "truncated": False,
                "evidence": "git-diff/read-only"}

    def changed_files(self, base: str, head: str = "HEAD") -> list[dict[str, str]]:
        base = _safe_revision(base)
        head = _safe_revision(head)
        raw = self._run(["diff", "--no-ext-diff", "--no-textconv", "--no-renames",
                         "--name-status", "-z", base, head, "--"])
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GitDataError("Git path output is not valid UTF-8") from exc
        if decoded and not decoded.endswith("\0"):
            raise GitDataError("Git name-status output is not NUL terminated")
        parts = decoded.split("\0")
        if parts and parts[-1] == "":
            parts.pop()
        if len(parts) % 2:
            raise GitDataError("Git name-status output is malformed")
        changes = []
        allowed = {"A": "added", "M": "modified", "D": "deleted", "T": "type-changed",
                   "U": "unmerged", "X": "unknown", "B": "broken"}
        for index in range(0, len(parts), 2):
            status, raw_path = parts[index], parts[index + 1]
            if status not in allowed:
                raise GitDataError("Git returned an unsupported change status")
            path = _safe_relative_text(raw_path)
            changes.append({"path": path, "status": status, "change": allowed[status]})
        return sorted(changes, key=lambda item: (item["path"], item["status"]))

    def blame(self, path: str | os.PathLike[str], *, start: int = 1,
              end: int | None = None, revision: str = "HEAD") -> list[dict[str, Any]]:
        relative = _safe_repo_path(self.root, path)
        revision = _safe_revision(revision)
        if not isinstance(start, int) or start < 1:
            raise GitDataError("blame start line must be positive")
        if end is None:
            end = min(start + 499, 1_000_000_000)
        if not isinstance(end, int) or end < start or end - start >= 500:
            raise GitDataError("blame range must contain between one and 500 lines")
        raw = self._run(["blame", "--line-porcelain", "--date=iso-strict",
                         "-L", "%d,%d" % (start, end), revision, "--", relative])
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GitDataError("Git blame output is not valid UTF-8") from exc
        records: list[dict[str, Any]] = []
        current: dict[str, Any] | None = None
        for line in text.splitlines():
            header = re.fullmatch(r"([0-9a-f^]{40,65})\s+(\d+)\s+(\d+)(?:\s+\d+)?", line)
            if header:
                commit = header.group(1).lstrip("^")
                if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
                    raise GitDataError("Git blame returned an invalid commit id")
                current = {"commit": commit, "original_line": int(header.group(2)),
                           "line": int(header.group(3)), "author": "", "author_time": 0,
                           "author_tz": "", "summary": "", "filename": relative}
                continue
            if current is None:
                if line.strip():
                    raise GitDataError("Git blame output began without a record header")
                continue
            if line.startswith("author "):
                current["author"] = line[7:][:512]
            elif line.startswith("author-time "):
                try:
                    current["author_time"] = int(line[12:])
                except ValueError as exc:
                    raise GitDataError("Git blame returned an invalid author time") from exc
            elif line.startswith("author-tz "):
                current["author_tz"] = line[10:][:16]
            elif line.startswith("summary "):
                current["summary"] = line[8:][:1024]
            elif line.startswith("filename "):
                current["filename"] = _safe_relative_text(line[9:])
            elif line.startswith("\t"):
                # Source is deliberately not returned or cached.  The tab line
                # merely closes the porcelain record.
                current["source_stored"] = False
                records.append(current)
                current = None
        if current is not None:
            raise GitDataError("Git blame output ended before source evidence")
        if any(not start <= item["line"] <= end for item in records):
            raise GitDataError("Git blame returned a line outside the requested range")
        return sorted(records, key=lambda item: item["line"])

    def introducing_commit_candidates(
            self, path: str | os.PathLike[str], lines: Iterable[int], *,
            revision: str = "HEAD", limit: int = 20) -> dict[str, Any]:
        if not isinstance(limit, int) or not 1 <= limit <= 100:
            raise GitDataError("candidate limit must be between one and 100")
        selected = sorted(set(lines))
        if not selected or len(selected) > 500 or any(
                not isinstance(line, int) or line < 1 for line in selected):
            raise GitDataError("candidate lines must contain one to 500 positive integers")
        # Fetch contiguous spans only.  This avoids reading unrelated source
        # evidence and stays under the same 500-line blame boundary.
        spans: list[tuple[int, int]] = []
        span_start = previous = selected[0]
        for line in selected[1:]:
            if line != previous + 1:
                spans.append((span_start, previous))
                span_start = line
            previous = line
        spans.append((span_start, previous))
        if len(spans) > 32:
            raise GitDataError("candidate line selection creates too many disjoint blame spans")
        records = []
        for first, last in spans:
            records.extend(self.blame(path, start=first, end=last, revision=revision))
        wanted = set(selected)
        records = [item for item in records if item["line"] in wanted]
        counts = Counter(item["commit"] for item in records)
        metadata = {item["commit"]: item for item in records}
        candidates = []
        for commit, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]:
            item = metadata[commit]
            candidates.append({
                "commit": commit, "attributed_lines": count,
                "fraction": round(count / len(selected), 6),
                "author": item["author"], "author_time": item["author_time"],
                "summary": item["summary"], "evidence": "git-blame-attribution",
                "proven_introducing_commit": False,
            })
        return {
            "path": _safe_repo_path(self.root, path), "revision": _safe_revision(revision),
            "requested_lines": selected, "attributed_lines": len(records),
            "candidates": candidates,
            "limitation": "blame attribution is a candidate signal; no historical build, test, exploit, or bisect was run",
        }


def diff(root: str | os.PathLike[str], base: str, head: str = "HEAD", **kwargs) -> dict[str, Any]:
    return GitRepository(root).diff(base, head, **kwargs)


def changed_files(root: str | os.PathLike[str], base: str,
                  head: str = "HEAD") -> list[dict[str, str]]:
    return GitRepository(root).changed_files(base, head)


def blame(root: str | os.PathLike[str], path: str | os.PathLike[str],
          **kwargs) -> list[dict[str, Any]]:
    return GitRepository(root).blame(path, **kwargs)


def introducing_commit_candidates(root: str | os.PathLike[str], path: str | os.PathLike[str],
                                   lines: Iterable[int], **kwargs) -> dict[str, Any]:
    return GitRepository(root).introducing_commit_candidates(path, lines, **kwargs)


def _root_id(root: str | os.PathLike[str]) -> str:
    try:
        normalized = str(Path(root).expanduser().resolve()).replace("\\", "/").casefold()
    except (OSError, RuntimeError, ValueError, TypeError) as exc:
        raise SemanticCacheError("semantic database root is invalid") from exc
    return _sha(normalized)


def _validate_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HASH_RX.fullmatch(value):
        raise SemanticCacheError(label + " is not a SHA-256 digest")
    return value


def _ir_path(value: Any) -> str:
    try:
        return _safe_relative_text(value)
    except GitDataError as exc:
        raise SemanticCacheError("IR contains an unsafe path") from exc


def _record_without_id(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key != "record_id"}


def _record_id(record: dict[str, Any]) -> str:
    return _sha(_canonical(_record_without_id(record)))


def _portable_symbol(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise SemanticCacheError("IR symbol record is invalid")
    output: dict[str, Any] = {}
    for key in ("name", "kind", "line", "parameter_count", "method", "route", "target"):
        value = item.get(key)
        if value is None:
            if key == "parameter_count" and key in item:
                output[key] = None
            continue
        if isinstance(value, str):
            maximum = 1024 if key == "route" else 512
            if len(value) > maximum or _CONTROL_RX.search(value):
                raise SemanticCacheError("IR symbol text is invalid or too large")
            output[key] = value
        elif isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 1_000_000_000:
            output[key] = value
        else:
            raise SemanticCacheError("IR symbol value has an invalid type")
    if not output:
        raise SemanticCacheError("IR symbol record contains no portable fields")
    return output


def _resolve_dependencies(files: list[dict[str, Any]]) -> dict[str, list[str]]:
    paths = {item["path"] for item in files}
    by_module = {item["module"]: item["path"] for item in files
                 if isinstance(item.get("module"), str) and item["module"]}
    suffixes = ("", ".js", ".jsx", ".ts", ".tsx", ".java", ".cs", ".go",
                ".rs", ".c", ".cc", ".cpp", ".h", ".hpp", ".php")
    dependencies: dict[str, list[str]] = {}
    for item in files:
        current = PurePosixPath(item["path"])
        resolved = set()
        for imported in item.get("imports", []):
            if not isinstance(imported, dict) or not isinstance(imported.get("specifier"), str):
                continue
            specifier = imported["specifier"].strip()
            if not specifier:
                continue
            module_candidate = specifier.replace("\\", ".").replace("::", ".")
            if module_candidate in by_module:
                resolved.add(by_module[module_candidate])
                continue
            # Java/C# imports often name a type one segment below the module.
            parent_module = module_candidate.rsplit(".", 1)[0] if "." in module_candidate else ""
            if parent_module in by_module:
                resolved.add(by_module[parent_module])
                continue
            if specifier.startswith("."):
                joined = current.parent.joinpath(specifier).as_posix()
                normalized_parts = []
                escaped = False
                for part in PurePosixPath(joined).parts:
                    if part == "..":
                        if not normalized_parts:
                            escaped = True
                            break
                        normalized_parts.pop()
                    elif part not in {"", "."}:
                        normalized_parts.append(part)
                if escaped:
                    continue
                base = "/".join(normalized_parts)
                candidates = [base + suffix for suffix in suffixes]
                candidates.extend(base.rstrip("/") + "/index" + suffix for suffix in suffixes[1:])
                match = next((candidate for candidate in candidates if candidate in paths), None)
                if match:
                    resolved.add(match)
        dependencies[item["path"]] = sorted(resolved)
    return dependencies


class SemanticDatabase:
    """Content-addressed, source-free incremental semantic metadata."""

    def __init__(self, root: str | os.PathLike[str], *, analyzer_id: str = ANALYZER_ID):
        if not isinstance(analyzer_id, str) or not 1 <= len(analyzer_id) <= 200 or _CONTROL_RX.search(analyzer_id):
            raise SemanticCacheError("analyzer id is invalid")
        self.repository_id = _root_id(root)
        self.analyzer_id = analyzer_id
        self.records: dict[str, dict[str, Any]] = {}
        self.reverse_dependencies: dict[str, list[str]] = {}

    def update(self, ir: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(ir, dict) or ir.get("schema") != "attestor-polyglot-ir/3.5":
            raise SemanticCacheError("IR schema is not supported")
        raw_files = ir.get("files")
        if not isinstance(raw_files, list) or len(raw_files) > MAX_CACHE_ENTRIES:
            raise SemanticCacheError("IR file list is invalid or too large")
        files = []
        seen = set()
        for item in raw_files:
            if not isinstance(item, dict):
                raise SemanticCacheError("IR file record is invalid")
            path = _ir_path(item.get("path"))
            if path in seen:
                raise SemanticCacheError("IR contains duplicate file paths")
            seen.add(path)
            language = item.get("language")
            module = item.get("module")
            content_sha = _validate_hash(item.get("sha256"), "IR content hash")
            if not isinstance(language, str) or not language or len(language) > 64:
                raise SemanticCacheError("IR language is invalid")
            if not isinstance(module, str) or len(module) > 1024 or _CONTROL_RX.search(module):
                raise SemanticCacheError("IR module is invalid")
            imports = []
            raw_imports = item.get("imports", [])
            if not isinstance(raw_imports, list) or len(raw_imports) > 10_000:
                raise SemanticCacheError("IR import list is invalid or too large")
            for imported in raw_imports:
                if not isinstance(imported, dict) or not isinstance(imported.get("specifier"), str):
                    raise SemanticCacheError("IR import record is invalid")
                specifier = imported["specifier"]
                if len(specifier) > 512 or _CONTROL_RX.search(specifier):
                    raise SemanticCacheError("IR import specifier is invalid")
                import_kind = imported.get("kind", "")
                import_line = imported.get("line", 1)
                if not isinstance(import_kind, str) or len(import_kind) > 64 or \
                        _CONTROL_RX.search(import_kind):
                    raise SemanticCacheError("IR import kind is invalid")
                if not isinstance(import_line, int) or isinstance(import_line, bool) or \
                        not 1 <= import_line <= 1_000_000_000:
                    raise SemanticCacheError("IR import line is invalid")
                imports.append({"kind": str(imported.get("kind", ""))[:64],
                                "specifier": specifier,
                                "line": import_line})
            portable = {}
            for kind in ("types", "functions", "calls", "routes"):
                symbols = item.get(kind, [])
                if not isinstance(symbols, list) or len(symbols) > 10_000:
                    raise SemanticCacheError("IR symbol list is invalid or too large")
                portable[kind] = [_portable_symbol(symbol) for symbol in symbols]
            files.append({"path": path, "language": language, "module": module,
                          "content_sha256": content_sha, "imports": imports,
                          "symbols": portable})
        files.sort(key=lambda item: item["path"])
        dependencies = _resolve_dependencies(files)
        new_records: dict[str, dict[str, Any]] = {}
        for item in files:
            path = item["path"]
            semantic_payload = {"module": item["module"], "imports": item["imports"],
                                "symbols": item["symbols"]}
            record = {
                "path": path, "language": item["language"],
                "content_sha256": item["content_sha256"], "module": item["module"],
                "dependencies": dependencies[path],
                "semantic_sha256": _sha(_canonical(semantic_payload)),
                "counts": {key: len(value) for key, value in item["symbols"].items()},
                "source_stored": False,
            }
            record["record_id"] = _record_id(record)
            new_records[path] = record
        old_records = self.records
        added = sorted(new_records.keys() - old_records.keys())
        removed = sorted(old_records.keys() - new_records.keys())
        changed = sorted(path for path in new_records.keys() & old_records.keys()
                         if new_records[path]["record_id"] != old_records[path]["record_id"])
        unchanged = sorted(path for path in new_records.keys() & old_records.keys()
                           if new_records[path]["record_id"] == old_records[path]["record_id"])
        reverse = {path: [] for path in new_records}
        for source, record in new_records.items():
            for target in record["dependencies"]:
                reverse.setdefault(target, []).append(source)
        self.records = new_records
        self.reverse_dependencies = {key: sorted(set(value))
                                     for key, value in sorted(reverse.items())}
        directly_changed = sorted(set(added + removed + changed))
        impacted = self.impact(directly_changed, include_changed=True)
        return {"added": added, "removed": removed, "changed": changed,
                "unchanged": unchanged, "impacted": impacted,
                "requires_analysis": sorted(set(added + changed + impacted))}

    def impact(self, paths: Iterable[str], *, include_changed: bool = False,
               transitive: bool = True) -> list[str]:
        starts = sorted(set(_ir_path(path) for path in paths))
        seen = set(starts)
        impacted = set(starts if include_changed else [])
        queue = deque(starts)
        while queue:
            target = queue.popleft()
            for dependent in self.reverse_dependencies.get(target, []):
                if dependent not in seen:
                    seen.add(dependent)
                    impacted.add(dependent)
                    if transitive:
                        queue.append(dependent)
        return sorted(impacted)

    def _body(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "repository_id": self.repository_id, "analyzer_id": self.analyzer_id,
            "records": {key: self.records[key] for key in sorted(self.records)},
            "reverse_dependencies": {
                key: sorted(self.reverse_dependencies[key])
                for key in sorted(self.reverse_dependencies)
            },
            "privacy": {"source_code_stored": False, "absolute_paths_stored": False},
        }

    def to_document(self) -> dict[str, Any]:
        body = self._body()
        return {**body, "database_sha256": _sha(_canonical(body))}

    def verify(self) -> bool:
        try:
            self._validate_document(self.to_document(), self.repository_id,
                                    expected_analyzer=self.analyzer_id)
            return True
        except SemanticCacheError:
            return False

    def save(self, path: str | os.PathLike[str]) -> None:
        if not self.verify():
            raise SemanticCacheError("refusing to persist an invalid semantic database")
        destination = Path(path).expanduser()
        if destination.is_symlink():
            raise SemanticCacheError("refusing to replace a semantic database symlink")
        destination = destination.absolute()
        destination.parent.mkdir(parents=True, exist_ok=True)
        document = self.to_document()
        data = json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
        encoded = data.encode("utf-8")
        if len(encoded) > MAX_CACHE_BYTES:
            raise SemanticCacheError("semantic database exceeds its persistence boundary")
        descriptor, temporary = tempfile.mkstemp(prefix=".attestor-semantic-", suffix=".tmp",
                                                  dir=str(destination.parent))
        try:
            if os.name != "nt":
                os.chmod(temporary, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            if os.name != "nt":
                directory_descriptor = os.open(destination.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    @classmethod
    def load(cls, path: str | os.PathLike[str], root: str | os.PathLike[str], *,
             analyzer_id: str = ANALYZER_ID) -> "SemanticDatabase":
        location = Path(path).expanduser()
        if location.is_symlink():
            raise SemanticCacheError("refusing to load a semantic database symlink")
        location = location.absolute()
        if not location.is_file():
            raise SemanticCacheError("semantic database is not a file")
        try:
            size = location.stat().st_size
        except OSError as exc:
            raise SemanticCacheError("semantic database cannot be inspected") from exc
        if size <= 0 or size > MAX_CACHE_BYTES:
            raise SemanticCacheError("semantic database is empty or too large")
        try:
            raw = location.read_bytes()
            document = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_pairs,
                                  parse_constant=lambda value: (_ for _ in ()).throw(
                                      SemanticCacheError("semantic database contains a non-finite number")))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SemanticCacheError("semantic database cannot be parsed") from exc
        expected_root = _root_id(root)
        cls._validate_document(document, expected_root, expected_analyzer=analyzer_id)
        database = cls(root, analyzer_id=analyzer_id)
        database.records = document["records"]
        database.reverse_dependencies = document["reverse_dependencies"]
        return database

    @staticmethod
    def _validate_document(document: Any, expected_root: str,
                           *, expected_analyzer: str) -> None:
        if not isinstance(document, dict):
            raise SemanticCacheError("semantic database document is not an object")
        if document.get("schema") != SCHEMA or document.get("schema_version") != SCHEMA_VERSION:
            raise SemanticCacheError("semantic database schema/version mismatch")
        if document.get("repository_id") != expected_root:
            raise SemanticCacheError("semantic database belongs to another repository")
        if document.get("analyzer_id") != expected_analyzer:
            raise SemanticCacheError("semantic database analyzer version mismatch")
        if set(document) != {"schema", "schema_version", "repository_id", "analyzer_id",
                            "records", "reverse_dependencies", "privacy",
                            "database_sha256"}:
            raise SemanticCacheError("semantic database contains unknown or missing fields")
        records = document.get("records")
        reverse = document.get("reverse_dependencies")
        if not isinstance(records, dict) or not isinstance(reverse, dict) or \
                len(records) > MAX_CACHE_ENTRIES:
            raise SemanticCacheError("semantic database tables are invalid or too large")
        for key, record in records.items():
            path = _ir_path(key)
            if path != key or not isinstance(record, dict) or record.get("path") != key:
                raise SemanticCacheError("semantic database record path is invalid")
            if set(record) != {"path", "language", "content_sha256", "module",
                              "dependencies", "semantic_sha256", "counts",
                              "source_stored", "record_id"}:
                raise SemanticCacheError("semantic database record fields are invalid")
            if not isinstance(record.get("language"), str) or not record["language"] or \
                    len(record["language"]) > 64:
                raise SemanticCacheError("semantic database language is invalid")
            if not isinstance(record.get("module"), str) or len(record["module"]) > 1024 or \
                    _CONTROL_RX.search(record["module"]):
                raise SemanticCacheError("semantic database module is invalid")
            _validate_hash(record.get("content_sha256"), "record content hash")
            _validate_hash(record.get("semantic_sha256"), "record semantic hash")
            record_id = _validate_hash(record.get("record_id"), "record id")
            if record_id != _record_id(record):
                raise SemanticCacheError("semantic database record hash mismatch")
            if record.get("source_stored") is not False:
                raise SemanticCacheError("semantic database privacy marker is invalid")
            counts = record.get("counts")
            if not isinstance(counts, dict) or set(counts) != {"types", "functions", "calls", "routes"} or \
                    any(not isinstance(value, int) or isinstance(value, bool) or value < 0
                        for value in counts.values()):
                raise SemanticCacheError("semantic database symbol counts are invalid")
            dependencies = record.get("dependencies")
            if not isinstance(dependencies, list) or dependencies != sorted(set(dependencies)):
                raise SemanticCacheError("semantic database dependencies are invalid")
            if any(_ir_path(value) != value or value not in records for value in dependencies):
                raise SemanticCacheError("semantic database dependency target is invalid")
        expected_reverse = {path: [] for path in records}
        for source, record in records.items():
            for target in record["dependencies"]:
                expected_reverse[target].append(source)
        expected_reverse = {key: sorted(set(value)) for key, value in sorted(expected_reverse.items())}
        if reverse != expected_reverse:
            raise SemanticCacheError("semantic database reverse dependency index mismatch")
        privacy = document.get("privacy")
        if privacy != {"source_code_stored": False, "absolute_paths_stored": False}:
            raise SemanticCacheError("semantic database privacy contract mismatch")
        digest = _validate_hash(document.get("database_sha256"), "database hash")
        body = {key: value for key, value in document.items() if key != "database_sha256"}
        if digest != _sha(_canonical(body)):
            raise SemanticCacheError("semantic database hash mismatch")


def change_impact(repository: GitRepository | str | os.PathLike[str],
                  database: SemanticDatabase, base: str,
                  head: str = "HEAD") -> dict[str, Any]:
    if not isinstance(database, SemanticDatabase) or not database.verify():
        raise SemanticCacheError("change impact requires a valid semantic database")
    repo = repository if isinstance(repository, GitRepository) else GitRepository(repository)
    if database.repository_id != _root_id(repo.root):
        raise SemanticCacheError("semantic database and Git repository identities differ")
    repository_prefix = repo.repository_scope_prefix()
    repository_changes = repo.changed_files(base, head)
    if repository_prefix:
        changes = []
        for item in repository_changes:
            repository_path = item["path"]
            if not repository_path.startswith(repository_prefix):
                continue
            local_path = _safe_relative_text(repository_path[len(repository_prefix):])
            changes.append({**item, "path": local_path,
                            "repository_path": repository_path})
    else:
        changes = repository_changes
    changed_paths = [item["path"] for item in changes]
    impacted = database.impact(changed_paths, include_changed=True)
    return {
        "base": _safe_revision(base), "head": _safe_revision(head),
        "changes": changes, "changed_paths": sorted(changed_paths),
        "impacted_paths": impacted,
        "analysis_scope": sorted(set(changed_paths + impacted)),
        "path_namespace": "semantic-database-root-relative",
        "repository_scope_prefix": repository_prefix,
        "repository_changes_observed": len(repository_changes),
        "changes_outside_scope": len(repository_changes) - len(changes),
        "evidence": "git-name-status plus cached reverse dependencies",
        "limitations": [
            "dynamic loading, reflection, generated code, and unresolved imports can hide dependencies",
            "impact is a conservative cached graph traversal, not runtime reachability proof",
        ],
    }


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "ANALYZER_ID", "CommandResult",
    "GitIntelligenceError", "GitTimeoutError", "GitOutputLimitError",
    "GitDataError", "SemanticCacheError", "GitRepository", "SemanticDatabase",
    "diff", "changed_files", "blame", "introducing_commit_candidates",
    "change_impact",
]
