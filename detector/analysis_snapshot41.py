#!/usr/bin/env python3
"""Immutable, content-addressed repository snapshots for Attestor 4.1.3.

The snapshot is the trust boundary shared by every 4.1 analyzer.  It reads each
regular file at most once, never follows a symlink, applies explicit byte/file
budgets, and retains immutable bytes so later stages cannot observe a different
working-tree state.  Capturing a snapshot performs no imports, target-code
execution, process creation, network access, or filesystem writes.
"""
from __future__ import annotations

import hashlib
import heapq
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import MappingProxyType
from typing import Any, Iterator, Mapping


SCHEMA = "attestor.analysis-snapshot/4.1"
VERSION = "4.1.3"
_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", ".venv", "venv", "node_modules", "vendor",
    "dist", "build", "target", "bin", "obj", ".gradle", ".next",
    "coverage",
})
_LANGUAGE = {
    ".py": "python", ".pyw": "python", ".js": "javascript",
    ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript",
    ".cts": "typescript", ".json": "json", ".graphql": "graphql",
    ".gql": "graphql", ".proto": "protobuf", ".sql": "sql",
    ".avsc": "avro",
}


class SnapshotError(ValueError):
    """A snapshot boundary, path, or integrity check failed closed."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise SnapshotError("snapshot evidence must be bounded JSON data") from exc


def _sha(value: bytes | Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _report(body: dict[str, Any]) -> dict[str, Any]:
    result = dict(body)
    result["report_sha256"] = _sha(result)
    return result


@dataclass(frozen=True)
class SnapshotLimits:
    max_files: int = 5_000
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 128 * 1024 * 1024
    max_path_chars: int = 4_096
    max_gaps: int = 20_000
    max_entries_per_directory: int = 20_000

    def __post_init__(self) -> None:
        checks = {
            "max_files": (self.max_files, 1, 100_000),
            "max_file_bytes": (self.max_file_bytes, 1, 64 * 1024 * 1024),
            "max_total_bytes": (self.max_total_bytes, 1, 2 * 1024 * 1024 * 1024),
            "max_path_chars": (self.max_path_chars, 32, 32_768),
            "max_gaps": (self.max_gaps, 1, 200_000),
            "max_entries_per_directory": (
                self.max_entries_per_directory, 1, 200_000),
        }
        for name, (value, low, high) in checks.items():
            if type(value) is not int or not low <= value <= high:
                raise SnapshotError(f"{name} must be an integer between {low} and {high}")


@dataclass(frozen=True)
class SnapshotFile:
    path: str
    language: str
    size: int
    sha256: str
    _content: bytes = field(repr=False, compare=True)

    @property
    def content(self) -> bytes:
        return self._content

    def text(self) -> tuple[str, bool]:
        """Decode UTF-8 without throwing; the bool says replacement was needed."""
        try:
            return self._content.decode("utf-8"), False
        except UnicodeDecodeError:
            return self._content.decode("utf-8", errors="replace"), True

    def evidence(self) -> dict[str, Any]:
        return {"path": self.path, "language": self.language, "size": self.size,
                "sha256": self.sha256}


@dataclass(frozen=True)
class SourceSnapshot:
    root: str
    files: tuple[SnapshotFile, ...]
    gaps: tuple[Mapping[str, Any], ...]
    limits: SnapshotLimits
    snapshot_sha256: str
    _index: Mapping[str, SnapshotFile] = field(repr=False, compare=False)

    def get(self, relative_path: str) -> SnapshotFile:
        safe = safe_relative(relative_path)
        try:
            return self._index[safe]
        except KeyError as exc:
            raise SnapshotError(f"path is not present in snapshot: {safe}") from exc

    def report(self) -> dict[str, Any]:
        body = {
            "schema": SCHEMA,
            "version": VERSION,
            "analysis_level": "immutable-content-addressed-static-source",
            "snapshot_sha256": self.snapshot_sha256,
            "root": self.root,
            "inventory": {
                "file_count": len(self.files),
                "total_bytes": sum(item.size for item in self.files),
                "files": [item.evidence() for item in self.files],
            },
            "coverage": {
                "complete": not self.gaps,
                "gaps": [dict(gap) for gap in self.gaps],
            },
            "limits": {name: getattr(self.limits, name)
                       for name in self.limits.__dataclass_fields__},
            "static_contract": {
                "target_code_executed": False,
                "target_modules_imported": False,
                "processes_started": False,
                "network_accessed": False,
                "filesystem_writes": False,
                "symlinks_followed": False,
            },
        }
        return _report(body)


def safe_relative(value: str | os.PathLike[str]) -> str:
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise SnapshotError("relative path must be text or path-like") from exc
    if not isinstance(raw, str) or not raw or len(raw) > 32_768 or "\x00" in raw:
        raise SnapshotError("relative path is invalid")
    portable = raw.replace("\\", "/")
    # PurePosixPath normalizes dot and empty segments.  Validate the lexical
    # spelling first so distinct caller inputs cannot alias the same evidence
    # path and so Windows drive/UNC paths fail on every host platform.
    segments = portable.split("/")
    windows = PureWindowsPath(raw)
    if (portable.startswith("/") or windows.is_absolute() or windows.drive or
            any(part in {"", ".", ".."} for part in segments)):
        raise SnapshotError("relative path escapes the snapshot root")
    pure = PurePosixPath(portable)
    return pure.as_posix()


def _is_link_or_reparse(info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode):
        return True
    attrs = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attrs & reparse)


def _is_singly_linked(info: os.stat_result) -> bool:
    """Return whether one directory entry is the file's only hard link.

    A second hard link can let a path outside the selected tree mutate the same
    inode without changing the in-tree path.  The immutable snapshot profile
    therefore treats multiply-linked files as an explicit coverage gap.
    """
    return int(getattr(info, "st_nlink", 1)) == 1


def _gap(reason: str, path: str = "", detail: str = "") -> Mapping[str, Any]:
    row = {"reason": reason, "path": path}
    if detail:
        row["detail"] = detail[:512]
    return MappingProxyType(row)


def _lexical_absolute(path: Path) -> Path:
    """Return an absolute spelling without resolving any link component."""
    return Path(os.path.abspath(os.fspath(path)))


def _assert_real_components(path: Path, *, start: Path | None = None) -> None:
    """Reject a link/reparse point in the existing lexical path components.

    This is repeated around file reads.  Together with the opened-file identity
    checks it makes detected concurrent path swaps explicit coverage gaps
    instead of silently mixing those bytes.  It is not an atomic whole-tree
    filesystem snapshot and does not claim to defeat every restored-metadata
    race in an actively hostile directory.
    """
    absolute = _lexical_absolute(path)
    floor = _lexical_absolute(start) if start is not None else None
    if floor is not None:
        try:
            relative = absolute.relative_to(floor)
        except ValueError as exc:
            raise SnapshotError("path escapes snapshot root") from exc
        current = floor
        parts = relative.parts
        floor_info = os.lstat(floor)
        if _is_link_or_reparse(floor_info):
            raise SnapshotError("snapshot root may not be a link or reparse point")
    else:
        current = Path(absolute.anchor)
        parts = absolute.parts[1:]
    for part in parts:
        current = current / part
        info = os.lstat(current)
        if _is_link_or_reparse(info):
            raise SnapshotError("snapshot path contains a link or reparse point")


def _walk(root: Path, limits: SnapshotLimits) -> Iterator[tuple[Path, str] | Mapping[str, Any]]:
    pending: list[tuple[Path, str]] = [(root, "")]
    while pending:
        directory, prefix = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = heapq.nsmallest(
                    limits.max_entries_per_directory + 1, iterator,
                    key=lambda item: (item.name.casefold(), item.name))
        except OSError as exc:
            yield _gap("directory-unreadable", prefix, type(exc).__name__)
            continue
        if len(entries) > limits.max_entries_per_directory:
            entries.pop()
            yield _gap("max-entries-per-directory", prefix,
                       str(limits.max_entries_per_directory))
        children: list[tuple[Path, str]] = []
        for entry in entries:
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            try:
                safe = safe_relative(relative)
            except SnapshotError:
                yield _gap("invalid-path", relative[:limits.max_path_chars])
                continue
            if len(safe) > limits.max_path_chars:
                yield _gap("path-too-long", safe[:limits.max_path_chars])
                continue
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                yield _gap("entry-unreadable", safe, type(exc).__name__)
                continue
            if _is_link_or_reparse(info):
                yield _gap("symlink-or-reparse-skipped", safe)
            elif stat.S_ISDIR(info.st_mode):
                if entry.name.casefold() in _SKIP_DIRS:
                    yield _gap("excluded-directory-policy", safe)
                else:
                    children.append((Path(entry.path), safe))
            elif stat.S_ISREG(info.st_mode):
                # Windows DirEntry metadata may report st_nlink=0 even for a
                # normal file.  The authoritative hard-link check is made via
                # Path.stat immediately before the descriptor is opened.
                yield Path(entry.path), safe
            else:
                yield _gap("non-regular-file-skipped", safe)
        pending.extend(reversed(children))


def capture(root: str | os.PathLike[str], limits: SnapshotLimits | None = None) -> SourceSnapshot:
    """Capture one bounded immutable view of *root*, never following links."""
    limits = limits or SnapshotLimits()
    try:
        supplied = Path(root)
    except TypeError as exc:
        raise SnapshotError("root must be path-like") from exc
    try:
        lexical_root = _lexical_absolute(supplied)
        _assert_real_components(lexical_root)
        lexical_before = os.lstat(lexical_root)
        base = lexical_root.resolve(strict=True)
        # Resolve must not silently change the requested root.  Recheck the
        # lexical spelling and its identity immediately afterwards so a link
        # or junction swap during root setup fails closed before enumeration.
        _assert_real_components(lexical_root)
        lexical_after = os.lstat(lexical_root)
        root_info = os.lstat(base)
    except OSError as exc:
        raise SnapshotError("snapshot root is unavailable") from exc
    root_identity_before = (
        lexical_before.st_dev, lexical_before.st_ino, lexical_before.st_mode)
    root_identity_after = (
        lexical_after.st_dev, lexical_after.st_ino, lexical_after.st_mode)
    resolved_identity = (root_info.st_dev, root_info.st_ino, root_info.st_mode)
    if (root_identity_before != root_identity_after
            or root_identity_after != resolved_identity):
        raise SnapshotError("snapshot root changed while it was resolved")
    if not stat.S_ISDIR(root_info.st_mode) or _is_link_or_reparse(root_info):
        raise SnapshotError("snapshot root must be a real directory")

    files: list[SnapshotFile] = []
    gaps: list[Mapping[str, Any]] = []

    def add_gap(row: Mapping[str, Any]) -> bool:
        gaps.append(row)
        if len(gaps) >= limits.max_gaps:
            gaps[-1] = _gap(
                "max-gaps-reached", str(row.get("path", "")),
                "snapshot capture stopped at the configured gap budget")
            return False
        return True

    total = 0
    for candidate in _walk(base, limits):
        if not isinstance(candidate, tuple):
            if not add_gap(candidate):
                break
            continue
        path, relative = candidate
        if len(files) >= limits.max_files:
            add_gap(_gap("max-files-reached", relative))
            break
        try:
            _assert_real_components(path, start=base)
            before = path.stat(follow_symlinks=False)
            if _is_link_or_reparse(before) or not stat.S_ISREG(before.st_mode):
                if not add_gap(_gap("file-changed-or-link", relative)):
                    break
                continue
            if not _is_singly_linked(before):
                if not add_gap(_gap("multiple-hard-links-skipped", relative)):
                    break
                continue
            if before.st_size > limits.max_file_bytes:
                if not add_gap(_gap("max-file-bytes", relative, str(before.st_size))):
                    break
                continue
            if total + before.st_size > limits.max_total_bytes:
                add_gap(_gap("max-total-bytes", relative))
                break
            # Opening by path can race.  We compare identity/metadata before and
            # after and fail this file closed rather than claiming stable bytes.
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags)
            with os.fdopen(descriptor, "rb", closefd=True) as handle:
                content = handle.read(limits.max_file_bytes + 1)
                opened = os.fstat(handle.fileno())
            _assert_real_components(path, start=base)
            after = path.stat(follow_symlinks=False)
        except (OSError, SnapshotError) as exc:
            if not add_gap(_gap("file-unreadable", relative, type(exc).__name__)):
                break
            continue
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_open = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if (_is_link_or_reparse(after) or not _is_singly_linked(opened)
                or not _is_singly_linked(after) or identity_before != identity_open or
                identity_open != identity_after or len(content) != opened.st_size):
            if not add_gap(_gap("file-changed-during-capture", relative)):
                break
            continue
        if len(content) > limits.max_file_bytes:
            if not add_gap(_gap("max-file-bytes", relative, str(len(content)))):
                break
            continue
        language = _LANGUAGE.get(path.suffix.casefold(), "unknown")
        item = SnapshotFile(relative, language, len(content), _sha(content), content)
        files.append(item)
        total += len(content)

    files.sort(key=lambda item: item.path)
    gaps.sort(key=lambda row: (str(row.get("path", "")), str(row.get("reason", ""))))
    limit_evidence = {name: getattr(limits, name) for name in limits.__dataclass_fields__}
    manifest = {"schema": SCHEMA, "version": VERSION,
                "files": [item.evidence() for item in files],
                "gaps": [dict(row) for row in gaps], "limits": limit_evidence}
    digest = _sha(manifest)
    index = MappingProxyType({item.path: item for item in files})
    return SourceSnapshot(".", tuple(files), tuple(gaps), limits, digest, index)


def diff(current: SourceSnapshot, previous: SourceSnapshot) -> dict[str, Any]:
    """Return deterministic content-level invalidation evidence."""
    old = {item.path: item.sha256 for item in previous.files}
    new = {item.path: item.sha256 for item in current.files}
    body = {
        "schema": "attestor.snapshot-diff/4.1",
        "version": VERSION,
        "previous_snapshot_sha256": previous.snapshot_sha256,
        "current_snapshot_sha256": current.snapshot_sha256,
        "added": sorted(set(new) - set(old)),
        "removed": sorted(set(old) - set(new)),
        "changed": sorted(path for path in set(old) & set(new) if old[path] != new[path]),
        "unchanged": sorted(path for path in set(old) & set(new) if old[path] == new[path]),
        "static_contract": {"filesystem_writes": False, "network_accessed": False,
                            "target_code_executed": False},
    }
    return _report(body)


def verify_report(report: Mapping[str, Any]) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if type(report) is not dict:
        return False, ["report is not a JSON object"]
    schema = report.get("schema")
    if report.get("version") != VERSION or schema not in {SCHEMA, "attestor.snapshot-diff/4.1"}:
        errors.append("unsupported snapshot schema or version")
    supplied = report.get("report_sha256")
    body = {key: value for key, value in report.items() if key != "report_sha256"}
    try:
        expected = _sha(body)
    except SnapshotError:
        errors.append("report is not canonical JSON")
    else:
        if supplied != expected:
            errors.append("report digest mismatch")
    if schema == SCHEMA:
        inventory = report.get("inventory")
        coverage = report.get("coverage")
        limits = report.get("limits")
        if (not isinstance(inventory, dict) or not isinstance(coverage, dict) or
                not isinstance(limits, dict)):
            errors.append("snapshot inventory, coverage, or limits are malformed")
        else:
            files = inventory.get("files")
            gaps = coverage.get("gaps")
            valid_files = isinstance(files, list) and all(type(row) is dict for row in files)
            valid_gaps = isinstance(gaps, list) and all(type(row) is dict for row in gaps)
            if not valid_files or not valid_gaps:
                errors.append("snapshot files or gaps are malformed")
            else:
                paths: list[str] = []
                total = 0
                for row in files:
                    try:
                        path = safe_relative(row.get("path"))
                    except SnapshotError:
                        errors.append("snapshot file path is invalid")
                        continue
                    size = row.get("size")
                    digest = row.get("sha256")
                    if (type(size) is not int or size < 0 or
                            not isinstance(digest, str) or
                            not re.fullmatch(r"[0-9a-f]{64}", digest) or
                            not isinstance(row.get("language"), str)):
                        errors.append("snapshot file evidence is invalid")
                        continue
                    paths.append(path)
                    total += size
                if paths != sorted(set(paths)):
                    errors.append("snapshot file inventory is not unique and sorted")
                if inventory.get("file_count") != len(files) or inventory.get("total_bytes") != total:
                    errors.append("snapshot inventory totals mismatch")
                try:
                    parsed_limits = SnapshotLimits(**limits)
                except (TypeError, SnapshotError):
                    errors.append("snapshot limits are invalid")
                else:
                    manifest = {"schema": SCHEMA, "version": VERSION,
                                "files": files, "gaps": gaps,
                                "limits": {name: getattr(parsed_limits, name)
                                           for name in parsed_limits.__dataclass_fields__}}
                    if report.get("snapshot_sha256") != _sha(manifest):
                        errors.append("snapshot manifest digest mismatch")
    return not errors, errors


capture_snapshot = capture
