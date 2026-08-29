#!/usr/bin/env python3
"""Bounded, read-only observation adapters for Attestor 4.2 Owner Control.

This module has no shell, subprocess, socket, mutation, persistence, or
credential-store capability.  The public Owner Control coordinator consumes a
one-use capability before calling these adapters.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import stat
import struct
import sys
from typing import Any, Mapping

import computer_scan41
import control_policy42 as policy


VERSION = "4.2"
SCHEMA = "attestor-owner-control-inventory/4.2"
MAX_ENTRIES_PER_DIRECTORY = policy.MAX_ENTRIES_PER_DIRECTORY
MAX_HASH_FILE_BYTES = policy.MAX_HASH_FILE_BYTES
MAX_TOTAL_HASH_BYTES = policy.MAX_TOTAL_HASH_BYTES
READ_BLOCK_BYTES = 128 * 1024


class ControlInventoryError(ValueError):
    """A read-only inventory request or filesystem boundary failed closed."""


def _is_link_or_reparse_metadata(metadata: os.stat_result) -> bool:
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse)


def _lstat(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ControlInventoryError(f"{label} is unavailable") from exc
    if _is_link_or_reparse_metadata(metadata):
        raise ControlInventoryError(
            f"{label} contains a link or reparse point")
    return metadata


def _local_fixed(path: Path) -> bool:
    spelling = os.fspath(path)
    if spelling.replace("\\", "/").startswith("//"):
        return False
    if os.name != "nt":
        return True
    anchor = path.anchor
    if not anchor or anchor.startswith("\\\\"):
        return False
    try:
        import ctypes
        return int(ctypes.windll.kernel32.GetDriveTypeW(anchor)) == 3
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def _safe_root(value: str) -> tuple[Path, os.stat_result]:
    if type(value) is not str:
        raise ControlInventoryError("inventory root must be text")
    spelling = value.replace("\\", "/")
    if not value or "\x00" in value or spelling.startswith("//"):
        raise ControlInventoryError("inventory root must be a local path")
    supplied = Path(value).expanduser()
    if not supplied.is_absolute():
        raise ControlInventoryError("inventory root must be absolute")
    if any(part in {".", ".."} for part in supplied.parts):
        raise ControlInventoryError("inventory root contains traversal")
    current = Path(supplied.anchor)
    _lstat(current, "inventory root")
    for part in supplied.parts[1:]:
        if policy.is_protected_directory_name(part):
            raise ControlInventoryError(
                "inventory root enters a protected directory")
        current = current / part
        _lstat(current, "inventory root")
    try:
        root = supplied.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ControlInventoryError("inventory root is unavailable") from exc
    metadata = _lstat(root, "inventory root")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ControlInventoryError("inventory root must be a directory")
    if not _local_fixed(root):
        raise ControlInventoryError(
            "network and removable inventory roots are denied")
    return root, metadata


def _root_identity(root: Path, metadata: os.stat_result) -> str:
    normalized = os.path.normcase(os.path.normpath(os.fspath(root)))
    return policy.digest_json({
        "device": int(metadata.st_dev),
        "inode": int(metadata.st_ino),
        "resolved_path": normalized,
    })


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        stat.S_IFMT(metadata.st_mode),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


def _path_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return _file_identity(metadata) + (int(metadata.st_ctime_ns),)


def _hash_regular_file(
    path: Path,
    *,
    expected: os.stat_result,
) -> tuple[str, int]:
    if (_is_link_or_reparse_metadata(expected)
            or not stat.S_ISREG(expected.st_mode)
            or int(getattr(expected, "st_nlink", 1)) != 1
            or not 0 <= int(expected.st_size) <= MAX_HASH_FILE_BYTES):
        raise ControlInventoryError("file is ineligible for bounded hashing")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ControlInventoryError("file could not be opened safely") from exc
    digest = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(descriptor)
        if (_is_link_or_reparse_metadata(opened)
                or not stat.S_ISREG(opened.st_mode)
                or int(getattr(opened, "st_nlink", 1)) != 1
                or (opened.st_dev, opened.st_ino)
                != (expected.st_dev, expected.st_ino)):
            raise ControlInventoryError(
                "file identity changed before hashing")
        while True:
            block = os.read(descriptor, READ_BLOCK_BYTES)
            if not block:
                break
            total += len(block)
            if total > MAX_HASH_FILE_BYTES:
                raise ControlInventoryError(
                    "file grew beyond the hash boundary")
            digest.update(block)
    except OSError as exc:
        raise ControlInventoryError("file could not be hashed") from exc
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise ControlInventoryError("file changed while hashing") from exc
    if (_is_link_or_reparse_metadata(after)
            or _file_identity(expected) != _file_identity(opened)
            or _file_identity(opened) != _file_identity(after)
            or _path_identity(expected) != _path_identity(after)
            or total != int(expected.st_size)):
        raise ControlInventoryError("file changed while hashing")
    return digest.hexdigest(), total


def _scoped_regular_file(
    root: Path,
    relative: str,
) -> tuple[Path, os.stat_result]:
    candidate = root.joinpath(*Path(relative).parts)
    current = root
    for part in Path(relative).parts[:-1]:
        if part in {"", ".", ".."} or policy.is_protected_directory_name(part):
            raise ControlInventoryError("file path is outside the safe scope")
        current = current / part
        metadata = _lstat(current, "file parent")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ControlInventoryError("file parent is not a directory")
    metadata = _lstat(candidate, "file")
    if (not stat.S_ISREG(metadata.st_mode)
            or int(getattr(metadata, "st_nlink", 1)) != 1):
        raise ControlInventoryError("file is not one regular scoped file")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ControlInventoryError("file escaped its scoped root") from exc
    return resolved, metadata


def _safe_text(value: Any, maximum: int = 2_000) -> str:
    rows: list[str] = []
    size = 0
    bidi = {
        0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D,
        0x202E, 0x2066, 0x2067, 0x2068, 0x2069,
    }
    for character in str(value or ""):
        number = ord(character)
        if number < 0x20 or 0x7F <= number <= 0x9F:
            clean = "\\u%04x" % number
        elif number in bidi:
            clean = "\\u%04x" % number
        else:
            clean = character
        if size + len(clean) > maximum:
            break
        rows.append(clean)
        size += len(clean)
    return "".join(rows)


def _memory_total_bytes() -> tuple[int | None, str]:
    if os.name == "nt":
        try:
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            status = MEMORYSTATUSEX()
            status.dwLength = ctypes.sizeof(status)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(
                    ctypes.byref(status)):
                return None, "unavailable"
            return int(status.ullTotalPhys), "windows-api"
        except (AttributeError, OSError, TypeError, ValueError):
            return None, "unavailable"
    try:
        pages = int(os.sysconf("SC_PHYS_PAGES"))
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
        if pages > 0 and page_size > 0:
            return pages * page_size, "posix-sysconf"
    except (AttributeError, OSError, TypeError, ValueError):
        return None, "unavailable"
    return None, "unavailable"


def _os_version() -> dict[str, Any]:
    if os.name == "nt" and hasattr(sys, "getwindowsversion"):
        version = sys.getwindowsversion()
        return {
            "family": "windows",
            "major": int(version.major),
            "minor": int(version.minor),
            "build": int(version.build),
        }
    if hasattr(os, "uname"):
        value = os.uname()
        return {
            "family": _safe_text(value.sysname, 80).casefold(),
            "release": _safe_text(value.release, 120),
        }
    return {"family": _safe_text(os.name, 40)}


def system_inventory(request: Mapping[str, Any]) -> dict[str, Any]:
    """Collect bounded, non-identifying system facts without a subprocess."""
    try:
        policy.create_plan(
            policy.SYSTEM_INVENTORY,
            dict(request),
            session_id="0" * 32,
        )
    except (TypeError, policy.ControlPolicyError) as exc:
        raise ControlInventoryError("system-inventory request is invalid") from exc
    memory_bytes, memory_source = _memory_total_bytes()
    storage: list[dict[str, Any]] = []
    gaps: list[str] = []
    for index, raw_root in enumerate(request["storage_roots"], 1):
        try:
            root, metadata = _safe_root(raw_root)
            usage = shutil.disk_usage(root)
            storage.append({
                "root_index": index,
                "root_identity_sha256": _root_identity(root, metadata),
                "total_bytes": int(usage.total),
                "used_bytes": int(usage.used),
                "free_bytes": int(usage.free),
                "path_emitted": False,
            })
        except (ControlInventoryError, OSError, ValueError):
            gaps.append(
                "an explicitly scoped storage root was unavailable or unsafe")
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "kind": policy.SYSTEM_INVENTORY,
        "status": "partial" if gaps else "complete",
        "system": {
            "os": _os_version(),
            "architecture_bits": struct.calcsize("P") * 8,
            "logical_processors": int(os.cpu_count() or 0),
            "physical_memory_bytes": memory_bytes,
            "memory_evidence_source": memory_source,
            "hostname_emitted": False,
            "username_emitted": False,
            "network_identifiers_emitted": False,
        },
        "storage": storage,
        "coverage": {"complete": not gaps, "gaps": gaps},
        "execution": _execution_evidence(files_read=False),
    }


def _execution_evidence(*, files_read: bool) -> dict[str, bool]:
    return {
        "credential_store_accessed": False,
        "file_contents_emitted": False,
        "filesystem_mutated": False,
        "files_read_for_hashing": files_read,
        "mutation_executed": False,
        "network_accessed": False,
        "persistence_created": False,
        "process_executed": False,
        "shell_invoked": False,
    }


def find_files(request: Mapping[str, Any]) -> dict[str, Any]:
    """Find bounded regular files and return metadata plus optional hashes."""
    # Reuse the strict policy validator without trusting a truthy flag or a
    # caller-defined request shape.  The temporary session is data only and
    # performs no filesystem operation.
    try:
        policy.create_plan(
            policy.FIND_FILES,
            dict(request),
            session_id="0" * 32,
        )
    except (TypeError, policy.ControlPolicyError) as exc:
        raise ControlInventoryError("find-files request is invalid") from exc

    selected_roots: list[tuple[Path, os.stat_result]] = []
    gaps: list[str] = []
    for value in request["roots"]:
        try:
            selected_roots.append(_safe_root(value))
        except ControlInventoryError:
            gaps.append(
                "an explicitly scoped search root was unavailable or unsafe")
    results: list[dict[str, Any]] = []
    directories_seen = 0
    files_seen = 0
    linked_skipped = 0
    protected_skipped = 0
    sensitive_skipped = 0
    unreadable = 0
    cross_filesystem_skipped = 0
    entries_omitted = 0
    hash_failures = 0
    hash_budget_used = 0
    stop = False
    extension_filter = set(request["extensions"])
    name_filter = request["name_contains"].casefold()

    for root_index, (root, root_metadata) in enumerate(selected_roots, 1):
        if stop:
            break
        stack: list[tuple[Path, int]] = [(root, 0)]
        while stack:
            if directories_seen >= request["max_directories"]:
                gaps.append("the directory traversal boundary was reached")
                stop = True
                break
            directory, depth = stack.pop()
            try:
                directory_metadata = directory.lstat()
            except OSError:
                unreadable += 1
                continue
            if (_is_link_or_reparse_metadata(directory_metadata)
                    or not stat.S_ISDIR(directory_metadata.st_mode)):
                linked_skipped += 1
                continue
            if directory_metadata.st_dev != root_metadata.st_dev:
                cross_filesystem_skipped += 1
                continue
            directories_seen += 1
            try:
                entries: list[os.DirEntry[str]] = []
                with os.scandir(directory) as stream:
                    for entry in stream:
                        if len(entries) >= MAX_ENTRIES_PER_DIRECTORY:
                            entries_omitted += 1
                            break
                        entries.append(entry)
                entries.sort(key=lambda row: (row.name.casefold(), row.name))
            except OSError:
                unreadable += 1
                continue
            children: list[Path] = []
            for entry in entries:
                try:
                    # Windows cloud-backed filesystems can expose st_dev == 0
                    # through DirEntry.stat while os.stat exposes the actual
                    # volume identity. Use the latter for the boundary check.
                    metadata = os.stat(entry.path, follow_symlinks=False)
                except OSError:
                    unreadable += 1
                    continue
                if _is_link_or_reparse_metadata(metadata):
                    linked_skipped += 1
                    continue
                if metadata.st_dev != root_metadata.st_dev:
                    cross_filesystem_skipped += 1
                    continue
                if stat.S_ISDIR(metadata.st_mode):
                    if policy.is_protected_directory_name(entry.name):
                        protected_skipped += 1
                    elif depth < request["max_depth"]:
                        children.append(Path(entry.path))
                    else:
                        gaps.append("the directory depth boundary omitted entries")
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    continue
                files_seen += 1
                if files_seen > request["max_files"]:
                    gaps.append("the file traversal boundary was reached")
                    stop = True
                    break
                if policy.is_sensitive_file_name(entry.name):
                    sensitive_skipped += 1
                    continue
                suffix = Path(entry.name).suffix.casefold()
                if extension_filter and suffix not in extension_filter:
                    continue
                if name_filter and name_filter not in entry.name.casefold():
                    continue
                if int(getattr(metadata, "st_nlink", 1)) != 1:
                    linked_skipped += 1
                    continue
                try:
                    relative = Path(entry.path).relative_to(root).as_posix()
                except ValueError:
                    linked_skipped += 1
                    continue
                try:
                    scoped_path, metadata = _scoped_regular_file(root, relative)
                except ControlInventoryError:
                    linked_skipped += 1
                    continue
                row: dict[str, Any] = {
                    "root_index": root_index,
                    "relative_path": _safe_text(relative),
                    "bytes": int(metadata.st_size),
                    "modified_time_ns": int(metadata.st_mtime_ns),
                    "suffix": _safe_text(suffix, 80),
                    "content_emitted": False,
                    "sha256": None,
                    "hash_state": "not-requested",
                }
                if request["hash_files"]:
                    if metadata.st_size > MAX_HASH_FILE_BYTES:
                        row["hash_state"] = "file-too-large"
                    elif hash_budget_used + metadata.st_size > MAX_TOTAL_HASH_BYTES:
                        row["hash_state"] = "total-hash-boundary"
                        gaps.append("the total file-hash byte boundary was reached")
                    else:
                        try:
                            digest, size = _hash_regular_file(
                                scoped_path, expected=metadata)
                            row["sha256"] = digest
                            row["hash_state"] = "hashed"
                            hash_budget_used += size
                        except ControlInventoryError:
                            row["hash_state"] = "failed-closed"
                            hash_failures += 1
                results.append(row)
                if len(results) >= request["max_results"]:
                    gaps.append("the result boundary was reached")
                    stop = True
                    break
            if stop:
                break
            for child in reversed(children):
                stack.append((child, depth + 1))

    gaps = list(dict.fromkeys(gaps))[:100]
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "kind": policy.FIND_FILES,
        "status": "partial" if gaps or not selected_roots else "complete",
        "roots": [
            {
                "root_index": index,
                "root_identity_sha256": _root_identity(root, metadata),
                "path_emitted": False,
            }
            for index, (root, metadata) in enumerate(selected_roots, 1)
        ],
        "summary": {
            "directories_seen": directories_seen,
            "files_seen": min(files_seen, request["max_files"]),
            "results_returned": len(results),
            "hash_bytes_read": hash_budget_used,
            "hash_failures": hash_failures,
            "linked_or_reparse_or_hardlinked_skipped": linked_skipped,
            "protected_directories_skipped": protected_skipped,
            "sensitive_files_skipped": sensitive_skipped,
            "cross_filesystem_skipped": cross_filesystem_skipped,
            "unreadable_entries": unreadable,
            "entry_boundary_omissions": entries_omitted,
        },
        "files": results,
        "coverage": {"complete": not gaps, "gaps": gaps},
        "execution": _execution_evidence(
            files_read=any(row["hash_state"] == "hashed" for row in results)),
    }


def computer_project_scan(request: Mapping[str, Any]) -> dict[str, Any]:
    """Delegate to Attestor's established permissioned static project scanner."""
    try:
        policy.create_plan(
            policy.COMPUTER_PROJECT_SCAN,
            dict(request),
            session_id="0" * 32,
        )
    except (TypeError, policy.ControlPolicyError) as exc:
        raise ControlInventoryError(
            "computer-project-scan request is invalid") from exc
    try:
        report = computer_scan41.scan_computer(
            authorized=True,
            scope=request["scope"],
            max_projects=request["max_projects"],
            review_improvements=request["review_improvements"],
        )
    except (OSError, PermissionError, RuntimeError, TypeError, ValueError) as exc:
        raise ControlInventoryError(
            "computer project scan failed closed") from exc
    if type(report) is not dict:
        raise ControlInventoryError(
            "computer project scan returned an invalid report")
    try:
        detached = policy.require_json_object(report)
    except policy.ControlPolicyError as exc:
        raise ControlInventoryError(
            "computer project scan report exceeded its boundary") from exc
    effects = detached.get("execution")
    required_false = (
        "target_code_executed", "network_accessed", "target_files_written",
        "discovered_files_written", "improvements_applied",
        "os_privilege_elevation_requested", "access_control_bypass_requested",
    )
    if (type(effects) is not dict
            or any(effects.get(field) is not False for field in required_false)):
        raise ControlInventoryError(
            "computer project scan reported a forbidden side effect")
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "kind": policy.COMPUTER_PROJECT_SCAN,
        "status": detached.get("status", "unknown"),
        "computer_scan": detached,
        "execution": _execution_evidence(files_read=False),
    }


def execute_observation(plan: Mapping[str, Any]) -> dict[str, Any]:
    """Execute one already-authorized observation plan.

    Capability issuance and consumption intentionally live in
    :mod:`owner_control42`; this function never accepts a boolean permission.
    """
    try:
        exact = policy.require_plan(plan)
    except policy.ControlPolicyError as exc:
        raise ControlInventoryError("observation plan is invalid") from exc
    action = exact["action"]
    if action not in policy.OBSERVATION_ACTIONS:
        raise ControlInventoryError(
            "plan-only mutation evidence is not executable")
    request = exact["request"]
    if action == policy.SYSTEM_INVENTORY:
        return system_inventory(request)
    if action == policy.FIND_FILES:
        return find_files(request)
    if action == policy.COMPUTER_PROJECT_SCAN:
        return computer_project_scan(request)
    raise ControlInventoryError("observation action is unavailable")


__all__ = [
    "ControlInventoryError", "MAX_HASH_FILE_BYTES", "MAX_TOTAL_HASH_BYTES",
    "SCHEMA", "VERSION", "computer_project_scan", "execute_observation",
    "find_files", "system_inventory",
]
