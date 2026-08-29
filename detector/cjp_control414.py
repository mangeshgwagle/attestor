#!/usr/bin/env python3
"""Cockroach Janta Party's permission-bound local enterprise file control.

The controller is intentionally local and artifact-scoped.  It can inspect
authorized files, understand authorized SQLite/SQL artifacts, preview exact
replacement bytes, and apply a previously previewed replacement transaction.
It never grants account, network, credential, process, administrator, registry,
service, persistence, or corporate-system authority.
"""
from __future__ import annotations

import ast
import base64
import binascii
import difflib
import hashlib
import hmac
import itertools
import json
import os
import stat
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable
import xml.etree.ElementTree as ElementTree

import cjp_authorization414 as authorization
import database_intelligence414
import secret_guard
import variant414

try:
    import tomllib
except ImportError:  # pragma: no cover - Attestor 4.1.4 targets Python 3.11+
    tomllib = None


VERSION = "4.1.4"
SCHEMA = "attestor-cjp-local-control/4.1.4"
REQUEST_SCHEMA = "attestor-cjp-control-request/4.1.4"
CANDIDATE_SCHEMA = "attestor-cjp-file-candidate/4.1.4"
PROFILE_SLUG = "cockroach-janta-party"
MAX_REQUEST_BYTES = 128 * 1024
MAX_CANDIDATE_DOCUMENT_BYTES = 48 * 1024 * 1024
MAX_CHANGED_FILES = 12
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_CHANGE_BYTES = 32 * 1024 * 1024
MAX_DIFF_BYTES = 2 * 1024 * 1024
MAX_DIFF_LINES = 20_000
MAX_DIFF_INPUT_LINES = 10_000
MAX_TEXT_CHARS = 4 * 1024 * 1024
# Nesting deeper than this is refused before the parser ever sees it. The
# documents this module reads are requests and permissions -- a handful of
# levels -- so 64 is far above anything legitimate and far below anything that
# strains a parser. The bound is stated here rather than left to whatever
# recursion the interpreter happens to allow: CPython's limit varies with
# platform, C stack size and version, so a control that relies on RecursionError
# enforces different rules on Windows and Linux and none at all on a build with
# a generous stack.
MAX_JSON_DEPTH = 64
SHA256_RE = authorization.SHA256_RE
_ACTIONS = frozenset({
    "inspect-files", "analyze-database", "preview-file-edit",
})
_REQUEST_KEYS = frozenset({
    "schema", "profile", "action", "root", "files", "organization",
    "issuer", "owner_statement", "purpose", "ttl_seconds",
    "candidate_bundle", "backup_root",
})
_CANDIDATE_KEYS = frozenset({
    "schema", "changes", "candidate_sha256",
})
_CHANGE_KEYS = frozenset({
    "path", "before_sha256", "after_sha256", "encoding", "content",
})
_BINARY_EXECUTABLE_SUFFIXES = frozenset({
    ".app", ".com", ".cpl", ".dll", ".dmg", ".drv", ".dylib", ".efi",
    ".exe", ".iso", ".jar", ".ko", ".lnk", ".msi", ".msix", ".ocx",
    ".reg", ".scr", ".so", ".sys", ".vbs", ".wsf",
})
_SQLITE_SUFFIXES = frozenset({".db", ".sqlite", ".sqlite3"})
_BIDI_CONTROLS = frozenset({
    "\u061c", "\u200e", "\u200f", "\u202a", "\u202b", "\u202c",
    "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069",
})


class CJPControlError(ValueError):
    """A CJP request, candidate, permission, or transaction failed closed."""

    def __init__(
        self,
        message: str,
        *,
        cleanup_errors: Iterable[str] = (),
    ) -> None:
        super().__init__(message)
        self.cleanup_errors = tuple(
            str(value)[:256] for value in list(cleanup_errors)[:64])


def _response_language() -> dict[str, Any]:
    profile = variant414.require_compiled_profile(
        variant414.COCKROACH_JANTA_PARTY)
    return {
        **variant414.response_language_metadata(profile),
        "profile_sha256": variant414.profile_identity(profile),
        "verified": True,
    }


def _canonical(value: Any) -> bytes:
    try:
        raw = json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (OverflowError, RecursionError, TypeError, ValueError) as exc:
        raise CJPControlError(
            "control evidence is not deterministic JSON") from exc
    if len(raw) > MAX_CANDIDATE_DOCUMENT_BYTES:
        raise CJPControlError("control evidence exceeds its byte boundary")
    return raw


def _sha(value: Any) -> str:
    return hashlib.sha256(
        value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CJPControlError("JSON document contains a duplicate key")
        result[key] = value
    return result


def _json_depth(text: str) -> int:
    """The deepest bracket nesting in `text`, ignoring brackets in strings.

    A single pass, no recursion, so the answer does not depend on the
    interpreter's stack. Brackets inside string literals are not structure --
    ``{"a": "[[[["}`` is depth one -- so the scanner tracks whether it is
    inside a string and honours backslash escapes. Anything malformed is left
    for ``json.loads`` to reject; this only counts.
    """
    depth = maximum = 0
    in_string = escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > maximum:
                maximum = depth
        elif character in "]}":
            depth -= 1
    return maximum


def _load_json_file(
    value: str | os.PathLike[str],
    *,
    maximum: int,
    label: str,
) -> tuple[dict[str, Any], Path]:
    path = _regular_file(value, maximum=maximum, label=label)
    raw, _digest, _metadata = _secure_read(
        path, maximum=maximum, label=label, collect=True)
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise CJPControlError(
            label + " must be exactly one UTF-8 JSON document") from exc
    # Checked before parsing, so a hostile document is refused rather than
    # handed to a recursive-descent parser to survive or not.
    if _json_depth(text) > MAX_JSON_DEPTH:
        raise CJPControlError(
            "%s nests deeper than %d levels" % (label, MAX_JSON_DEPTH))
    try:
        document = json.loads(
            text, object_pairs_hook=_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                CJPControlError("JSON non-finite number is forbidden")))
    except CJPControlError:
        raise
    except (RecursionError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise CJPControlError(
            label + " must be exactly one UTF-8 JSON document") from exc
    if type(document) is not dict:
        raise CJPControlError(label + " must be one JSON object")
    return document, path


def _is_link_or_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse)


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    """Return identity fields stable across path-stat and descriptor-stat.

    On Windows cloud-backed filesystems, ``lstat`` and ``fstat`` can report
    different ctime values for the same unchanged file.  Ctime remains part of
    the path-to-path comparison via ``_path_identity``; excluding it only from
    the descriptor binding avoids false mutation alarms without weakening the
    before/after path check.
    """
    return (
        int(info.st_dev),
        int(info.st_ino),
        stat.S_IFMT(info.st_mode),
        int(info.st_size),
        int(info.st_mtime_ns),
    )


def _path_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return _identity(info) + (int(info.st_ctime_ns),)


def _looks_network_spelled(value: str) -> bool:
    return value.replace("\\", "/").startswith("//")


def _is_local_fixed_path(path: Path) -> bool:
    spelling = os.fspath(path)
    if _looks_network_spelled(spelling):
        return False
    if os.name != "nt":
        return True
    anchor = path.anchor
    if not anchor or _looks_network_spelled(anchor):
        return False
    try:
        import ctypes
        return int(ctypes.windll.kernel32.GetDriveTypeW(anchor)) == 3
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def _lexical_absolute(
    value: str | os.PathLike[str],
    *,
    base: Path,
    label: str,
) -> Path:
    try:
        text = os.fspath(value)
    except TypeError as exc:
        raise CJPControlError(label + " path must be local text") from exc
    if not isinstance(text, str) or not text.strip() or "\x00" in text:
        raise CJPControlError(label + " path must be nonempty local text")
    if _looks_network_spelled(text):
        raise CJPControlError(label + " cannot use a network path")
    supplied = Path(text).expanduser()
    lexical = supplied if supplied.is_absolute() else base / supplied
    if not lexical.anchor:
        raise CJPControlError(label + " has no filesystem anchor")
    current = Path(lexical.anchor)
    try:
        if _is_link_or_reparse(current):
            raise CJPControlError(
                label + " crosses a link or reparse point")
        for part in lexical.parts[1:]:
            if part in {"", "."}:
                continue
            if part == "..":
                raise CJPControlError(
                    label + " cannot contain parent traversal")
            current = current / part
            if _is_link_or_reparse(current):
                raise CJPControlError(
                    label + " crosses a link or reparse point")
    except OSError as exc:
        raise CJPControlError(label + " is unavailable") from exc
    return lexical


def _regular_file(
    value: str | os.PathLike[str],
    *,
    maximum: int,
    label: str,
) -> Path:
    supplied = _lexical_absolute(
        value, base=Path.cwd(), label=label)
    try:
        path = supplied.resolve(strict=True)
        info = path.lstat()
    except OSError as exc:
        raise CJPControlError(label + " is unavailable") from exc
    if (_is_link_or_reparse(path) or not stat.S_ISREG(info.st_mode)):
        raise CJPControlError(label + " must be a regular file")
    if not _is_local_fixed_path(path):
        raise CJPControlError(label + " must be on a local fixed filesystem")
    if int(getattr(info, "st_nlink", 1)) != 1:
        raise CJPControlError(label + " cannot have multiple hard links")
    if not 0 < info.st_size <= maximum:
        raise CJPControlError(label + " exceeds its byte boundary")
    return path


def _safe_directory(
    value: str | os.PathLike[str],
    *,
    base: Path,
    label: str,
) -> Path:
    if type(value) is not str or not value.strip():
        raise CJPControlError(label + " must be a nonempty local path")
    supplied = _lexical_absolute(value, base=base, label=label)
    try:
        path = supplied.resolve(strict=True)
        info = path.lstat()
    except OSError as exc:
        raise CJPControlError(label + " is unavailable") from exc
    if (_is_link_or_reparse(path) or not stat.S_ISDIR(info.st_mode)):
        raise CJPControlError(label + " must be an existing regular directory")
    if not _is_local_fixed_path(path):
        raise CJPControlError(label + " must be on a local fixed filesystem")
    return path


def _root_identity_sha256(root: Path) -> str:
    try:
        resolved = root.resolve(strict=True)
        info = resolved.lstat()
    except (OSError, RuntimeError, ValueError) as exc:
        raise CJPControlError(
            "authorized root identity is unavailable") from exc
    if (_is_link_or_reparse(resolved)
            or not stat.S_ISDIR(info.st_mode)
            or not _is_local_fixed_path(resolved)):
        raise CJPControlError("authorized root identity is unsafe")
    normalized = os.path.normcase(os.path.normpath(os.fspath(resolved)))
    return _sha({
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "resolved_path": normalized,
    })


def _assert_root_identity(root: Path, expected_sha256: str) -> None:
    if SHA256_RE.fullmatch(expected_sha256) is None:
        raise CJPControlError(
            "authorized root identity evidence is invalid")
    current = _root_identity_sha256(root)
    if not hmac.compare_digest(current, expected_sha256):
        raise CJPControlError(
            "authorized root identity changed before local control")


def _secure_read(
    path: Path,
    *,
    maximum: int,
    label: str,
    collect: bool,
) -> tuple[bytes, str, os.stat_result]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise CJPControlError(label + " is unavailable") from exc
    if (_is_link_or_reparse(path) or not stat.S_ISREG(before.st_mode)):
        raise CJPControlError(label + " must be a regular non-link file")
    if int(getattr(before, "st_nlink", 1)) != 1:
        raise CJPControlError(label + " cannot have multiple hard links")
    if not 0 < int(before.st_size) <= maximum:
        raise CJPControlError(label + " exceeds its byte boundary")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CJPControlError(label + " could not be opened") from exc
    chunks: list[bytes] = []
    digest = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(descriptor)
        if (_is_link_or_reparse(path)
                or not stat.S_ISREG(opened.st_mode)
                or int(getattr(opened, "st_nlink", 1)) != 1
                or (opened.st_dev, opened.st_ino)
                != (before.st_dev, before.st_ino)):
            raise CJPControlError(
                label + " identity changed before reading")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > maximum:
                raise CJPControlError(
                    label + " grew beyond its byte boundary")
            digest.update(block)
            if collect:
                chunks.append(block)
    except OSError as exc:
        raise CJPControlError(label + " could not be read") from exc
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise CJPControlError(label + " changed while being read") from exc
    if (_is_link_or_reparse(path)
            or _identity(before) != _identity(opened)
            or _identity(opened) != _identity(after)
            or _path_identity(before) != _path_identity(after)
            or total != int(before.st_size)):
        raise CJPControlError(label + " changed while being read")
    return (b"".join(chunks) if collect else b""), digest.hexdigest(), opened


def _relative(value: Any) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > 2_048:
        raise CJPControlError("file scope contains an invalid relative path")
    if "\\" in value or "\x00" in value:
        raise CJPControlError(
            "file scope paths must use canonical forward slashes")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(
            part in {"", ".", ".."} or ":" in part for part in path.parts):
        raise CJPControlError("file scope path is unsafe")
    canonical = path.as_posix()
    if canonical != value:
        raise CJPControlError("file scope path is not canonical")
    return canonical


def _resolve_target(
    root: Path,
    relative: str,
    *,
    maximum: int = MAX_FILE_BYTES,
) -> Path:
    relative = _relative(relative)
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    current = root
    for part in PurePosixPath(relative).parts[:-1]:
        current = current / part
        if _is_link_or_reparse(current):
            raise CJPControlError(
                "file scope traverses a link or reparse point")
    if _is_link_or_reparse(candidate):
        raise CJPControlError(
            "file scope targets a link or reparse point")
    try:
        resolved = candidate.resolve(strict=True)
        info = resolved.stat()
    except OSError as exc:
        raise CJPControlError(
            "file scope target is unavailable") from exc
    if root != resolved and root not in resolved.parents:
        raise CJPControlError("file scope escapes the authorized root")
    if not resolved.is_file() or not stat.S_ISREG(info.st_mode):
        raise CJPControlError(
            "file scope target must be one regular file")
    if getattr(info, "st_nlink", 1) != 1:
        raise CJPControlError(
            "file scope target with multiple hard links is refused")
    if not 0 < info.st_size <= maximum:
        raise CJPControlError(
            "file scope target exceeds the edit byte boundary")
    return resolved


def _sha_file(path: Path, maximum: int = MAX_FILE_BYTES) -> str:
    _data, digest, _metadata = _secure_read(
        path, maximum=maximum, label="scoped file", collect=False)
    return digest


def _resolve_reference(base: Path, value: Any, label: str) -> Path:
    if type(value) is not str or not value.strip():
        raise CJPControlError(label + " path is required")
    supplied = Path(value).expanduser()
    if not supplied.is_absolute():
        supplied = base / supplied
    return _regular_file(
        supplied, maximum=MAX_CANDIDATE_DOCUMENT_BYTES, label=label)


def _resolve_root(base: Path, value: Any) -> Path:
    return _safe_directory(value, base=base, label="authorized root")


def _request_identity(
    request: dict[str, Any],
    root: Path,
    *,
    root_identity_sha256: str,
) -> str:
    return _sha({
        "schema": REQUEST_SCHEMA,
        "profile": PROFILE_SLUG,
        "action": request["action"],
        "root": str(root),
        "root_identity_sha256": root_identity_sha256,
        "files": request["files"],
        "organization": request["organization"],
        "issuer": request["issuer"],
        "owner_statement": request["owner_statement"],
        "purpose": request["purpose"],
        "ttl_seconds": request["ttl_seconds"],
        "candidate_bundle": request["candidate_bundle"],
        "backup_root": request["backup_root"],
    })


def load_request(
    value: str | os.PathLike[str],
) -> tuple[dict[str, Any], Path, Path]:
    """Load a strict, non-authority request document and resolve its root."""
    request, request_path = _load_json_file(
        value, maximum=MAX_REQUEST_BYTES, label="CJP control request")
    if set(request) != _REQUEST_KEYS or request.get("schema") != REQUEST_SCHEMA:
        raise CJPControlError(
            "CJP control request has an unsupported schema or shape")
    if request.get("profile") != PROFILE_SLUG:
        raise CJPControlError(
            "CJP control is available only to the exact Cockroach profile")
    action = request.get("action")
    if type(action) is not str or action not in _ACTIONS:
        raise CJPControlError("CJP control action is unsupported")
    files = request.get("files")
    if type(files) is not list or not 1 <= len(files) <= MAX_CHANGED_FILES:
        raise CJPControlError(
            "CJP control requires one to twelve exact files")
    normalized = [_relative(item) for item in files]
    if normalized != files or len({item.casefold() for item in files}) != len(files):
        raise CJPControlError(
            "CJP file scope has duplicate or noncanonical paths")
    for field, maximum in (
            ("organization", 64), ("issuer", 256),
            ("owner_statement", 2_048), ("purpose", 2_048)):
        item = request.get(field)
        if type(item) is not str or not item.strip() or len(
                item.encode("utf-8")) > maximum:
            raise CJPControlError(
                "CJP control request field is invalid: " + field)
    if request["organization"] not in authorization.ALLOWED_ORGANIZATIONS:
        raise CJPControlError(
            "organization must be exactly TCS or Tata Consultancy Services")
    ttl = request.get("ttl_seconds")
    if type(ttl) is not int or not 30 <= ttl <= 900:
        raise CJPControlError(
            "CJP authorization lifetime must be 30 to 900 seconds")
    candidate = request.get("candidate_bundle")
    backup = request.get("backup_root")
    if type(candidate) is not str or type(backup) is not str:
        raise CJPControlError(
            "candidate_bundle and backup_root must be text")
    if action == "preview-file-edit" and not candidate.strip():
        raise CJPControlError(
            "file-edit preview requires a candidate bundle")
    if action != "preview-file-edit" and (candidate.strip() or backup.strip()):
        raise CJPControlError(
            "candidate and backup paths are valid only for file editing")
    root = _resolve_root(request_path.parent, request.get("root"))
    maximum = (
        MAX_FILE_BYTES if action == "preview-file-edit"
        else authorization.MAX_FILE_BYTES)
    for relative in normalized:
        _resolve_target(root, relative, maximum=maximum)
    return request, request_path, root


def _decode_change(row: Any) -> tuple[str, str, str, bytes, str]:
    if type(row) is not dict or set(row) != _CHANGE_KEYS:
        raise CJPControlError(
            "candidate change has an unsupported shape")
    relative = _relative(row.get("path"))
    before = row.get("before_sha256")
    after = row.get("after_sha256")
    if (type(before) is not str or SHA256_RE.fullmatch(before) is None or
            type(after) is not str or SHA256_RE.fullmatch(after) is None):
        raise CJPControlError(
            "candidate change requires exact lowercase SHA-256 identities")
    encoding = row.get("encoding")
    content = row.get("content")
    if type(encoding) is not str or encoding not in {"utf-8", "base64"}:
        raise CJPControlError(
            "candidate change encoding must be utf-8 or base64")
    if type(content) is not str:
        raise CJPControlError("candidate change content must be text")
    try:
        data = (
            content.encode("utf-8", "strict") if encoding == "utf-8"
            else base64.b64decode(content.encode("ascii"), validate=True))
    except (UnicodeError, ValueError, binascii.Error) as exc:
        raise CJPControlError(
            "candidate change content encoding is invalid") from exc
    if not 0 < len(data) <= MAX_FILE_BYTES:
        raise CJPControlError(
            "candidate change exceeds the file byte boundary")
    if _sha(data) != after:
        raise CJPControlError(
            "candidate change after_sha256 does not match its bytes")
    if before == after:
        raise CJPControlError("candidate change does not alter its target")
    return relative, before, after, data, encoding


def load_candidate(
    value: str | os.PathLike[str],
    *,
    root: Path,
    expected_paths: Iterable[str],
    authorized_sha256: dict[str, str],
) -> tuple[dict[str, Any], list[dict[str, Any]], Path]:
    """Load complete replacement bytes and bind them to current exact files."""
    document, path = _load_json_file(
        value, maximum=MAX_CANDIDATE_DOCUMENT_BYTES,
        label="CJP candidate bundle")
    if set(document) != _CANDIDATE_KEYS or document.get(
            "schema") != CANDIDATE_SCHEMA:
        raise CJPControlError(
            "CJP candidate bundle has an unsupported schema or shape")
    raw_changes = document.get("changes")
    if type(raw_changes) is not list or not 1 <= len(
            raw_changes) <= MAX_CHANGED_FILES:
        raise CJPControlError(
            "CJP candidate must contain one to twelve replacements")
    decoded: list[dict[str, Any]] = []
    total = 0
    for raw in raw_changes:
        relative, before, after, data, encoding = _decode_change(raw)
        total += len(data)
        if total > MAX_CHANGE_BYTES:
            raise CJPControlError(
                "CJP candidate exceeds the total replacement boundary")
        target = _resolve_target(root, relative)
        actual = _sha_file(target)
        if (actual != before
                or authorized_sha256.get(relative) != before):
            raise CJPControlError(
                "CJP candidate is stale or outside its authorized evidence for "
                + relative)
        if target.suffix.casefold() in _BINARY_EXECUTABLE_SUFFIXES:
            raise CJPControlError(
                "executable/system artifact editing is outside CJP local control")
        header, header_digest, _metadata = _secure_read(
            target, maximum=MAX_FILE_BYTES,
            label="CJP target", collect=True)
        if header_digest != before:
            raise CJPControlError(
                "CJP target changed while it was classified")
        if header[:16] == database_intelligence414.SQLITE_MAGIC:
            raise CJPControlError(
                "SQLite snapshots are read-only in CJP local control")
        decoded.append({
            "path": relative,
            "before_sha256": before,
            "after_sha256": after,
            "content": data,
            "encoding": encoding,
            "target": target,
        })
    expected = list(expected_paths)
    actual_paths = [row["path"] for row in decoded]
    if (set(actual_paths) != set(expected) or
            len({item.casefold() for item in actual_paths}) != len(actual_paths)):
        raise CJPControlError(
            "candidate replacements do not exactly match the authorized files")
    claimed = document.get("candidate_sha256")
    if type(claimed) is not str or SHA256_RE.fullmatch(claimed) is None:
        raise CJPControlError("candidate bundle identity is invalid")
    body = {key: item for key, item in document.items()
            if key != "candidate_sha256"}
    if _sha(body) != claimed:
        raise CJPControlError(
            "candidate bundle SHA-256 does not match")
    return document, decoded, path


def _parse_json_candidate(data: bytes) -> None:
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise CJPControlError("replacement JSON does not parse") from exc
    # This is a replacement file someone is asking to write, so the depth bound
    # is checked here for the same reason as in `_load_json_file`.
    if _json_depth(text) > MAX_JSON_DEPTH:
        raise CJPControlError(
            "replacement JSON nests deeper than %d levels" % MAX_JSON_DEPTH)
    try:
        json.loads(
            text,
            object_pairs_hook=_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                CJPControlError("JSON non-finite number is forbidden")))
    except CJPControlError:
        raise
    except (RecursionError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise CJPControlError(
            "replacement JSON does not parse") from exc


def _candidate_validation(path: str, data: bytes) -> dict[str, Any]:
    suffix = PurePosixPath(path).suffix.casefold()
    parser = "not-applicable"
    parsed = True
    reason = ""
    try:
        if suffix in {".py", ".pyi"}:
            parser = "python-ast"
            ast.parse(data.decode("utf-8", "strict"))
        elif suffix in {".json", ".jsonl"}:
            parser = "strict-json"
            if suffix == ".jsonl":
                for line in data.splitlines():
                    if line.strip():
                        _parse_json_candidate(line)
            else:
                _parse_json_candidate(data)
        elif suffix == ".toml":
            parser = "tomllib"
            if tomllib is None:
                raise CJPControlError("TOML validation is unavailable")
            tomllib.loads(data.decode("utf-8", "strict"))
        elif suffix in {".xml", ".svg"}:
            parser = "xml-elementtree"
            ElementTree.fromstring(data)
    except (CJPControlError, ElementTree.ParseError, RecursionError,
            SyntaxError, UnicodeError, ValueError) as exc:
        parsed = False
        reason = type(exc).__name__
    secret_findings: list[dict[str, Any]] = []
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeError:
        text = ""
    if text:
        secret_findings = secret_guard.scan_text(
            text[:MAX_TEXT_CHARS], path, max_findings=100)
    return {
        "path": path,
        "parser": parser,
        "syntax_valid": parsed,
        "syntax_error_type": reason,
        "credential_like_findings": len(secret_findings),
        "credential_material_emitted": False,
        "eligible_for_apply": parsed and not secret_findings,
    }


def _exceeds_diff_line_budget(text: str) -> bool:
    count = 0
    for boundary in (
            "\n", "\r", "\v", "\f", "\x1c", "\x1d", "\x1e",
            "\x85", "\u2028", "\u2029"):
        count += text.count(boundary)
        if count > MAX_DIFF_INPUT_LINES:
            return True
    return False


def _bounded_diff(path: str, before: bytes, after: bytes) -> dict[str, Any]:
    try:
        old_text = before.decode("utf-8", "strict")
        new_text = after.decode("utf-8", "strict")
    except UnicodeError:
        return {
            "path": path, "kind": "binary",
            "content_emitted": False, "truncated": False,
            "before_bytes": len(before), "after_bytes": len(after),
        }
    # Avoid materializing millions of tiny lines or asking SequenceMatcher to
    # compare an adversarial high-cardinality line set.  Exact candidate/file
    # hashes remain in the preview binding even when display is withheld.
    if (_exceeds_diff_line_budget(old_text)
            or _exceeds_diff_line_budget(new_text)):
        return {
            "path": path,
            "kind": "text-diff-withheld-complexity",
            "content_emitted": False,
            "truncated": True,
            "before_bytes": len(before),
            "after_bytes": len(after),
            "withheld_reason": (
                "text line count exceeds the bounded diff-computation budget"),
        }
    diff_rows = difflib.unified_diff(
        old_text.splitlines(keepends=True),
        new_text.splitlines(keepends=True),
        fromfile="before/" + path,
        tofile="after/" + path,
        n=3,
    )
    selected = list(itertools.islice(diff_rows, MAX_DIFF_LINES + 1))
    truncated = len(selected) > MAX_DIFF_LINES
    if truncated:
        selected.pop()
    raw = "".join(selected).encode("utf-8")
    if len(raw) > MAX_DIFF_BYTES:
        # The original string is valid UTF-8.  ``ignore`` can therefore remove
        # only a final code point split by this byte boundary.
        safe_text = raw[:MAX_DIFF_BYTES].decode("utf-8", "ignore")
        raw = safe_text.encode("utf-8")
        truncated = True
    return {
        "path": path, "kind": "utf-8-unified-diff",
        "content_emitted": True, "truncated": truncated,
        "diff": raw.decode("utf-8", "strict"),
        "before_bytes": len(before), "after_bytes": len(after),
    }


def _preview(
    changes: list[dict[str, Any]],
    *,
    operation_sha256: str,
    candidate_sha256: str,
    root_identity_sha256: str,
    backup_root_identity_sha256: str,
) -> dict[str, Any]:
    if (SHA256_RE.fullmatch(operation_sha256) is None
            or SHA256_RE.fullmatch(candidate_sha256) is None
            or SHA256_RE.fullmatch(root_identity_sha256) is None
            or (backup_root_identity_sha256
                and SHA256_RE.fullmatch(
                    backup_root_identity_sha256) is None)):
        raise CJPControlError(
            "preview evidence requires exact operation and candidate identities")
    diffs: list[dict[str, Any]] = []
    validations: list[dict[str, Any]] = []
    for change in changes:
        before, before_digest, _metadata = _secure_read(
            change["target"], maximum=MAX_FILE_BYTES,
            label="preview target", collect=True)
        if before_digest != change["before_sha256"]:
            raise CJPControlError(
                "target changed while preview was prepared")
        validation = _candidate_validation(
            change["path"], change["content"])
        before_validation = _candidate_validation(
            change["path"], before)
        source_secret_count = before_validation[
            "credential_like_findings"]
        candidate_secret_count = validation[
            "credential_like_findings"]
        validation["source_credential_like_findings"] = source_secret_count
        validation["candidate_credential_like_findings"] = (
            candidate_secret_count)
        validation["credential_like_findings"] = (
            source_secret_count + candidate_secret_count)
        validation["eligible_for_apply"] = (
            validation["syntax_valid"]
            and validation["credential_like_findings"] == 0)
        validations.append(validation)
        if validation["credential_like_findings"]:
            diffs.append({
                "path": change["path"],
                "kind": "withheld-credential-risk",
                "content_emitted": False,
                "truncated": False,
                "before_bytes": len(before),
                "after_bytes": len(change["content"]),
                "withheld_reason": (
                    "credential-like material detected by redacted scan"),
            })
        else:
            diffs.append(_bounded_diff(
                change["path"], before, change["content"]))
    eligible = all(row["eligible_for_apply"] for row in validations)
    body = {
        "changed_files": len(changes),
        "candidate_bytes": sum(len(row["content"]) for row in changes),
        # Display diffs are intentionally bounded and can truncate before the
        # candidate side of a large hunk.  These exact identities make the
        # confirmation evidence independent of display truncation.
        "exact_binding": {
            "operation_sha256": operation_sha256,
            "candidate_sha256": candidate_sha256,
            "root_identity_sha256": root_identity_sha256,
            "backup_root_identity_sha256":
                backup_root_identity_sha256,
            "files": [
                {
                    "path": row["path"],
                    "before_sha256": row["before_sha256"],
                    "after_sha256": row["after_sha256"],
                    "after_bytes": len(row["content"]),
                }
                for row in changes
            ],
        },
        "diffs": diffs,
        "validations": validations,
        "eligible_for_apply": eligible,
        "execution": {
            "candidate_code_executed": False,
            "database_or_migration_executed": False,
            "network_accessed": False,
        },
    }
    body["preview_evidence_sha256"] = _sha(body)
    return body


def _inspection(
    root: Path,
    files: list[str],
    *,
    authorized_sha256: dict[str, str],
    expected_root_identity_sha256: str,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for relative in files:
        _assert_root_identity(root, expected_root_identity_sha256)
        target = _resolve_target(
            root, relative, maximum=authorization.MAX_FILE_BYTES)
        _data, digest, info = _secure_read(
            target, maximum=authorization.MAX_FILE_BYTES,
            label="inspected file", collect=False)
        if digest != authorized_sha256.get(relative):
            raise CJPControlError(
                "inspected file no longer matches its authorization evidence")
        rows.append({
            "path": relative,
            "sha256": digest,
            "bytes": int(info.st_size),
            "suffix": target.suffix.casefold(),
            "executable_bit": bool(stat.S_IMODE(info.st_mode) & 0o111),
            "content_emitted": False,
        })
    _assert_root_identity(root, expected_root_identity_sha256)
    return {
        "files": rows,
        "summary": {
            "files": len(rows),
            "bytes": sum(row["bytes"] for row in rows),
        },
    }


def _database_analysis(
    root: Path,
    files: list[str],
    *,
    authorized_sha256: dict[str, str],
    expected_root_identity_sha256: str,
) -> dict[str, Any]:
    reports: list[dict[str, Any]] = []
    for relative in files:
        _assert_root_identity(root, expected_root_identity_sha256)
        target = _resolve_target(
            root, relative, maximum=authorization.MAX_FILE_BYTES)
        expected = authorized_sha256.get(relative)
        if type(expected) is not str:
            raise CJPControlError(
                "database artifact lacks authorization evidence")
        if _sha_file(
                target, maximum=authorization.MAX_FILE_BYTES) != expected:
            raise CJPControlError(
                "database artifact changed after authorization")
        reports.append(database_intelligence414.understand(
            target, expected_sha256=expected))
        _assert_root_identity(root, expected_root_identity_sha256)
    return {
        "databases": reports,
        "summary": {
            "artifacts": len(reports),
            "sqlite": sum(row["kind"] == "sqlite" for row in reports),
            "sql_files": sum(row["kind"] == "sql-file" for row in reports),
        },
    }


def _fresh_empty_subdirectory(root: Path, name: str) -> Path:
    if _is_link_or_reparse(root):
        raise CJPControlError(
            "backup root became a link or reparse point")
    destination = root / name
    if destination.exists() or destination.is_symlink():
        raise CJPControlError(
            "operation backup directory already exists")
    try:
        destination.mkdir(mode=0o700)
    except OSError as exc:
        raise CJPControlError(
            "operation backup directory could not be created") from exc
    if _is_link_or_reparse(destination) or not destination.is_dir():
        raise CJPControlError(
            "operation backup directory failed its safety check")
    return destination


def _backup_target(base: Path, relative: str) -> Path:
    destination = base.joinpath(*PurePosixPath(relative).parts)
    current = base
    for part in PurePosixPath(relative).parts[:-1]:
        current = current / part
        if current.exists():
            if _is_link_or_reparse(current) or not current.is_dir():
                raise CJPControlError(
                    "backup path crossed an unsafe directory")
        else:
            try:
                current.mkdir(mode=0o700)
            except OSError as exc:
                raise CJPControlError(
                    "backup directory could not be created") from exc
    if destination.exists() or destination.is_symlink():
        raise CJPControlError("backup target already exists")
    return destination


def _exclusive_backup_copy(
    target: Path,
    destination: Path,
    *,
    expected_sha256: str,
) -> bytes:
    """Create one backup without ever opening an existing destination."""
    data, digest, source_info = _secure_read(
        target, maximum=MAX_FILE_BYTES,
        label="backup source", collect=True)
    if digest != expected_sha256:
        raise CJPControlError(
            "backup source no longer matches the preview")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    flags |= int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    descriptor = -1
    owned_identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(destination, flags, 0o600)
        opened = os.fstat(descriptor)
        owned_identity = (int(opened.st_dev), int(opened.st_ino))
        if (not stat.S_ISREG(opened.st_mode)
                or int(getattr(opened, "st_nlink", 1)) != 1):
            raise CJPControlError(
                "exclusive backup destination is unsafe")
        view = memoryview(data)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise CJPControlError(
                    "exclusive backup write did not progress")
            written += count
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, stat.S_IMODE(source_info.st_mode))
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        final = destination.lstat()
        if (_is_link_or_reparse(destination)
                or (int(final.st_dev), int(final.st_ino)) != owned_identity
                or int(getattr(final, "st_nlink", 1)) != 1
                or _sha_file(destination) != expected_sha256):
            raise CJPControlError(
                "exclusive backup failed its integrity check")
        return data
    except (CJPControlError, OSError) as exc:
        cleanup_errors: list[str] = []
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as cleanup_exc:
                cleanup_errors.append(
                    "backup-descriptor-close:"
                    + type(cleanup_exc).__name__)
        if owned_identity is not None:
            try:
                current = destination.lstat()
                if (int(current.st_dev), int(current.st_ino)) == owned_identity:
                    destination.unlink()
            except OSError as cleanup_exc:
                cleanup_errors.append(
                    "partial-backup-cleanup:"
                    + type(cleanup_exc).__name__)
        if cleanup_errors:
            raise CJPControlError(
                "exclusive backup cleanup failed after "
                + type(exc).__name__,
                cleanup_errors=cleanup_errors) from exc
        raise


def _stage_bytes(target: Path, data: bytes) -> Path:
    descriptor = -1
    stage_name = ""
    try:
        descriptor, stage_name = tempfile.mkstemp(
            prefix=".attestor-cjp-stage-", dir=str(target.parent))
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        stage = Path(stage_name)
        stage.chmod(stat.S_IMODE(target.stat().st_mode))
        if _is_link_or_reparse(stage) or _sha_file(stage) != _sha(data):
            raise CJPControlError(
                "staged replacement failed its integrity check")
        return stage
    except (OSError, CJPControlError) as exc:
        cleanup_errors: list[str] = []
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as cleanup_exc:
                cleanup_errors.append(
                    "stage-descriptor-close:"
                    + type(cleanup_exc).__name__)
        if stage_name:
            try:
                Path(stage_name).unlink(missing_ok=True)
            except OSError as cleanup_exc:
                cleanup_errors.append(
                    "partial-stage-cleanup:"
                    + type(cleanup_exc).__name__)
        if cleanup_errors:
            raise CJPControlError(
                "replacement-stage cleanup failed after "
                + type(exc).__name__,
                cleanup_errors=cleanup_errors) from exc
        raise


def _apply_transaction(
    root: Path,
    changes: list[dict[str, Any]],
    *,
    operation_sha256: str,
    transaction_sha256: str,
    backup_root: Path,
    expected_root_identity_sha256: str,
    expected_backup_root_identity_sha256: str,
) -> dict[str, Any]:
    # One root-wide lock serializes every CJP edit in the authorized root,
    # including different operations that happen to touch the same file.
    lock = root / ".attestor-cjp-control.lock"
    lock_fd = -1
    lock_owned = False
    lock_identity: tuple[int, int] | None = None
    backup_directory: Path | None = None
    stages: dict[str, Path] = {}
    backups: dict[str, Path] = {}
    rollback_payloads: dict[str, bytes] = {}
    applied: list[dict[str, Any]] = []
    rolled_back = False
    rollback_errors: list[str] = []
    cleanup_errors: list[str] = []
    transaction_result: dict[str, Any] | None = None
    try:
        if SHA256_RE.fullmatch(transaction_sha256) is None:
            raise CJPControlError(
                "transaction identity is invalid")
        _assert_root_identity(root, expected_root_identity_sha256)
        _assert_root_identity(
            backup_root, expected_backup_root_identity_sha256)
        try:
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            flags |= int(getattr(os, "O_BINARY", 0))
            flags |= int(getattr(os, "O_NOFOLLOW", 0))
            lock_fd = os.open(
                lock, flags, 0o600)
            lock_owned = True
            lock_info = os.fstat(lock_fd)
            lock_identity = (
                int(lock_info.st_dev), int(lock_info.st_ino))
            if (not stat.S_ISREG(lock_info.st_mode)
                    or int(getattr(lock_info, "st_nlink", 1)) != 1):
                raise CJPControlError(
                    "CJP transaction lock is unsafe")
            os.write(lock_fd, (transaction_sha256 + "\n").encode("ascii"))
            os.fsync(lock_fd)
        except OSError as exc:
            raise CJPControlError(
                "another CJP transaction holds the authorized root") from exc
        _assert_root_identity(root, expected_root_identity_sha256)
        _assert_root_identity(
            backup_root, expected_backup_root_identity_sha256)
        for change in changes:
            _assert_root_identity(root, expected_root_identity_sha256)
            target = _resolve_target(root, change["path"])
            if _sha_file(target) != change["before_sha256"]:
                raise CJPControlError(
                    "stale-state guard failed for " + change["path"])
        _assert_root_identity(
            backup_root, expected_backup_root_identity_sha256)
        backup_directory = _fresh_empty_subdirectory(
            backup_root, transaction_sha256)
        backup_directory_identity_sha256 = _root_identity_sha256(
            backup_directory)
        for change in changes:
            _assert_root_identity(root, expected_root_identity_sha256)
            _assert_root_identity(
                backup_root, expected_backup_root_identity_sha256)
            _assert_root_identity(
                backup_directory, backup_directory_identity_sha256)
            target = _resolve_target(root, change["path"])
            backup = _backup_target(
                backup_directory, change["path"])
            rollback_payloads[change["path"]] = _exclusive_backup_copy(
                target, backup,
                expected_sha256=change["before_sha256"])
            backups[change["path"]] = backup
            stages[change["path"]] = _stage_bytes(
                target, change["content"])
        if len(backups) != len(changes):
            raise CJPControlError(
                "complete verified backup set was not created")
        for change in sorted(changes, key=lambda item: item["path"].casefold()):
            _assert_root_identity(root, expected_root_identity_sha256)
            target = _resolve_target(root, change["path"])
            if _sha_file(target) != change["before_sha256"]:
                raise CJPControlError(
                    "immediate stale-state guard failed for " + change["path"])
            stage = stages[change["path"]]
            try:
                _assert_root_identity(root, expected_root_identity_sha256)
                os.replace(stage, target)
            except OSError as exc:
                raise CJPControlError(
                    "atomic replacement failed for " + change["path"]) from exc
            stages.pop(change["path"], None)
            applied.append(change)
            _assert_root_identity(root, expected_root_identity_sha256)
            if _sha_file(target) != change["after_sha256"]:
                raise CJPControlError(
                    "replacement integrity check failed for " + change["path"])
        for change in changes:
            _assert_root_identity(
                backup_root, expected_backup_root_identity_sha256)
            _assert_root_identity(
                backup_directory, backup_directory_identity_sha256)
            if _sha_file(backups[change["path"]]) != change["before_sha256"]:
                raise CJPControlError(
                    "persistent backup changed before transaction completion")
        # Recheck every target after all backup verification.  This catches an
        # external writer that races a completed replacement without honoring
        # Attestor's root-wide transaction lock.
        _assert_root_identity(root, expected_root_identity_sha256)
        _assert_root_identity(
            backup_root, expected_backup_root_identity_sha256)
        _assert_root_identity(
            backup_directory, backup_directory_identity_sha256)
        for change in changes:
            target = _resolve_target(root, change["path"])
            if _sha_file(target) != change["after_sha256"]:
                raise CJPControlError(
                    "final target verification failed for " + change["path"])
        _assert_root_identity(root, expected_root_identity_sha256)
        transaction_result = {
            "status": "applied",
            "transaction_sha256": transaction_sha256,
            "applied_files": len(applied),
            "backup_directory": str(backup_directory),
            "backup_persisted": True,
            "rolled_back": False,
            "result_sha256": {
                change["path"]: change["after_sha256"] for change in changes
            },
        }
        return transaction_result
    except (CJPControlError, OSError) as exc:
        if isinstance(exc, CJPControlError):
            cleanup_errors.extend(exc.cleanup_errors)
        for change in reversed(applied):
            rollback_stage: Path | None = None
            backup = backups.get(change["path"])
            try:
                _assert_root_identity(root, expected_root_identity_sha256)
                target = _resolve_target(root, change["path"])
                original = rollback_payloads.get(change["path"])
                if (backup is None or original is None
                        or _sha(original) != change["before_sha256"]
                        or
                        _sha_file(target) != change["after_sha256"]):
                    raise CJPControlError(
                        "rollback refused an externally changed target")
                rollback_stage = _stage_bytes(target, original)
                _assert_root_identity(root, expected_root_identity_sha256)
                target = _resolve_target(root, change["path"])
                if _sha_file(target) != change["after_sha256"]:
                    raise CJPControlError(
                        "rollback target changed before replacement")
                os.replace(rollback_stage, target)
                rollback_stage = None
                _assert_root_identity(root, expected_root_identity_sha256)
                if _sha_file(target) != change["before_sha256"]:
                    raise CJPControlError(
                        "rollback integrity check failed")
            except (CJPControlError, OSError) as rollback_exc:
                if isinstance(rollback_exc, CJPControlError):
                    cleanup_errors.extend(rollback_exc.cleanup_errors)
                rollback_errors.append(
                    change["path"] + ": " + type(rollback_exc).__name__)
            finally:
                if rollback_stage is not None:
                    try:
                        rollback_stage.unlink(missing_ok=True)
                    except OSError as cleanup_exc:
                        cleanup_label = (
                            change["path"] + ": rollback-stage-cleanup:"
                            + type(cleanup_exc).__name__)
                        rollback_errors.append(cleanup_label)
                        cleanup_errors.append(cleanup_label)
        rolled_back = bool(applied) and not rollback_errors
        backup_complete = bool(changes) and len(backups) == len(changes)
        if backup_complete:
            try:
                _assert_root_identity(
                    backup_root, expected_backup_root_identity_sha256)
                backup_complete = all(
                    _sha_file(backups[change["path"]])
                    == change["before_sha256"]
                    for change in changes)
            except (CJPControlError, OSError):
                backup_complete = False
        transaction_result = {
            "status": "rolled-back" if rolled_back else "failed",
            "applied_files_before_failure": len(applied),
            "backup_directory": (
                str(backup_directory) if backup_directory else ""),
            "backup_directory_created": backup_directory is not None,
            "backup_persisted": backup_complete,
            "verified_backup_files": len(backups),
            "rolled_back": rolled_back,
            "rollback_errors": rollback_errors,
            "error_type": type(exc).__name__,
        }
        return transaction_result
    finally:
        for path, stage in stages.items():
            try:
                stage.unlink(missing_ok=True)
            except OSError as cleanup_exc:
                cleanup_errors.append(
                    path + ": stage-cleanup:"
                    + type(cleanup_exc).__name__)
        if lock_fd >= 0:
            try:
                os.close(lock_fd)
            except OSError as cleanup_exc:
                cleanup_errors.append(
                    "transaction-lock-close:"
                    + type(cleanup_exc).__name__)
        if lock_owned and lock_identity is not None:
            try:
                current = lock.lstat()
                if (int(current.st_dev), int(current.st_ino)) == lock_identity:
                    lock.unlink()
                else:
                    cleanup_errors.append(
                        "transaction-lock-cleanup:identity-changed")
            except FileNotFoundError:
                current = None
            except OSError as cleanup_exc:
                cleanup_errors.append(
                    "transaction-lock-cleanup:"
                    + type(cleanup_exc).__name__)
        if transaction_result is not None:
            bounded_cleanup_errors = list(
                dict.fromkeys(cleanup_errors))[:64]
            transaction_result["cleanup_complete"] = (
                not bounded_cleanup_errors)
            transaction_result["cleanup_errors"] = (
                bounded_cleanup_errors)


def control(
    request_file: str | os.PathLike[str],
    *,
    permission_confirmed: bool = False,
    apply: bool = False,
    apply_confirmed: bool = False,
    preview_evidence_sha256: str = "",
) -> dict[str, Any]:
    """Run one CJP-only, explicitly confirmed local control session."""
    if type(permission_confirmed) is not bool or type(apply) is not bool or type(
            apply_confirmed) is not bool or type(
            preview_evidence_sha256) is not str:
        raise CJPControlError(
            "permission controls require literal booleans and a text digest")
    if apply_confirmed and not apply:
        raise CJPControlError(
            "apply confirmation is invalid without an apply request")
    if not permission_confirmed:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "profile": PROFILE_SLUG,
            "response_language": _response_language(),
            "status": "authorization-required",
            "action": "none",
            "authorization": authorization.denied_status(),
            "authority_boundaries": {
                "account_access": False,
                "administrator_or_privilege_elevation": False,
                "arbitrary_process_or_shell_execution": False,
                "corporate_network_or_service_access": False,
                "credential_or_account_authority": False,
                "credential_collection_or_use": False,
                "secret_bearing_diff_emitted": False,
                "local_exact_files_only": True,
                "permission_persisted": False,
            },
        }
    if apply:
        if SHA256_RE.fullmatch(preview_evidence_sha256) is None:
            raise CJPControlError(
                "apply requires the exact preview_evidence_sha256 from a "
                "prior preview-only run")
    elif preview_evidence_sha256:
        raise CJPControlError(
            "preview evidence is accepted only for a separate apply run")
    request, request_path, root = load_request(request_file)
    action = request["action"]
    if apply and action != "preview-file-edit":
        raise CJPControlError(
            "apply is available only after a file-edit preview")

    # The operation identity contains the exact request paths and owner
    # assertion, but no file content is read here.  Authorization validates the
    # assertion before its scope-capture reads any target bytes.
    requested_root_identity_sha256 = _root_identity_sha256(root)
    operation_sha256 = _request_identity(
        request, root,
        root_identity_sha256=requested_root_identity_sha256)
    registry = authorization.AuthorizationRegistry()
    preview_manifest = registry.issue_preview_authorization(
        root,
        tuple(request["files"]),
        organization=request["organization"],
        issuer=request["issuer"],
        owner_statement=request["owner_statement"],
        purpose=request["purpose"],
        allowed_actions=(action,),
        operation_sha256=operation_sha256,
        confirmed=permission_confirmed,
        ttl_seconds=request["ttl_seconds"],
    )
    if not hmac.compare_digest(
            preview_manifest["root_identity_sha256"],
            requested_root_identity_sha256):
        raise CJPControlError(
            "authorized root changed during permission issuance")
    preview_audit = registry.consume(
        preview_manifest,
        root=root,
        requested_actions=(action,),
        operation_sha256=operation_sha256,
    )
    if not hmac.compare_digest(
            preview_audit["root_identity_sha256"],
            requested_root_identity_sha256):
        raise CJPControlError(
            "authorized root changed during permission consumption")
    authorized_sha256 = {
        row["relative_path"]: row["sha256"]
        for row in preview_manifest["file_scope"]
    }
    if set(authorized_sha256) != set(request["files"]):
        raise CJPControlError(
            "authorization scope does not match the exact request files")

    candidate_document: dict[str, Any] | None = None
    changes: list[dict[str, Any]] = []
    candidate_sha256 = ""
    backup_root: Path | None = None
    backup_root_identity_sha256 = ""
    if action == "preview-file-edit":
        _assert_root_identity(root, requested_root_identity_sha256)
        candidate_path = _resolve_reference(
            request_path.parent, request["candidate_bundle"],
            "CJP candidate bundle")
        candidate_document, changes, _ = load_candidate(
            candidate_path, root=root, expected_paths=request["files"],
            authorized_sha256=authorized_sha256)
        _assert_root_identity(root, requested_root_identity_sha256)
        candidate_sha256 = candidate_document["candidate_sha256"]
        if request["backup_root"].strip():
            backup_root = _safe_directory(
                request["backup_root"], base=request_path.parent,
                label="CJP backup root")
            backup_root_identity_sha256 = _root_identity_sha256(
                backup_root)
        if apply and backup_root is None:
            raise CJPControlError(
                "apply requires an existing, explicit backup root")

    report: dict[str, Any] = {
        "schema": SCHEMA,
        "version": VERSION,
        "profile": PROFILE_SLUG,
        "response_language": _response_language(),
        "status": "authorized",
        "action": action,
        "operation_sha256": operation_sha256,
        "authorization": preview_audit,
        "authority_boundaries": {
            "account_access": False,
            "administrator_or_privilege_elevation": False,
            "arbitrary_process_or_shell_execution": False,
            "corporate_network_or_service_access": False,
            "credential_or_account_authority": False,
            "credential_collection_or_use": False,
            "secret_bearing_diff_emitted": False,
            "local_exact_files_only": True,
            "permission_persisted": False,
        },
    }
    if action == "inspect-files":
        report["result"] = _inspection(
            root, request["files"],
            authorized_sha256=authorized_sha256,
            expected_root_identity_sha256=(
                requested_root_identity_sha256))
        report["status"] = "inspected"
        return report
    if action == "analyze-database":
        report["result"] = _database_analysis(
            root, request["files"],
            authorized_sha256=authorized_sha256,
            expected_root_identity_sha256=(
                requested_root_identity_sha256))
        report["status"] = "understood"
        return report

    preview = _preview(
        changes,
        operation_sha256=operation_sha256,
        candidate_sha256=candidate_sha256,
        root_identity_sha256=requested_root_identity_sha256,
        backup_root_identity_sha256=(
            backup_root_identity_sha256))
    _assert_root_identity(root, requested_root_identity_sha256)
    if backup_root is not None:
        _assert_root_identity(
            backup_root, backup_root_identity_sha256)
    report["preview"] = preview
    report["status"] = "previewed"
    report["apply_requested"] = apply
    report["apply_performed"] = False
    report["two_phase_apply"] = {
        "prior_preview_digest_required": True,
        "supplied_digest_matches": (
            hmac.compare_digest(
                preview_evidence_sha256,
                preview["preview_evidence_sha256"])
            if apply else None),
    }
    if not apply:
        return report
    if not hmac.compare_digest(
            preview_evidence_sha256,
            preview["preview_evidence_sha256"]):
        raise CJPControlError(
            "supplied preview evidence does not match the recomputed exact "
            "preview; no edit was applied")
    if not preview["eligible_for_apply"]:
        report["status"] = "apply-refused"
        report["apply_refusal"] = (
            "candidate failed syntax or redacted credential gates")
        return report
    if backup_root is None:  # defended above; keep type narrowing explicit
        raise CJPControlError("apply backup root is unavailable")
    apply_manifest = registry.issue_apply_authorization(
        root,
        tuple(request["files"]),
        organization=request["organization"],
        issuer=request["issuer"],
        owner_statement=request["owner_statement"],
        purpose=request["purpose"],
        preview_audit=preview_audit,
        preview_evidence_sha256=preview["preview_evidence_sha256"],
        candidate_sha256=candidate_sha256,
        operation_sha256=operation_sha256,
        apply_confirmed=apply_confirmed,
        ttl_seconds=request["ttl_seconds"],
    )
    apply_audit = registry.consume(
        apply_manifest,
        root=root,
        requested_actions=("apply-file-edit",),
        operation_sha256=operation_sha256,
        candidate_sha256=candidate_sha256,
    )
    if not hmac.compare_digest(
            apply_audit["root_identity_sha256"],
            requested_root_identity_sha256):
        raise CJPControlError(
            "authorized root changed before apply")
    _assert_root_identity(root, requested_root_identity_sha256)
    _assert_root_identity(
        backup_root, backup_root_identity_sha256)
    transaction_sha256 = _sha({
        "schema": "attestor-cjp-file-transaction/4.1.4",
        "operation_sha256": operation_sha256,
        "candidate_sha256": candidate_sha256,
        "preview_evidence_sha256":
            preview["preview_evidence_sha256"],
        "apply_authorization_audit_sha256":
            apply_audit["audit_sha256"],
    })
    report["apply_authorization"] = apply_audit
    report["transaction"] = _apply_transaction(
        root, changes, operation_sha256=operation_sha256,
        transaction_sha256=transaction_sha256,
        backup_root=backup_root,
        expected_root_identity_sha256=(
            apply_audit["root_identity_sha256"]),
        expected_backup_root_identity_sha256=(
            backup_root_identity_sha256))
    report["apply_performed"] = (
        report["transaction"]["status"] == "applied")
    report["status"] = report["transaction"]["status"]
    return report


def _terminal_safe(value: str, *, allow_layout: bool = False) -> str:
    rows: list[str] = []
    for character in value:
        number = ord(character)
        if allow_layout and character in {"\n", "\t"}:
            rows.append(character)
        elif (number < 0x20 or 0x7F <= number <= 0x9F
                or character in _BIDI_CONTROLS):
            rows.append("\\u%04x" % number)
        else:
            rows.append(character)
    return "".join(rows)


def render_text(report: dict[str, Any]) -> str:
    """Render bounded session evidence without inventing authorization."""
    lines = [
        "Attestor 4.1.4 · Cockroach Janta Party local control",
        "Response language: C3 (Attestor-specific; not CEFR)",
        "Status: " + _terminal_safe(str(report.get("status", "invalid"))),
        "Action: " + _terminal_safe(str(report.get("action", "unknown"))),
        "Operation SHA-256: " + _terminal_safe(
            str(report.get("operation_sha256", ""))),
    ]
    boundaries = report.get("authority_boundaries", {})
    if isinstance(boundaries, dict):
        lines.extend([
            "",
            "Authority boundary",
            "  Exact local files only: %s" % (
                "yes" if boundaries.get("local_exact_files_only") else "no"),
            "  Account/network/admin/shell/credential authority: denied",
            "  Permission persisted: no",
        ])
    result = report.get("result")
    if isinstance(result, dict) and "summary" in result:
        lines.extend(["", "Summary", _terminal_safe(json.dumps(
            result["summary"], sort_keys=True, ensure_ascii=False))])
    preview = report.get("preview")
    if isinstance(preview, dict):
        lines.extend([
            "",
            "Preview",
            "  Changed files: %s" % _terminal_safe(
                str(preview.get("changed_files", 0))),
            "  Eligible for apply: %s" % (
                "yes" if preview.get("eligible_for_apply") else "no"),
            "  Evidence SHA-256: %s" % _terminal_safe(str(preview.get(
                "preview_evidence_sha256", ""))),
        ])
        for diff in preview.get("diffs", []):
            if isinstance(diff, dict) and diff.get("content_emitted"):
                lines.extend([
                    "", _terminal_safe(
                        str(diff.get("diff", "")), allow_layout=True)])
            elif isinstance(diff, dict):
                kind = str(diff.get("kind", "withheld"))
                reason = str(diff.get(
                    "withheld_reason",
                    "non-text replacement content is not emitted"))
                lines.append(
                    "  Preview withheld [%s]: %s (%s)" % (
                        _terminal_safe(kind),
                        _terminal_safe(str(diff.get("path", ""))),
                        _terminal_safe(reason)))
    transaction = report.get("transaction")
    if isinstance(transaction, dict):
        lines.extend([
            "",
            "Transaction",
            "  Status: " + _terminal_safe(
                str(transaction.get("status", "invalid"))),
            "  Backup: " + _terminal_safe(
                str(transaction.get("backup_directory", ""))),
            "  Rolled back: %s" % (
                "yes" if transaction.get("rolled_back") else "no"),
            "  Cleanup complete: %s" % (
                "yes" if transaction.get("cleanup_complete") else "no"),
        ])
        cleanup_errors = transaction.get("cleanup_errors", [])
        if isinstance(cleanup_errors, list):
            for error in cleanup_errors[:64]:
                lines.append(
                    "  Cleanup error: "
                    + _terminal_safe(str(error)))
    return "\n".join(lines).rstrip() + "\n"


__all__ = [
    "CANDIDATE_SCHEMA",
    "CJPControlError",
    "MAX_CHANGED_FILES",
    "PROFILE_SLUG",
    "REQUEST_SCHEMA",
    "SCHEMA",
    "VERSION",
    "control",
    "load_candidate",
    "load_request",
    "render_text",
]
