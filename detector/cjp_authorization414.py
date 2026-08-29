#!/usr/bin/env python3
"""One-use local-file authorization manifests for Cockroach Janta Party.

This module is an authorization boundary, not an editor or executor.  It
captures an exact, content-hashed set of regular local files and issues a
short-lived capability from an in-memory registry.  A capability is usable
only once by the registry that issued it.  It cannot authorize accounts,
credentials, networking, persistence, target-code execution, or an action
outside the compiled allowlist.

Normal authorizations are preview-only.  Applying an edit requires a second
authorization, issued only after a ``preview-file-edit`` authorization was
consumed, and bound to exact preview-evidence and candidate SHA-256 digests.
The module never reads or writes file contents except to hash the explicitly
scoped input files, and audit evidence contains hashes and byte counts rather
than file contents.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
from typing import Any, Callable, Iterable, Mapping, Sequence

import variant414


VERSION = "4.1.4"
MANIFEST_SCHEMA = "attestor-cjp-local-authorization/4.1.4"
AUDIT_SCHEMA = "attestor-cjp-local-authorization-audit/4.1.4"
DENIED_SCHEMA = "attestor-cjp-local-authorization-status/4.1.4"

INSPECT_FILES = "inspect-files"
ANALYZE_DATABASE = "analyze-database"
PREVIEW_FILE_EDIT = "preview-file-edit"
APPLY_FILE_EDIT = "apply-file-edit"
PREVIEW_ACTION_ORDER = (
    INSPECT_FILES,
    ANALYZE_DATABASE,
    PREVIEW_FILE_EDIT,
)
ACTION_ORDER = PREVIEW_ACTION_ORDER + (APPLY_FILE_EDIT,)
PREVIEW_ACTIONS = frozenset(PREVIEW_ACTION_ORDER)
ALLOWED_ACTIONS = frozenset(ACTION_ORDER)
ALLOWED_ORGANIZATIONS = frozenset({
    "Tata Consultancy Services",
    "TCS",
})

MAX_FILES = 128
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_PATH_BYTES = 1_024
MAX_COMPONENT_BYTES = 255
MAX_TEXT_BYTES = 2_048
MAX_PURPOSE_BYTES = 1_024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_JSON_NODES = 8_192
MAX_JSON_DEPTH = 24
MAX_TTL_SECONDS = 15 * 60
MIN_TTL_SECONDS = 1
READ_BLOCK_BYTES = 128 * 1024

SHA256_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
NONCE_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
_WINDOWS_DEVICES = frozenset({
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
})
_BIDI_CONTROLS = frozenset(chr(value) for value in (
    0x061C, 0x200E, 0x200F,
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2066, 0x2067, 0x2068, 0x2069,
))

_PREVIEW_CONTROLS = {
    "account_authority": False,
    "apply_authorized_for_exact_candidate": False,
    "automatic_apply": False,
    "credential_authority": False,
    "dry_run": True,
    "network_authority": False,
    "permission_persisted": False,
    "target_code_execution_authority": False,
}
_APPLY_CONTROLS = {
    **_PREVIEW_CONTROLS,
    "apply_authorized_for_exact_candidate": True,
    "dry_run": False,
}


class AuthorizationError(PermissionError):
    """A local-file capability or scope failed closed."""


def _canonical(value: Any) -> bytes:
    """Return bounded deterministic JSON using exact JSON container types."""
    pending: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    estimated = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise AuthorizationError(
                "authorization evidence exceeds the structure boundary")
        if current is None or type(current) is bool:
            estimated += 5
        elif type(current) is int:
            if not -(2 ** 63) <= current <= 2 ** 63 - 1:
                raise AuthorizationError(
                    "authorization evidence integer is outside the boundary")
            estimated += 24
        elif type(current) is str:
            size = len(current.encode("utf-8"))
            if size > MAX_TEXT_BYTES:
                raise AuthorizationError(
                    "authorization evidence text is outside the boundary")
            estimated += size + 3
        elif type(current) is list:
            if len(current) > MAX_JSON_NODES:
                raise AuthorizationError(
                    "authorization evidence collection is outside the boundary")
            estimated += len(current) + 2
            pending.extend((item, depth + 1) for item in current)
        elif type(current) is dict:
            if len(current) > MAX_JSON_NODES:
                raise AuthorizationError(
                    "authorization evidence collection is outside the boundary")
            estimated += len(current) + 2
            for key, item in current.items():
                if type(key) is not str:
                    raise AuthorizationError(
                        "authorization evidence keys must be text")
                key_size = len(key.encode("utf-8"))
                if key_size > MAX_TEXT_BYTES:
                    raise AuthorizationError(
                        "authorization evidence key is outside the boundary")
                estimated += key_size + 3
                pending.append((item, depth + 1))
        else:
            raise AuthorizationError(
                "authorization evidence contains a non-JSON value")
        if estimated > MAX_MANIFEST_BYTES:
            raise AuthorizationError(
                "authorization evidence exceeds the byte boundary")
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise AuthorizationError(
            "authorization evidence is not deterministic JSON") from exc
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise AuthorizationError(
            "authorization evidence exceeds the byte boundary")
    return encoded


def _sha_json(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def operation_sha256(operation: Any) -> str:
    """Return the digest callers bind to one exact bounded operation plan."""
    return _sha_json(operation)


def _exact_sha(value: Any, label: str) -> str:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise AuthorizationError(
            f"{label} must be an exact lowercase SHA-256 digest")
    return value


def _bounded_text(
        value: Any,
        label: str,
        *,
        minimum: int = 1,
        maximum: int = MAX_TEXT_BYTES,
        ) -> str:
    if type(value) is not str:
        raise AuthorizationError(f"{label} must be text")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise AuthorizationError(f"{label} is not valid Unicode") from exc
    if not minimum <= len(encoded) <= maximum:
        raise AuthorizationError(f"{label} is outside the text boundary")
    if value != value.strip():
        raise AuthorizationError(
            f"{label} cannot start or end with whitespace")
    if any(
            ord(character) < 0x20
            or 0x7F <= ord(character) <= 0x9F
            or character in _BIDI_CONTROLS
            for character in value):
        raise AuthorizationError(
            f"{label} contains unsupported control characters")
    return value


def _organization(value: Any) -> str:
    if type(value) is not str or value not in ALLOWED_ORGANIZATIONS:
        raise AuthorizationError(
            "organization must be exactly Tata Consultancy Services or TCS")
    return value


def _nonce(value: Any | None) -> str:
    if value is None:
        return secrets.token_hex(32)
    if type(value) is not str or NONCE_RE.fullmatch(value) is None:
        raise AuthorizationError(
            "authorization nonce must be 64 lowercase hexadecimal characters")
    return value


def _ttl(value: Any) -> int:
    if type(value) is not int or not MIN_TTL_SECONDS <= value <= MAX_TTL_SECONDS:
        raise AuthorizationError(
            f"authorization expiry must be between {MIN_TTL_SECONDS} and "
            f"{MAX_TTL_SECONDS} seconds")
    return value


def _profile() -> tuple[str, str]:
    """Return the exact intact Cockroach profile slug and current identity."""
    try:
        selected = variant414.require_compiled_profile(
            variant414.COCKROACH_JANTA_PARTY)
        identity = variant414.profile_identity(selected)
    except (AttributeError, TypeError, ValueError) as exc:
        raise AuthorizationError(
            "the canonical Cockroach Janta Party profile is unavailable") from exc
    if (selected.slug != "cockroach-janta-party"
            or type(identity) is not str
            or SHA256_RE.fullmatch(identity) is None):
        raise AuthorizationError(
            "the canonical Cockroach Janta Party profile identity is invalid")
    return selected.slug, identity


def _is_link_or_reparse_metadata(metadata: os.stat_result) -> bool:
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


def _lstat(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AuthorizationError(f"{label} is unavailable") from exc
    if _is_link_or_reparse_metadata(metadata):
        raise AuthorizationError(f"{label} contains a link or reparse point")
    return metadata


def _looks_network_spelled(value: str) -> bool:
    normalized = value.replace("\\", "/")
    return normalized.startswith("//")


def _is_local_fixed_root(path: Path) -> bool:
    """Reject UNC, mapped-network, removable, and unknown Windows roots."""
    spelling = os.fspath(path)
    if _looks_network_spelled(spelling):
        return False
    if os.name != "nt":
        # The portable standard library cannot reliably classify a POSIX
        # mount as local or remote.  This module grants no network operation;
        # callers must not present a remote mount as a local enterprise root.
        return True
    anchor = path.anchor
    if not anchor or _looks_network_spelled(anchor):
        return False
    try:
        import ctypes
        # DRIVE_FIXED == 3.  Mapped network, removable, optical, RAM-disk,
        # unknown, and unavailable roots are denied.
        return int(ctypes.windll.kernel32.GetDriveTypeW(anchor)) == 3
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def _safe_relative(value: Any) -> str:
    if type(value) is not str:
        raise AuthorizationError("file scope paths must be text")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise AuthorizationError("file scope path is not valid Unicode") from exc
    if (not 1 <= len(encoded) <= MAX_PATH_BYTES
            or value.startswith(("/", "\\"))
            or "\\" in value
            or _looks_network_spelled(value)):
        raise AuthorizationError(
            "file scope path must be a bounded portable relative path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise AuthorizationError("file scope path can escape its root")
    for part in parts:
        if len(part.encode("utf-8")) > MAX_COMPONENT_BYTES:
            raise AuthorizationError("file scope path component is too long")
        if part != part.strip() or part.endswith("."):
            raise AuthorizationError(
                "file scope path has a non-portable component")
        if any(
                ord(character) < 0x20
                or 0x7F <= ord(character) <= 0x9F
                or character in _BIDI_CONTROLS
                or character in '<>:"|?*'
                for character in part):
            raise AuthorizationError(
                "file scope path has an unsupported component")
        stem = part.split(".", 1)[0].rstrip(" .").upper()
        if stem in _WINDOWS_DEVICES:
            raise AuthorizationError(
                "file scope path uses a reserved device name")
    return value


def _real_root(value: str | os.PathLike[str]) -> tuple[Path, os.stat_result]:
    try:
        supplied_text = os.fspath(value)
    except TypeError as exc:
        raise AuthorizationError("authorization root must be path-like") from exc
    if not isinstance(supplied_text, str) or _looks_network_spelled(supplied_text):
        raise AuthorizationError("network authorization roots are denied")
    supplied = Path(supplied_text).expanduser()
    try:
        lexical = supplied if supplied.is_absolute() else Path.cwd() / supplied
        # Walk the lexical spelling before resolving it so a symlink/reparse
        # component cannot be hidden by ``resolve``.
        current = Path(lexical.anchor)
        if not lexical.anchor:
            raise AuthorizationError(
                "authorization root has no filesystem anchor")
        _lstat(current, "authorization root")
        for part in lexical.parts[1:]:
            if part in {"", "."}:
                continue
            if part == "..":
                raise AuthorizationError(
                    "authorization root cannot contain parent traversal")
            current = current / part
            _lstat(current, "authorization root")
        root = lexical.resolve(strict=True)
        metadata = _lstat(root, "authorization root")
    except AuthorizationError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuthorizationError("authorization root is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise AuthorizationError(
            "authorization root must be a real directory")
    if not _is_local_fixed_root(root):
        raise AuthorizationError(
            "authorization root must be on a local fixed filesystem")
    return root, metadata


def _root_identity(root: Path, metadata: os.stat_result) -> str:
    # The resolved spelling is included inside a digest, not emitted.
    normalized = os.path.normcase(os.path.normpath(os.fspath(root)))
    return _sha_json({
        "device": int(metadata.st_dev),
        "inode": int(metadata.st_ino),
        "resolved_path": normalized,
    })


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    """Return fields that are stable across path-stat and descriptor-stat.

    Windows cloud filesystems can expose different ``st_ctime_ns`` values for
    ``lstat(path)`` and ``fstat(open(path))`` even when both handles identify
    the same unchanged file.  Comparing that field across the two APIs made
    legitimate authorization fail nondeterministically.  We still compare
    ctime between the two path observations below, where its semantics are
    consistent, while this identity binds the descriptor to the content and
    inode that were authorized.
    """
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        stat.S_IFMT(metadata.st_mode),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


def _path_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return _identity(metadata) + (int(metadata.st_ctime_ns),)


def _secure_file_digest(
        root: Path,
        root_metadata: os.stat_result,
        relative: str,
        ) -> tuple[str, int]:
    path = root.joinpath(*relative.split("/"))
    current = root
    for component in relative.split("/"):
        current = current / component
        _lstat(current, "authorized file path")
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root):
            raise AuthorizationError(
                "authorized file path escaped its root")
        before = _lstat(path, "authorized file")
    except AuthorizationError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuthorizationError("authorized file is unavailable") from exc
    if not stat.S_ISREG(before.st_mode):
        raise AuthorizationError(
            "authorized file must be a regular file")
    if int(getattr(before, "st_nlink", 1)) != 1:
        raise AuthorizationError(
            "authorized file must not be a multiply linked file")
    if before.st_dev != root_metadata.st_dev:
        raise AuthorizationError(
            "authorized file crosses a filesystem boundary")
    if before.st_size > MAX_FILE_BYTES:
        raise AuthorizationError(
            "authorized file exceeds the per-file byte boundary")

    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AuthorizationError("authorized file could not be opened") from exc
    digest = hashlib.sha256()
    size = 0
    try:
        opened = os.fstat(descriptor)
        if (_is_link_or_reparse_metadata(opened)
                or not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino)
                != (before.st_dev, before.st_ino)):
            raise AuthorizationError(
                "authorized file identity changed before reading")
        while True:
            block = os.read(descriptor, READ_BLOCK_BYTES)
            if not block:
                break
            size += len(block)
            if size > MAX_FILE_BYTES:
                raise AuthorizationError(
                    "authorized file grew beyond the byte boundary")
            digest.update(block)
    except OSError as exc:
        raise AuthorizationError("authorized file could not be read") from exc
    finally:
        os.close(descriptor)
    try:
        after = _lstat(path, "authorized file")
    except AuthorizationError:
        raise
    if (_identity(before) != _identity(opened)
            or _identity(opened) != _identity(after)
            or _path_identity(before) != _path_identity(after)
            or size != before.st_size):
        raise AuthorizationError(
            "authorized file changed during scope capture")
    return digest.hexdigest(), size


def _path_values(
        values: Sequence[str] | Iterable[str],
        ) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray, Mapping)):
        raise AuthorizationError(
            "file scope must be an explicit sequence of relative paths")
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise AuthorizationError(
            "file scope must be an explicit sequence of relative paths") from exc
    rows: list[str] = []
    seen: set[str] = set()
    try:
        for raw in iterator:
            if len(rows) >= MAX_FILES:
                raise AuthorizationError(
                    "file scope exceeds the file-count boundary")
            relative = _safe_relative(raw)
            folded = relative.casefold()
            if folded in seen:
                raise AuthorizationError(
                    "file scope contains duplicate or case-colliding paths")
            seen.add(folded)
            rows.append(relative)
    except AuthorizationError:
        raise
    except Exception as exc:
        raise AuthorizationError(
            "file scope iteration failed closed") from exc
    if not rows:
        raise AuthorizationError("file scope cannot be empty")
    return tuple(sorted(rows, key=lambda item: (item.casefold(), item)))


def capture_file_scope(
        root: str | os.PathLike[str],
        relative_paths: Sequence[str] | Iterable[str],
        ) -> dict[str, Any]:
    """Capture exact SHA-256 scope for bounded regular local files.

    The result contains relative paths, content hashes, and byte counts, never
    contents.  Every existing path component is checked without following a
    symbolic link or Windows reparse point.
    """
    selected_root, root_metadata = _real_root(root)
    paths = _path_values(relative_paths)
    rows: list[dict[str, Any]] = []
    total = 0
    for relative in paths:
        digest, size = _secure_file_digest(
            selected_root, root_metadata, relative)
        total += size
        if total > MAX_TOTAL_BYTES:
            raise AuthorizationError(
                "file scope exceeds the total byte boundary")
        rows.append({
            "relative_path": relative,
            "sha256": digest,
            "size": size,
        })
    root_after = _lstat(selected_root, "authorization root")
    if _identity(root_metadata) != _identity(root_after):
        raise AuthorizationError(
            "authorization root changed during scope capture")
    return {
        "root_identity_sha256": _root_identity(
            selected_root, root_metadata),
        "files": rows,
        "file_count": len(rows),
        "total_bytes": total,
        "file_scope_sha256": _sha_json(rows),
    }


def _actions(
        values: Sequence[str] | Iterable[str],
        *,
        apply: bool,
        ) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray, Mapping)):
        raise AuthorizationError(
            "allowed actions must be an explicit sequence")
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise AuthorizationError(
            "allowed actions must be an explicit sequence") from exc
    rows: list[Any] = []
    try:
        for item in iterator:
            if len(rows) >= len(ALLOWED_ACTIONS):
                raise AuthorizationError(
                    "allowed actions exceed the count boundary")
            rows.append(item)
    except AuthorizationError:
        raise
    except Exception as exc:
        raise AuthorizationError(
            "allowed action iteration failed closed") from exc
    if (not rows
            or len(rows) > len(ALLOWED_ACTIONS)
            or any(type(item) is not str for item in rows)
            or len(set(rows)) != len(rows)):
        raise AuthorizationError("allowed actions are invalid")
    selected = set(rows)
    expected_domain = {APPLY_FILE_EDIT} if apply else PREVIEW_ACTIONS
    if not selected <= expected_domain:
        raise AuthorizationError(
            "an action is outside this authorization kind")
    ordered = tuple(action for action in ACTION_ORDER if action in selected)
    if apply and ordered != (APPLY_FILE_EDIT,):
        raise AuthorizationError(
            "apply authorization must contain only apply-file-edit")
    return ordered


def _manifest_body(
        *,
        authorization_kind: str,
        organization: str,
        issuer: str,
        owner_statement: str,
        purpose: str,
        scope: Mapping[str, Any],
        allowed_actions: tuple[str, ...],
        operation_digest: str,
        candidate_digest: str | None,
        preview_authorization_audit_digest: str | None,
        preview_evidence_digest: str | None,
        issued_at: int,
        expires_at: int,
        nonce: str,
        ) -> dict[str, Any]:
    profile_slug, profile_digest = _profile()
    apply = authorization_kind == "apply"
    return {
        "schema": MANIFEST_SCHEMA,
        "version": VERSION,
        "authorization_kind": authorization_kind,
        "profile": {
            "slug": profile_slug,
            "profile_sha256": profile_digest,
        },
        "organization": organization,
        "issuer": issuer,
        "owner_statement": owner_statement,
        "purpose": purpose,
        "attestation": {
            "issuer_asserted_permission": True,
            "identity_independently_verified": False,
            "legal_authority_determined_by_attestor": False,
        },
        "root_identity_sha256": scope["root_identity_sha256"],
        "file_scope": scope["files"],
        "file_count": scope["file_count"],
        "total_bytes": scope["total_bytes"],
        "file_scope_sha256": scope["file_scope_sha256"],
        "allowed_actions": list(allowed_actions),
        "operation_sha256": operation_digest,
        "candidate_sha256": candidate_digest,
        "preview_authorization_audit_sha256":
            preview_authorization_audit_digest,
        "preview_evidence_sha256": preview_evidence_digest,
        "issued_at_unix": issued_at,
        "expires_at_unix": expires_at,
        "nonce": nonce,
        "controls": dict(_APPLY_CONTROLS if apply else _PREVIEW_CONTROLS),
    }


_MANIFEST_KEYS = {
    "schema", "version", "authorization_kind", "profile", "organization",
    "issuer", "owner_statement", "purpose", "attestation",
    "root_identity_sha256", "file_scope", "file_count", "total_bytes",
    "file_scope_sha256", "allowed_actions", "operation_sha256",
    "candidate_sha256", "preview_authorization_audit_sha256",
    "preview_evidence_sha256", "issued_at_unix", "expires_at_unix", "nonce",
    "controls", "manifest_sha256",
}


def _validate_scope_shape(manifest: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    files = manifest.get("file_scope")
    if type(files) is not list or not 1 <= len(files) <= MAX_FILES:
        return ["manifest file scope is invalid"]
    seen: set[str] = set()
    total = 0
    previous: tuple[str, str] | None = None
    for row in files:
        if type(row) is not dict or set(row) != {
                "relative_path", "sha256", "size"}:
            errors.append("manifest file scope row is invalid")
            continue
        relative = row.get("relative_path")
        try:
            safe = _safe_relative(relative)
        except AuthorizationError:
            errors.append("manifest file scope path is invalid")
            continue
        key = (safe.casefold(), safe)
        if previous is not None and key <= previous:
            errors.append("manifest file scope is not canonically ordered")
        previous = key
        if safe.casefold() in seen:
            errors.append("manifest file scope contains a collision")
        seen.add(safe.casefold())
        digest = row.get("sha256")
        size = row.get("size")
        if type(digest) is not str or SHA256_RE.fullmatch(digest) is None:
            errors.append("manifest file digest is invalid")
        if type(size) is not int or not 0 <= size <= MAX_FILE_BYTES:
            errors.append("manifest file size is invalid")
        else:
            total += size
    if total > MAX_TOTAL_BYTES:
        errors.append("manifest total byte boundary is exceeded")
    if manifest.get("file_count") != len(files):
        errors.append("manifest file count does not match")
    if manifest.get("total_bytes") != total:
        errors.append("manifest total bytes do not match")
    try:
        expected_scope_digest = _sha_json(files)
    except AuthorizationError:
        errors.append("manifest file scope is outside the boundary")
    else:
        if manifest.get("file_scope_sha256") != expected_scope_digest:
            errors.append("manifest file scope digest does not match")
    return errors


def verify_manifest(value: Any) -> tuple[bool, list[str]]:
    """Verify structure and integrity, but not issuance or unused state.

    Only :meth:`AuthorizationRegistry.consume` can establish that a manifest
    was issued by the live registry, remains unexpired, and has not been used.
    """
    errors: list[str] = []
    try:
        _canonical(value)
    except AuthorizationError:
        return False, [
            "authorization manifest is not bounded deterministic JSON"]
    if type(value) is not dict:
        return False, ["authorization manifest is not an exact object"]
    if set(value) != _MANIFEST_KEYS:
        errors.append("authorization manifest keys are invalid")
    if (value.get("schema") != MANIFEST_SCHEMA
            or value.get("version") != VERSION):
        errors.append("authorization manifest schema or version is invalid")
    kind = value.get("authorization_kind")
    if kind not in {"preview", "apply"} or type(kind) is not str:
        errors.append("authorization manifest kind is invalid")
    profile = value.get("profile")
    try:
        slug, identity = _profile()
    except AuthorizationError:
        errors.append("canonical Cockroach profile identity is unavailable")
        slug, identity = "", ""
    if (type(profile) is not dict
            or set(profile) != {"slug", "profile_sha256"}
            or profile.get("slug") != slug
            or profile.get("profile_sha256") != identity):
        errors.append(
            "authorization manifest is not bound to the canonical "
            "Cockroach Janta Party profile")
    try:
        _organization(value.get("organization"))
        _bounded_text(value.get("issuer"), "issuer", maximum=256)
        _bounded_text(
            value.get("owner_statement"),
            "owner statement",
            minimum=8,
            maximum=MAX_TEXT_BYTES,
        )
        _bounded_text(
            value.get("purpose"),
            "purpose",
            minimum=4,
            maximum=MAX_PURPOSE_BYTES,
        )
    except AuthorizationError as exc:
        errors.append(str(exc))
    if value.get("attestation") != {
            "issuer_asserted_permission": True,
            "identity_independently_verified": False,
            "legal_authority_determined_by_attestor": False,
    }:
        errors.append("authorization attestation is invalid")
    for field in (
            "root_identity_sha256", "file_scope_sha256",
            "operation_sha256"):
        candidate = value.get(field)
        if type(candidate) is not str or SHA256_RE.fullmatch(candidate) is None:
            errors.append(f"authorization {field} is invalid")
    errors.extend(_validate_scope_shape(value))
    actions = value.get("allowed_actions")
    try:
        expected_actions = _actions(
            actions if type(actions) is list else (),
            apply=kind == "apply",
        )
    except AuthorizationError as exc:
        errors.append(str(exc))
        expected_actions = ()
    if type(actions) is list and actions != list(expected_actions):
        errors.append("authorization actions are not canonically ordered")
    candidate = value.get("candidate_sha256")
    preview_audit = value.get("preview_authorization_audit_sha256")
    preview_evidence = value.get("preview_evidence_sha256")
    if kind == "preview":
        if any(item is not None for item in (
                candidate, preview_audit, preview_evidence)):
            errors.append(
                "preview authorization contains apply-only bindings")
        expected_controls = _PREVIEW_CONTROLS
    elif kind == "apply":
        for field, item in (
                ("candidate_sha256", candidate),
                ("preview_authorization_audit_sha256", preview_audit),
                ("preview_evidence_sha256", preview_evidence)):
            if type(item) is not str or SHA256_RE.fullmatch(item) is None:
                errors.append(f"apply authorization {field} is invalid")
        expected_controls = _APPLY_CONTROLS
    else:
        expected_controls = {}
    if value.get("controls") != expected_controls:
        errors.append("authorization controls are invalid")
    issued = value.get("issued_at_unix")
    expires = value.get("expires_at_unix")
    if (type(issued) is not int
            or type(expires) is not int
            or issued < 0
            or expires <= issued
            or expires - issued > MAX_TTL_SECONDS):
        errors.append("authorization timestamps are invalid")
    nonce = value.get("nonce")
    if type(nonce) is not str or NONCE_RE.fullmatch(nonce) is None:
        errors.append("authorization nonce is invalid")
    claimed = value.get("manifest_sha256")
    if type(claimed) is not str or SHA256_RE.fullmatch(claimed) is None:
        errors.append("authorization manifest digest is invalid")
    else:
        body = {
            key: item for key, item in value.items()
            if key != "manifest_sha256"
        }
        try:
            actual = _sha_json(body)
        except AuthorizationError:
            errors.append("authorization manifest body is outside the boundary")
        else:
            if not hmac.compare_digest(claimed, actual):
                errors.append("authorization manifest digest does not match")
    return not errors, errors


_AUDIT_KEYS = {
    "schema", "version", "status", "authorization_kind", "profile",
    "organization", "authorized_actions", "manifest_sha256",
    "nonce_sha256", "root_identity_sha256", "file_scope_sha256",
    "file_evidence", "file_count", "total_bytes", "operation_sha256",
    "candidate_sha256", "preview_authorization_audit_sha256",
    "preview_evidence_sha256", "issuer_sha256", "owner_statement_sha256",
    "purpose_sha256", "authorization_issued_at_unix",
    "authorization_expires_at_unix", "consumed_at_unix",
    "permission_retained", "file_contents_included", "controls",
    "audit_sha256",
}


def verify_audit(value: Any) -> tuple[bool, list[str]]:
    """Verify content-free authorization-consumption evidence."""
    errors: list[str] = []
    try:
        _canonical(value)
    except AuthorizationError:
        return False, ["authorization audit is not bounded deterministic JSON"]
    if type(value) is not dict:
        return False, ["authorization audit is not an exact object"]
    if set(value) != _AUDIT_KEYS:
        errors.append("authorization audit keys are invalid")
    if (value.get("schema") != AUDIT_SCHEMA
            or value.get("version") != VERSION
            or value.get("status") != "authorized-once"):
        errors.append("authorization audit schema or status is invalid")
    kind = value.get("authorization_kind")
    if kind not in {"preview", "apply"}:
        errors.append("authorization audit kind is invalid")
    profile = value.get("profile")
    try:
        slug, identity = _profile()
    except AuthorizationError:
        slug, identity = "", ""
    if profile != {"slug": slug, "profile_sha256": identity}:
        errors.append("authorization audit profile binding is invalid")
    if value.get("organization") not in ALLOWED_ORGANIZATIONS:
        errors.append("authorization audit organization is invalid")
    actions = value.get("authorized_actions")
    try:
        expected_actions = _actions(
            actions if type(actions) is list else (),
            apply=kind == "apply",
        )
    except AuthorizationError:
        errors.append("authorization audit actions are invalid")
        expected_actions = ()
    if type(actions) is list and actions != list(expected_actions):
        errors.append("authorization audit actions are not canonical")
    for field in (
            "manifest_sha256", "nonce_sha256", "root_identity_sha256",
            "file_scope_sha256", "operation_sha256", "issuer_sha256",
            "owner_statement_sha256", "purpose_sha256"):
        item = value.get(field)
        if type(item) is not str or SHA256_RE.fullmatch(item) is None:
            errors.append(f"authorization audit {field} is invalid")
    for field in (
            "candidate_sha256",
            "preview_authorization_audit_sha256",
            "preview_evidence_sha256"):
        item = value.get(field)
        if kind == "apply":
            if type(item) is not str or SHA256_RE.fullmatch(item) is None:
                errors.append(f"apply audit {field} is invalid")
        elif item is not None:
            errors.append(f"preview audit {field} must be absent")
    evidence = value.get("file_evidence")
    if type(evidence) is not list or not 1 <= len(evidence) <= MAX_FILES:
        errors.append("authorization audit file evidence is invalid")
        evidence = []
    total = 0
    for row in evidence:
        if (type(row) is not dict
                or set(row) != {
                    "relative_path_sha256", "content_sha256", "size"}
                or type(row.get("relative_path_sha256")) is not str
                or SHA256_RE.fullmatch(
                    row.get("relative_path_sha256", "")) is None
                or type(row.get("content_sha256")) is not str
                or SHA256_RE.fullmatch(row.get("content_sha256", "")) is None
                or type(row.get("size")) is not int
                or not 0 <= row.get("size", -1) <= MAX_FILE_BYTES):
            errors.append("authorization audit file evidence row is invalid")
            continue
        total += row["size"]
    if (value.get("file_count") != len(evidence)
            or value.get("total_bytes") != total):
        errors.append("authorization audit file totals are invalid")
    issued = value.get("authorization_issued_at_unix")
    expires = value.get("authorization_expires_at_unix")
    consumed = value.get("consumed_at_unix")
    if (type(issued) is not int
            or type(expires) is not int
            or type(consumed) is not int
            or not issued <= consumed < expires):
        errors.append("authorization audit timestamps are invalid")
    controls = _APPLY_CONTROLS if kind == "apply" else _PREVIEW_CONTROLS
    if value.get("controls") != controls:
        errors.append("authorization audit controls are invalid")
    if (value.get("permission_retained") is not False
            or value.get("file_contents_included") is not False):
        errors.append("authorization audit retention controls are invalid")
    claimed = value.get("audit_sha256")
    if type(claimed) is not str or SHA256_RE.fullmatch(claimed) is None:
        errors.append("authorization audit digest is invalid")
    else:
        body = {
            key: item for key, item in value.items()
            if key != "audit_sha256"
        }
        try:
            actual = _sha_json(body)
        except AuthorizationError:
            errors.append("authorization audit body is outside the boundary")
        else:
            if not hmac.compare_digest(claimed, actual):
                errors.append("authorization audit digest does not match")
    return not errors, errors


def denied_status() -> dict[str, Any]:
    """Return the default state without inspecting any path."""
    slug, identity = _profile()
    body = {
        "schema": DENIED_SCHEMA,
        "version": VERSION,
        "status": "authorization-required",
        "authorized": False,
        "profile": {
            "slug": slug,
            "profile_sha256": identity,
        },
        "allowed_actions": list(ACTION_ORDER),
        "defaults": {
            "apply": False,
            "dry_run": True,
            "network": False,
            "permission_persistence": False,
        },
    }
    body["status_sha256"] = _sha_json(body)
    return body


class AuthorizationRegistry:
    """In-memory issuer and one-use nonce registry.

    The registry deliberately has no save/load API.  A manifest copied to
    disk or presented to a fresh process is not authority because the issuing
    registry's in-memory record is also required.
    """

    def __init__(self, *, clock: Callable[[], float] | None = None):
        if clock is not None and not callable(clock):
            raise AuthorizationError("authorization clock must be callable")
        self._clock = clock if clock is not None else time.time
        self._issued: dict[str, str] = {}
        self._used: set[str] = set()
        self._audits: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    def _now(self) -> int:
        try:
            value = self._clock()
        except Exception as exc:
            raise AuthorizationError(
                "authorization clock is unavailable") from exc
        if type(value) not in {int, float}:
            raise AuthorizationError(
                "authorization clock returned a non-number")
        integer = int(value)
        if integer < 0:
            raise AuthorizationError(
                "authorization clock returned an invalid time")
        return integer

    def _register(self, body: dict[str, Any]) -> dict[str, Any]:
        manifest = dict(body)
        manifest["manifest_sha256"] = _sha_json(manifest)
        valid, errors = verify_manifest(manifest)
        if not valid:
            raise AuthorizationError(
                "authorization manifest construction failed: "
                + "; ".join(errors[:3]))
        nonce = manifest["nonce"]
        with self._lock:
            if nonce in self._issued or nonce in self._used:
                raise AuthorizationError(
                    "authorization nonce was already issued")
            self._issued[nonce] = manifest["manifest_sha256"]
        # Return a detached exact JSON value so callers cannot mutate registry
        # state through object aliasing.
        return json.loads(_canonical(manifest))

    def issue_preview_authorization(
            self,
            root: str | os.PathLike[str],
            relative_paths: Sequence[str] | Iterable[str],
            *,
            organization: str,
            issuer: str,
            owner_statement: str,
            purpose: str,
            allowed_actions: Sequence[str] | Iterable[str],
            operation_sha256: str,
            confirmed: bool = False,
            ttl_seconds: int = 300,
            nonce: str | None = None,
            ) -> dict[str, Any]:
        """Issue one preview-only grant after an exact owner assertion."""
        if confirmed is not True:
            raise AuthorizationError(
                "explicit owner-permission confirmation is required")
        organization = _organization(organization)
        issuer = _bounded_text(issuer, "issuer", maximum=256)
        owner_statement = _bounded_text(
            owner_statement,
            "owner statement",
            minimum=8,
            maximum=MAX_TEXT_BYTES,
        )
        purpose = _bounded_text(
            purpose,
            "purpose",
            minimum=4,
            maximum=MAX_PURPOSE_BYTES,
        )
        actions = _actions(allowed_actions, apply=False)
        operation_digest = _exact_sha(
            operation_sha256, "operation_sha256")
        ttl = _ttl(ttl_seconds)
        token_nonce = _nonce(nonce)
        scope = capture_file_scope(root, relative_paths)
        issued = self._now()
        body = _manifest_body(
            authorization_kind="preview",
            organization=organization,
            issuer=issuer,
            owner_statement=owner_statement,
            purpose=purpose,
            scope=scope,
            allowed_actions=actions,
            operation_digest=operation_digest,
            candidate_digest=None,
            preview_authorization_audit_digest=None,
            preview_evidence_digest=None,
            issued_at=issued,
            expires_at=issued + ttl,
            nonce=token_nonce,
        )
        return self._register(body)

    def issue_apply_authorization(
            self,
            root: str | os.PathLike[str],
            relative_paths: Sequence[str] | Iterable[str],
            *,
            organization: str,
            issuer: str,
            owner_statement: str,
            purpose: str,
            operation_sha256: str,
            candidate_sha256: str,
            preview_audit: Mapping[str, Any],
            preview_evidence_sha256: str,
            apply_confirmed: bool = False,
            ttl_seconds: int = 180,
            nonce: str | None = None,
            ) -> dict[str, Any]:
        """Issue a separate exact-candidate apply grant.

        ``preview_audit`` must be the content-free evidence returned when this
        same registry consumed a ``preview-file-edit`` authorization.
        """
        if apply_confirmed is not True:
            raise AuthorizationError(
                "separate explicit apply confirmation is required")
        organization = _organization(organization)
        issuer = _bounded_text(issuer, "issuer", maximum=256)
        owner_statement = _bounded_text(
            owner_statement,
            "owner statement",
            minimum=8,
            maximum=MAX_TEXT_BYTES,
        )
        purpose = _bounded_text(
            purpose,
            "purpose",
            minimum=4,
            maximum=MAX_PURPOSE_BYTES,
        )
        operation_digest = _exact_sha(
            operation_sha256, "operation_sha256")
        candidate_digest = _exact_sha(
            candidate_sha256, "candidate_sha256")
        preview_evidence_digest = _exact_sha(
            preview_evidence_sha256, "preview_evidence_sha256")
        ttl = _ttl(ttl_seconds)
        token_nonce = _nonce(nonce)
        valid, errors = verify_audit(preview_audit)
        if not valid:
            raise AuthorizationError(
                "preview authorization audit is invalid: "
                + "; ".join(errors[:3]))
        preview_operation_digest = _exact_sha(
            preview_audit.get("operation_sha256"),
            "preview audit operation_sha256",
        )
        if not hmac.compare_digest(
                operation_digest, preview_operation_digest):
            raise AuthorizationError(
                "apply operation does not match the preview authorization")
        preview_audit_digest = preview_audit["audit_sha256"]
        with self._lock:
            registered = self._audits.get(preview_audit_digest)
            if registered is None or not hmac.compare_digest(
                    _canonical(registered), _canonical(dict(preview_audit))):
                raise AuthorizationError(
                    "preview authorization audit was not consumed by "
                    "this registry")
        if (preview_audit["authorization_kind"] != "preview"
                or PREVIEW_FILE_EDIT
                not in preview_audit["authorized_actions"]):
            raise AuthorizationError(
                "apply authorization requires a preview-file-edit audit")
        if preview_audit["organization"] != organization:
            raise AuthorizationError(
                "apply organization does not match the preview authorization")
        scope = capture_file_scope(root, relative_paths)
        if (scope["root_identity_sha256"]
                != preview_audit["root_identity_sha256"]
                or scope["file_scope_sha256"]
                != preview_audit["file_scope_sha256"]):
            raise AuthorizationError(
                "apply file scope does not match the preview authorization")
        issued = self._now()
        body = _manifest_body(
            authorization_kind="apply",
            organization=organization,
            issuer=issuer,
            owner_statement=owner_statement,
            purpose=purpose,
            scope=scope,
            allowed_actions=(APPLY_FILE_EDIT,),
            operation_digest=operation_digest,
            candidate_digest=candidate_digest,
            preview_authorization_audit_digest=preview_audit_digest,
            preview_evidence_digest=preview_evidence_digest,
            issued_at=issued,
            expires_at=issued + ttl,
            nonce=token_nonce,
        )
        return self._register(body)

    def consume(
            self,
            manifest: Mapping[str, Any] | None,
            *,
            root: str | os.PathLike[str],
            requested_actions: Sequence[str] | Iterable[str],
            operation_sha256: str,
            candidate_sha256: str | None = None,
            ) -> dict[str, Any]:
        """Consume one exact grant and return content-free audit evidence."""
        valid, errors = verify_manifest(manifest)
        if not valid:
            raise AuthorizationError(
                "authorization manifest is denied: "
                + "; ".join(errors[:3]))
        if type(manifest) is not dict:
            raise AuthorizationError(
                "authorization manifest is not an exact object")
        kind = manifest["authorization_kind"]
        requested = _actions(
            requested_actions, apply=kind == "apply")
        if list(requested) != manifest["allowed_actions"]:
            raise AuthorizationError(
                "requested actions do not exactly match the authorization")
        operation_digest = _exact_sha(
            operation_sha256, "operation_sha256")
        if not hmac.compare_digest(
                operation_digest, manifest["operation_sha256"]):
            raise AuthorizationError(
                "requested operation does not match the authorization")
        if kind == "apply":
            candidate_digest = _exact_sha(
                candidate_sha256, "candidate_sha256")
            if not hmac.compare_digest(
                    candidate_digest, manifest["candidate_sha256"]):
                raise AuthorizationError(
                    "requested candidate does not match the authorization")
        elif candidate_sha256 is not None:
            raise AuthorizationError(
                "preview authorization cannot carry an apply candidate")
        nonce = manifest["nonce"]
        now = self._now()
        with self._lock:
            issued_digest = self._issued.get(nonce)
            if issued_digest is None or not hmac.compare_digest(
                    issued_digest, manifest["manifest_sha256"]):
                raise AuthorizationError(
                    "authorization was not issued by this in-memory registry")
            if nonce in self._used:
                raise AuthorizationError(
                    "authorization nonce was already consumed")
            if (now < manifest["issued_at_unix"]
                    or now >= manifest["expires_at_unix"]):
                raise AuthorizationError(
                    "authorization is not valid at the current time")
            scope = capture_file_scope(
                root,
                [
                    row["relative_path"]
                    for row in manifest["file_scope"]
                ],
            )
            if (scope["root_identity_sha256"]
                    != manifest["root_identity_sha256"]
                    or scope["files"] != manifest["file_scope"]
                    or scope["file_scope_sha256"]
                    != manifest["file_scope_sha256"]):
                raise AuthorizationError(
                    "authorized file scope changed or does not match")
            file_evidence = [
                {
                    "relative_path_sha256":
                        _sha_text(row["relative_path"]),
                    "content_sha256": row["sha256"],
                    "size": row["size"],
                }
                for row in manifest["file_scope"]
            ]
            audit_body: dict[str, Any] = {
                "schema": AUDIT_SCHEMA,
                "version": VERSION,
                "status": "authorized-once",
                "authorization_kind": kind,
                "profile": dict(manifest["profile"]),
                "organization": manifest["organization"],
                "authorized_actions": list(requested),
                "manifest_sha256": manifest["manifest_sha256"],
                "nonce_sha256": _sha_text(nonce),
                "root_identity_sha256": manifest["root_identity_sha256"],
                "file_scope_sha256": manifest["file_scope_sha256"],
                "file_evidence": file_evidence,
                "file_count": manifest["file_count"],
                "total_bytes": manifest["total_bytes"],
                "operation_sha256": manifest["operation_sha256"],
                "candidate_sha256": manifest["candidate_sha256"],
                "preview_authorization_audit_sha256":
                    manifest["preview_authorization_audit_sha256"],
                "preview_evidence_sha256":
                    manifest["preview_evidence_sha256"],
                "issuer_sha256": _sha_text(manifest["issuer"]),
                "owner_statement_sha256":
                    _sha_text(manifest["owner_statement"]),
                "purpose_sha256": _sha_text(manifest["purpose"]),
                "authorization_issued_at_unix":
                    manifest["issued_at_unix"],
                "authorization_expires_at_unix":
                    manifest["expires_at_unix"],
                "permission_retained": False,
                "file_contents_included": False,
                "controls": dict(manifest["controls"]),
            }
            audit: dict[str, Any] | None = None
            # Scope hashing can consume most of a short authorization's life.
            # Re-sample after that work and require a stable completion second
            # before publishing or consuming authority.
            for _attempt in range(3):
                completed_at = self._now()
                if (completed_at < manifest["issued_at_unix"]
                        or completed_at >= manifest["expires_at_unix"]):
                    raise AuthorizationError(
                        "authorization expired while its scope was verified")
                candidate = {
                    **audit_body,
                    "consumed_at_unix": completed_at,
                }
                candidate["audit_sha256"] = _sha_json(candidate)
                audit_valid, audit_errors = verify_audit(candidate)
                if not audit_valid:
                    raise AuthorizationError(
                        "authorization audit construction failed: "
                        + "; ".join(audit_errors[:3]))
                commit_at = self._now()
                if (commit_at < completed_at
                        or commit_at < manifest["issued_at_unix"]
                        or commit_at >= manifest["expires_at_unix"]):
                    raise AuthorizationError(
                        "authorization expired or clock changed before consume")
                if commit_at == completed_at:
                    audit = candidate
                    break
            if audit is None:
                raise AuthorizationError(
                    "authorization clock did not stabilize before consume")
            # Mark the nonce used only after every check and audit construction
            # succeeds, but before releasing the lock or returning authority.
            self._used.add(nonce)
            detached = json.loads(_canonical(audit))
            self._audits[audit["audit_sha256"]] = detached
            return json.loads(_canonical(detached))


__all__ = [
    "ALLOWED_ACTIONS",
    "ALLOWED_ORGANIZATIONS",
    "ANALYZE_DATABASE",
    "APPLY_FILE_EDIT",
    "AUDIT_SCHEMA",
    "AuthorizationError",
    "AuthorizationRegistry",
    "DENIED_SCHEMA",
    "INSPECT_FILES",
    "MANIFEST_SCHEMA",
    "PREVIEW_FILE_EDIT",
    "VERSION",
    "capture_file_scope",
    "denied_status",
    "operation_sha256",
    "verify_audit",
    "verify_manifest",
]
