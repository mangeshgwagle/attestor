#!/usr/bin/env python3
"""Reproducible release and plugin-permission hardening for Attestor 4.2."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA = "attestor-release-manifest/3.0"
PRODUCT_VERSION = "4.2"
MAX_FILES = 50_000
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_FILE_BYTES = 128 * 1024 * 1024
FORBIDDEN_DIRS = {
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".hypothesis",
    ".tox", ".nox", ".pytype", ".pyre", ".venv", "venv", ".eggs",
    ".ipynb_checkpoints", "htmlcov", ".git", ".hg", ".svn",
}
FORBIDDEN_FILES = {
    ".env", "keys.env", ".coverage", "coverage.xml", ".attestor-cache.json",
    ".ds_store", "thumbs.db", "desktop.ini", "credentials.json",
    "secrets.json", "id_rsa", "id_ed25519",
}
FORBIDDEN_SENSITIVE_SUFFIXES = {
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore",
    ".db", ".sqlite", ".sqlite3", ".token", ".entitlement",
}
SAFE_ENV_TEMPLATES = {".env.example", ".env.sample", ".env.template", ".env.dist"}
WINDOWS_FORBIDDEN_CHARACTERS = frozenset('<>:"|?*')
WINDOWS_RESERVED_NAMES = frozenset({
    "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$",
    *("COM%d" % number for number in range(1, 10)),
    *("LPT%d" % number for number in range(1, 10)),
})
SAFE_PLUGIN_CAPABILITIES = {"read-workspace", "emit-findings", "write-temp", "read-config-schema"}
KNOWN_PLUGIN_CAPABILITIES = SAFE_PLUGIN_CAPABILITIES | {
    "network", "run-process", "write-workspace", "read-secrets", "read-outside-workspace",
}


class HardeningError(ValueError):
    pass


def _forbidden_environment_file(name: str) -> bool:
    folded = name.casefold()
    return ((folded == ".env" or folded == ".envrc" or folded.startswith(".env."))
            and folded not in SAFE_ENV_TEMPLATES)


def _forbidden_sensitive_file(name: str) -> bool:
    """Reject runtime credentials, signing keys, state stores, and bearer caches."""
    folded = name.casefold()
    if folded in FORBIDDEN_FILES:
        return True
    if Path(folded).suffix in FORBIDDEN_SENSITIVE_SUFFIXES:
        return True
    if re.fullmatch(r".+\.(?:db|sqlite|sqlite3)-(?:wal|shm|journal)", folded):
        return True
    return re.fullmatch(
        r"(?:client[_-]secret|service[_-]account).*\.json", folded
    ) is not None


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _relative_files(root: Path) -> list[Path]:
    files: list[Path] = []
    total = 0
    for current, directories, names in os.walk(root, followlinks=False):
        here = Path(current)
        directories[:] = sorted(
            name for name in directories if name.casefold() not in FORBIDDEN_DIRS)
        for name in sorted(names):
            item = here / name
            if item.is_symlink():
                continue
            try:
                size = item.stat().st_size
            except OSError as exc:
                raise HardeningError("cannot inspect release file") from exc
            if size > MAX_FILE_BYTES:
                raise HardeningError("release file exceeds %d bytes: %s" % (MAX_FILE_BYTES, name))
            files.append(item); total += size
            if len(files) > MAX_FILES or total > MAX_TOTAL_BYTES:
                raise HardeningError("release tree exceeds the packaging boundary")
    return files


def audit_tree(root: str | os.PathLike[str]) -> dict[str, Any]:
    base = Path(root).expanduser().resolve()
    if not base.is_dir():
        raise HardeningError("release root is not a directory")
    forbidden: list[str] = []
    links: list[str] = []
    case_names: dict[str, str] = {}
    collisions: list[str] = []
    entries = []
    total = 0
    for item in sorted(base.rglob("*"), key=lambda value: value.as_posix().casefold()):
        relative = item.relative_to(base).as_posix()
        if item.is_symlink():
            links.append(relative); continue
        if any(part.casefold() in FORBIDDEN_DIRS for part in item.relative_to(base).parts):
            forbidden.append(relative); continue
        unsafe_reason = _unsafe_entry_reason(relative)
        if unsafe_reason:
            forbidden.append("%s (unsafe cross-platform name: %s)" % (
                relative, unsafe_reason))
        if not item.is_file():
            continue
        try:
            size = item.stat().st_size
        except OSError as exc:
            raise HardeningError("cannot inspect release file") from exc
        if size > MAX_FILE_BYTES:
            raise HardeningError(
                "release file exceeds %d bytes: %s" % (MAX_FILE_BYTES, relative))
        if len(entries) >= MAX_FILES or total + size > MAX_TOTAL_BYTES:
            raise HardeningError("release tree exceeds the packaging boundary")
        transient_ui_log = re.fullmatch(
            r"\.ui[a-z0-9._-]*-server\.(?:err|out|log)", item.name, re.I) is not None
        if _forbidden_sensitive_file(item.name) or _forbidden_environment_file(item.name) \
                or item.suffix.lower() in {".pyc", ".pyo"} \
                or item.name.lower().endswith(".log") or transient_ui_log:
            forbidden.append(relative)
        folded = relative.casefold()
        if folded in case_names and case_names[folded] != relative:
            collisions.append(case_names[folded] + " <> " + relative)
        case_names[folded] = relative
        try:
            data = item.read_bytes()
        except OSError as exc:
            raise HardeningError("cannot read release file") from exc
        if len(data) > MAX_FILE_BYTES:
            raise HardeningError(
                "release file exceeds %d bytes: %s" % (MAX_FILE_BYTES, relative))
        if total + len(data) > MAX_TOTAL_BYTES:
            raise HardeningError("release tree exceeds the packaging boundary")
        total += len(data)
        entries.append({"path": relative, "bytes": len(data), "sha256": _sha(data)})
    body = {"schema": SCHEMA, "product_version": PRODUCT_VERSION,
            "files": entries, "file_count": len(entries), "bytes": total}
    body["manifest_sha256"] = _sha(json.dumps(
        body, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    body.update({"ok": not forbidden and not links and not collisions,
                 "forbidden": forbidden, "links": links, "case_collisions": collisions})
    return body


def _unsafe_entry_reason(name: Any) -> str:
    """Return why an archive-style relative path is unsafe on supported hosts."""
    if not isinstance(name, str) or not name:
        return "empty or non-text path"
    if name.startswith("/") or "\\" in name:
        return "absolute or backslash path"
    parts = name.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return "empty or traversal path component"
    for part in parts:
        if any(ord(character) < 32 or ord(character) == 127 for character in part):
            return "control character"
        if any(character in WINDOWS_FORBIDDEN_CHARACTERS for character in part):
            return "Windows-forbidden character"
        if part.endswith((" ", ".")):
            return "trailing space or period"
        device_stem = part.split(".", 1)[0].rstrip(" .").upper()
        if device_stem in WINDOWS_RESERVED_NAMES:
            return "Windows-reserved device name"
    return ""


def _safe_entry(name: str) -> bool:
    return not _unsafe_entry_reason(name)


def _validated_manifest(manifest: Any, prefix: str) -> tuple[
        dict[str, dict[str, Any]], set[str], list[str]]:
    """Return exact expected files/directories or bounded structural errors."""
    errors: list[str] = []
    expected: dict[str, dict[str, Any]] = {}
    expected_directories: set[str] = set()
    if (not isinstance(prefix, str) or
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}", prefix) or
            not _safe_entry(prefix)):
        errors.append("manifest archive prefix is invalid")
    if type(manifest) is not dict:
        return expected, expected_directories, errors + ["manifest is not an object"]
    rows = manifest.get("files")
    if (manifest.get("schema") != SCHEMA or manifest.get("product_version") != PRODUCT_VERSION or
            type(rows) is not list or len(rows) > MAX_FILES):
        errors.append("manifest header or file boundary is invalid")
        rows = rows if type(rows) is list and len(rows) <= MAX_FILES else []
    paths: list[str] = []
    folded: dict[str, str] = {}
    total = 0
    for index, row in enumerate(rows):
        if type(row) is not dict or set(row) != {"path", "bytes", "sha256"}:
            errors.append("manifest file row %d is invalid" % index); continue
        path = row.get("path")
        size = row.get("bytes")
        digest = row.get("sha256")
        if (not isinstance(path, str) or not _safe_entry(path) or
                type(size) is not int or not 0 <= size <= MAX_FILE_BYTES or
                not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            errors.append("manifest file row %d is invalid" % index); continue
        leaf = path.rsplit("/", 1)[-1]
        if _forbidden_sensitive_file(leaf) or _forbidden_environment_file(leaf):
            errors.append("manifest contains forbidden runtime artifact: " + path)
            continue
        folded_path = path.casefold()
        if folded_path in folded:
            errors.append("manifest has duplicate or case-colliding path: " + path)
            continue
        folded[folded_path] = path
        paths.append(path); total += size
        archive_name = prefix + "/" + path
        if not _safe_entry(archive_name):
            errors.append("manifest archive path is invalid: " + path); continue
        expected[archive_name] = {"bytes": size, "sha256": digest}
        parts = archive_name.split("/")
        expected_directories.update(
            "/".join(parts[:position]) + "/" for position in range(1, len(parts)))
    if paths != sorted(paths, key=lambda value: value.casefold()):
        errors.append("manifest file rows are not in canonical path order")
    if (type(manifest.get("file_count")) is not int or
            manifest.get("file_count") != len(rows) or
            type(manifest.get("bytes")) is not int or manifest.get("bytes") != total):
        errors.append("manifest count or byte total is invalid")
    body = {"schema": manifest.get("schema"),
            "product_version": manifest.get("product_version"),
            "files": rows, "file_count": manifest.get("file_count"),
            "bytes": manifest.get("bytes")}
    claimed = manifest.get("manifest_sha256")
    if (not isinstance(claimed, str) or not re.fullmatch(r"[0-9a-f]{64}", claimed) or
            not hmac.compare_digest(claimed, _sha(json.dumps(
                body, sort_keys=True, separators=(",", ":")).encode("utf-8")))):
        errors.append("manifest digest is invalid")
    return expected, expected_directories, errors


def deterministic_zip(root: str | os.PathLike[str], output: str | os.PathLike[str],
                      *, prefix: str = "Attestor 4.2", epoch: int = 315532800) -> dict[str, Any]:
    base = Path(root).expanduser().resolve()
    destination = Path(output).expanduser().resolve()
    audit = audit_tree(base)
    if not audit["ok"]:
        raise HardeningError("release audit failed: %s" % ", ".join(
            audit["forbidden"] + audit["links"] + audit["case_collisions"]))
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}", prefix):
        raise HardeningError("archive prefix is invalid")
    if destination == base or base in destination.parents:
        raise HardeningError("archive output may not be inside the release tree")
    destination.parent.mkdir(parents=True, exist_ok=True)
    timestamp = time.gmtime(max(315532800, int(epoch)))[:6]
    fd, temporary = tempfile.mkstemp(prefix=".attestor-release-", suffix=".zip",
                                     dir=str(destination.parent))
    os.close(fd)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED,
                             compresslevel=9, strict_timestamps=False) as archive:
            for row in audit["files"]:
                entry_name = prefix + "/" + row["path"]
                if not _safe_entry(entry_name):
                    raise HardeningError("unsafe archive entry")
                source = base / row["path"]
                try:
                    with source.open("rb") as stream:
                        data = stream.read(MAX_FILE_BYTES + 1)
                except OSError as exc:
                    raise HardeningError("release file became unreadable after audit") from exc
                if (len(data) != row["bytes"] or len(data) > MAX_FILE_BYTES or
                        not hmac.compare_digest(_sha(data), row["sha256"])):
                    raise HardeningError("release file changed after audit: " + row["path"])
                info = zipfile.ZipInfo(entry_name, date_time=timestamp)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                executable = row["path"].endswith((".sh", ".py"))
                permissions = 0o755 if executable else 0o644
                info.external_attr = ((stat.S_IFREG | permissions) & 0xFFFF) << 16
                info.flag_bits |= 0x800
                archive.writestr(info, data, compresslevel=9)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    archive_bytes = destination.read_bytes()
    return {**audit, "archive": str(destination), "archive_bytes": len(archive_bytes),
            "archive_sha256": _sha(archive_bytes), "prefix": prefix, "epoch": int(epoch)}


def verify_zip(path: str | os.PathLike[str], manifest: dict[str, Any], *,
               prefix: str = "Attestor 4.2") -> dict[str, Any]:
    archive_path = Path(path).expanduser().resolve()
    expected, expected_directories, errors = _validated_manifest(manifest, prefix)
    observed: dict[str, dict[str, Any]] = {}
    seen_entries: dict[str, str] = {}
    total = 0
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            entries = archive.infolist()
            if len(entries) > MAX_FILES:
                errors.append("archive entry-count boundary exceeded")
            else:
                for info in entries:
                    directory = info.is_dir()
                    safe_name = info.filename[:-1] if directory and info.filename.endswith("/") \
                        else info.filename
                    folded = info.filename.casefold()
                    if not _safe_entry(safe_name) or folded in seen_entries:
                        errors.append("unsafe or duplicate entry: " + info.filename); continue
                    seen_entries[folded] = info.filename
                    if info.flag_bits & 0x1:
                        errors.append("encrypted entries are not accepted: " + info.filename); continue
                    mode = (info.external_attr >> 16) & 0xFFFF
                    kind = stat.S_IFMT(mode)
                    dos_directory = bool(info.external_attr & 0x10)
                    if directory:
                        # deterministic_zip emits file entries only. Rejecting
                        # explicit directories keeps verification byte-policy
                        # exact and leaves no unchecked directory mode bits.
                        errors.append("explicit directory entries are not accepted: " +
                                      info.filename)
                        continue
                    if kind != stat.S_IFREG or dos_directory:
                        errors.append("file entry is not an explicit regular file: " +
                                      info.filename); continue
                    if info.filename not in expected:
                        errors.append("unexpected entry: " + info.filename); continue
                    relative_path = info.filename[len(prefix) + 1:]
                    expected_permissions = (
                        0o755 if relative_path.endswith((".sh", ".py")) else 0o644
                    )
                    if stat.S_IMODE(mode) != expected_permissions:
                        errors.append("file entry has invalid permissions: " +
                                      info.filename); continue
                    if info.file_size > MAX_FILE_BYTES or total + info.file_size > MAX_TOTAL_BYTES:
                        errors.append("archive expansion boundary exceeded"); break
                    data = archive.read(info); total += len(data)
                    observed[info.filename] = {"bytes": len(data), "sha256": _sha(data)}
    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError,
            ValueError, EOFError) as exc:
        errors.append("archive could not be read: %s" % type(exc).__name__)
    for name, row in expected.items():
        if observed.get(name) != {"bytes": row["bytes"], "sha256": row["sha256"]}:
            errors.append("manifest mismatch: " + name)
    for name in observed.keys() - expected.keys():
        errors.append("unexpected entry: " + name)
    return {"ok": not errors, "files": len(observed), "bytes": total,
            "archive_sha256": _sha(archive_path.read_bytes()) if archive_path.is_file() else "",
            "errors": errors}


@dataclass(frozen=True)
class PluginDecision:
    plugin_id: str
    accepted: bool
    requested: tuple[str, ...]
    granted: tuple[str, ...]
    denied: tuple[str, ...]
    execution: str
    reason: str


def evaluate_plugin_manifest(manifest: Any,
                             allowed: set[str] | None = None) -> PluginDecision:
    allowed = set(SAFE_PLUGIN_CAPABILITIES if allowed is None else allowed)
    if not isinstance(manifest, dict):
        raise HardeningError("plugin manifest must be an object")
    plugin_id = manifest.get("id")
    requested = manifest.get("capabilities")
    if not isinstance(plugin_id, str) or not re.fullmatch(r"[a-z][a-z0-9.-]{2,95}", plugin_id):
        raise HardeningError("plugin id is invalid")
    if not isinstance(requested, list) or len(requested) > 32 or any(
            item not in KNOWN_PLUGIN_CAPABILITIES for item in requested):
        raise HardeningError("plugin capabilities are invalid or unknown")
    requested_set = set(requested)
    denied = sorted(requested_set - allowed)
    accepted = not denied
    return PluginDecision(
        plugin_id, accepted, tuple(sorted(requested_set)),
        tuple(sorted(requested_set & allowed)), tuple(denied),
        "not-executed" if not accepted else "eligible-for-separate-os-sandbox",
        ("all requested capabilities fit policy" if accepted else
         "untrusted plugin execution refused; denied: " + ", ".join(denied)),
    )


def sanitized_environment(environment: dict[str, str] | None = None) -> dict[str, str]:
    source = os.environ if environment is None else environment
    allowed = {"PATH", "PATHEXT", "SystemRoot", "WINDIR", "COMSPEC", "TEMP", "TMP", "HOME", "USERPROFILE"}
    result = {key: value for key, value in source.items() if key in allowed and isinstance(value, str)}
    result.update({"CI": "1", "NO_COLOR": "1", "PYTHONDONTWRITEBYTECODE": "1",
                   "ATTESTOR_NETWORK": "disabled", "ATTESTOR_PLUGIN_SECRET_ACCESS": "disabled"})
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root")
    parser.add_argument("--archive")
    parser.add_argument("--prefix", default="Attestor 4.2")
    parser.add_argument("--epoch", type=int, default=315532800)
    args = parser.parse_args(argv)
    report = deterministic_zip(args.root, args.archive, prefix=args.prefix, epoch=args.epoch) \
        if args.archive else audit_tree(args.root)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
