#!/usr/bin/env python3
"""Refresh the VS Code server bundle from the detector it was copied from.

Why this exists
---------------
`integrations/vscode/server/` ships its own copy of fifteen detector modules
plus a manifest recording each one's size and SHA-256, and
`test_staged_server_is_complete_current_and_digest_verified` checks that the
copies still match. Every change to a bundled module therefore breaks the
suite until the bundle is re-staged -- which happened four times in one day of
rule writing, each time diagnosed from scratch as if it were new.

That is a chore, and a chore done by hand is a chore done wrong eventually.
The failure mode is quiet and bad: re-copying the file without recomputing its
digest leaves a manifest that certifies the wrong bytes.

`--check` reports staleness without writing, which is what a release gate
wants; the default writes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import secrets
import stat
import sys

MANIFEST = "server-manifest.json"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_MANIFEST_FILES = 256
MAX_BUNDLE_FILE_BYTES = 128 * 1024 * 1024
_REPARSE_POINT = 0x400
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_BINARY = getattr(os, "O_BINARY", 0)


class BundleError(ValueError):
    """The bundle manifest or a source/destination boundary is unsafe."""


def _root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent.parent


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size,
            getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)))


def _normal_relative(raw: object) -> pathlib.PurePosixPath:
    """Return one canonical POSIX project-relative manifest path."""
    if not isinstance(raw, str) or not raw or "\x00" in raw or "\\" in raw:
        raise BundleError("manifest path is not a normalized relative path")
    path = pathlib.PurePosixPath(raw)
    windows = pathlib.PureWindowsPath(raw)
    if (path.is_absolute() or windows.is_absolute() or windows.drive
            or raw != path.as_posix() or raw.endswith("/")
            or any(part in {"", ".", ".."} for part in path.parts)):
        raise BundleError("unsafe manifest path: %r" % raw)
    if path.as_posix() == MANIFEST:
        raise BundleError("manifest may not stage itself")
    return path


def _contained(base: pathlib.Path,
               relative: pathlib.PurePosixPath) -> pathlib.Path:
    candidate = base.joinpath(*relative.parts)
    absolute_base = os.path.abspath(base)
    absolute_candidate = os.path.abspath(candidate)
    try:
        inside = os.path.commonpath([absolute_base, absolute_candidate]) == \
            os.path.commonpath([absolute_base])
    except ValueError as error:
        raise BundleError("manifest path crosses filesystem roots") from error
    if not inside:
        raise BundleError("manifest path escapes its project directory")
    return pathlib.Path(absolute_candidate)


def _validate_directory(path: pathlib.Path) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as error:
        raise BundleError("missing bundle directory: %s" % path) from error
    if stat.S_ISLNK(info.st_mode) or _is_reparse(info):
        raise BundleError("refusing symlink/reparse directory: %s" % path)
    if not stat.S_ISDIR(info.st_mode):
        raise BundleError("not a directory: %s" % path)
    return info


def _validate_parents(base: pathlib.Path, path: pathlib.Path) -> None:
    _validate_directory(base)
    relative = path.parent.relative_to(base)
    current = base
    for part in relative.parts:
        current /= part
        _validate_directory(current)


def _regular_info(path: pathlib.Path, *, missing_ok: bool = False
                  ) -> os.stat_result | None:
    if not os.path.lexists(path):
        if missing_ok:
            return None
        raise BundleError("missing regular file: %s" % path)
    try:
        info = os.lstat(path)
    except OSError as error:
        raise BundleError("cannot inspect file: %s" % path) from error
    if stat.S_ISLNK(info.st_mode) or _is_reparse(info):
        raise BundleError("refusing symlink/reparse file: %s" % path)
    if not stat.S_ISREG(info.st_mode):
        raise BundleError("refusing non-regular file: %s" % path)
    return info


def _read_regular(path: pathlib.Path, maximum: int) -> bytes:
    before = _regular_info(path)
    assert before is not None
    if before.st_size > maximum:
        raise BundleError("file exceeds %d-byte boundary: %s" % (maximum, path))
    descriptor = os.open(path, os.O_RDONLY | _BINARY | _NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or _is_reparse(opened)
                or (opened.st_dev, opened.st_ino) !=
                (before.st_dev, before.st_ino)):
            raise BundleError("file changed while opening: %s" % path)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise BundleError("file grew beyond boundary: %s" % path)
        if _identity(os.fstat(descriptor)) != _identity(opened):
            raise BundleError("file changed while reading: %s" % path)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        count = os.write(descriptor, view)
        if count <= 0:
            raise OSError("short write")
        view = view[count:]
    os.fsync(descriptor)


def _replace_regular(path: pathlib.Path, data: bytes,
                     expected: os.stat_result | None) -> None:
    """Write without following links or silently replacing a raced-in path."""
    parent_info = _validate_directory(path.parent)
    if expected is None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             _BINARY | _NOFOLLOW, 0o600)
        created = os.fstat(descriptor)
        try:
            _write_all(descriptor, data)
        except BaseException:
            os.close(descriptor)
            try:
                current = _regular_info(path, missing_ok=True)
                if (current is not None and
                        (current.st_dev, current.st_ino) ==
                        (created.st_dev, created.st_ino)):
                    path.unlink()
            except (BundleError, OSError):
                pass
            raise
        else:
            os.close(descriptor)
        current_parent = _validate_directory(path.parent)
        if ((current_parent.st_dev, current_parent.st_ino) !=
                (parent_info.st_dev, parent_info.st_ino)):
            raise BundleError("destination directory changed while writing")
        return

    temporary = path.parent / (".%s.%s.tmp" %
                               (path.name, secrets.token_hex(12)))
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             _BINARY | _NOFOLLOW, 0o600)
        try:
            _write_all(descriptor, data)
        finally:
            os.close(descriptor)
        current = _regular_info(path)
        assert current is not None
        if _identity(current) != _identity(expected):
            raise BundleError("destination changed before replacement: %s" % path)
        current_parent = _validate_directory(path.parent)
        if ((current_parent.st_dev, current_parent.st_ino) !=
                (parent_info.st_dev, parent_info.st_ino)):
            raise BundleError("destination directory changed before replacement")
        os.replace(temporary, path)
    finally:
        if os.path.lexists(temporary):
            temporary.unlink()


def _load_manifest(path: pathlib.Path) -> dict:
    try:
        manifest = json.loads(_read_regular(path, MAX_MANIFEST_BYTES)
                              .decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise BundleError("invalid bundle manifest: %s" % error) from error
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise BundleError("manifest files must be a list")
    if len(manifest["files"]) > MAX_MANIFEST_FILES:
        raise BundleError("manifest has too many files")
    return manifest


def restage(check_only: bool = False) -> int:
    try:
        root = pathlib.Path(os.path.abspath(_root()))
        server = root / "integrations" / "vscode" / "server"
        detector = root / "detector"
        _validate_directory(root)
        _validate_directory(detector)
        _validate_directory(server)
        manifest_path = server / MANIFEST
        manifest_info = _regular_info(manifest_path)
        assert manifest_info is not None
        manifest = _load_manifest(manifest_path)
        stale: list[str] = []
        missing: list[str] = []
        plans: list[tuple[dict, str, pathlib.Path, bytes,
                          os.stat_result | None, str]] = []
        seen: set[str] = set()

        for item in manifest["files"]:
            if not isinstance(item, dict) or "path" not in item:
                raise BundleError("each manifest file must be an object with path")
            relative = _normal_relative(item["path"])
            name = relative.as_posix()
            folded = name.casefold()
            if folded in seen:
                raise BundleError("duplicate/case-colliding manifest path: %s" % name)
            seen.add(folded)
            source = _contained(detector, relative)
            staged = _contained(server, relative)
            _validate_parents(detector, source)
            _validate_parents(server, staged)
            source_info = _regular_info(source, missing_ok=True)
            if source_info is None:
                missing.append(name)
                continue
            staged_info = _regular_info(staged, missing_ok=True)
            fresh = _read_regular(source, MAX_BUNDLE_FILE_BYTES)
            bundled = (_read_regular(staged, MAX_BUNDLE_FILE_BYTES)
                       if staged_info is not None else None)
            digest = hashlib.sha256(fresh).hexdigest()
            # Both halves matter. A copy whose bytes match but whose recorded
            # digest does not is a manifest certifying something it did not check.
            if (bundled != fresh or item.get("sha256") != digest
                    or item.get("size") != len(fresh)):
                stale.append(name)
                plans.append((item, name, staged, fresh, staged_info, digest))

        if missing:
            print("missing from detector/: %s" % ", ".join(missing), file=sys.stderr)
            return 2
        if not check_only:
            for item, _name, staged, fresh, staged_info, digest in plans:
                _replace_regular(staged, fresh, staged_info)
                item["size"] = len(fresh)
                item["sha256"] = digest
    except (BundleError, OSError, ValueError) as error:
        print("unsafe bundle: %s" % error, file=sys.stderr)
        return 2

    if check_only:
        if stale:
            print("stale: %s" % ", ".join(stale))
            return 1
        print("bundle is current (%d files)" % len(manifest.get("files", [])))
        return 0

    if stale:
        encoded = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
        try:
            _replace_regular(manifest_path, encoded, manifest_info)
        except (BundleError, OSError) as error:
            print("unsafe bundle: %s" % error, file=sys.stderr)
            return 2
        print("re-staged: %s" % ", ".join(stale))
    else:
        print("bundle was already current (%d files)"
              % len(manifest.get("files", [])))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="report staleness without writing; exits 1 if stale")
    args = parser.parse_args(argv)
    return restage(check_only=args.check)


if __name__ == "__main__":
    raise SystemExit(main())
