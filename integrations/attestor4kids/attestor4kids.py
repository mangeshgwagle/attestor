#!/usr/bin/env python3
"""Attestor 4Kids -- the same findings, considerably less composure.

What this is
------------
A voice, not an engine. Every finding printed here comes from the same
`detect.scan_source` the polite Attestor uses, at the same line, with the same rule
name. The only thing 4Kids adds is an opinion about it.

That is a deliberate limit, not laziness. Attestor's detection power lives in his
rule catalogues, and the honest count spans five of them --
`security_posture.total_explicit_rules` is the only place that adds them up::

    detect.RULES          98      the hand-written rules, one function each
    nativescan            24
    multilang             23      across csharp, go, java, rust, sql, ...
    advanced_rules       202
    precision_catalog 15,000
    ----------------------------
    total             15,347

This sentence once read "15,329" and was very nearly right; it was briefly
"corrected" to 92 by somebody who had counted only `detect.RULES` and assumed
the larger figure was a typo. Both numbers are real and they measure
different things, which is exactly why the total is computed rather than
written down.

A fork that swears cannot find a defect the original missed, and saying
otherwise would be the same mistake as expecting a bigger neural gate to help
when the gate has been flat for a while. If you want 4Kids to catch more,
write a rule -- that is the only thing that has ever moved the number.

The name is a joke. Do not point this at anything a child will read.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import random
import secrets
import stat
import sys

VERSION = "4Kids/1.0"
MANIFEST = ".attestor4kids-prank.json"
MAX_MANIFEST_BYTES = 16 * 1024
MAX_PRANK_FILE_BYTES = 16 * 1024
_REPARSE_POINT = 0x400
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_BINARY = getattr(os, "O_BINARY", 0)

# Escalates with severity, because a missing docstring and a command-injection
# hole should not get the same volume of abuse.
VOICE = {
    "LOW": [
        "mate. mate. what is this.",
        "this isn't broken, it's just embarrassing.",
        "I've seen worse. not today, but I have.",
        "somebody's future self is going to hate this.",
        "not a crime. still a choice.",
    ],
    "MEDIUM": [
        "oh, we're just doing whatever now, are we.",
        "this is going to bite you and I will be laughing.",
        "who hurt you, and did they also review this?",
        "bold. wrong, but bold.",
        "I'm not angry, I'm disappointed. no wait, I'm angry.",
    ],
    "HIGH": [
        "ABSOLUTELY NOT. what in the hell is this.",
        "this is a security hole you could drive a bus through.",
        "delete this. delete it. I'm not joking.",
        "somebody is going to own your entire box with this and it'll be deserved.",
        "put the keyboard down and walk away from the machine.",
    ],
}

CLEAN = [
    "nothing. clean. I hate it here, there's nothing to shout about.",
    "no findings. suspicious. run it again, I don't trust you.",
    "clean scan. don't let it go to your head.",
]

# Prank files. Every one is obviously a joke by name, is written only into a
# directory you name, and is recorded so `--unprank` can take back exactly what
# was left. Nothing here impersonates a real file, hides itself, or lands
# anywhere the caller did not point at.
PRANKS = {
    "DO_NOT_OPEN.txt": "you opened it.\n\nthat's it. that's the prank.\n",
    "final_FINAL_v3_actualfinal_USE_THIS_ONE.txt":
        "no it isn't. it never is.\n",
    "your_code_reviewed_by_attestor.txt":
        "I read it.\n\nI have notes.\n\nAll of the notes are 'why'.\n",
    "definitely_not_a_prank.txt":
        "it is a prank. run --unprank and I'll take it all back.\n",
    "README_FIRST_SERIOUSLY.txt":
        "nobody has ever read one of these and you are no exception.\n",
    "backup_backup_backup_final.txt":
        "three backups, zero of them tested. classic.\n",
}


def _severity_rank(value: str) -> int:
    return {"LOW": 0, "MEDIUM": 1, "HIGH": 2}.get(str(value).upper(), 0)


def roast(findings, seed=None, quiet=False) -> str:
    """Render findings in 4Kids' voice. The data is unchanged."""
    rng = random.Random(seed)
    if not findings:
        return "Attestor 4Kids %s\n\n%s\n" % (VERSION, rng.choice(CLEAN))

    findings = sorted(findings,
                      key=lambda f: -_severity_rank(f.get("severity", "LOW")))
    lines = ["Attestor 4Kids %s -- %d thing%s wrong with this"
             % (VERSION, len(findings), "" if len(findings) == 1 else "s"), ""]
    for finding in findings:
        severity = str(finding.get("severity", "LOW")).upper()
        lines.append("%s:%s  [%s] %s"
                     % (finding.get("path", "?"), finding.get("line", "?"),
                        severity, finding.get("rule", "?")))
        if not quiet:
            lines.append("  %s" % rng.choice(VOICE.get(severity, VOICE["LOW"])))
        # The actual finding still gets printed. A tool that buries the
        # diagnosis under the joke is just a joke.
        message = finding.get("message")
        if message:
            lines.append("  -> %s" % message)
        lines.append("")
    worst = _severity_rank(findings[0].get("severity", "LOW"))
    lines.append("fix the HIGH ones first. I'm serious about that part."
                 if worst == 2 else "none of it's fatal. do it anyway.")
    return "\n".join(lines)


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size,
            getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)))


def _directory_identity(info: os.stat_result) -> tuple[int, int]:
    # Directory size and mtime legitimately change when we create a child.
    return info.st_dev, info.st_ino


def _validate_directory(path: pathlib.Path) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as error:
        raise SystemExit("not a directory: %s" % path) from error
    if stat.S_ISLNK(info.st_mode) or _is_reparse(info):
        raise SystemExit("refusing symlink/reparse directory: %s" % path)
    if not stat.S_ISDIR(info.st_mode):
        raise SystemExit("not a directory: %s" % path)
    return info


def _validate_regular(path: pathlib.Path) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as error:
        raise SystemExit("cannot inspect file: %s" % path) from error
    if stat.S_ISLNK(info.st_mode) or _is_reparse(info):
        raise SystemExit("refusing symlink/reparse file: %s" % path)
    if not stat.S_ISREG(info.st_mode):
        raise SystemExit("refusing non-regular file: %s" % path)
    if info.st_nlink != 1:
        raise SystemExit("refusing hard-linked file: %s" % path)
    return info


def _safe_target(where: str) -> pathlib.Path:
    """An existing, unlinked directory that is not load-bearing.

    ``resolve()`` is intentionally not used: it follows exactly the symlink or
    reparse point this boundary needs to refuse.  Every existing component is
    inspected with ``lstat`` instead.
    """
    target = pathlib.Path(os.path.abspath(os.fspath(
        pathlib.Path(where).expanduser())))
    parts = {part.lower() for part in target.parts}
    if parts & {"windows", "system32", "program files", "boot", "etc", "usr",
                "bin", "sbin", "lib", "var"}:
        raise SystemExit("not putting joke files in %s. pick somewhere yours."
                         % target)
    if target == pathlib.Path(target.anchor):
        raise SystemExit("that's a drive root. no.")
    chain = [target]
    chain.extend(target.parents)
    for component in reversed(chain):
        _validate_directory(component)
    return target


def _assert_same_directory(target: pathlib.Path,
                           expected: tuple[int, int]) -> None:
    if _directory_identity(_validate_directory(target)) != expected:
        raise SystemExit("selected directory changed during the operation")


def _read_regular(path: pathlib.Path,
                  maximum: int) -> tuple[bytes, tuple[int, int, int, int]]:
    """Read one bounded file without following a final-component link."""
    before = _validate_regular(path)
    if before.st_size > maximum:
        raise SystemExit("file is too large to trust: %s" % path)
    descriptor = os.open(path, os.O_RDONLY | _BINARY | _NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or _is_reparse(opened)
                or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) !=
                (before.st_dev, before.st_ino)):
            raise SystemExit("file changed while opening: %s" % path)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(4096, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise SystemExit("file is too large to trust: %s" % path)
        after = os.fstat(descriptor)
        if (after.st_nlink != 1 or _is_reparse(after)
                or _identity(after) != _identity(opened)):
            raise SystemExit("file changed while reading: %s" % path)
        return b"".join(chunks), _identity(opened)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]
    os.fsync(descriptor)


def _exclusive_write(path: pathlib.Path, data: bytes,
                     target: pathlib.Path,
                     target_identity: tuple[int, int]
                     ) -> tuple[int, int, int, int]:
    """Create a file once; never open or truncate an existing path."""
    _assert_same_directory(target, target_identity)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         _BINARY | _NOFOLLOW, 0o600)
    opened = os.fstat(descriptor)
    try:
        if (not stat.S_ISREG(opened.st_mode) or _is_reparse(opened)
                or opened.st_nlink != 1):
            raise SystemExit("new path is not a private regular file: %s" % path)
        _write_all(descriptor, data)
        final = os.fstat(descriptor)
        if final.st_nlink != 1 or _is_reparse(final):
            raise SystemExit("new file was linked during creation: %s" % path)
        created = _identity(final)
    except BaseException:
        os.close(descriptor)
        try:
            current = os.lstat(path)
            if ((current.st_dev, current.st_ino) ==
                    (opened.st_dev, opened.st_ino)):
                path.unlink()
        except OSError:
            pass
        raise
    else:
        os.close(descriptor)
    _assert_same_directory(target, target_identity)
    return created


def _unlink_identity(path: pathlib.Path,
                     expected: tuple[int, int, int, int],
                     target: pathlib.Path,
                     target_identity: tuple[int, int]) -> bool:
    """Unlink only the exact regular, single-link file inspected earlier."""
    _assert_same_directory(target, target_identity)
    if not os.path.lexists(path):
        return False
    current = _validate_regular(path)
    if _identity(current) != expected:
        raise SystemExit("file changed before removal: %s" % path)
    path.unlink()
    _assert_same_directory(target, target_identity)
    return True


def _atomic_replace(path: pathlib.Path, data: bytes,
                    expected: tuple[int, int, int, int] | None,
                    target: pathlib.Path,
                    target_identity: tuple[int, int]
                    ) -> tuple[int, int, int, int]:
    """Exclusively create a new file, or atomically replace the one inspected."""
    if expected is None:
        return _exclusive_write(path, data, target, target_identity)
    temporary = target / (".attestor4kids-%s.tmp" % secrets.token_hex(12))
    temporary_identity = _exclusive_write(temporary, data, target,
                                          target_identity)
    try:
        current = _validate_regular(path)
        if _identity(current) != expected:
            raise SystemExit("manifest changed before replacement")
        _assert_same_directory(target, target_identity)
        os.replace(temporary, path)
        _assert_same_directory(target, target_identity)
        return _identity(_validate_regular(path))
    except BaseException:
        if os.path.lexists(temporary):
            _unlink_identity(temporary, temporary_identity, target,
                             target_identity)
        raise


def _load_manifest(path: pathlib.Path
                   ) -> tuple[list[str], tuple[int, int, int, int] | None]:
    if not os.path.lexists(path):
        return [], None
    raw, identity = _read_regular(path, MAX_MANIFEST_BYTES)
    try:
        names = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise SystemExit("manifest is unreadable; refusing to guess") from error
    if (not isinstance(names, list)
            or any(not isinstance(name, str) or name not in PRANKS
                   or "/" in name or "\\" in name for name in names)
            or len(names) != len(set(names))):
        raise SystemExit("manifest contains invalid file names; refusing")
    return names, identity


def prank(where: str, count: int = 4, seed=None) -> int:
    target = _safe_target(where)
    target_identity = _directory_identity(_validate_directory(target))
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise SystemExit("prank count must be a non-negative integer")
    rng = random.Random(seed)
    chosen = rng.sample(sorted(PRANKS), min(count, len(PRANKS)))
    manifest = target / MANIFEST
    previous, manifest_identity = _load_manifest(manifest)
    written: list[str] = []
    created: list[tuple[pathlib.Path, tuple[int, int, int, int]]] = []

    # Validate all pre-existing names before creating the first file.  A
    # malicious link therefore fails the operation instead of merely being
    # skipped as though it were an ordinary collision.
    for name in previous:
        path = target / name
        if os.path.lexists(path):
            _validate_regular(path)
    for name in chosen:
        path = target / name
        if os.path.lexists(path):
            _validate_regular(path)
            continue
    try:
        for name in chosen:
            path = target / name
            if os.path.lexists(path):
                continue
            payload = PRANKS[name].encode("utf-8")
            created_identity = _exclusive_write(
                path, payload, target, target_identity)
            created.append((path, created_identity))
            written.append(name)
        manifest_payload = (json.dumps(sorted(set(previous) | set(written)),
                                       indent=2) + "\n").encode("utf-8")
        _atomic_replace(manifest, manifest_payload, manifest_identity, target,
                        target_identity)
    except BaseException:
        for path, created_identity in reversed(created):
            if os.path.lexists(path):
                _unlink_identity(path, created_identity, target,
                                 target_identity)
        raise
    print("dropped %d file(s) in %s" % (len(written), target))
    for name in written:
        print("  %s" % name)
    print("\nundo with: --unprank %s" % target)
    return 0


def unprank(where: str) -> int:
    """Remove exactly what was left, and nothing else."""
    target = _safe_target(where)
    target_identity = _directory_identity(_validate_directory(target))
    manifest = target / MANIFEST
    if not os.path.lexists(manifest):
        print("no prank manifest in %s -- nothing of mine to take back."
              % target)
        return 0
    try:
        names, manifest_identity = _load_manifest(manifest)
    except SystemExit as error:
        print(str(error))
        return 1

    removable: list[tuple[str, pathlib.Path, tuple[int, int, int, int]]] = []
    remaining: list[str] = []
    # Preflight every manifest entry before deleting any of them.
    for name in names:
        path = target / name
        if not os.path.lexists(path):
            continue
        try:
            content, file_identity = _read_regular(
                path, MAX_PRANK_FILE_BYTES)
        except SystemExit as error:
            print(str(error))
            return 1
        if content == PRANKS[name].encode("utf-8"):
            removable.append((name, path, file_identity))
        else:
            remaining.append(name)

    removed = 0
    for _name, path, file_identity in removable:
        try:
            if _unlink_identity(path, file_identity, target, target_identity):
                removed += 1
        except SystemExit as error:
            print(str(error))
            return 1

    assert manifest_identity is not None
    if remaining:
        payload = (json.dumps(sorted(remaining), indent=2) + "\n").encode("utf-8")
        try:
            _atomic_replace(manifest, payload, manifest_identity, target,
                            target_identity)
        except SystemExit as error:
            print(str(error))
            return 1
    else:
        try:
            _unlink_identity(manifest, manifest_identity, target,
                             target_identity)
        except SystemExit as error:
            print(str(error))
            return 1
    print("took back %d file(s) from %s" % (removed, target))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("path", nargs="?", help="file or directory to scan")
    parser.add_argument("--detector", help="path to Attestor's detector/ directory")
    parser.add_argument("--severity", default="LOW",
                        choices=("LOW", "MEDIUM", "HIGH"))
    parser.add_argument("--quiet", action="store_true",
                        help="findings without the commentary")
    parser.add_argument("--seed", type=int, help="fix the roast for testing")
    parser.add_argument("--prank", metavar="DIR",
                        help="leave joke files in DIR (reversible)")
    parser.add_argument("--unprank", metavar="DIR",
                        help="remove the joke files from DIR")
    parser.add_argument("--count", type=int, default=4)
    args = parser.parse_args(argv)

    if args.unprank:
        return unprank(args.unprank)
    if args.prank:
        return prank(args.prank, args.count, args.seed)
    if not args.path:
        parser.error("give me something to scan, or --prank a directory")

    detector = args.detector or os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))), "detector")
    sys.path.insert(0, detector)
    try:
        import detect
    except ImportError:
        print("can't find Attestor's detector. pass --detector /path/to/detector")
        return 2

    findings = []
    root = pathlib.Path(args.path)
    files = [root] if root.is_file() else sorted(
        p for p in root.rglob("*") if p.is_file())
    for path in files:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        language = detect.language_for(str(path)) if hasattr(
            detect, "language_for") else None
        try:
            found = detect.scan_source(source, str(path), language, deep=True)
        except Exception:                                   # noqa: BLE001
            continue
        for item in found:
            row = item._asdict() if hasattr(item, "_asdict") else dict(
                path=str(path), line=getattr(item, "line", "?"),
                rule=getattr(item, "rule", "?"),
                severity=getattr(item, "severity", "LOW"),
                message=getattr(item, "message", ""))
            if _severity_rank(row.get("severity")) >= _severity_rank(
                    args.severity):
                findings.append(row)

    print(roast(findings, seed=args.seed, quiet=args.quiet))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
