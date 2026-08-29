#!/usr/bin/env python3
"""Attestor sweeps: deletes what you point him at, and refuses the rest.

Why this exists
---------------
Attestor could barely delete anything before this. Nearly every `unlink` in the
tree removes a temporary file he created seconds earlier; the only two real
deletions are `codegen`'s output-directory clean and a partial-backup cleanup
that first confirms by device and inode that the file is the one it made.

This adds a general one. It deletes real files you asked to be gone -- build
output, caches, artifacts, whole trees of them -- which is considerably more
than Attestor could do yesterday.

Why the guards stay
-------------------
The guards are not what stops it deleting; they are what stops it deleting
*something else*. A sweeper without them is not more capable, it is the same
capability with a chance of taking the directory above the one you meant. The
list below is copied in spirit from `codegen`, which already refuses the
filesystem root, the home directory, anything containing the working
directory, and links.

Every run is a dry run unless `--apply` is passed, and every run prints
exactly what it would remove first. That is the same shape as
`verified_remediation`: the plan is free, the commitment is separate.
"""
from __future__ import annotations

import argparse
import fnmatch
import os
import pathlib
import shutil
import sys

VERSION = "attestor-sweep/1.0"

# Names worth removing by default. Deliberately artifacts only -- things a
# build reproduces -- never sources.
DEFAULT_PATTERNS = (
    "__pycache__", "*.pyc", "*.pyo", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", "*.egg-info", "build", "dist", ".tox", "node_modules",
    "*.o", "*.obj", "*.class", ".DS_Store", "Thumbs.db",
)

# Never removed, whatever the pattern says. Losing one of these costs work
# that no build reproduces.
NEVER = frozenset({
    ".git", ".hg", ".svn", ".ssh", ".gnupg", ".aws", ".config",
    "node_modules.bak", ".env", ".venv", "venv",
})

# Everything Attestor writes, and nothing else. He namespaces every artifact he
# creates -- backups, stages, locks, caches, vault and memory scratch -- under
# `.attestor` or `.attestor35`, which makes provenance a property of the name rather
# than something to be inferred.
#
# That is what lets `--mine` be aggressive where the general sweep cannot be.
# The general sweep must refuse your home directory, because `build` and
# `dist` there could be anyone's; `--mine` can run in it safely, because
# `.attestor-backups` could only ever be Attestor's. The guard moved from the location
# to the name, and the name is the stronger of the two.
ATTESTOR_ARTIFACTS = (
    ".attestor", ".attestor-*", ".attestor35-*", ".attestor_solve", ".attestor-cache",
    ".attestor-cache.json", ".attestor-backups", ".attestor-cjp-control.lock",
    ".attestor35-repair.lock",
)

# Backups live as `<name>.<stamp>.<sha12>.bak` -- but only inside a
# `.attestor-backups` directory. A stray `.bak` elsewhere belongs to somebody
# else's editor and is not Attestor's to remove.
ATTESTOR_BACKUP_HOME = ".attestor-backups"


def _refuse(reason: str) -> None:
    raise SystemExit("refusing: " + reason)


def safe_root(where: str, mine: bool = False) -> pathlib.Path:
    """The directory a sweep may run inside, or an exit.

    Mirrors `codegen._clean_output_dir`: the danger is never the delete
    itself, it is being pointed one level higher than intended.

    `mine` relaxes the *location* rules, because in that mode the *name* rules
    are doing the work. Sweeping `~` for `build` directories could take
    somebody's project; sweeping `~` for `.attestor-backups` can only take Attestor's
    own leavings, however far up you point it.
    """
    target = pathlib.Path(where).expanduser()
    if not target.exists():
        _refuse("%s does not exist" % target)
    resolved = target.resolve()
    if not resolved.is_dir():
        _refuse("%s is not a directory" % resolved)

    # Kept in both modes. Walking an entire filesystem is not a safety
    # question so much as a pointless one, and a link is a trapdoor either way.
    if resolved == pathlib.Path(resolved.anchor):
        _refuse("%s is a filesystem root" % resolved)
    if target.is_symlink() or (os.name == "nt" and _is_reparse(target)):
        _refuse("%s is a link; sweeping through one leaves the target gone "
                "and the link intact" % target)

    if mine:
        return resolved

    home = pathlib.Path.home().resolve()
    if resolved == home:
        _refuse("%s is your home directory (use --mine to clear Attestor's own "
                "artifacts here)" % resolved)
    cwd = pathlib.Path.cwd().resolve()
    if resolved == cwd or resolved in cwd.parents:
        _refuse("%s contains the working directory; run it from outside"
                % resolved)
    # A sweep that walks up out of its own root is the failure this whole
    # module is arranged around.
    if len(resolved.parts) <= 2:
        _refuse("%s is too close to the root to sweep safely" % resolved)
    return resolved


def _is_reparse(path: pathlib.Path) -> bool:
    try:
        return bool(path.lstat().st_file_attributes & 0x400)   # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return False


def matches(name: str, patterns) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)


def plan(root: pathlib.Path, patterns, mine: bool = False) -> list[pathlib.Path]:
    """Everything that would go, deepest first so directories empty cleanly."""
    doomed: list[pathlib.Path] = []
    for base, directories, files in os.walk(root, topdown=True):
        here = pathlib.Path(base)
        # Never descend into something protected, and never follow a link out
        # of the root: a symlinked node_modules should cost the link, not the
        # directory it points at.
        directories[:] = [d for d in directories
                          if d not in NEVER and not (here / d).is_symlink()]
        for name in list(directories):
            if matches(name, patterns):
                doomed.append(here / name)
                directories.remove(name)          # do not walk what dies
        for name in files:
            if name in NEVER:
                continue
            if matches(name, patterns):
                doomed.append(here / name)
            elif mine and name.endswith(".bak") \
                    and here.name == ATTESTOR_BACKUP_HOME:
                # Only inside Attestor's own backup directory. A `.bak` anywhere
                # else is somebody's editor doing its job.
                doomed.append(here / name)
    return sorted(doomed, key=lambda p: len(p.parts), reverse=True)


def size_of(path: pathlib.Path) -> int:
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    total = 0
    for base, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += (pathlib.Path(base) / name).stat().st_size
            except OSError:
                pass
    return total


def sweep(where: str, patterns, apply: bool, mine: bool = False) -> int:
    root = safe_root(where, mine)
    doomed = plan(root, patterns, mine)
    if not doomed:
        print("%s: nothing of %s to sweep in %s"
              % (VERSION, "Attestor's own" if mine else "that kind", root))
        return 0

    total = 0
    print("%s: %d item(s) under %s" % (VERSION, len(doomed), root))
    for path in doomed:
        size = size_of(path)
        total += size
        kind = "dir " if path.is_dir() else "file"
        print("  %s %10s  %s" % (kind, "{:,}".format(size),
                                 path.relative_to(root)))
    print("\ntotal: %s bytes" % "{:,}".format(total))

    if not apply:
        print("\nDry run. Nothing was deleted. Re-run with --apply.")
        return 0

    removed = failed = 0
    for path in doomed:
        # Re-check containment at delete time, not just at plan time: a
        # directory can be swapped for a link between the walk and the unlink.
        try:
            live = path.resolve()
        except OSError:
            failed += 1
            continue
        if root not in live.parents and live != root:
            print("  skipped (escaped the root): %s" % path)
            failed += 1
            continue
        try:
            if path.is_symlink() or path.is_file():
                path.unlink()
            elif path.is_dir():
                shutil.rmtree(path)
            removed += 1
        except OSError as error:
            print("  could not remove %s: %s" % (path, error))
            failed += 1
    print("\nremoved %d, failed %d, freed ~%s bytes"
          % (removed, failed, "{:,}".format(total)))
    return 0 if not failed else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("directory")
    parser.add_argument("--pattern", action="append",
                        help="override the defaults; repeatable")
    parser.add_argument("--mine", action="store_true",
                        help="remove only what Attestor himself wrote -- backups, "
                             "stages, locks, caches. Runs anywhere, including "
                             "your home directory, because the .attestor namespace "
                             "is the guard.")
    parser.add_argument("--apply", action="store_true",
                        help="actually delete; without it this only reports")
    args = parser.parse_args(argv)
    if args.mine and args.pattern:
        raise SystemExit("--mine is the pattern; do not pass --pattern with it")
    patterns = (ATTESTOR_ARTIFACTS if args.mine
                else tuple(args.pattern) if args.pattern
                else DEFAULT_PATTERNS)
    return sweep(args.directory, patterns, args.apply, args.mine)


if __name__ == "__main__":
    raise SystemExit(main())
