#!/usr/bin/env python3
"""Watch mode -- monitors file changes and automatically re-scans modified files.
Uses polling for cross-platform compatibility (no inotify dependency)."""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Callable

WATCH_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".c", ".h", ".cpp", ".cxx", ".cc", ".hpp",
    ".java", ".go", ".rs", ".rb", ".php",
    ".yml", ".yaml", ".json", ".toml", ".tf",
    ".env", ".sh", ".bash", ".ps1",
}

SKIP_DIRS = {
    ".git", ".svn", "node_modules", "__pycache__", ".tox", ".venv",
    "venv", "dist", "build", ".next", ".nuxt", "coverage", ".cache",
}


def _get_file_mtimes(root: str) -> dict[str, float]:
    mtimes = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            ext = Path(fname).suffix.lower()
            if ext in WATCH_EXTENSIONS:
                fpath = os.path.join(dirpath, fname)
                try:
                    mtimes[fpath] = os.path.getmtime(fpath)
                except OSError:
                    pass
    return mtimes


def _detect_changes(
    old: dict[str, float],
    new: dict[str, float],
) -> tuple[list[str], list[str], list[str]]:
    modified = []
    added = []
    deleted = []

    for path, mtime in new.items():
        if path not in old:
            added.append(path)
        elif mtime > old[path]:
            modified.append(path)

    for path in old:
        if path not in new:
            deleted.append(path)

    return modified, added, deleted


def watch(
    root: str,
    callback: Callable[[list[str], list[str], list[str]], None],
    interval: float = 1.0,
    on_start: Callable[[], None] | None = None,
):
    root = os.path.abspath(root)
    print(f"\n  [Watch] Monitoring {root}")
    print(f"  [Watch] Interval: {interval}s")
    print(f"  [Watch] Extensions: {', '.join(sorted(WATCH_EXTENSIONS)[:10])}...")
    print(f"  [Watch] Press Ctrl+C to stop\n")

    mtimes = _get_file_mtimes(root)
    print(f"  [Watch] Tracking {len(mtimes)} files\n")

    if on_start:
        on_start()

    try:
        while True:
            time.sleep(interval)
            new_mtimes = _get_file_mtimes(root)
            modified, added, deleted = _detect_changes(mtimes, new_mtimes)

            if modified or added or deleted:
                timestamp = time.strftime("%H:%M:%S")
                changes = []
                if modified:
                    changes.append(f"{len(modified)} modified")
                if added:
                    changes.append(f"{len(added)} added")
                if deleted:
                    changes.append(f"{len(deleted)} deleted")
                print(f"  [{timestamp}] Changes: {', '.join(changes)}")

                callback(modified, added, deleted)
                mtimes = new_mtimes
            else:
                mtimes = new_mtimes
    except KeyboardInterrupt:
        print("\n  [Watch] Stopped.")


def scan_callback_factory(scan_modes: list[str] | None = None):
    modes = scan_modes or ["secrets", "exploits"]

    def callback(modified: list[str], added: list[str], deleted: list[str]):
        changed = modified + added
        if not changed:
            return

        for fpath in changed:
            ext = Path(fpath).suffix.lower()
            print(f"    Scanning: {fpath}")

            if "secrets" in modes:
                try:
                    import secret_scanner
                    findings = secret_scanner.scan_file(fpath)
                    if findings:
                        print(f"      SECRETS: {len(findings)} found!")
                        for f in findings:
                            print(f"        [{f.severity}] {f.rule_id}: {f.redacted}")
                except ImportError:
                    pass

            if "exploits" in modes:
                try:
                    import exploit_detector
                    findings = exploit_detector.scan_file(fpath)
                    if findings:
                        print(f"      EXPLOITS: {len(findings)} found!")
                        for f in findings:
                            print(f"        [{f.severity}] {f.rule_id}: {f.description}")
                except ImportError:
                    pass

            if "js" in modes and ext in (".js", ".jsx", ".ts", ".tsx"):
                try:
                    import js_scanner
                    findings = js_scanner.scan_file(fpath)
                    if findings:
                        print(f"      JS/TS: {len(findings)} found!")
                        for f in findings:
                            print(f"        [{f.severity}] {f.rule_id}: {f.description}")
                except ImportError:
                    pass

            if "iac" in modes:
                try:
                    import iac_scanner
                    findings = iac_scanner.scan_file(fpath)
                    if findings:
                        print(f"      IaC: {len(findings)} found!")
                        for f in findings:
                            print(f"        [{f.severity}] {f.rule_id}: {f.description}")
                except ImportError:
                    pass

            if "payloads" in modes:
                try:
                    import payload_decoder
                    findings = payload_decoder.scan_file(fpath)
                    suspicious = [f for f in findings if f.is_suspicious]
                    if suspicious:
                        print(f"      PAYLOADS: {len(suspicious)} suspicious!")
                        for f in suspicious:
                            print(f"        [{f.severity}] {f.encoding}: {f.decoded[:60]}...")
                except ImportError:
                    pass

        print()

    return callback
