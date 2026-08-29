#!/usr/bin/env python3
"""Privacy-preserving repository memory for Attestor 3.0.

Memory stores architecture summaries, relative paths, content hashes, finding
fingerprints, and decision digests. It never stores source code, snippets,
finding messages, raw rationales, environment values, or credentials.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import repo_intel


SCHEMA = "attestor-repository-memory/3.0"
MAX_FILES = 10_000
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_EVENTS = 5_000
SKIP_DIRS = set(repo_intel.SKIP_DIRS) | {".attestor", ".attestor-backups"}
SECRETISH = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|authorization)\s*[:=]|"
    r"\b(?:sk-proj-|sk-svcacct-|github_pat_|gh[opusr]_|glpat-|xox[baprs]-|AIza)"
)


class MemoryError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _sha(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _within(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except (OSError, ValueError) as exc:
        raise MemoryError("path escapes repository root") from exc


def _manifest(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    skipped: list[str] = []
    total = 0
    for current, directories, filenames in os.walk(root, followlinks=False):
        here = Path(current)
        directories[:] = sorted(name for name in directories
                                 if name not in SKIP_DIRS and not (here / name).is_symlink())
        for name in sorted(filenames):
            item = here / name
            relative = _within(root, item)
            if item.is_symlink():
                skipped.append(relative + " (link)")
                continue
            try:
                size = item.stat().st_size
            except OSError:
                skipped.append(relative + " (unreadable)")
                continue
            if len(rows) >= MAX_FILES or total + size > MAX_TOTAL_BYTES:
                skipped.append(relative + " (memory boundary)")
                continue
            try:
                digest = _sha(item.read_bytes())
            except OSError:
                skipped.append(relative + " (unreadable)")
                continue
            total += size
            rows.append({"path": relative, "sha256": digest, "bytes": size})
    return rows, skipped


def _finding_key(root: Path, finding: Any) -> str | None:
    if hasattr(finding, "__dict__"):
        finding = vars(finding)
    if not isinstance(finding, dict):
        return None
    rule = finding.get("rule")
    raw_path = finding.get("path")
    line = finding.get("line", 1)
    if not isinstance(rule, str) or not rule or not isinstance(raw_path, str):
        return None
    try:
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = root / candidate
        relative = _within(root, candidate)
        number = max(1, int(line))
    except (MemoryError, OSError, TypeError, ValueError):
        return None
    return _sha("%s\0%s\0%d" % (rule, relative, number))


def snapshot(root: str | os.PathLike[str], findings: Iterable[Any] = ()) -> dict[str, Any]:
    base = Path(root).expanduser().resolve()
    if not base.is_dir():
        raise MemoryError("repository root is not a directory")
    files, skipped = _manifest(base)
    graph = repo_intel.analyze(str(base))
    finding_keys = sorted(set(filter(None, (_finding_key(base, item) for item in findings))))
    architecture = {
        "modules": len(graph.get("modules", {})),
        "definitions": len(graph.get("definitions", {})),
        "resolved_call_edges": sum(bool(item.get("target")) for item in graph.get("resolved_calls", [])),
        "entrypoints": sorted(graph.get("entrypoints", []))[:1_000],
        "import_cycles": graph.get("import_cycles", [])[:200],
        "config_keys_used": sorted({item.get("key") for item in graph.get("config_used", [])
                                     if item.get("key") and item.get("key") != "<dynamic>"})[:1_000],
    }
    content = {
        "schema": SCHEMA, "repository": base.name,
        "repository_id": _sha(str(base).casefold()), "files": files,
        "skipped": skipped[:1_000], "architecture": architecture,
        "finding_keys": finding_keys,
        "privacy": {
            "source_code_stored": False, "finding_messages_stored": False,
            "secret_values_stored": False, "absolute_paths_stored": False,
        },
    }
    content["snapshot_id"] = _sha(_canonical(content))
    return content


def snapshot_target(root: str | os.PathLike[str], findings: Iterable[Any] = ()) -> dict[str, Any]:
    """Snapshot exactly a selected file, or delegate to repository snapshotting.

    A file analysis must not silently widen repository-memory scope to every
    sibling in its parent directory.  The file snapshot stores only its relative
    name, size, digest, finding identities, and an explicitly unavailable
    architecture summary.
    """
    supplied = Path(root).expanduser()
    if supplied.is_symlink():
        raise MemoryError("memory target is not a regular file")
    target = supplied.resolve()
    if target.is_dir():
        return snapshot(target, findings)
    if not target.is_file():
        raise MemoryError("memory target is not a regular file")
    try:
        size = target.stat().st_size
        if size > MAX_TOTAL_BYTES:
            raise MemoryError("memory target exceeds the byte boundary")
        digest = _sha(target.read_bytes())
    except OSError as exc:
        raise MemoryError("memory target cannot be read") from exc
    base = target.parent
    finding_keys = sorted(set(filter(None, (_finding_key(base, item) for item in findings))))
    content = {
        "schema": SCHEMA, "repository": target.name,
        "repository_id": _sha(str(target).casefold()),
        "files": [{"path": target.name, "sha256": digest, "bytes": size}],
        "skipped": [],
        "architecture": {
            "modules": 0, "definitions": 0, "resolved_call_edges": 0,
            "entrypoints": [], "import_cycles": [], "config_keys_used": [],
            "state": "not-derived-for-single-file-scope",
        },
        "finding_keys": finding_keys,
        "scope": {"kind": "file", "siblings_read": False},
        "privacy": {
            "source_code_stored": False, "finding_messages_stored": False,
            "secret_values_stored": False, "absolute_paths_stored": False,
        },
    }
    content["snapshot_id"] = _sha(_canonical(content))
    return content


def compare(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    if previous.get("schema") != SCHEMA or current.get("schema") != SCHEMA:
        raise MemoryError("snapshot schema mismatch")
    if previous.get("repository_id") != current.get("repository_id"):
        raise MemoryError("snapshots belong to different repositories")
    old_files = {item["path"]: item["sha256"] for item in previous.get("files", [])}
    new_files = {item["path"]: item["sha256"] for item in current.get("files", [])}
    old_findings = set(previous.get("finding_keys", []))
    new_findings = set(current.get("finding_keys", []))
    return {
        "schema": "attestor-repository-memory-diff/3.0",
        "baseline": previous.get("snapshot_id"), "current": current.get("snapshot_id"),
        "files": {
            "added": sorted(new_files.keys() - old_files.keys()),
            "removed": sorted(old_files.keys() - new_files.keys()),
            "changed": sorted(path for path in old_files.keys() & new_files.keys()
                              if old_files[path] != new_files[path]),
            "unchanged": sum(old_files[path] == new_files[path]
                             for path in old_files.keys() & new_files.keys()),
        },
        "findings": {
            "new": sorted(new_findings - old_findings),
            "resolved": sorted(old_findings - new_findings),
            "persistent": len(old_findings & new_findings),
        },
        "architecture_changed": previous.get("architecture") != current.get("architecture"),
    }


def _safe_label(label: str) -> str:
    if not isinstance(label, str):
        raise MemoryError("decision label must be text")
    cleaned = " ".join(label.split())[:120]
    return "[redacted: credential-like text]" if SECRETISH.search(cleaned) else cleaned


class MemoryLog:
    def __init__(self, path: str | os.PathLike[str], repository_id: str,
                 authentication_key: bytes | None = None):
        self.path = Path(path).expanduser().resolve()
        if not re.fullmatch(r"[0-9a-f]{64}", repository_id or ""):
            raise MemoryError("repository id is invalid")
        if authentication_key is not None and len(authentication_key) < 16:
            raise MemoryError("authentication key must contain at least 16 bytes")
        self.repository_id = repository_id
        self.key = authentication_key
        self.document = self._load()

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema": SCHEMA, "repository_id": self.repository_id,
                    "chain": "hmac-sha256" if self.key else "sha256",
                    "events": []}
        if not self.path.is_file() or self.path.stat().st_size > 4 * 1024 * 1024:
            raise MemoryError("memory log is invalid or too large")
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise MemoryError("memory log cannot be parsed") from exc
        if value.get("schema") != SCHEMA or value.get("repository_id") != self.repository_id:
            raise MemoryError("memory log identity mismatch")
        if len(value.get("events", [])) > MAX_EVENTS:
            raise MemoryError("memory log exceeds event boundary")
        self.document = value
        if not self.verify():
            raise MemoryError("memory log integrity verification failed")
        return value

    def _digest(self, event: dict[str, Any]) -> str:
        payload = _canonical(event)
        return hmac.new(self.key, payload, hashlib.sha256).hexdigest() if self.key else _sha(payload)

    def verify(self) -> bool:
        previous = "0" * 64
        for stored in self.document.get("events", []):
            if not isinstance(stored, dict) or stored.get("previous") != previous:
                return False
            event = {key: value for key, value in stored.items() if key != "digest"}
            if not hmac.compare_digest(str(stored.get("digest", "")), self._digest(event)):
                return False
            previous = stored["digest"]
        return True

    def append(self, kind: str, finding_key: str, outcome: str,
               rationale: str, label: str = "") -> dict[str, Any]:
        if len(self.document["events"]) >= MAX_EVENTS:
            raise MemoryError("memory log is full")
        if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", kind or ""):
            raise MemoryError("event kind is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", finding_key or ""):
            raise MemoryError("finding key is invalid")
        if outcome not in {"accepted", "rejected", "fixed", "false-positive", "deferred"}:
            raise MemoryError("decision outcome is invalid")
        if not isinstance(rationale, str) or len(rationale) > 32_000:
            raise MemoryError("rationale is invalid or too large")
        previous = self.document["events"][-1]["digest"] if self.document["events"] else "0" * 64
        event = {
            "sequence": len(self.document["events"]) + 1,
            "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "kind": kind, "finding_key": finding_key, "outcome": outcome,
            "label": _safe_label(label), "rationale_sha256": _sha(rationale),
            "rationale_stored": False, "previous": previous,
        }
        event["digest"] = self._digest(event)
        self.document["events"].append(event)
        return event

    def save(self) -> None:
        if not self.verify():
            raise MemoryError("refusing to save an invalid memory chain")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(self.document, indent=2, sort_keys=True) + "\n"
        fd, temporary = tempfile.mkstemp(prefix=".attestor-memory-", suffix=".tmp",
                                         dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(data); handle.flush(); os.fsync(handle.fileno())
            if os.name != "nt":
                os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root")
    parser.add_argument("--compare")
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    current = snapshot(args.root)
    result: dict[str, Any] = current
    if args.compare:
        baseline = json.loads(Path(args.compare).read_text(encoding="utf-8"))
        result = compare(baseline, current)
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
