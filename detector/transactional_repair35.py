#!/usr/bin/env python3
"""Proof-gated, rollback-capable multi-file repair transactions for Attestor 3.5.

Repair plans are data, never executable callbacks.  Verification hooks run only
through :mod:`execution_fabric35`, against disposable before/after copies of the
entire workspace.  A verified plan remains a dry run unless applying it receives
a second, explicit authorization.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from execution_fabric35 import (
    ExecutionAuthorization,
    ExecutionFabric,
    ExecutionRequest,
    ExecutionResult,
)


SCHEMA = "attestor-transactional-repair/3.5"
LOCK_NAME = ".attestor35-repair.lock"
SOURCE_SUFFIXES = {
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".java", ".cs", ".go", ".rs", ".c", ".h", ".cc", ".cpp", ".cxx",
    ".hpp", ".php", ".rb", ".swift", ".kt", ".kts", ".scala",
}
_SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
_RULE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_HOOK_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_FORBIDDEN_PATH_CHARS = frozenset('<>:"|?*')
_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"}
    | {"COM" + str(index) for index in range(1, 10)}
    | {"LPT" + str(index) for index in range(1, 10)}
    | {"COM" + digit for digit in "\u00b9\u00b2\u00b3"}
    | {"LPT" + digit for digit in "\u00b9\u00b2\u00b3"})


class RepairError(ValueError):
    """A plan or workspace violates a non-negotiable repair invariant."""


def _sha(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8", "replace")


def normalize_relative_path(value: str) -> str:
    """Return one portable NFC path or reject ambiguity/escape syntax."""
    if not isinstance(value, str):
        raise RepairError("change path must be text")
    value = value.replace("\\", "/")
    if unicodedata.normalize("NFC", value) != value:
        raise RepairError("change path must use canonical NFC spelling")
    if not value or len(value) > 512:
        raise RepairError("change path is empty, too long, or contains reserved syntax")
    if value.startswith("/") or value.startswith("//"):
        raise RepairError("change path must be workspace-relative")
    raw_parts = value.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise RepairError("change path contains an empty, dot, or parent segment")
    for part in raw_parts:
        stem = part.split(".", 1)[0].rstrip(" .").upper()
        if any(character in _FORBIDDEN_PATH_CHARS or
               unicodedata.category(character) in {"Cc", "Cf", "Cs"}
               for character in part):
            raise RepairError("change path contains a non-portable segment")
        utf8_bytes = len(part.encode("utf-8", "strict"))
        utf16_units = len(part.encode("utf-16-le", "strict")) // 2
        if (len(part) > 255 or utf8_bytes > 255 or utf16_units > 255 or
                part.rstrip(" .") != part or stem in _WINDOWS_RESERVED_NAMES):
            raise RepairError("change path contains a non-portable segment")
    path = PurePosixPath(*raw_parts)
    if path.is_absolute() or path.as_posix().casefold() == LOCK_NAME.casefold():
        raise RepairError("change path is reserved or absolute")
    return path.as_posix()


@dataclass(frozen=True)
class FileChange:
    """Add (hash=None), update, or delete (content=None) one regular file."""

    path: str
    before_sha256: str | None
    new_content: bytes | str | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", normalize_relative_path(self.path))
        if self.before_sha256 is not None:
            digest = str(self.before_sha256).lower()
            if not _SHA_RE.fullmatch(digest):
                raise RepairError("before_sha256 must be a lowercase SHA-256 digest")
            object.__setattr__(self, "before_sha256", digest)
        if isinstance(self.new_content, str):
            object.__setattr__(self, "new_content",
                               self.new_content.encode("utf-8", "strict"))
        elif self.new_content is not None and not isinstance(self.new_content, bytes):
            raise RepairError("new_content must be bytes, text, or None")
        if self.before_sha256 is None and self.new_content is None:
            raise RepairError("an absent file cannot be deleted")

    @property
    def operation(self) -> str:
        if self.before_sha256 is None:
            return "add"
        if self.new_content is None:
            return "delete"
        return "update"

    @property
    def after_sha256(self) -> str | None:
        return _sha(self.new_content) if self.new_content is not None else None


@dataclass(frozen=True)
class ChangeSet:
    changes: tuple[FileChange, ...]
    target_rules: tuple[str, ...] = ()
    target_fingerprints: tuple[str, ...] = ()
    rationale: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "changes", tuple(self.changes))
        rules = tuple(self.target_rules)
        fingerprints = tuple(self.target_fingerprints)
        if any(not isinstance(item, str) or not _RULE_RE.fullmatch(item) for item in rules):
            raise RepairError("target rule identifier is invalid")
        if any(not isinstance(item, str) or not _SHA_RE.fullmatch(item)
               for item in fingerprints):
            raise RepairError("target fingerprint must be a SHA-256 digest")
        object.__setattr__(self, "target_rules", tuple(sorted(set(rules))))
        object.__setattr__(self, "target_fingerprints", tuple(sorted(set(fingerprints))))
        if not self.changes:
            raise RepairError("a change set must contain at least one file")
        folded: dict[str, str] = {}
        for change in self.changes:
            if not isinstance(change, FileChange):
                raise RepairError("changes must contain FileChange records")
            key = change.path.casefold()
            if key in folded:
                raise RepairError("duplicate or case-colliding change paths")
            folded[key] = change.path
        if not self.target_rules and not self.target_fingerprints:
            raise RepairError("a change set must bind itself to target findings")
        if (not isinstance(self.rationale, str) or len(self.rationale) > 2_000 or
                "\x00" in self.rationale):
            raise RepairError("repair rationale is too large or invalid")

    @property
    def digest(self) -> str:
        return _sha(_canonical({
            "schema": SCHEMA,
            "changes": [{"path": item.path, "before": item.before_sha256,
                         "after": item.after_sha256, "operation": item.operation}
                        for item in self.changes],
            "target_rules": self.target_rules,
            "target_fingerprints": self.target_fingerprints,
            "rationale_sha256": _sha(self.rationale),
        }))


@dataclass(frozen=True)
class VerificationHook:
    """A declarative container command.  Callables and host commands are absent."""

    name: str
    kind: str
    image: str
    command: tuple[str, ...]
    accepted_exit_codes: tuple[int, ...] = (0,)
    runtime: str = ""
    environment: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "command", tuple(self.command))
        codes = tuple(self.accepted_exit_codes)
        if not codes or any(not isinstance(code, int) or code < 0 or code > 255
                            for code in codes):
            raise RepairError("accepted exit codes are invalid")
        object.__setattr__(self, "accepted_exit_codes",
                           tuple(sorted(set(codes))))
        object.__setattr__(self, "environment", MappingProxyType(dict(self.environment)))
        if not isinstance(self.name, str) or not _HOOK_NAME_RE.fullmatch(self.name):
            raise RepairError("verification hook name is invalid")
        if not isinstance(self.kind, str) or self.kind not in {"scanner", "build", "test"}:
            raise RepairError("verification hook kind must be scanner, build, or test")
        if not self.command:
            raise RepairError("verification hook command is empty")


@dataclass(frozen=True)
class ApplyAuthorization:
    granted: bool = False
    reason: str = ""
    actor: str = ""

    def valid(self) -> bool:
        return bool(self.granted and isinstance(self.reason, str)
                    and isinstance(self.actor, str)
                    and 4 <= len(self.reason.strip()) <= 512
                    and len(self.actor.strip()) <= 128
                    and "\x00" not in self.reason and "\x00" not in self.actor)


@dataclass(frozen=True)
class RepairPolicy:
    max_changed_files: int = 64
    max_file_bytes: int = 4 * 1024 * 1024
    max_change_bytes: int = 16 * 1024 * 1024
    max_workspace_files: int = 50_000
    max_workspace_bytes: int = 1024 * 1024 * 1024
    max_growth_ratio: float = 6.0
    minimum_source_preservation: float = 0.20
    required_hook_kinds: tuple[str, ...] = ("scanner", "build", "test")

    def __post_init__(self) -> None:
        kinds = tuple(self.required_hook_kinds)
        if any(not isinstance(item, str) or item not in {"scanner", "build", "test"}
               for item in kinds):
            raise RepairError("required hook kinds are invalid")
        object.__setattr__(self, "required_hook_kinds", tuple(sorted(set(kinds))))
        if not 1 <= self.max_changed_files <= 1_024:
            raise RepairError("changed-file limit is invalid")
        if not 1_024 <= self.max_file_bytes <= 128 * 1024 * 1024:
            raise RepairError("per-file size limit is invalid")
        if not self.max_file_bytes <= self.max_change_bytes <= 512 * 1024 * 1024:
            raise RepairError("change-set size limit is invalid")
        if not 10 <= self.max_workspace_files <= 500_000:
            raise RepairError("workspace file limit is invalid")
        if not self.max_change_bytes <= self.max_workspace_bytes <= 8 * 1024**3:
            raise RepairError("workspace size limit is invalid")
        if not 1.0 <= self.max_growth_ratio <= 20:
            raise RepairError("growth ratio is invalid")
        if not 0.05 <= self.minimum_source_preservation <= 1.0:
            raise RepairError("source preservation ratio is invalid")
        # Required controls may be made stricter by adding hooks, never weaker.
        if not {"scanner", "build", "test"}.issubset(self.required_hook_kinds):
            raise RepairError("scanner, build, and test verification are mandatory")


@dataclass(frozen=True)
class RepairResult:
    status: str
    verified: bool
    applied: bool
    rolled_back: bool
    change_set_sha256: str
    reasons: tuple[str, ...]
    evidence: Mapping[str, Any]


@dataclass(frozen=True)
class _WorkspaceSnapshot:
    manifest_sha256: str
    files: tuple[tuple[str, str, int], ...]
    total_bytes: int


@dataclass(frozen=True)
class _Finding:
    key: str
    fingerprint: str
    rule: str
    path: str


def _safe_target(root: Path, relative: str, *, permit_missing: bool) -> Path:
    root = root.resolve(strict=True)
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    current = root
    parts = PurePosixPath(relative).parts
    for index, part in enumerate(parts):
        current = current / part
        if current.exists() or current.is_symlink():
            if current.is_symlink():
                raise RepairError("change path traverses a symbolic link")
            if index < len(parts) - 1 and not current.is_dir():
                raise RepairError("change parent is not a directory")
        elif index < len(parts) - 1 and not permit_missing:
            raise RepairError("change parent directory does not exist")
    resolved_parent = candidate.parent.resolve(strict=False)
    try:
        resolved_parent.relative_to(root)
    except ValueError as exc:
        raise RepairError("change path escapes the workspace") from exc
    return candidate


def _public_api(data: bytes, suffix: str) -> set[str]:
    text = data.decode("utf-8", "replace")
    if suffix in {".py", ".pyi"}:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return set()
        return {node.name for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and not node.name.startswith("_")}
    patterns = []
    if suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
        patterns = [r"\bexport\s+(?:default\s+)?(?:async\s+)?(?:function|class|const|let|var)\s+([A-Za-z_$][\w$]*)"]
    elif suffix in {".java", ".cs", ".kt", ".kts", ".scala"}:
        patterns = [r"\bpublic\s+(?:static\s+)?(?:class|interface|enum|record|[\w<>,?\[\]]+)\s+([A-Za-z_]\w*)"]
    elif suffix == ".go":
        patterns = [r"(?m)^\s*(?:func|type|var|const)\s+([A-Z]\w*)"]
    elif suffix in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".rs", ".php", ".rb", ".swift"}:
        # Conservative exported/declaration approximation for deletion defense.
        patterns = [r"(?m)^\s*(?:pub(?:lic)?\s+)?(?:class|struct|enum|fn|function|def)\s+([A-Za-z_]\w*)"]
    result: set[str] = set()
    for pattern in patterns:
        result.update(re.findall(pattern, text))
    return result


class TransactionalRepair:
    def __init__(self, workspace: str | os.PathLike[str], fabric: ExecutionFabric,
                 policy: RepairPolicy | None = None, *, replace_file=os.replace) -> None:
        root = Path(workspace).expanduser().resolve(strict=True)
        if not root.is_dir() or root.is_symlink():
            raise RepairError("workspace must be a real directory")
        if (not callable(getattr(fabric, "run", None)) or
                not callable(getattr(fabric, "verify_transcript", None))):
            raise RepairError("verification requires an ExecutionFabric-compatible object")
        self.workspace = root
        self.fabric = fabric
        self.policy = policy or RepairPolicy()
        self._replace_file = replace_file

    def _snapshot(self, *, ignore_lock: bool = False,
                  root: Path | None = None) -> _WorkspaceSnapshot:
        snapshot_root = (root or self.workspace).resolve(strict=True)
        rows: list[tuple[str, str, int]] = []
        total = 0
        count = 0
        for current, directories, names in os.walk(snapshot_root, followlinks=False):
            here = Path(current)
            for name in sorted(directories):
                item = here / name
                if item.is_symlink():
                    raise RepairError("workspace contains a symbolic-link directory")
            for name in sorted(names):
                item = here / name
                relative = item.relative_to(snapshot_root).as_posix()
                if ignore_lock and relative == LOCK_NAME:
                    continue
                if item.is_symlink():
                    raise RepairError("workspace contains a symbolic-link file")
                if not item.is_file():
                    raise RepairError("workspace contains a non-regular file")
                try:
                    data = item.read_bytes()
                except OSError as exc:
                    raise RepairError("workspace file could not be read") from exc
                count += 1
                total += len(data)
                if count > self.policy.max_workspace_files:
                    raise RepairError("workspace exceeds the file-count boundary")
                if len(data) > self.policy.max_file_bytes:
                    raise RepairError("workspace file exceeds the per-file boundary")
                if total > self.policy.max_workspace_bytes:
                    raise RepairError("workspace exceeds the byte boundary")
                rows.append((relative, _sha(data), len(data)))
        rows.sort(key=lambda row: row[0].casefold())
        folded: dict[str, str] = {}
        for path, _digest, _size in rows:
            if path.casefold() in folded and folded[path.casefold()] != path:
                raise RepairError("workspace contains case-colliding paths")
            folded[path.casefold()] = path
        manifest = _sha(_canonical(rows))
        return _WorkspaceSnapshot(manifest, tuple(rows), total)

    def _validate_plan(self, change_set: ChangeSet,
                       snapshot: _WorkspaceSnapshot) -> None:
        if len(change_set.changes) > self.policy.max_changed_files:
            raise RepairError("change set exceeds the changed-file boundary")
        known = {path: (digest, size) for path, digest, size in snapshot.files}
        total_new = 0
        for change in change_set.changes:
            target = _safe_target(self.workspace, change.path,
                                  permit_missing=change.operation == "add")
            current = known.get(change.path)
            if change.operation == "add":
                if current is not None or target.exists():
                    raise RepairError("add operation targets an existing file")
                if not target.parent.is_dir():
                    raise RepairError("add operation requires an existing parent directory")
            else:
                if current is None or not target.is_file():
                    raise RepairError("update/delete operation targets a missing file")
                if current[0] != change.before_sha256:
                    raise RepairError("stale before_sha256 for %s" % change.path)
            suffix = target.suffix.lower()
            if change.operation == "delete" and suffix in SOURCE_SUFFIXES:
                raise RepairError("source-file deletion is outside the repair policy")
            if change.new_content is None:
                continue
            new_size = len(change.new_content)
            total_new += new_size
            if new_size > self.policy.max_file_bytes or total_new > self.policy.max_change_bytes:
                raise RepairError("replacement content exceeds the repair size boundary")
            if current is not None:
                old = target.read_bytes()
                if _sha(change.new_content) == current[0]:
                    raise RepairError("update does not change the target artifact")
                if len(old) >= 100 and suffix in SOURCE_SUFFIXES and new_size < int(
                        len(old) * self.policy.minimum_source_preservation):
                    raise RepairError("replacement erases too much source")
                if new_size > max(4_096, int(len(old) * self.policy.max_growth_ratio)):
                    raise RepairError("replacement exceeds the growth boundary")
                missing_api = sorted(_public_api(old, suffix) -
                                     _public_api(change.new_content, suffix))
                if missing_api:
                    raise RepairError("replacement removes public API: " +
                                      ", ".join(missing_api[:8]))
            if suffix in {".py", ".pyi"}:
                try:
                    ast.parse(change.new_content.decode("utf-8", "strict"))
                except (SyntaxError, UnicodeDecodeError) as exc:
                    raise RepairError("replacement Python source does not parse") from exc

    @staticmethod
    def _relax_disposable_permissions(root: Path) -> None:
        try:
            root.chmod(0o777)
        except OSError as exc:
            raise RepairError("disposable workspace permissions could not be prepared") from exc
        for current, directories, names in os.walk(root, followlinks=False):
            here = Path(current)
            for name in directories:
                try:
                    (here / name).chmod(0o777)
                except OSError as exc:
                    raise RepairError("disposable directory permissions could not be prepared") from exc
            for name in names:
                item = here / name
                try:
                    old_mode = stat.S_IMODE(item.stat().st_mode)
                    item.chmod(0o777 if old_mode & 0o111 else 0o666)
                except OSError as exc:
                    raise RepairError("disposable file permissions could not be prepared") from exc

    @staticmethod
    def _apply_to_copy(root: Path, changes: Sequence[FileChange]) -> None:
        for change in changes:
            target = _safe_target(root, change.path, permit_missing=True)
            if change.new_content is None:
                target.unlink()
            else:
                target.write_bytes(change.new_content)

    def _invoke(self, hook: VerificationHook, workspace: Path,
                authorization: ExecutionAuthorization) -> ExecutionResult:
        request = ExecutionRequest(
            image=hook.image, command=hook.command, workspace=workspace,
            runtime=hook.runtime, environment=hook.environment,
            label=("repair-%s-%s" % (hook.kind, hook.name))[:64],
        )
        return self.fabric.run_disposable(request, authorization)

    @staticmethod
    def _parse_findings(result: ExecutionResult) -> tuple[_Finding, ...]:
        try:
            body = json.loads(result.stdout)
        except (TypeError, json.JSONDecodeError) as exc:
            raise RepairError("scanner output is not one JSON document") from exc
        if not isinstance(body, dict) or not isinstance(body.get("findings"), list):
            raise RepairError("scanner JSON must contain a findings array")
        findings: list[_Finding] = []
        keys: set[str] = set()
        if len(body["findings"]) > 100_000:
            raise RepairError("scanner finding count exceeds the evidence boundary")
        for raw in body["findings"]:
            if not isinstance(raw, dict):
                raise RepairError("scanner finding must be an object")
            rule = raw.get("rule")
            path = raw.get("path")
            if not isinstance(rule, str) or not _RULE_RE.fullmatch(rule):
                raise RepairError("scanner finding rule is invalid")
            try:
                path = normalize_relative_path(path)
            except RepairError as exc:
                raise RepairError("scanner finding path is invalid") from exc
            message = raw.get("message", "")
            if not isinstance(message, str) or len(message) > 4_096:
                raise RepairError("scanner finding message is invalid")
            supplied = raw.get("fingerprint", "")
            if supplied and (not isinstance(supplied, str) or not _SHA_RE.fullmatch(supplied)):
                raise RepairError("scanner finding fingerprint is invalid")
            fingerprint = supplied or _sha(_canonical(
                {"rule": rule, "path": path, "message": message}))
            # Semantic key excludes line numbers so harmless line movement is not new.
            key = _sha(_canonical({"rule": rule, "path": path,
                                  "message": message, "fingerprint": supplied or ""}))
            if key in keys:
                raise RepairError("scanner emitted a duplicate finding identity")
            keys.add(key)
            findings.append(_Finding(key, fingerprint, rule, path))
        return tuple(findings)

    @staticmethod
    def _result_summary(result: ExecutionResult) -> dict[str, Any]:
        return {
            "status": result.status, "returncode": result.returncode,
            "timed_out": result.timed_out, "truncated": result.truncated,
            "runtime": result.runtime, "request_sha256": result.request_sha256,
            "transcript_tail": result.transcript[-1]["event_hash"] if result.transcript else "",
        }

    def _verify(self, baseline: Path, candidate: Path, change_set: ChangeSet,
                hooks: Sequence[VerificationHook], authorization: ExecutionAuthorization
                ) -> tuple[bool, list[str], dict[str, Any]]:
        reasons: list[str] = []
        evidence: dict[str, Any] = {"hooks": {}, "scanner": {}}
        before_scans: dict[str, tuple[_Finding, ...]] = {}
        after_scans: dict[str, tuple[_Finding, ...]] = {}
        for phase, root in (("before", baseline), ("after", candidate)):
            for hook in hooks:
                # Each hook receives its own full-project clone.  A build/test
                # cannot contaminate scanner evidence or make a later hook pass.
                try:
                    with tempfile.TemporaryDirectory(
                            prefix="attestor35-%s-%s-" % (phase, hook.name)) as hook_tmp:
                        run_root = Path(hook_tmp) / phase
                        shutil.copytree(root, run_root, symlinks=True)
                        self._relax_disposable_permissions(run_root)
                        result = self._invoke(hook, run_root, authorization)
                except Exception:  # noqa: BLE001 - untrusted execution boundary fails closed
                    reasons.append("%s %s hook raised at the execution-fabric boundary" %
                                   (phase, hook.name))
                    continue
                if not isinstance(result, ExecutionResult):
                    reasons.append("%s %s hook returned an invalid result type" %
                                   (phase, hook.name))
                    continue
                evidence["hooks"]["%s:%s" % (phase, hook.name)] = self._result_summary(result)
                try:
                    transcript_valid = self.fabric.verify_transcript(result.transcript)
                except Exception:  # noqa: BLE001 - verifier failure is not evidence
                    transcript_valid = False
                if not transcript_valid:
                    reasons.append("%s %s hook returned an invalid signed transcript" %
                                   (phase, hook.name))
                    continue
                if not result.completed:
                    reasons.append("%s %s hook did not complete in the execution fabric" %
                                   (phase, hook.name))
                    continue
                if result.truncated:
                    reasons.append("%s %s hook exceeded the output evidence boundary" %
                                   (phase, hook.name))
                    continue
                if hook.kind == "scanner":
                    if result.returncode not in hook.accepted_exit_codes:
                        reasons.append("%s scanner %s returned an unaccepted exit code" %
                                       (phase, hook.name))
                        continue
                    try:
                        parsed = self._parse_findings(result)
                    except RepairError as exc:
                        reasons.append("%s scanner %s: %s" % (phase, hook.name, exc))
                        continue
                    (before_scans if phase == "before" else after_scans)[hook.name] = parsed
                elif phase == "after" and result.returncode not in hook.accepted_exit_codes:
                    reasons.append("after %s hook %s failed" % (hook.kind, hook.name))

        scanner_names = {hook.name for hook in hooks if hook.kind == "scanner"}
        if set(before_scans) != scanner_names or set(after_scans) != scanner_names:
            reasons.append("complete before/after scanner evidence is required")
        else:
            before_all = [item for name in sorted(scanner_names) for item in before_scans[name]]
            after_all = [item for name in sorted(scanner_names) for item in after_scans[name]]
            for name in sorted(scanner_names):
                before_keys = {item.key for item in before_scans[name]}
                after_keys = {item.key for item in after_scans[name]}
                new = sorted(after_keys - before_keys)
                if new:
                    reasons.append("scanner %s reports %d new finding(s)" % (name, len(new)))
            target_rules = set(change_set.target_rules)
            target_fingerprints = set(change_set.target_fingerprints)
            matches = lambda item: (item.rule in target_rules or
                                    item.fingerprint in target_fingerprints)
            before_target = sum(matches(item) for item in before_all)
            after_target = sum(matches(item) for item in after_all)
            evidence["scanner"] = {
                "before_findings": len(before_all), "after_findings": len(after_all),
                "target_before": before_target, "target_after": after_target,
                "new_findings": sum(len({item.key for item in after_scans[name]} -
                                        {item.key for item in before_scans[name]})
                                    for name in scanner_names),
            }
            if before_target <= 0:
                reasons.append("target findings were not observed in the before snapshot")
            elif after_target >= before_target:
                reasons.append("the change set did not reduce its target findings")
        return not reasons, reasons, evidence

    def _acquire_lock(self, change_set: ChangeSet) -> int:
        path = self.workspace / LOCK_NAME
        descriptor: int | None = None
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(descriptor, (change_set.digest + "\n").encode("ascii"))
            return descriptor
        except FileExistsError as exc:
            raise RepairError("another Attestor repair transaction holds the workspace lock") from exc
        except OSError as exc:
            cleanup_detail = ""
            if descriptor is not None:
                os.close(descriptor)
                try:
                    path.unlink()
                except OSError as cleanup_exc:
                    cleanup_detail = "; incomplete lock cleanup: %s" % type(cleanup_exc).__name__
            raise RepairError("workspace lock could not be created" + cleanup_detail) from exc

    def _target_matches_before(self, change: FileChange) -> bool:
        target = _safe_target(self.workspace, change.path, permit_missing=True)
        if change.before_sha256 is None:
            return not target.exists() and not target.is_symlink()
        return target.is_file() and not target.is_symlink() and _sha(target.read_bytes()) == change.before_sha256

    def _atomic_apply(self, change_set: ChangeSet,
                      expected_snapshot: _WorkspaceSnapshot) -> tuple[bool, bool, list[str], dict[str, Any]]:
        reasons: list[str] = []
        evidence: dict[str, Any] = {}
        lock_fd: int | None = None
        backup_root: Path | None = None
        staged: dict[str, Path] = {}
        backups: dict[str, Path] = {}
        mutated: list[FileChange] = []
        rolled_back = False
        try:
            lock_fd = self._acquire_lock(change_set)
            current = self._snapshot(ignore_lock=True)
            if current.manifest_sha256 != expected_snapshot.manifest_sha256:
                raise RepairError("workspace changed after verification; apply refused")
            backup_root = Path(tempfile.mkdtemp(prefix=".attestor35-backup-",
                                                dir=str(self.workspace.parent)))
            for change in change_set.changes:
                target = _safe_target(self.workspace, change.path, permit_missing=True)
                backup = backup_root.joinpath(*PurePosixPath(change.path).parts)
                if change.before_sha256 is not None:
                    backup.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(target, backup)
                    backups[change.path] = backup
                if change.new_content is not None:
                    descriptor, stage_name = tempfile.mkstemp(
                        prefix=".attestor35-stage-", dir=str(target.parent))
                    with os.fdopen(descriptor, "wb") as handle:
                        handle.write(change.new_content)
                        handle.flush()
                        os.fsync(handle.fileno())
                    stage = Path(stage_name)
                    if target.exists():
                        try:
                            stage.chmod(stat.S_IMODE(target.stat().st_mode))
                        except OSError as exc:
                            raise RepairError("staged replacement permissions could not be preserved") from exc
                    staged[change.path] = stage
            for change in sorted(change_set.changes, key=lambda item: item.path.casefold()):
                if not self._target_matches_before(change):
                    raise RepairError("stale-state guard failed immediately before %s" %
                                      change.path)
                target = _safe_target(self.workspace, change.path, permit_missing=True)
                if change.new_content is None:
                    target.unlink()
                else:
                    stage = staged[change.path]
                    if (stage.is_symlink() or not stage.is_file() or
                            _sha(stage.read_bytes()) != change.after_sha256):
                        raise RepairError("staged replacement failed its integrity guard")
                    self._replace_file(stage, target)
                mutated.append(change)
            evidence["applied_files"] = len(mutated)
            evidence["workspace_manifest_before"] = expected_snapshot.manifest_sha256
            evidence["workspace_manifest_after"] = self._snapshot(
                ignore_lock=True).manifest_sha256
            return True, False, reasons, evidence
        except (OSError, RepairError) as exc:
            reasons.append(str(exc) or type(exc).__name__)
            rollback_errors: list[str] = []
            for change in reversed(mutated):
                try:
                    target = _safe_target(self.workspace, change.path, permit_missing=True)
                    if change.before_sha256 is None:
                        if target.is_file() and _sha(target.read_bytes()) == change.after_sha256:
                            target.unlink()
                        elif target.exists() or target.is_symlink():
                            raise RepairError("rollback refused to overwrite externally changed addition")
                    else:
                        if change.new_content is None:
                            if target.exists() or target.is_symlink():
                                raise RepairError("rollback refused to overwrite recreated deletion")
                        elif not (target.is_file() and not target.is_symlink() and
                                  _sha(target.read_bytes()) == change.after_sha256):
                            raise RepairError("rollback refused to overwrite externally changed replacement")
                        self._replace_file(backups[change.path], target)
                except (OSError, RepairError) as rollback_exc:
                    rollback_errors.append("%s: %s" % (change.path, rollback_exc))
            rolled_back = bool(mutated) and not rollback_errors
            if rollback_errors:
                reasons.extend(rollback_errors)
                evidence["recovery_backup"] = str(backup_root) if backup_root else ""
            evidence["mutated_before_failure"] = len(mutated)
            return False, rolled_back, reasons, evidence
        finally:
            for stage in staged.values():
                try:
                    if stage.exists():
                        stage.unlink()
                except OSError as cleanup_exc:
                    evidence.setdefault("cleanup_errors", []).append(
                        "staged-file cleanup: %s" % type(cleanup_exc).__name__)
            if lock_fd is not None:
                os.close(lock_fd)
                try:
                    (self.workspace / LOCK_NAME).unlink()
                except OSError as cleanup_exc:
                    evidence.setdefault("cleanup_errors", []).append(
                        "workspace-lock cleanup: %s" % type(cleanup_exc).__name__)
            # Preserve backups only when rollback failed and manual recovery is needed.
            if backup_root is not None and not evidence.get("recovery_backup"):
                shutil.rmtree(backup_root, ignore_errors=True)

    def repair(
        self,
        change_set: ChangeSet,
        hooks: Sequence[VerificationHook],
        *,
        execution_authorization: ExecutionAuthorization | None = None,
        apply: bool = False,
        apply_authorization: ApplyAuthorization | None = None,
    ) -> RepairResult:
        reasons: list[str] = []
        evidence: dict[str, Any] = {"schema": SCHEMA, "dry_run": not apply}
        if not isinstance(change_set, ChangeSet):
            return RepairResult("refused", False, False, False, "",
                                ("change_set must be a ChangeSet",), evidence)
        digest = change_set.digest
        try:
            hooks = tuple(hooks)
            if not hooks or any(not isinstance(item, VerificationHook) for item in hooks):
                raise RepairError("hooks must contain declarative VerificationHook records")
            names = [item.name for item in hooks]
            if len(names) != len(set(names)):
                raise RepairError("verification hook names must be unique")
            kinds = {item.kind for item in hooks}
            missing = set(self.policy.required_hook_kinds) - kinds
            if missing:
                raise RepairError("missing mandatory verification hooks: " +
                                  ", ".join(sorted(missing)))
            if (not isinstance(execution_authorization, ExecutionAuthorization) or
                    not execution_authorization.valid()):
                raise RepairError("explicit execution authorization is required")
            if apply and (not isinstance(apply_authorization, ApplyAuthorization) or
                          not apply_authorization.valid()):
                raise RepairError("explicit, separate apply authorization is required")
            initial = self._snapshot()
            if (self.workspace / LOCK_NAME).exists():
                raise RepairError("workspace is already locked by a repair transaction")
            self._validate_plan(change_set, initial)
        except (OSError, RepairError, TypeError) as exc:
            return RepairResult("refused", False, False, False, digest,
                                (str(exc),), evidence)

        try:
            with tempfile.TemporaryDirectory(prefix="attestor35-repair-") as temporary:
                temporary_root = Path(temporary)
                baseline = temporary_root / "before"
                candidate = temporary_root / "after"
                shutil.copytree(self.workspace, baseline, symlinks=True)
                if self._snapshot(root=baseline).manifest_sha256 != initial.manifest_sha256:
                    raise RepairError("disposable before copy does not match its source manifest")
                if self._snapshot().manifest_sha256 != initial.manifest_sha256:
                    raise RepairError("workspace changed while creating the verification snapshot")
                shutil.copytree(baseline, candidate, symlinks=True)
                self._apply_to_copy(candidate, change_set.changes)
                verified, verify_reasons, verification = self._verify(
                    baseline, candidate, change_set, hooks, execution_authorization)
                reasons.extend(verify_reasons)
                evidence.update(verification)
                if self._snapshot().manifest_sha256 != initial.manifest_sha256:
                    verified = False
                    reasons.append("workspace changed during disposable verification")
        except (OSError, RepairError, shutil.Error) as exc:
            verified = False
            reasons.append("disposable verification failed: %s" % exc)

        if not verified:
            return RepairResult("rejected", False, False, False, digest,
                                tuple(reasons), evidence)
        evidence["workspace_manifest_verified"] = initial.manifest_sha256
        if not apply:
            return RepairResult("verified-dry-run", True, False, False, digest,
                                (), evidence)
        applied, rolled_back, apply_reasons, apply_evidence = self._atomic_apply(
            change_set, initial)
        evidence.update(apply_evidence)
        if applied:
            return RepairResult("applied", True, True, False, digest, (), evidence)
        return RepairResult("rolled-back" if rolled_back else "apply-failed",
                            True, False, rolled_back, digest,
                            tuple(apply_reasons), evidence)


__all__ = [
    "ApplyAuthorization", "ChangeSet", "FileChange", "RepairError", "RepairPolicy",
    "RepairResult", "TransactionalRepair", "VerificationHook", "normalize_relative_path",
]
