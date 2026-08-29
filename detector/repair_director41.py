#!/usr/bin/env python3
"""Attestor 4.1.3 proof-gated multi-candidate repair director.

The director closes an important orchestration gap without pretending that code
generation is proof.  It can create deterministic mechanical Python candidates,
ingest complete multi-file candidates from an external producer, perform a
bounded static comparison, and rank the survivors.  A candidate becomes
``verified`` only when :mod:`transactional_repair35` completes its mandatory
scanner, build, and test hooks in the eligible execution fabric.  Applying a
verified candidate still requires a separate authorization.

No provider is contacted, target source is not imported, and target code is not
executed by the default path.
"""
from __future__ import annotations

import argparse
import ast
import base64
import dataclasses
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
from typing import Any, Iterable, Mapping, Sequence

import execution_fabric35
import scanengine
import transactional_repair35
import verified_remediation


SCHEMA = "attestor-repair-director/4.1"
CANDIDATE_SCHEMA = "attestor-repair-candidate/4.1"
VERSION = "4.1.3"
MAX_CANDIDATES = 16
MAX_CHANGED_FILES = 64
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_PROVIDER_BYTES = 20 * 1024 * 1024
MAX_PUBLIC_CANDIDATE_BYTES = 4 * 1024 * 1024
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
_RULE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
_SEVERITY = {"CRITICAL": 40, "HIGH": 16, "MEDIUM": 5, "LOW": 1, "INFO": 0}


class RepairDirectorError(ValueError):
    """A candidate or director boundary is invalid."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False,
                      default=str).encode("utf-8")


def _sha(value: bytes | str | Any) -> str:
    if not isinstance(value, (bytes, str)):
        value = _canonical(value)
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _relative(value: Any) -> str:
    if not isinstance(value, str):
        raise RepairDirectorError("candidate path must be text")
    try:
        return transactional_repair35.normalize_relative_path(value)
    except transactional_repair35.RepairError as exc:
        raise RepairDirectorError("candidate path is unsafe") from exc


def _is_link_or_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse)


def _workspace(value: str | os.PathLike[str]) -> Path:
    supplied = Path(value).expanduser()
    try:
        spelling = supplied if supplied.is_absolute() else Path.cwd() / supplied
        current = Path(spelling.anchor)
        for part in spelling.parts[1:]:
            if part in {"", "."}:
                continue
            if part == "..":
                current = current.parent
                continue
            current = current / part
            if _is_link_or_reparse(current):
                raise RepairDirectorError(
                    "repair workspace path cannot traverse a link or reparse point")
        base = Path(os.path.abspath(os.fspath(spelling))).resolve(strict=True)
    except RepairDirectorError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise RepairDirectorError("repair workspace is unavailable") from exc
    if not base.is_dir() or _is_link_or_reparse(base):
        raise RepairDirectorError("repair workspace must be a real directory")
    return base


def _target(root: Path, relative: str, *, missing: bool = False) -> Path:
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    lexical = root
    for part in PurePosixPath(relative).parts[:-1]:
        lexical = lexical / part
        if _is_link_or_reparse(lexical):
            raise RepairDirectorError("candidate parent cannot be a link or reparse point")
    try:
        resolved_parent = candidate.parent.resolve(strict=True)
        resolved_parent.relative_to(root)
    except (OSError, ValueError) as exc:
        raise RepairDirectorError("candidate parent escapes the workspace") from exc
    resolved = resolved_parent / candidate.name
    if _is_link_or_reparse(resolved):
        raise RepairDirectorError("candidate targets a link or reparse point")
    if not missing and not resolved.is_file():
        raise RepairDirectorError("candidate targets a missing or non-regular file")
    return resolved


def _read_baseline(path: Path) -> bytes:
    """Reject oversized baselines by metadata, then retain a race-safe read cap."""
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
            raise RepairDirectorError("baseline file exceeds the size boundary")
        with path.open("rb") as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
    except RepairDirectorError:
        raise
    except OSError as exc:
        raise RepairDirectorError("baseline file is unavailable") from exc
    if len(raw) > MAX_FILE_BYTES:
        raise RepairDirectorError("baseline file exceeds the size boundary")
    return raw


def _read_provider_file(path: Path) -> bytes:
    """Read one provider JSON file without crossing its declared byte boundary."""
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_PROVIDER_BYTES:
            raise RepairDirectorError("candidate file exceeds the size boundary")
        with path.open("rb") as stream:
            raw = stream.read(MAX_PROVIDER_BYTES + 1)
    except RepairDirectorError:
        raise
    except OSError as exc:
        raise RepairDirectorError("candidate file is unavailable") from exc
    if len(raw) > MAX_PROVIDER_BYTES:
        raise RepairDirectorError("candidate file exceeds the size boundary")
    return raw


@dataclasses.dataclass(frozen=True)
class CandidateChange:
    path: str
    before_sha256: str | None
    content: bytes | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _relative(self.path))
        if self.before_sha256 is not None and not _SHA_RE.fullmatch(self.before_sha256):
            raise RepairDirectorError("before_sha256 must be a lowercase SHA-256 digest")
        if self.content is not None and not isinstance(self.content, bytes):
            raise RepairDirectorError("candidate content must be bytes or null")
        if self.before_sha256 is None and self.content is None:
            raise RepairDirectorError("an absent file cannot be deleted")
        if self.content is not None and len(self.content) > MAX_FILE_BYTES:
            raise RepairDirectorError("candidate file exceeds the size boundary")

    @property
    def operation(self) -> str:
        return "add" if self.before_sha256 is None else "delete" if self.content is None else "update"

    @property
    def after_sha256(self) -> str | None:
        return _sha(self.content) if self.content is not None else None


@dataclasses.dataclass(frozen=True)
class RepairCandidate:
    candidate_id: str
    producer: str
    changes: tuple[CandidateChange, ...]
    target_rules: tuple[str, ...]
    target_fingerprints: tuple[str, ...] = ()
    rationale: str = ""
    producer_evidence: Mapping[str, Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(self.candidate_id):
            raise RepairDirectorError("candidate_id is invalid")
        if not isinstance(self.producer, str) or not self.producer or len(self.producer) > 128:
            raise RepairDirectorError("producer is invalid")
        object.__setattr__(self, "changes", tuple(self.changes))
        rules = tuple(sorted(set(self.target_rules)))
        fingerprints = tuple(sorted(set(self.target_fingerprints)))
        if not self.changes or len(self.changes) > MAX_CHANGED_FILES:
            raise RepairDirectorError("candidate changed-file count is invalid")
        if any(not _RULE_RE.fullmatch(item) for item in rules):
            raise RepairDirectorError("candidate target rule is invalid")
        if any(not _SHA_RE.fullmatch(item) for item in fingerprints):
            raise RepairDirectorError("candidate target fingerprint is invalid")
        if not rules and not fingerprints:
            raise RepairDirectorError("candidate is not bound to a target finding")
        if len(self.rationale.encode("utf-8")) > 2_000 or "\x00" in self.rationale:
            raise RepairDirectorError("candidate rationale is invalid")
        if sum(len(item.content or b"") for item in self.changes) > MAX_TOTAL_BYTES:
            raise RepairDirectorError("candidate exceeds the total content boundary")
        folded: set[str] = set()
        for item in self.changes:
            if item.path.casefold() in folded:
                raise RepairDirectorError("candidate has duplicate or case-colliding paths")
            folded.add(item.path.casefold())
        try:
            evidence = json.loads(_canonical(dict(self.producer_evidence)))
        except (TypeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
            raise RepairDirectorError("producer evidence is not bounded JSON") from exc
        if len(_canonical(evidence)) > 64 * 1024:
            raise RepairDirectorError("producer evidence exceeds the boundary")
        object.__setattr__(self, "target_rules", rules)
        object.__setattr__(self, "target_fingerprints", fingerprints)
        object.__setattr__(self, "producer_evidence", evidence)

    @property
    def digest(self) -> str:
        return _sha({
            "schema": CANDIDATE_SCHEMA, "id": self.candidate_id,
            "producer": self.producer,
            "changes": [{"path": row.path, "before": row.before_sha256,
                         "after": row.after_sha256, "operation": row.operation}
                        for row in self.changes],
            "target_rules": self.target_rules,
            "target_fingerprints": self.target_fingerprints,
            "rationale_sha256": _sha(self.rationale),
            "producer_evidence_sha256": _sha(self.producer_evidence),
        })

    def change_set(self) -> transactional_repair35.ChangeSet:
        return transactional_repair35.ChangeSet(
            changes=tuple(transactional_repair35.FileChange(
                row.path, row.before_sha256, row.content) for row in self.changes),
            target_rules=self.target_rules,
            target_fingerprints=self.target_fingerprints,
            rationale=self.rationale,
        )


def _decode_content(row: Mapping[str, Any]) -> bytes | None:
    has_text = "content" in row
    has_b64 = "content_base64" in row
    if has_text and has_b64:
        raise RepairDirectorError("candidate change has two content encodings")
    if has_text:
        value = row["content"]
        if value is None:
            return None
        if not isinstance(value, str):
            raise RepairDirectorError("candidate text content must be text or null")
        return value.encode("utf-8", "strict")
    if has_b64:
        value = row["content_base64"]
        if not isinstance(value, str) or len(value) > (MAX_FILE_BYTES * 2):
            raise RepairDirectorError("candidate base64 content is invalid")
        try:
            return base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise RepairDirectorError("candidate base64 content is invalid") from exc
    raise RepairDirectorError("candidate change omitted content")


def candidate_from_document(document: Mapping[str, Any], root: str | os.PathLike[str]) -> RepairCandidate:
    """Parse one complete candidate and bind it to the current workspace."""
    if type(document) is not dict or document.get("schema") != CANDIDATE_SCHEMA:
        raise RepairDirectorError("candidate schema is unsupported")
    base = _workspace(root)
    raw_changes = document.get("changes")
    if type(raw_changes) is not list or not 1 <= len(raw_changes) <= MAX_CHANGED_FILES:
        raise RepairDirectorError("candidate changes must be a bounded array")
    changes: list[CandidateChange] = []
    for raw in raw_changes:
        if type(raw) is not dict:
            raise RepairDirectorError("candidate change must be an object")
        relative = _relative(raw.get("path"))
        before = raw.get("before_sha256")
        if before is not None and not isinstance(before, str):
            raise RepairDirectorError("before_sha256 has an invalid type")
        content = _decode_content(raw)
        target = _target(base, relative, missing=before is None)
        if before is None:
            if target.exists():
                raise RepairDirectorError("add candidate targets an existing path")
        else:
            if _sha(_read_baseline(target)) != before:
                raise RepairDirectorError("candidate is stale for " + relative)
        changes.append(CandidateChange(relative, before, content))
    rules = document.get("target_rules", [])
    fingerprints = document.get("target_fingerprints", [])
    if type(rules) is not list or type(fingerprints) is not list:
        raise RepairDirectorError("candidate target identities must be arrays")
    return RepairCandidate(
        str(document.get("candidate_id", "")), str(document.get("producer", "")),
        tuple(changes), tuple(str(item) for item in rules),
        tuple(str(item) for item in fingerprints),
        str(document.get("rationale", "")),
        document.get("producer_evidence", {}) if type(document.get("producer_evidence", {})) is dict else {},
    )


def candidate_from_provider_text(text: str, root: str | os.PathLike[str]) -> RepairCandidate:
    """Accept exactly one JSON candidate; markdown/code-fence extraction is forbidden."""
    if not isinstance(text, str) or not 1 <= len(text.encode("utf-8")) <= MAX_PROVIDER_BYTES:
        raise RepairDirectorError("provider candidate response is empty or oversized")
    def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise RepairDirectorError("provider candidate contains a duplicate JSON key")
            result[key] = value
        return result
    try:
        document = json.loads(text, object_pairs_hook=strict_object)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise RepairDirectorError("provider response is not exactly one JSON document") from exc
    return candidate_from_document(document, root)


def _finding_row(value: Any) -> dict[str, Any]:
    if dataclasses.is_dataclass(value):
        value = dataclasses.asdict(value)
    if not isinstance(value, Mapping):
        value = {name: getattr(value, name, "") for name in
                 ("path", "line", "rule", "message", "fingerprint")}
    return {str(key): item for key, item in value.items()}


def _finding_relative(base: Path, value: Any) -> str:
    text = str(value or "")
    try:
        path = Path(text)
        if path.is_absolute():
            return path.resolve(strict=True).relative_to(base).as_posix()
    except (OSError, ValueError):
        raise RepairDirectorError("finding path is outside the repair workspace")
    return _relative(text)


def mechanical_candidates(root: str | os.PathLike[str], findings: Iterable[Any], *,
                          maximum: int = 8) -> list[RepairCandidate]:
    """Generate bounded, deterministic complete-source candidates for supported Python rules."""
    if not 0 <= int(maximum) <= MAX_CANDIDATES:
        raise RepairDirectorError("mechanical candidate limit is invalid")
    base = _workspace(root)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for raw in findings:
        row = _finding_row(raw)
        try:
            relative = _finding_relative(base, row.get("path"))
        except RepairDirectorError:
            continue
        if _RULE_RE.fullmatch(str(row.get("rule", ""))):
            grouped.setdefault(relative, []).append(row)
    candidates: list[RepairCandidate] = []
    for relative in sorted(grouped, key=str.casefold):
        if len(candidates) >= maximum:
            break
        target = _target(base, relative)
        if target.suffix.lower() not in {".py", ".pyi"}:
            continue
        try:
            raw_source = _read_baseline(target)
            source = raw_source.decode("utf-8", "strict")
            proposal = verified_remediation.propose_fixes(source, relative, grouped[relative])
        except (RepairDirectorError, OSError, UnicodeError, ValueError, SyntaxError):
            continue
        if not proposal.changed or not proposal.improved_source:
            continue
        resolved_rules = sorted(set(edit.rule for edit in proposal.edits
                                    if edit.rule != "import"))
        bound = [row for row in grouped[relative]
                 if str(row.get("rule", "")) in set(resolved_rules)]
        rules = tuple(sorted(set(str(row.get("rule")) for row in bound)))
        fingerprints = tuple(sorted(set(str(row.get("fingerprint")) for row in bound
                                        if _SHA_RE.fullmatch(str(row.get("fingerprint", ""))))))
        if not rules and not fingerprints:
            continue
        content = proposal.improved_source.encode("utf-8")
        before = _sha(raw_source)
        identifier = "mechanical-%02d-%s" % (len(candidates) + 1, _sha([relative, rules, before])[:16])
        candidates.append(RepairCandidate(
            identifier, "attestor-deterministic-remediation/4.1",
            (CandidateChange(relative, before, content),), rules, fingerprints,
            "Apply deterministic source transformations for supported findings.",
            {"proposal_sha256": _sha({"target": proposal.target,
                                      "before": proposal.original_sha256,
                                      "after": proposal.candidate_sha256,
                                      "rules": resolved_rules}),
             "resolved_rules": resolved_rules,
             "refusal_count": len(proposal.refusals)},
        ))
    return candidates


def _issue_identity(issue: Any, *, mapped_path: str = "") -> tuple[str, str, str]:
    path = mapped_path or str(getattr(issue, "path", ""))
    return (str(getattr(issue, "rule", "")), path.replace("\\", "/"),
            str(getattr(issue, "message", "")))


def _scan_file(path: Path, display_path: str) -> tuple[list[tuple[str, str, str]], list[dict[str, Any]]]:
    result = scanengine.scan([str(path)], jobs=1, deep=True, tools=False, use_cache=False,
                             max_bytes=MAX_FILE_BYTES)
    identities = [_issue_identity(issue, mapped_path=display_path) for issue in result.issues]
    public = [{"rule": issue.rule, "severity": issue.severity,
               "message": issue.message[:1_000], "path": display_path,
               "line": max(1, int(issue.line))} for issue in result.issues]
    if result.errors:
        raise RepairDirectorError("static scan could not complete for " + display_path)
    return identities, public


def static_evaluate(root: str | os.PathLike[str], candidate: RepairCandidate) -> dict[str, Any]:
    """Compare changed artifacts without executing target code or writing the workspace."""
    base = _workspace(root)
    change_set = candidate.change_set()  # reuse the strict typed plan boundary
    baselines: dict[str, bytes] = {}
    for change in candidate.changes:
        target = _target(base, change.path, missing=change.before_sha256 is None)
        if change.before_sha256 is None:
            if target.exists():
                raise RepairDirectorError("candidate add became stale for " + change.path)
        else:
            raw = _read_baseline(target)
            if _sha(raw) != change.before_sha256:
                raise RepairDirectorError("candidate changed-file guard became stale for " + change.path)
            baselines[change.path] = raw
    before_rows: list[tuple[str, str, str]] = []
    after_rows: list[tuple[str, str, str]] = []
    after_public: list[dict[str, Any]] = []
    parse_errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="attestor41-static-candidate-") as folder:
        stage = Path(folder)
        for index, change in enumerate(candidate.changes):
            if change.before_sha256 is not None:
                suffix = PurePosixPath(change.path).suffix.lower()
                baseline = stage / ("baseline-%03d%s" % (index, suffix or ".txt"))
                baseline.write_bytes(baselines[change.path])
                identities, _ = _scan_file(baseline, change.path)
                before_rows.extend(identities)
            if change.content is None:
                continue
            suffix = PurePosixPath(change.path).suffix.lower()
            if suffix in {".py", ".pyi"}:
                try:
                    ast.parse(change.content.decode("utf-8", "strict"), filename=change.path)
                except (SyntaxError, UnicodeDecodeError) as exc:
                    parse_errors.append("%s: %s" % (change.path, type(exc).__name__))
                    continue
            staged = stage / ("candidate-%03d%s" % (index, suffix or ".txt"))
            staged.write_bytes(change.content)
            identities, public = _scan_file(staged, change.path)
            after_rows.extend(identities)
            after_public.extend(public)
    before = set(before_rows)
    after = set(after_rows)
    new = after - before
    resolved = before - after
    targets = set(candidate.target_rules)
    target_before = sum(rule in targets for rule, _path, _message in before)
    target_after = sum(rule in targets for rule, _path, _message in after)
    introduced = [row for row in after_public
                  if (row["rule"], row["path"], row["message"]) in new]
    severe_new = sum(_SEVERITY.get(row["severity"].upper(), 5) for row in introduced)
    reasons = list(parse_errors)
    if not candidate.target_rules:
        reasons.append(
            "fingerprint-only target resolution cannot be proven by the changed-file static comparator")
    if target_before <= 0:
        reasons.append("target rules were not observed in the changed-file baseline")
    if target_before > 0 and target_after >= target_before:
        reasons.append("candidate did not reduce its changed-file target findings")
    if any(row["severity"].upper() in {"CRITICAL", "HIGH"} for row in introduced):
        reasons.append("candidate introduced a high-severity static finding")
    changed_bytes = sum(len(row.content or b"") for row in candidate.changes)
    score = max(-1_000_000, len(resolved) * 100 - severe_new * 10 -
                len(candidate.changes) * 2 - min(changed_bytes // 16_384, 100))
    status = "static-qualified" if not reasons else "refused"
    body = {
        "candidate_id": candidate.candidate_id, "candidate_sha256": candidate.digest,
        "change_set_sha256": change_set.digest, "status": status,
        "verified": False, "applied": False, "score": score,
        "changed_files": len(candidate.changes), "changed_bytes": changed_bytes,
        "static": {"before_findings": len(before), "after_findings": len(after),
                   "resolved": len(resolved), "introduced": len(new),
                   "target_before": target_before, "target_after": target_after,
                   "introduced_findings": introduced[:100]},
        "reasons": reasons,
        "assurance": {"target_code_executed": False, "network_accessed": False,
                      "workspace_written": False,
                      "static_qualification_is_verification": False},
    }
    body["evaluation_sha256"] = _sha(body)
    return body


def direct(root: str | os.PathLike[str], *, issue: str = "",
           findings: Iterable[Any] = (), candidates: Sequence[RepairCandidate] = (),
           mechanical: bool = True, maximum_candidates: int = 8,
           include_candidate_source: bool = False,
           hooks: Sequence[transactional_repair35.VerificationHook] = (),
           execution_authorization: execution_fabric35.ExecutionAuthorization | None = None,
           apply: bool = False,
           apply_authorization: transactional_repair35.ApplyAuthorization | None = None,
           fabric: execution_fabric35.ExecutionFabric | None = None) -> dict[str, Any]:
    """Rank candidates and optionally submit the best one to mandatory proof gates."""
    base = _workspace(root)
    if not isinstance(issue, str) or len(issue.encode("utf-8")) > 64 * 1024:
        raise RepairDirectorError("issue is not bounded text")
    if not 1 <= int(maximum_candidates) <= MAX_CANDIDATES:
        raise RepairDirectorError("maximum_candidates is invalid")
    finding_rows = [_finding_row(item) for item in findings]
    proposed = list(candidates)
    if mechanical and len(proposed) < maximum_candidates:
        proposed.extend(mechanical_candidates(
            base, finding_rows, maximum=maximum_candidates - len(proposed)))
    if len(proposed) > maximum_candidates:
        proposed = proposed[:maximum_candidates]
    ids: set[str] = set()
    evaluations = []
    for candidate in proposed:
        if not isinstance(candidate, RepairCandidate):
            raise RepairDirectorError("candidates must be RepairCandidate records")
        if candidate.candidate_id in ids:
            raise RepairDirectorError("candidate IDs must be unique")
        ids.add(candidate.candidate_id)
        available_rules = {str(row.get("rule", "")) for row in finding_rows}
        available_fingerprints = {str(row.get("fingerprint", "")) for row in finding_rows
                                  if _SHA_RE.fullmatch(str(row.get("fingerprint", "")))}
        bound = bool(set(candidate.target_rules) & available_rules or
                     set(candidate.target_fingerprints) & available_fingerprints)
        if not bound:
            evaluations.append({
                "candidate_id": candidate.candidate_id,
                "candidate_sha256": candidate.digest, "status": "refused",
                "verified": False, "applied": False, "score": -1_000_000,
                "reasons": ["candidate target identities do not intersect the supplied findings"],
                "assurance": {"target_code_executed": False,
                              "network_accessed": False, "workspace_written": False,
                              "static_qualification_is_verification": False},
            })
            continue
        try:
            evaluations.append(static_evaluate(base, candidate))
        except (OSError, ValueError, transactional_repair35.RepairError) as exc:
            evaluations.append({
                "candidate_id": candidate.candidate_id,
                "candidate_sha256": candidate.digest, "status": "refused",
                "verified": False, "applied": False, "score": -1_000_000,
                "reasons": ["static candidate boundary refused: " + type(exc).__name__],
                "assurance": {"target_code_executed": False, "network_accessed": False,
                              "workspace_written": False,
                              "static_qualification_is_verification": False},
            })
    evaluations.sort(key=lambda row: (-int(row.get("score", -1_000_000)),
                                      str(row.get("candidate_id", ""))))
    qualified = [row for row in evaluations if row.get("status") == "static-qualified"]
    selected = qualified[0]["candidate_id"] if qualified else ""
    transaction: dict[str, Any] | None = None
    execution_requested = bool(hooks or execution_authorization or apply or apply_authorization)
    if execution_requested:
        if not selected:
            transaction = {"status": "refused", "verified": False, "applied": False,
                           "reasons": ["no statically qualified candidate exists"]}
        elif not hooks or execution_authorization is None:
            transaction = {"status": "refused", "verified": False, "applied": False,
                           "reasons": ["verification requires scanner, build, and test hooks plus execution authorization"]}
        else:
            chosen = next(item for item in proposed if item.candidate_id == selected)
            engine = transactional_repair35.TransactionalRepair(
                base, fabric or execution_fabric35.ExecutionFabric())
            result = engine.repair(
                chosen.change_set(), tuple(hooks),
                execution_authorization=execution_authorization,
                apply=bool(apply), apply_authorization=apply_authorization)
            transaction = dataclasses.asdict(result)
            for row in evaluations:
                if row["candidate_id"] == selected:
                    row["status"] = result.status
                    row["verified"] = bool(result.verified)
                    row["applied"] = bool(result.applied)
                    row["transaction_sha256"] = _sha(transaction)
                    break
    verified = sum(row.get("verified") is True for row in evaluations)
    applied = sum(row.get("applied") is True for row in evaluations)
    gaps = []
    if not proposed:
        gaps.append("no concrete repair candidate was produced or supplied")
    if qualified and not execution_requested:
        gaps.append("static qualification is not verification; scanner/build/test gates were not authorized")
    if not hooks:
        gaps.append("mandatory scanner, build, and test hooks were not supplied")
    status = "applied" if applied else "verified-dry-run" if verified else \
        "candidates-qualified" if qualified else "no-qualified-candidate"
    hooks_executed = bool(
        transaction and isinstance(transaction.get("evidence"), Mapping)
        and transaction["evidence"].get("hooks"))
    selected_output: dict[str, Any] | None = None
    if selected and include_candidate_source:
        chosen = next(item for item in proposed if item.candidate_id == selected)
        total = sum(len(change.content or b"") for change in chosen.changes)
        if total <= MAX_PUBLIC_CANDIDATE_BYTES:
            changes = []
            complete = True
            for change in chosen.changes:
                row: dict[str, Any] = {
                    "path": change.path, "operation": change.operation,
                    "before_sha256": change.before_sha256,
                    "after_sha256": change.after_sha256,
                }
                if change.content is None:
                    row["content"] = None
                else:
                    try:
                        row["content"] = change.content.decode("utf-8", "strict")
                    except UnicodeDecodeError:
                        row["content_withheld"] = "binary candidate content is not emitted"
                        complete = False
                changes.append(row)
            selected_row = next(row for row in evaluations
                                if row["candidate_id"] == selected)
            selected_output = {
                "schema": CANDIDATE_SCHEMA, "version": VERSION,
                "candidate_id": chosen.candidate_id, "producer": chosen.producer,
                "candidate_sha256": chosen.digest,
                "state": "verified-result" if selected_row.get("verified") is True
                         else "unverified-review-candidate",
                "complete": complete, "applied": selected_row.get("applied") is True,
                "target_rules": list(chosen.target_rules),
                "target_fingerprints": list(chosen.target_fingerprints),
                "rationale": chosen.rationale, "changes": changes,
                "warning": "Static qualification is not behavioral verification. Run the mandatory scanner/build/test gates before use.",
            }
            selected_output["output_sha256"] = _sha(selected_output)
        else:
            selected_output = {
                "schema": CANDIDATE_SCHEMA, "version": VERSION,
                "candidate_id": chosen.candidate_id, "candidate_sha256": chosen.digest,
                "state": "withheld-size-boundary", "complete": False,
                "changes": [], "maximum_bytes": MAX_PUBLIC_CANDIDATE_BYTES,
            }
            selected_output["output_sha256"] = _sha(selected_output)
    body = {
        "schema": SCHEMA, "version": VERSION, "root": str(base), "status": status,
        "issue": {"present": bool(issue), "sha256": _sha(issue),
                  "bytes": len(issue.encode("utf-8"))},
        "summary": {"candidates": len(evaluations), "static_qualified": len(qualified),
                    "verified": verified, "applied": applied},
        "selected_candidate": selected, "evaluations": evaluations,
        "selected_candidate_output": selected_output,
        "transaction": transaction,
        "coverage": {"gaps": gaps, "candidate_limit": maximum_candidates,
                     "candidate_generation": "deterministic-supported-rules-and-supplied-producers",
                     "arbitrary_generation_available": False,
                     "candidate_parser_process_isolated": False,
                     "candidate_parser_boundaries": {
                         "provider_bytes": MAX_PROVIDER_BYTES,
                         "candidates": MAX_CANDIDATES,
                         "changed_files": MAX_CHANGED_FILES,
                         "total_candidate_bytes": MAX_TOTAL_BYTES,
                     }},
        "execution": {
            "target_code_executed": hooks_executed,
            "network_accessed": False, "workspace_written": bool(applied),
            "host_execution_fallback": False,
            "separate_execution_authorization": True,
            "separate_apply_authorization": True,
        },
        "delivery_stages": ["scope", "candidate", "static-compare", "rank",
                            "scanner", "build", "test", "security-review",
                            "separately-authorized-apply", "rollback"],
        "limitations": [
            "A generated or supplied candidate is untrusted until mandatory proof gates pass.",
            "Static qualification does not prove behavioral correctness.",
            "The deterministic producer supports only explicitly modeled transformations.",
            "External model/provider calls are never made by this module.",
            "Candidate parsing and static comparison run in the coordinator process under byte/count limits; OS process isolation is not provided for this stage.",
        ],
    }
    body["report_sha256"] = _sha(body)
    return body


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root")
    parser.add_argument("--issue", default="")
    parser.add_argument("--candidate-json", action="append", default=[])
    parser.add_argument("--no-mechanical", action="store_true")
    parser.add_argument("--maximum-candidates", type=int, default=8)
    parser.add_argument("--include-candidate-source", action="store_true")
    parser.add_argument("--format", choices=("json", "text"), default="text")
    args = parser.parse_args(argv)
    candidates = []
    for path in args.candidate_json:
        try:
            raw = _read_provider_file(Path(path))
        except RepairDirectorError as exc:
            parser.error(str(exc))
        candidates.append(candidate_from_provider_text(raw.decode("utf-8"), args.root))
    scan = scanengine.scan([args.root], jobs=1, deep=True, tools=False, use_cache=False)
    report = direct(args.root, issue=args.issue, findings=scan.issues,
                    candidates=candidates, mechanical=not args.no_mechanical,
                    maximum_candidates=args.maximum_candidates,
                    include_candidate_source=args.include_candidate_source)
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        summary = report["summary"]
        print("Attestor 4.1.3 Repair Director: %s" % report["status"])
        print("Candidates: %(candidates)d; static-qualified: %(static_qualified)d; "
              "verified: %(verified)d; applied: %(applied)d" % summary)
        if report["selected_candidate"]:
            print("Selected: " + report["selected_candidate"])
        for gap in report["coverage"]["gaps"]:
            print("GAP: " + gap)
    return 0 if report["status"] in {"applied", "verified-dry-run", "candidates-qualified"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
