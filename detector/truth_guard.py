#!/usr/bin/env python3
"""Evidence-bound response claim validation for Attestor 3.0.

Truth Guard never calls a model, network, shell, importer, or target program.  It
accepts JSON-shaped claims and evidence, checks only machine-verifiable
predicates, and emits a deterministic report whose public values are bounded and
credential-redacted.  Unsupported prose is converted to an explicit abstention
instead of being repeated as fact.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

import secret_guard


VERSION = "3.0.0"
SCHEMA = "attestor-truth-guard/1.0"
STATES = frozenset({"observed", "derived", "unknown", "refuted"})
SUPPORTED_KINDS = frozenset({
    "value", "count", "file", "finding", "rule", "improvement",
    "coverage", "artifact", "statement",
})
MAX_CLAIMS = 256
MAX_INPUT_NODES = 100_000
MAX_DEPTH = 24
MAX_EVIDENCE = 8_000
MAX_PUBLIC_EVIDENCE = 1_024
MAX_TEXT_CHARS = 2_000
MAX_PREVIEW_CHARS = 512
MAX_SAFE_RESPONSE_CHARS = 64 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_SECRET_SCAN_CHARS = 16 * 1024

_MISSING = object()
_PASS = frozenset({"passed", "pass", "verified", "ok", "success"})
_FAIL = frozenset({"failed", "fail", "error", "invalid", "rejected", "timeout"})
_SENSITIVE_COMPONENT = re.compile(
    r"^(?:key|secret|password|passwd|pwd|token|credential|private_key|api_key|"
    r"access_token|auth_token|client_secret)$", re.I)
_INLINE_SECRET = re.compile(
    r"(?i)(?:authorization\s*:\s*bearer|bearer|api[_-]?key|access[_-]?token|"
    r"client[_-]?secret|password)\s*(?:[:=]\s*)?[A-Za-z0-9_./+~-]{12,}")
_ABSOLUTE_SAFETY = re.compile(
    r"(?i)\b(?:completely secure|100\s*%\s*(?:safe|secure)|guaranteed safe|"
    r"zero risk|no vulnerabilities|no bugs|no errors(?: exist| remain)?|perfectly safe)\b")
_QUALIFIED_ABSENCE = re.compile(
    r"(?i)\b(?:from|by|within) (?:the )?(?:enabled|supplied|observed|static) (?:checks|evidence|scan)\b")


class TruthGuardError(ValueError):
    """Raised for non-JSON or dangerously oversized API input."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(value: Any) -> str:
    _assert_json_tree(value)
    return hashlib.sha256(_canonical(_identity_safe(value))).hexdigest()


def _bounded(value: Any, limit: int = MAX_TEXT_CHARS) -> tuple[str, bool]:
    text = str(value)
    if len(text) <= limit:
        return text, False
    return text[:limit] + " [truncated]", True


def _sensitive_pointer(pointer: str) -> bool:
    components = [_pointer_unescape(item) for item in pointer.split("/")[1:]]
    return any(_SENSITIVE_COMPONENT.fullmatch(item or "") for item in components)


def _contains_secret(value: str) -> bool:
    sample = value[:MAX_SECRET_SCAN_CHARS]
    if not sample or sample in {"[REDACTED]", "<redacted>", "[redacted]"}:
        return False
    return bool(_INLINE_SECRET.search(sample) or secret_guard.scan_text(
        sample, "truth-guard-response.txt", max_findings=1))


def _bounded_public_key(key: str, *, limit: int, redacted_label: str,
                        used: set[str]) -> str:
    """Return a bounded object key without allowing silent key collisions."""
    if not isinstance(key, str):
        raise TruthGuardError("object keys must be strings")
    if _contains_secret(key):
        base = redacted_label
    elif len(key) <= limit:
        base = key
    else:
        suffix = "~sha256:" + hashlib.sha256(
            key.encode("utf-8", errors="surrogatepass")).hexdigest()
        base = key[:max(0, limit - len(suffix))] + suffix
    candidate = base
    collision = 1
    while candidate in used:
        suffix = "~collision:%d" % collision
        candidate = base[:max(0, limit - len(suffix))] + suffix
        collision += 1
    used.add(candidate)
    return candidate


def _identity_safe(value: Any, sensitive: bool = False) -> Any:
    """Remove secret material before any stable-ID hashing operation."""
    if value is None or isinstance(value, bool) or type(value) in {int, float}:
        return "<redacted>" if sensitive and value not in {None, False, 0} else value
    if isinstance(value, str):
        if sensitive or _contains_secret(value):
            return "<redacted>"
        return value[:2_000]
    if type(value) is dict:
        output = {}
        used: set[str] = set()
        redacted_key_number = 0
        for key in sorted(value):
            if not isinstance(key, str):
                raise TruthGuardError("object keys must be strings")
            secret_key = _contains_secret(key)
            if secret_key:
                redacted_key_number += 1
            safe_key = _bounded_public_key(
                key, limit=512,
                redacted_label="<redacted-key-%d>" % redacted_key_number,
                used=used)
            output[safe_key] = _identity_safe(value[key], _SENSITIVE_COMPONENT.fullmatch(key) is not None)
        return output
    if type(value) in {list, tuple}:
        return [_identity_safe(item, sensitive) for item in value[:1_024]]
    return "<unsupported>"


def _safe_text(value: Any, *, sensitive: bool = False,
               limit: int = MAX_TEXT_CHARS) -> tuple[str, bool, bool]:
    text, truncated = _bounded(value, limit)
    redacted = sensitive or _contains_secret(text)
    return ("[REDACTED: credential-like material]" if redacted else text,
            redacted, truncated)


def _public_value(value: Any, pointer: str = "") -> tuple[Any, bool, bool]:
    sensitive = _sensitive_pointer(pointer)
    if sensitive:
        if type(value) in {list, dict, tuple}:
            if value:
                return "[REDACTED: credential-like material]", True, False
        elif value not in (None, "", False, 0, "[REDACTED]", "<redacted>"):
            return "[REDACTED: credential-like material]", True, False
    if value is None or isinstance(value, bool):
        return value, False, False
    if isinstance(value, int) and not isinstance(value, bool):
        return value, False, False
    if isinstance(value, float):
        return (value if math.isfinite(value) else "[non-finite]"), False, False
    if isinstance(value, str):
        return _safe_text(value, sensitive=sensitive, limit=MAX_PREVIEW_CHARS)
    if isinstance(value, (list, tuple)):
        return "collection[%d]" % len(value), False, False
    if isinstance(value, dict):
        return "object[%d]" % len(value), False, False
    return "[unsupported value]", False, False


def _assert_json_tree(value: Any) -> None:
    seen: set[int] = set()
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_INPUT_NODES:
            raise TruthGuardError("structured input exceeds node limit")
        if depth > MAX_DEPTH:
            raise TruthGuardError("structured input exceeds nesting limit")
        if item is None or isinstance(item, (str, bool, int)):
            return
        if isinstance(item, float):
            if not math.isfinite(item):
                raise TruthGuardError("non-finite numbers are not valid evidence")
            return
        if type(item) not in {dict, list, tuple}:
            raise TruthGuardError("input must contain only JSON-shaped values")
        marker = id(item)
        if marker in seen:
            raise TruthGuardError("cyclic structured input is not supported")
        seen.add(marker)
        if type(item) is dict:
            for key in sorted(item):
                if not isinstance(key, str):
                    raise TruthGuardError("object keys must be strings")
                visit(item[key], depth + 1)
        else:
            for child in item:
                visit(child, depth + 1)
        seen.remove(marker)

    visit(value, 0)


def _pointer_escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _pointer_unescape(value: str) -> str:
    return value.replace("~1", "/").replace("~0", "~")


def _pointer(value: str) -> str:
    raw = str(value or "").strip()
    if raw in {"", "$"}:
        return ""
    if raw.startswith("$."):
        raw = raw[2:]
    if raw.startswith("/"):
        parts = raw[1:].split("/") if len(raw) > 1 else []
        # Reject malformed JSON Pointer escapes instead of guessing.
        if any(re.search(r"~(?![01])", part) for part in parts):
            raise TruthGuardError("invalid JSON pointer escape")
        return "/" + "/".join(parts) if parts else ""
    if any(part == "" for part in raw.split(".")):
        raise TruthGuardError("invalid dotted evidence path")
    return "/" + "/".join(_pointer_escape(part) for part in raw.split("."))


def _get(value: Any, pointer: str) -> tuple[Any, bool]:
    current = value
    if not pointer:
        return current, True
    for encoded in pointer[1:].split("/"):
        part = _pointer_unescape(encoded)
        if type(current) is dict and part in current:
            current = current[part]
        elif type(current) in {list, tuple} and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return None, False
    return current, True


def _normalize_path(raw: Any, root: Path | None = None) -> str:
    text = str(raw or "").replace("\\", "/").strip()
    if not text:
        return ""
    candidate = Path(text)
    if root is not None:
        workspace_normalized = None
        try:
            resolved = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
            workspace_normalized = resolved.relative_to(root).as_posix()
        except (OSError, ValueError):
            # Fall through to a bounded display-only path.  No failed
            # containment check is treated as workspace evidence.
            workspace_normalized = None
        if workspace_normalized is not None:
            return ("[REDACTED-PATH]" if _contains_secret(workspace_normalized)
                    else workspace_normalized)
    parts = [part for part in PurePosixPath(text).parts if part not in {"", ".", "/"}]
    normalized = "/".join(parts[-8:])[:1_024]
    return "[REDACTED-PATH]" if _contains_secret(normalized) else normalized


@dataclass
class _Evidence:
    id: str
    kind: str
    pointer: str
    raw: Any
    public: Any
    redacted: bool = False
    truncated: bool = False

    def row(self) -> dict[str, Any]:
        pointer, pointer_redacted, _ = _safe_text(self.pointer, limit=1_024)
        return {"id": self.id, "kind": self.kind, "pointer": pointer,
                "value": self.public, "redacted": self.redacted,
                "truncated": self.truncated, "pointer_redacted": pointer_redacted}


class EvidenceIndex:
    """Bounded index over a JSON report plus optional workspace metadata."""

    def __init__(self, report: dict[str, Any], root: str | os.PathLike[str] | None = None):
        self.report = report
        self.root = Path(root).expanduser().resolve() if root is not None else None
        self.entries: dict[str, _Evidence] = {}
        self.by_pointer: dict[str, str] = {}
        self.findings: list[dict[str, Any]] = []
        self.improvements: list[dict[str, Any]] = []
        self.artifacts: list[dict[str, Any]] = []
        self.input_truncated = False
        self._walk(report, "", 0)
        self._collect_semantic_rows(report)

    def _add(self, kind: str, pointer: str, raw: Any, public: Any = _MISSING,
             *, redacted: bool = False, truncated: bool = False,
             identity: Any | None = None) -> str:
        if pointer in self.by_pointer:
            return self.by_pointer[pointer]
        if len(self.entries) >= MAX_EVIDENCE:
            self.input_truncated = True
            return ""
        identifier = "ev-" + _digest({"kind": kind, "pointer": pointer,
                                      "identity": identity if identity is not None else pointer})[:20]
        if public is _MISSING:
            public, redacted, truncated = _public_value(raw, pointer)
        self.entries[identifier] = _Evidence(
            identifier, kind, pointer, raw, public, redacted, truncated)
        self.by_pointer[pointer] = identifier
        return identifier

    def _walk(self, value: Any, pointer: str, depth: int) -> None:
        if len(self.entries) >= MAX_EVIDENCE or depth > MAX_DEPTH:
            self.input_truncated = True
            return
        self._add("json", pointer, value)
        if type(value) is dict:
            for key in sorted(value):
                self._walk(value[key], pointer + "/" + _pointer_escape(key), depth + 1)
        elif type(value) in {list, tuple}:
            for index, child in enumerate(value):
                self._walk(child, pointer + "/" + str(index), depth + 1)

    def _collect_semantic_rows(self, value: Any, pointer: str = "") -> None:
        if type(value) is dict:
            rule = value.get("rule", value.get("rule_id", value.get("ruleId")))
            if isinstance(rule, str) and rule:
                try:
                    line = max(1, int(value.get("line", 1)))
                except (TypeError, ValueError):
                    line = 1
                self.findings.append({
                    "rule": rule[:512], "path": _normalize_path(value.get("path", ""), self.root),
                    "line": line, "pointer": pointer,
                    "fingerprint": str(value.get("fingerprint", ""))[:128],
                })
            for key in sorted(value):
                self._collect_semantic_rows(value[key], pointer + "/" + _pointer_escape(key))
        elif type(value) in {list, tuple}:
            for index, child in enumerate(value):
                self._collect_semantic_rows(child, pointer + "/" + str(index))
        if pointer == "/improvements" and type(value) in {list, tuple}:
            self.improvements = [item for item in value if type(item) is dict]
        if pointer in {"/artifacts", "/model_artifacts"} and type(value) in {list, tuple}:
            self.artifacts.extend(item for item in value if type(item) is dict)

    def json_ref(self, pointer: str) -> tuple[str, Any, bool]:
        normalized = _pointer(pointer)
        raw, exists = _get(self.report, normalized)
        if not exists:
            return "", None, False
        identifier = self.by_pointer.get(normalized) or self._add("json", normalized, raw)
        return identifier, raw, True

    def synthetic(self, kind: str, identity: Any, public: Any, raw: Any = None) -> str:
        pointer = "/@" + kind + "/" + _digest(identity)[:20]
        return self._add(kind, pointer, raw, public, identity=identity)

    def finding_matches(self, rule: str, path: str = "", line: int | None = None) -> list[dict[str, Any]]:
        normalized = _normalize_path(path, self.root) if path else ""
        rows = [row for row in self.findings if row["rule"] == rule
                and (not normalized or row["path"] == normalized)
                and (line is None or row["line"] == line)]
        unique = {(row["rule"], row["path"], row["line"]): row for row in rows}
        return [unique[key] for key in sorted(unique)]

    def finding_ref(self, row: Mapping[str, Any]) -> str:
        identity = {key: row.get(key) for key in ("rule", "path", "line")}
        public = dict(identity)
        return self.synthetic("finding", identity, public, raw=identity)

    def check_file(self, raw_path: Any, line: int | None = None) -> dict[str, Any]:
        display = _normalize_path(raw_path, self.root)
        result = {"path": display, "state": "unknown", "exists": None,
                  "line": line, "line_exists": None, "reason": "workspace root was not supplied"}
        if self.root is None:
            result["ref"] = self.synthetic("file", {"path": display, "line": line}, result)
            return result
        text = str(raw_path or "")
        lexical = Path(text)
        lexical = lexical if lexical.is_absolute() else self.root / lexical
        try:
            resolved = lexical.resolve()
            resolved.relative_to(self.root)
        except (OSError, ValueError):
            result["reason"] = "path escapes the supplied workspace root"
            result["ref"] = self.synthetic("file", {"path": display, "line": line}, result)
            return result
        cursor = self.root
        try:
            relative_parts = lexical.absolute().relative_to(self.root).parts
        except ValueError:
            relative_parts = ()
        for part in relative_parts:
            cursor = cursor / part
            if cursor.is_symlink():
                result["reason"] = "symbolic-link paths are not followed"
                result["ref"] = self.synthetic("file", {"path": display, "line": line}, result)
                return result
        if not resolved.exists():
            result.update(state="observed", exists=False, reason="path does not exist in workspace")
        elif not resolved.is_file():
            result.update(state="observed", exists=False, reason="path exists but is not a regular file")
        else:
            try:
                size = resolved.stat().st_size
                if size > MAX_FILE_BYTES:
                    result["reason"] = "file exceeds bounded line-validation limit"
                else:
                    data = resolved.read_bytes()
                    lines = 0 if not data else data.count(b"\n") + (0 if data.endswith(b"\n") else 1)
                    line_exists = None if line is None else 1 <= line <= lines
                    result.update(state="observed", exists=True, line_exists=line_exists,
                                  lines=lines, reason="regular workspace file was observed")
            except OSError:
                result["reason"] = "file metadata could not be read"
        result["ref"] = self.synthetic("file", {"path": display, "line": line}, result)
        return result


def _numeric_checks(index: EvidenceIndex) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    specifications: list[tuple[str, str, Any]] = [
        ("/summary/findings", "/findings", lambda value: len(value) if type(value) in {list, tuple} else _MISSING),
        ("/summary/attack_paths", "/attack_paths", lambda value: len(value) if type(value) in {list, tuple} else _MISSING),
        ("/summary/dependencies", "/supply_chain/inventory/dependencies",
         lambda value: len(value) if type(value) in {list, tuple} else _MISSING),
        ("/summary/component_errors", "/errors", lambda value: len(value) if type(value) in {list, tuple} else _MISSING),
        ("/summary/verified_improvements", "/improvements",
         lambda value: sum(type(item) is dict and item.get("accepted") is True for item in value)
         if type(value) in {list, tuple} else _MISSING),
        ("/summary/refused_improvements", "/improvements",
         lambda value: sum(type(item) is dict and item.get("accepted") is not True for item in value)
         if type(value) in {list, tuple} else _MISSING),
        ("/semantic/metrics/semantic_findings", "/semantic/findings",
         lambda value: len(value) if type(value) in {list, tuple} else _MISSING),
        ("/semantic/metrics/files_discovered", "/semantic/files",
         lambda value: len(value) if type(value) in {list, tuple} else _MISSING),
    ]
    checks: list[dict[str, Any]] = []
    lookup: dict[str, dict[str, Any]] = {}
    for reported_path, source_path, derive in specifications:
        reported_ref, reported, reported_exists = index.json_ref(reported_path)
        source_ref, source, source_exists = index.json_ref(source_path)
        if not reported_exists and not source_exists:
            continue
        derived = derive(source) if source_exists else _MISSING
        state = "unknown"
        if reported_exists and derived is not _MISSING:
            state = "consistent" if type(reported) is int and not isinstance(reported, bool) \
                and reported >= 0 and reported == derived else "contradiction"
        identity = {"reported": reported_path, "source": source_path}
        derived_ref = index.synthetic("derived-count", identity, derived if derived is not _MISSING else "unknown", derived)
        row = {
            "id": "num-" + _digest(identity)[:20], "reported_path": reported_path,
            "derived_from": source_path, "reported": reported if reported_exists else "unknown",
            "derived": derived if derived is not _MISSING else "unknown", "state": state,
            "evidence_refs": sorted(filter(None, (reported_ref, source_ref, derived_ref))),
        }
        checks.append(row); lookup[reported_path] = row

    findings = index.report.get("findings")
    severity = _get(index.report, "/summary/severity")
    if type(findings) in {list, tuple} and severity[1] and type(severity[0]) is dict:
        for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            pointer = "/summary/severity/" + name
            ref, reported, exists = index.json_ref(pointer)
            derived = sum(type(item) is dict and str(item.get("severity", "")).upper() == name
                          for item in findings)
            if not exists and not derived:
                continue
            dref = index.synthetic("derived-count", {"severity": name}, derived, derived)
            state = "consistent" if exists and type(reported) is int and reported == derived else "contradiction"
            row = {"id": "num-" + _digest({"severity": name})[:20], "reported_path": pointer,
                   "derived_from": "/findings[*].severity", "reported": reported if exists else "unknown",
                   "derived": derived, "state": state,
                   "evidence_refs": sorted(filter(None, (ref, dref)))}
            checks.append(row); lookup[pointer] = row
    return sorted(checks, key=lambda row: row["id"]), lookup


def _tree_has_secret(value: Any, pointer: str = "", budget: list[int] | None = None) -> bool:
    remaining = budget if budget is not None else [MAX_INPUT_NODES]
    if remaining[0] <= 0:
        return True
    remaining[0] -= 1
    if _sensitive_pointer(pointer):
        if type(value) in {list, dict, tuple}:
            if value:
                return True
        elif value not in (None, "", False, 0, "[REDACTED]", "<redacted>"):
            return True
    if isinstance(value, str):
        if value.lower() in {"[redacted]", "<redacted>", "[redacted: credential-like material]"}:
            return False
        return _sensitive_pointer(pointer) or _contains_secret(value)
    if type(value) is dict:
        return any(_contains_secret(key) or
                   _tree_has_secret(value[key], pointer + "/" + _pointer_escape(key), remaining)
                   for key in sorted(value))
    if type(value) in {list, tuple}:
        return any(_tree_has_secret(child, pointer + "/" + str(index), remaining)
                   for index, child in enumerate(value))
    return False


def _report_integrity(index: EvidenceIndex) -> dict[str, Any]:
    claimed = index.report.get("report_sha256")
    ref, _, exists = index.json_ref("/report_sha256")
    row = {"state": "unknown", "claimed": "", "computed": "",
           "evidence_refs": [ref] if ref else [],
           "reason": "report did not provide an integrity digest"}
    if not exists:
        return row
    if not isinstance(claimed, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", claimed):
        row.update(state="mismatch", claimed="[invalid digest]",
                   reason="report_sha256 is not a SHA-256 hexadecimal digest")
        return row
    row["claimed"] = claimed.lower()
    payload = {key: value for key, value in index.report.items()
               if key != "report_sha256" and not key.startswith("_")}
    if _tree_has_secret(payload):
        row["reason"] = "integrity was not recomputed because evidence contains unredacted secret-like material"
        return row
    computed = hashlib.sha256(_canonical(payload)).hexdigest()
    row["computed"] = computed
    row["state"] = "verified" if computed == claimed.lower() else "mismatch"
    row["reason"] = ("report digest matches canonical structured evidence" if row["state"] == "verified"
                     else "report digest does not match canonical structured evidence")
    cref = index.synthetic("computed-digest", {"report": "canonical"}, computed, computed)
    row["evidence_refs"] = sorted(filter(None, (ref, cref)))
    return row


def _probe_passed(probe: Any) -> bool:
    if type(probe) is not dict:
        return False
    if isinstance(probe.get("passed"), bool):
        return bool(probe["passed"])
    return str(probe.get("status", "")).lower() in _PASS


def _probe_skip_is_safe(row: Mapping[str, Any], probe: Mapping[str, Any]) -> bool:
    """Allow only the one skip that avoids retaining a credential for mutation.

    A skipped assurance probe is normally missing proof.  Secret-removal edits
    are different: reversing the edit would require reconstructing and retaining
    the credential that the pipeline deliberately discarded.  The exception is
    therefore bound to the edit and rescan evidence, not merely to prose in the
    probe's detail field.
    """
    if str(probe.get("status", "")).lower() != "skipped":
        return False
    if str(probe.get("name", "")).lower() != "mutation:reverse-fix":
        return False
    if probe.get("cases") != 0:
        return False
    edits = row.get("edits")
    verification = row.get("verification")
    if type(edits) not in {list, tuple} or type(verification) is not dict:
        return False
    substantive = [edit for edit in edits
                   if type(edit) is dict and str(edit.get("rule", "")).lower() != "import"]
    if not substantive or not all(
            str(edit.get("kind", "")).lower() == "externalize-secret"
            and str(edit.get("rule", "")).lower() == "hardcoded-secret"
            and edit.get("mutation_before") in (None, "")
            for edit in substantive):
        return False
    resolved = verification.get("resolved_findings")
    return (type(resolved) in {list, tuple} and bool(resolved)
            and all(type(item) is dict
                    and str(item.get("rule", "")).lower() == "hardcoded-secret"
                    for item in resolved))


def _improvement_evidence(row: Mapping[str, Any]) -> tuple[str, list[str]]:
    reasons: list[str] = []
    accepted = row.get("accepted") is True
    if not accepted:
        return "refused", reasons
    if str(row.get("status", "")).lower() != "verified":
        reasons.append("accepted improvement is not labeled verified")
    verification = row.get("verification")
    if type(verification) is not dict or verification.get("accepted") is not True:
        reasons.append("candidate validation acceptance is absent")
    else:
        parser_state = str(verification.get("compiler_or_parser", "")).lower()
        if parser_state not in _PASS:
            reasons.append("parser/compiler verification did not pass")
        if verification.get("new_findings") not in ([], ()):
            reasons.append("candidate introduced new findings")
        if verification.get("new_failures") not in ([], ()):
            reasons.append("candidate introduced new failures")
        before, after = verification.get("findings_before"), verification.get("findings_after")
        if not (type(before) is int and type(after) is int and 0 <= after < before):
            reasons.append("rescan does not prove a finding reduction")
        if row.get("complete") is True and after != 0:
            reasons.append("complete improvement label contradicts remaining findings")
    remaining = row.get("remaining_count")
    if row.get("complete") is True and remaining not in (None, 0):
        reasons.append("complete improvement label contradicts remaining_count")
    if row.get("complete") is True and row.get("refusals"):
        reasons.append("complete improvement label contradicts recorded refusals")
    probes = row.get("probes")
    if (type(probes) not in {list, tuple} or not probes
            or not all(_probe_passed(item)
                       or (type(item) is dict and _probe_skip_is_safe(row, item))
                       for item in probes)):
        reasons.append("required deterministic assurance probes are absent or failed")
    improved = row.get("improved_source")
    withheld = row.get("improved_source_withheld") is True
    if not (isinstance(improved, str) and improved) and not withheld:
        reasons.append("no verified improved source or explicit safety withholding is present")
    if isinstance(improved, str) and improved and _contains_secret(improved):
        reasons.append("presented improved source contains credential-like material")
    if reasons:
        return "invalid", reasons
    if type(row.get("apply")) is dict and row["apply"].get("applied") is True:
        return "applied", reasons
    if isinstance(improved, str) and improved:
        return "available", reasons
    return "verified", reasons


def _artifact_evidence(row: Mapping[str, Any]) -> tuple[str, list[str]]:
    reasons: list[str] = []
    declared = str(row.get("evidence_level", row.get("status", "asserted"))).lower()
    verification = row.get("verification")
    checks = verification.get("checks", []) if type(verification) is dict else []
    passed = (type(verification) is dict and verification.get("passed") is True
              and type(checks) in {list, tuple} and bool(checks)
              and all(_probe_passed(item) for item in checks))
    if declared == "verified" and not passed:
        reasons.append("artifact claims verification without passing structured checks")
        return "invalid", reasons
    if passed:
        return "verified", reasons
    if row.get("observed") is True or row.get("path") or row.get("sha256"):
        return "observed", reasons
    return "asserted", reasons


def _coverage_states(index: EvidenceIndex) -> dict[str, dict[str, Any]]:
    states: dict[str, dict[str, Any]] = {}
    files_scanned = _get(index.report, "/workspace/files_scanned")
    files_discovered = _get(index.report, "/workspace/files_discovered")
    skipped = _get(index.report, "/workspace/skipped")
    errors = _get(index.report, "/workspace/errors")
    if files_scanned[1] or files_discovered[1]:
        scanned = files_scanned[0] if type(files_scanned[0]) is int else 0
        discovered = files_discovered[0] if type(files_discovered[0]) is int else scanned
        skip_count = len(skipped[0]) if skipped[1] and type(skipped[0]) in {list, tuple} else 0
        error_count = len(errors[0]) if errors[1] and type(errors[0]) in {list, tuple} else 0
        state = ("empty" if discovered == 0 else "complete"
                 if scanned == discovered and not skip_count and not error_count else "partial")
        states["scan"] = {"state": state, "files_discovered": discovered,
                          "files_scanned": scanned, "skipped": skip_count, "errors": error_count}
    else:
        states["scan"] = {"state": "unknown", "reason": "workspace coverage was not supplied"}

    advisory, exists = _get(index.report, "/supply_chain/advisory_assessment")
    if exists and type(advisory) is dict:
        verification = advisory.get("verification") if type(advisory.get("verification")) is dict else {}
        raw_state = str(advisory.get("state", "unknown")).lower()
        if raw_state == "unavailable":
            state = "unavailable"
        elif raw_state == "invalid" or not verification.get("valid", False):
            state = "invalid"
        elif not verification.get("authenticated", False):
            state = "unauthenticated"
        elif raw_state in {"stale", "expired"}:
            state = "stale"
        else:
            state = "authenticated-offline"
        states["advisory"] = {"state": state, "live": advisory.get("live_status") is True,
                              "affected": advisory.get("affected", "unknown")}
    else:
        states["advisory"] = {"state": "not-run", "live": False,
                              "reason": "advisory assessment was not supplied"}
    return states


def _evidence_audit(index: EvidenceIndex, numeric: Sequence[Mapping[str, Any]],
                    integrity: Mapping[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    contradictions: list[dict[str, Any]] = []
    for check in numeric:
        if check["state"] == "contradiction":
            contradictions.append({
                "id": "ctr-" + _digest({"numeric": check["id"]})[:20],
                "kind": "numeric-inconsistency", "claim_ids": [],
                "message": "reported numeric value conflicts with derived structured evidence",
                "evidence_refs": list(check["evidence_refs"]),
            })
    if integrity.get("state") == "mismatch":
        contradictions.append({
            "id": "ctr-" + _digest({"integrity": "mismatch"})[:20],
            "kind": "report-integrity", "claim_ids": [],
            "message": "report integrity digest is invalid",
            "evidence_refs": list(integrity.get("evidence_refs", [])),
        })
    findings = index.report.get("findings")
    status = str(index.report.get("status", "")).lower()
    if status == "clean" and type(findings) in {list, tuple} and findings:
        sref, _, _ = index.json_ref("/status"); fref, _, _ = index.json_ref("/findings")
        contradictions.append({
            "id": "ctr-" + _digest({"status": "clean-with-findings"})[:20],
            "kind": "status-inconsistency", "claim_ids": [],
            "message": "clean status conflicts with non-empty findings",
            "evidence_refs": sorted(filter(None, (sref, fref))),
        })
    improvement_audit = []
    for index_number, row in enumerate(index.improvements):
        level, reasons = _improvement_evidence(row)
        target = _normalize_path(row.get("target", ""), index.root)
        ref = index.synthetic("improvement", {"target": target, "index": index_number},
                              {"target": target, "evidence_level": level})
        improvement_audit.append({"target": target, "evidence_level": level,
                                  "reasons": reasons, "evidence_ref": ref})
        if level == "invalid":
            contradictions.append({
                "id": "ctr-" + _digest({"improvement": target, "index": index_number})[:20],
                "kind": "forged-improvement", "claim_ids": [],
                "message": "accepted/verified improvement lacks required verification evidence",
                "evidence_refs": [ref],
            })
    artifact_audit = []
    for index_number, row in enumerate(index.artifacts):
        artifact_id = str(row.get("id", row.get("name", "artifact-%d" % index_number)))[:256]
        level, reasons = _artifact_evidence(row)
        ref = index.synthetic("artifact", {"id": artifact_id, "index": index_number},
                              {"id": artifact_id, "evidence_level": level})
        artifact_audit.append({"id": artifact_id, "evidence_level": level,
                               "reasons": reasons, "evidence_ref": ref})
        if level == "invalid":
            contradictions.append({
                "id": "ctr-" + _digest({"artifact": artifact_id, "index": index_number})[:20],
                "kind": "artifact-evidence", "claim_ids": [],
                "message": "artifact verification label lacks passing checks",
                "evidence_refs": [ref],
            })
    audit = {"coverage": _coverage_states(index), "improvements": improvement_audit,
             "model_artifacts": artifact_audit}
    return sorted(contradictions, key=lambda row: row["id"]), audit


def _comparison(actual: Any, expected: Any, operator: str) -> bool | None:
    if operator == "eq":
        return type(actual) is type(expected) and actual == expected
    if operator == "ne":
        return not (type(actual) is type(expected) and actual == expected)
    if operator in {"gt", "gte", "lt", "lte"}:
        if (type(actual) not in {int, float} or type(expected) not in {int, float}
                or not math.isfinite(float(actual)) or not math.isfinite(float(expected))):
            return None
        return {"gt": actual > expected, "gte": actual >= expected,
                "lt": actual < expected, "lte": actual <= expected}[operator]
    if operator == "contains":
        if isinstance(actual, str) and isinstance(expected, str):
            return expected in actual
        if type(actual) in {list, tuple, dict}:
            return expected in actual
        return None
    return None


def _predicate_identity(raw: Mapping[str, Any], kind: str) -> dict[str, Any]:
    pointer = _pointer(str(raw.get("evidence_path", raw.get("collection_path", "")))) \
        if raw.get("evidence_path", raw.get("collection_path")) else ""
    expected = raw.get("expected", raw.get("value", _MISSING))
    sensitive = _sensitive_pointer(pointer) or (isinstance(expected, str) and _contains_secret(expected))
    safe_expected: Any = "<redacted>" if sensitive else expected
    if safe_expected is _MISSING:
        safe_expected = "<missing>"
    if type(safe_expected) not in {str, bool, int, float, type(None)}:
        safe_expected = "<structured>"
    return {
        "kind": kind, "pointer": pointer, "operator": str(raw.get("operator", "eq")).lower(),
        "expected": safe_expected, "path": _normalize_path(raw.get("path", raw.get("target", ""))),
        "line": raw.get("line"), "rule": str(raw.get("rule", ""))[:512],
        "scope": str(raw.get("scope", ""))[:128],
        "artifact_id": str(raw.get("artifact_id", raw.get("id", "")))[:256],
    }


def _claim_id(raw: Mapping[str, Any], kind: str, text: str) -> tuple[str, dict[str, Any]]:
    predicate = _predicate_identity(raw, kind)
    meaningful = any(value not in {"", None, "<missing>"} for key, value in predicate.items()
                     if key != "kind")
    identity = predicate if meaningful else {"kind": kind, "text": text}
    return "clm-" + _digest(identity)[:20], predicate


def _verdict(claim_id: str, kind: str, text: str, state: str, reason: str,
             refs: Sequence[str], predicate: Mapping[str, Any], *,
             input_id: str = "") -> dict[str, Any]:
    if state not in STATES:
        raise TruthGuardError("internal claim state is invalid")
    accepted = state in {"observed", "derived"}
    abstention = "" if accepted else "I cannot substantiate this claim from the supplied evidence."
    return {
        "id": claim_id, "input_id": input_id, "kind": kind, "state": state,
        "accepted": accepted, "claim_text": text,
        "safe_text": text if accepted else abstention, "reason": reason,
        "evidence_refs": sorted(set(filter(None, refs))),
        "predicate": dict(predicate), "abstention": abstention,
    }


def _evaluate_claim(raw: Mapping[str, Any], index: EvidenceIndex,
                    numeric_lookup: Mapping[str, Mapping[str, Any]],
                    audit: Mapping[str, Any]) -> dict[str, Any]:
    kind = str(raw.get("kind", "value" if raw.get("evidence_path") else "statement")).lower()
    if kind not in SUPPORTED_KINDS:
        kind = "statement"
    text, _, _ = _safe_text(raw.get("text", "Structured claim"), limit=MAX_TEXT_CHARS)
    claim_id, predicate = _claim_id(raw, kind, text)
    input_id, _, _ = _safe_text(raw.get("id", ""), limit=128)
    refs: list[str] = []

    if _ABSOLUTE_SAFETY.search(text) and not _QUALIFIED_ABSENCE.search(text):
        return _verdict(claim_id, kind, text, "unknown",
                        "bounded static evidence cannot prove absolute absence of defects or risk",
                        refs, predicate, input_id=input_id)

    if kind in {"value", "statement"} and raw.get("evidence_path"):
        try:
            pointer = _pointer(str(raw["evidence_path"]))
        except TruthGuardError:
            return _verdict(claim_id, kind, text, "unknown", "evidence path is invalid",
                            refs, predicate, input_id=input_id)
        ref, actual, exists = index.json_ref(pointer); refs.append(ref)
        operator = str(raw.get("operator", "eq")).lower()
        if operator == "exists":
            state, reason = ("observed", "evidence path exists") if exists else \
                ("refuted", "evidence path does not exist")
            return _verdict(claim_id, kind, text, state, reason, refs, predicate, input_id=input_id)
        if operator == "not_exists":
            state, reason = ("refuted", "evidence path exists") if exists else \
                ("observed", "evidence path is absent")
            return _verdict(claim_id, kind, text, state, reason, refs, predicate, input_id=input_id)
        if not exists:
            return _verdict(claim_id, kind, text, "unknown", "evidence path is absent",
                            refs, predicate, input_id=input_id)
        if "expected" not in raw and "value" not in raw:
            return _verdict(claim_id, kind, text, "unknown", "claim has no expected value",
                            refs, predicate, input_id=input_id)
        expected = raw.get("expected", raw.get("value"))
        if (pointer == "/status" and str(expected).lower() == "clean"
                and type(index.report.get("findings")) in {list, tuple}
                and bool(index.report.get("findings"))):
            findings_ref, _, _ = index.json_ref("/findings"); refs.append(findings_ref)
            return _verdict(claim_id, kind, text, "refuted",
                            "clean status conflicts with non-empty findings",
                            refs, predicate, input_id=input_id)
        numeric = numeric_lookup.get(pointer)
        comparison_source = actual
        state_on_match = "observed"
        if numeric and numeric.get("state") == "contradiction" and numeric.get("derived") != "unknown":
            comparison_source = numeric["derived"]
            refs.extend(numeric.get("evidence_refs", [])); state_on_match = "derived"
        matched = _comparison(comparison_source, expected, operator)
        if matched is None:
            return _verdict(claim_id, kind, text, "unknown", "operator cannot compare these value types",
                            refs, predicate, input_id=input_id)
        return _verdict(
            claim_id, kind, text, state_on_match if matched else "refuted",
            "claim matches %s evidence" % ("derived" if state_on_match == "derived" else "observed")
            if matched else "claim conflicts with structured evidence",
            refs, predicate, input_id=input_id)

    if kind == "count":
        raw_pointer = raw.get("collection_path", raw.get("evidence_path", ""))
        if not raw_pointer or "expected" not in raw:
            return _verdict(claim_id, kind, text, "unknown",
                            "count claim requires collection_path and expected", refs, predicate,
                            input_id=input_id)
        pointer = _pointer(str(raw_pointer))
        ref, collection, exists = index.json_ref(pointer); refs.append(ref)
        if not exists or type(collection) not in {list, tuple, dict}:
            return _verdict(claim_id, kind, text, "unknown", "count source is absent or not a collection",
                            refs, predicate, input_id=input_id)
        expected = raw["expected"]
        if type(expected) is not int or isinstance(expected, bool) or expected < 0:
            return _verdict(claim_id, kind, text, "unknown", "expected count must be a non-negative integer",
                            refs, predicate, input_id=input_id)
        derived = len(collection)
        dref = index.synthetic("derived-count", {"pointer": pointer}, derived, derived); refs.append(dref)
        return _verdict(claim_id, kind, text, "derived" if derived == expected else "refuted",
                        "collection length confirms claim" if derived == expected
                        else "collection length contradicts claim", refs, predicate, input_id=input_id)

    if kind == "file":
        if not raw.get("path"):
            return _verdict(claim_id, kind, text, "unknown", "file claim has no path", refs,
                            predicate, input_id=input_id)
        try:
            line = int(raw["line"]) if raw.get("line") is not None else None
        except (TypeError, ValueError):
            line = -1
        check = index.check_file(raw["path"], line); refs.append(check["ref"])
        operator = str(raw.get("operator", "exists")).lower()
        if check["state"] != "observed":
            return _verdict(claim_id, kind, text, "unknown", check["reason"], refs, predicate,
                            input_id=input_id)
        if operator == "not_exists":
            matched = check["exists"] is False
        else:
            matched = check["exists"] is True and (line is None or check["line_exists"] is True)
        return _verdict(claim_id, kind, text, "observed" if matched else "refuted",
                        "workspace location exists" if matched else "workspace location does not match claim",
                        refs, predicate, input_id=input_id)

    if kind in {"finding", "rule"}:
        rule = str(raw.get("rule", ""))
        if not rule:
            return _verdict(claim_id, kind, text, "unknown", "rule identifier is required",
                            refs, predicate, input_id=input_id)
        line = None
        if raw.get("line") is not None:
            try:
                line = max(1, int(raw["line"]))
            except (TypeError, ValueError):
                return _verdict(claim_id, kind, text, "unknown", "finding line is invalid",
                                refs, predicate, input_id=input_id)
        path = str(raw.get("path", "")) if kind == "finding" else ""
        matches = index.finding_matches(rule, path, line)
        refs.extend(index.finding_ref(row) for row in matches)
        if not matches:
            return _verdict(claim_id, kind, text, "refuted",
                            "rule/location is not present in supplied finding evidence",
                            refs, predicate, input_id=input_id)
        if kind == "finding" and path and index.root is not None:
            location = index.check_file(path, line); refs.append(location["ref"])
            if location["state"] != "observed":
                return _verdict(claim_id, kind, text, "unknown", location["reason"], refs,
                                predicate, input_id=input_id)
            if not location["exists"] or (line is not None and not location["line_exists"]):
                return _verdict(claim_id, kind, text, "refuted",
                                "reported finding location does not exist", refs, predicate,
                                input_id=input_id)
        return _verdict(claim_id, kind, text, "observed",
                        "rule/location exists in structured finding evidence", refs, predicate,
                        input_id=input_id)

    if kind == "improvement":
        target = _normalize_path(raw.get("target", raw.get("path", "")), index.root)
        desired = str(raw.get("expected", "verified")).lower()
        rows = [item for item in audit.get("improvements", [])
                if not target or item.get("target") == target]
        refs.extend(item.get("evidence_ref", "") for item in rows)
        if not rows:
            return _verdict(claim_id, kind, text, "refuted", "improvement evidence does not exist",
                            refs, predicate, input_id=input_id)
        levels = {item["evidence_level"] for item in rows}
        supported = (desired == "refused" and "refused" in levels) or (
            desired == "verified" and bool(levels & {"verified", "available", "applied"})) or (
            desired == "available" and bool(levels & {"available", "applied"})) or (
            desired == "applied" and "applied" in levels)
        return _verdict(claim_id, kind, text, "derived" if supported else "refuted",
                        "verification evidence supports improvement state" if supported
                        else "improvement label is unsupported or contradicted", refs, predicate,
                        input_id=input_id)

    if kind == "coverage":
        scope = str(raw.get("scope", "scan")).lower()
        desired = str(raw.get("expected", raw.get("state", "complete"))).lower()
        coverage = audit.get("coverage", {}).get(scope)
        if not coverage:
            return _verdict(claim_id, kind, text, "unknown", "coverage scope was not supplied",
                            refs, predicate, input_id=input_id)
        ref = index.synthetic("coverage", {"scope": scope}, coverage, coverage); refs.append(ref)
        actual = str(coverage.get("state", "unknown"))
        if desired in {"clean", "safe", "no-vulnerabilities"}:
            return _verdict(claim_id, kind, text, "unknown",
                            "coverage evidence cannot prove absence of vulnerabilities", refs,
                            predicate, input_id=input_id)
        if scope == "advisory" and desired == "live":
            matched = coverage.get("live") is True
        elif scope == "advisory" and desired == "authenticated":
            matched = actual == "authenticated-offline"
        elif scope == "advisory" and desired == "no-known-match":
            matched = actual == "authenticated-offline" and coverage.get("affected") == 0
        else:
            matched = actual == desired
        return _verdict(claim_id, kind, text, "derived" if matched else
                        ("unknown" if actual in {"unknown", "not-run", "unavailable"} else "refuted"),
                        "coverage evidence supports claim" if matched
                        else "coverage is incomplete, unavailable, or contradicts claim",
                        refs, predicate, input_id=input_id)

    if kind == "artifact":
        artifact_id = str(raw.get("artifact_id", raw.get("id", "")))
        desired = str(raw.get("expected", "verified")).lower()
        rows = [item for item in audit.get("model_artifacts", []) if item.get("id") == artifact_id]
        refs.extend(item.get("evidence_ref", "") for item in rows)
        if not rows:
            return _verdict(claim_id, kind, text, "unknown", "model artifact evidence is absent",
                            refs, predicate, input_id=input_id)
        hierarchy = {"asserted": 1, "observed": 2, "verified": 3, "invalid": 0}
        actual = max((item["evidence_level"] for item in rows), key=lambda item: hierarchy.get(item, 0))
        matched = hierarchy.get(actual, 0) >= hierarchy.get(desired, 99)
        return _verdict(claim_id, kind, text, "derived" if matched else "refuted",
                        "artifact evidence level meets claim" if matched
                        else "artifact evidence level is weaker than claimed", refs, predicate,
                        input_id=input_id)

    return _verdict(claim_id, kind, text, "unknown",
                    "free-form statement has no machine-verifiable predicate",
                    refs, predicate, input_id=input_id)


def _claim_contradictions(claims: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[Mapping[str, Any]]] = {}
    for claim in claims:
        predicate = claim.get("predicate", {})
        subject = json.dumps({key: predicate.get(key) for key in
                              ("kind", "pointer", "path", "line", "rule", "scope", "artifact_id")},
                             sort_keys=True, default=str)
        groups.setdefault(subject, []).append(claim)
    contradictions = []
    for subject, rows in sorted(groups.items()):
        for index, left in enumerate(rows):
            lp = left.get("predicate", {}); lop = lp.get("operator"); lexp = lp.get("expected")
            for right in rows[index + 1:]:
                rp = right.get("predicate", {}); rop = rp.get("operator"); rexp = rp.get("expected")
                conflict = ((lop == rop == "eq" and lexp != rexp)
                            or ({lop, rop} == {"exists", "not_exists"})
                            or (lexp == rexp and {lop, rop} == {"eq", "ne"}))
                if conflict:
                    identity = {"subject": subject, "claims": sorted((left["id"], right["id"]))}
                    contradictions.append({
                        "id": "ctr-" + _digest(identity)[:20], "kind": "claim-contradiction",
                        "claim_ids": identity["claims"],
                        "message": "claims make mutually exclusive assertions about the same subject",
                        "evidence_refs": sorted(set(left.get("evidence_refs", [])
                                                    + right.get("evidence_refs", []))),
                    })
    unique = {row["id"]: row for row in contradictions}
    return [unique[key] for key in sorted(unique)]


def _resolve_explicit_refs(raw: Mapping[str, Any], verdict: dict[str, Any],
                           index: EvidenceIndex) -> None:
    refs = raw.get("evidence_refs", [])
    if refs in (None, ""):
        return
    if type(refs) not in {list, tuple} or any(not isinstance(item, str) for item in refs):
        verdict.update(state="unknown", accepted=False,
                       reason="declared evidence references are not a string list",
                       safe_text="I cannot substantiate this claim from the supplied evidence.",
                       abstention="I cannot substantiate this claim from the supplied evidence.")
        return
    missing = []
    for item in refs:
        resolved = ""
        if item.startswith("json:"):
            resolved, _, exists = index.json_ref(item[5:])
            if not exists:
                missing.append(item)
        elif item in index.entries:
            resolved = item
        else:
            missing.append(item)
        if resolved:
            verdict["evidence_refs"].append(resolved)
    verdict["evidence_refs"] = sorted(set(verdict["evidence_refs"]))
    if missing:
        verdict.update(state="unknown", accepted=False,
                       reason="one or more declared evidence references do not exist",
                       safe_text="I cannot substantiate this claim from the supplied evidence.",
                       abstention="I cannot substantiate this claim from the supplied evidence.")


def _auto_claims(text: str) -> list[dict[str, Any]]:
    safe, _, _ = _safe_text(text, limit=MAX_SAFE_RESPONSE_CHARS)
    claims: list[dict[str, Any]] = []
    mappings = {
        "finding": "/summary/findings", "findings": "/summary/findings",
        "file": "/summary/files_scanned", "files": "/summary/files_scanned",
        "dependency": "/summary/dependencies", "dependencies": "/summary/dependencies",
        "attack path": "/summary/attack_paths", "attack paths": "/summary/attack_paths",
        "verified improvement": "/summary/verified_improvements",
        "verified improvements": "/summary/verified_improvements",
        "component error": "/summary/component_errors", "component errors": "/summary/component_errors",
    }
    for match in re.finditer(
            r"(?i)\b(\d{1,9})\s+(findings?|files?|dependencies?|attack paths?|"
            r"verified improvements?|component errors?)\b", safe):
        amount, label = int(match.group(1)), match.group(2).lower()
        claims.append({"kind": "value", "text": match.group(0),
                       "evidence_path": mappings[label], "expected": amount})
    if re.search(r"(?i)\bno findings\b", safe):
        claims.append({"kind": "value", "text": "no findings from enabled evidence",
                       "evidence_path": "/summary/findings", "expected": 0})
    booleans = [
        (r"(?i)\b(?:no target code was executed|target code was not executed)\b",
         "/execution/target_code_executed", False),
        (r"(?i)\b(?:no network access|network access was not used)\b",
         "/execution/network_access", False),
        (r"(?i)\b(?:no changes were applied|changes were not applied)\b",
         "/execution/changes_applied", False),
    ]
    for pattern, pointer, expected in booleans:
        match = re.search(pattern, safe)
        if match:
            claims.append({"kind": "value", "text": match.group(0),
                           "evidence_path": pointer, "expected": expected})
    if _ABSOLUTE_SAFETY.search(safe) and not _QUALIFIED_ABSENCE.search(safe):
        claims.append({"kind": "coverage", "scope": "scan", "expected": "clean",
                       "text": _ABSOLUTE_SAFETY.search(safe).group(0)})
    return claims


def validate_claims(claims: Sequence[Mapping[str, Any]], evidence: Mapping[str, Any], *,
                    root: str | os.PathLike[str] | None = None,
                    response_text: str = "", max_claims: int = MAX_CLAIMS) -> dict[str, Any]:
    """Validate structured response claims against supplied offline evidence."""
    if type(evidence) is not dict:
        raise TruthGuardError("evidence must be a JSON object")
    if type(claims) not in {list, tuple}:
        raise TruthGuardError("claims must be a JSON array")
    _assert_json_tree(evidence); _assert_json_tree(claims)
    limit = max(1, min(int(max_claims), MAX_CLAIMS))
    selected = list(claims[:limit])
    index = EvidenceIndex(evidence, root)
    numeric, numeric_lookup = _numeric_checks(index)
    integrity = _report_integrity(index)
    audit_contradictions, audit = _evidence_audit(index, numeric, integrity)
    verdicts: list[dict[str, Any]] = []
    raw_by_id: dict[str, Mapping[str, Any]] = {}
    for raw in selected:
        if type(raw) is not dict:
            raw = {"kind": "statement", "text": str(raw)}
        verdict = _evaluate_claim(raw, index, numeric_lookup, audit)
        _resolve_explicit_refs(raw, verdict, index)
        # Duplicate semantic predicates are emitted once under their stable ID.
        if verdict["id"] not in raw_by_id:
            raw_by_id[verdict["id"]] = raw; verdicts.append(verdict)

    if integrity.get("state") == "mismatch":
        for verdict in verdicts:
            if verdict["state"] != "unknown":
                verdict.update(
                    state="unknown", accepted=False,
                    reason="supplied report failed its integrity digest",
                    safe_text="I cannot substantiate this claim from the supplied evidence.",
                    abstention="I cannot substantiate this claim from the supplied evidence.")

    contradictions = audit_contradictions + _claim_contradictions(verdicts)
    contradictions = [dict(row) for row in {row["id"]: row for row in contradictions}.values()]
    contradictions.sort(key=lambda row: row["id"])
    counts = {state: sum(row["state"] == state for row in verdicts) for state in sorted(STATES)}
    accepted_text = [row["safe_text"] for row in verdicts if row["accepted"]]
    abstained = ["Abstained on %s: %s" % (row["id"], row["reason"])
                 for row in verdicts if not row["accepted"]]
    safe_response = "\n".join(accepted_text + abstained) or \
        "Truth Guard abstained: no supplied claim was substantiated."
    safe_response, _, response_truncated = _safe_text(
        safe_response, limit=MAX_SAFE_RESPONSE_CHARS)

    used_refs = set(integrity.get("evidence_refs", []))
    for collection in (verdicts, numeric, contradictions):
        for row in collection:
            used_refs.update(row.get("evidence_refs", []))
    for row in audit.get("improvements", []):
        used_refs.add(row.get("evidence_ref", ""))
    for row in audit.get("model_artifacts", []):
        used_refs.add(row.get("evidence_ref", ""))
    catalog = [index.entries[ref].row() for ref in sorted(used_refs)
               if ref in index.entries][:MAX_PUBLIC_EVIDENCE]

    supported = counts["observed"] + counts["derived"]
    status = ("verified" if verdicts and supported == len(verdicts) and not contradictions
              else "abstained" if not supported else "partial")
    response_meta = {"provided": bool(response_text), "characters": len(response_text),
                     "bounded": len(response_text) > MAX_SAFE_RESPONSE_CHARS,
                     "secret_like_material_redacted": _contains_secret(
                         response_text[:MAX_SECRET_SCAN_CHARS]) if response_text else False}
    report: dict[str, Any] = {
        "schema": SCHEMA, "version": VERSION, "status": status,
        "summary": {"claims_received": len(claims), "claims_evaluated": len(verdicts),
                    **counts, "contradictions": len(contradictions),
                    "claims_truncated": max(0, len(claims) - len(selected))},
        "claims": verdicts, "contradictions": contradictions,
        "numeric_checks": numeric, "evidence_catalog": catalog,
        "report_integrity": integrity, "evidence_audit": audit,
        "safe_response": safe_response, "response_input": response_meta,
        "bounds": {"max_claims": MAX_CLAIMS, "max_text_chars": MAX_TEXT_CHARS,
                   "max_safe_response_chars": MAX_SAFE_RESPONSE_CHARS,
                   "input_index_truncated": index.input_truncated,
                   "safe_response_truncated": response_truncated,
                   "public_evidence_truncated": len(used_refs) > len(catalog)},
        "execution": {"network_access": False, "model_execution": False,
                      "target_code_executed": False, "dynamic_code": False,
                      "filesystem_writes": False},
        "assurance": [
            "Observed means a direct structured value/location matched; derived means a bounded deterministic calculation matched.",
            "Unknown and refuted claims are replaced by abstention text, not repeated as facts.",
            "An empty or unavailable scan/advisory source is not evidence of absolute safety.",
        ],
    }
    report["report_sha256"] = hashlib.sha256(_canonical(report)).hexdigest()
    return report


guard = validate_claims
verify_claims = validate_claims


def guard_response(response_text: str, evidence: Mapping[str, Any],
                   claims: Sequence[Mapping[str, Any]] | None = None, *,
                   root: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Validate explicit claims, or conservatively extract known count/assurance forms."""
    if not isinstance(response_text, str):
        raise TruthGuardError("response_text must be text")
    selected = list(claims) if claims is not None else _auto_claims(response_text)
    if not selected:
        selected = [{"kind": "statement", "text": response_text or "empty response"}]
    return validate_claims(selected, evidence, root=root, response_text=response_text)


def redact_tree(value: Any, *, _pointer_value: str = "",
                _validated: bool = False) -> Any:
    """Return a recursively bounded, credential-redacted JSON-shaped copy."""
    if not _validated:
        _assert_json_tree(value)
    if value is None or isinstance(value, bool):
        return value
    if type(value) in {int, float}:
        return "[REDACTED: sensitive field]" if _sensitive_pointer(_pointer_value) else value
    if isinstance(value, str):
        safe, _, _ = _safe_text(
            value, sensitive=_sensitive_pointer(_pointer_value),
            limit=MAX_SAFE_RESPONSE_CHARS)
        return safe
    if type(value) in {list, tuple}:
        return [redact_tree(item, _pointer_value=_pointer_value + "/" + str(index),
                            _validated=True)
                for index, item in enumerate(value)]
    if type(value) is dict:
        output: dict[str, Any] = {}
        used: set[str] = set()
        redacted_key_number = 0
        for key in sorted(value):
            secret_key = _contains_secret(key)
            if secret_key:
                redacted_key_number += 1
            public_key = _bounded_public_key(
                key, limit=1_024,
                redacted_label="[REDACTED-KEY-%d]" % redacted_key_number,
                used=used)
            child_pointer = _pointer_value + "/" + _pointer_escape(key)
            output[public_key] = redact_tree(
                value[key], _pointer_value=child_pointer, _validated=True)
        return output
    raise TruthGuardError("value is not JSON-shaped")


def deterministic_json(report: Mapping[str, Any], *, indent: int | None = 2) -> str:
    """Serialize any JSON report deterministically with recursive redaction."""
    if type(report) is not dict:
        raise TruthGuardError("report must be a JSON object")
    _assert_json_tree(report)
    safe = redact_tree(report, _validated=True)
    return json.dumps(safe, sort_keys=True, indent=indent, ensure_ascii=False, allow_nan=False)


def render(report: Mapping[str, Any]) -> str:
    """Render only the safe, evidence-filtered response and a compact audit footer."""
    safe, _, _ = _safe_text(report.get("safe_response", "Truth Guard abstained."),
                            limit=MAX_SAFE_RESPONSE_CHARS)
    summary = report.get("summary", {}) if type(report.get("summary")) is dict else {}
    return "\n".join([
        safe, "", "Truth Guard: %s; observed=%s derived=%s unknown=%s refuted=%s contradictions=%s" % (
            report.get("status", "unknown"), summary.get("observed", 0),
            summary.get("derived", 0), summary.get("unknown", 0),
            summary.get("refuted", 0), summary.get("contradictions", 0)),
    ])


__all__ = [
    "SCHEMA", "VERSION", "STATES", "TruthGuardError", "validate_claims",
    "verify_claims", "guard", "guard_response", "redact_tree", "deterministic_json", "render",
]
