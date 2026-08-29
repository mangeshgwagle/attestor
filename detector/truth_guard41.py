#!/usr/bin/env python3
"""Truth Guard 3: source-bound, replayable evidence for Attestor 4.1.3.

Every bindable finding is tied to the complete source-file SHA-256, an exact
bounded byte range, a digest of those bytes, and the rule/config/analyzer/input
manifest digests that produced it.  Verification can re-read the selected tree
and refuses stale evidence.  The standard-library build offers authenticated
HMAC-SHA256; it explicitly does not pretend that shared-key authentication is a
public-key signature or non-repudiation.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping


VERSION = "4.1.3"
SCHEMA = "attestor.truth-guard/3.0"
MAX_FINDINGS = 20_000
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_SNIPPET_BYTES = 4_096
MAX_PUBLIC_BYTES = 32 * 1024 * 1024
MAX_MANIFEST_ENTRIES = 200_000
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_GUARD_KEYS = frozenset({"truth_guard3", "truth_guard2", "truth_guard_runtime",
                         "truth_guard", "report_sha256", "view_sha256",
                         "source_report_sha256"})


class TruthGuard41Error(ValueError):
    """A report cannot cross the Truth Guard 3 evidence boundary."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(value: Any) -> str:
    raw = value if isinstance(value, bytes) else _canonical(value)
    return hashlib.sha256(raw).hexdigest()


def _json_copy(value: Any) -> Any:
    try:
        encoded = _canonical(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise TruthGuard41Error("report is not bounded deterministic JSON") from exc
    if len(encoded) > MAX_PUBLIC_BYTES:
        raise TruthGuard41Error("report exceeds the 32 MiB Truth Guard boundary")
    return json.loads(encoded.decode("utf-8"))


def _clean_document(document: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): value for key, value in document.items()
            if str(key) not in _GUARD_KEYS and not str(key).startswith("_")}


def _safe_text(value: Any, maximum: int) -> str:
    return str(value or "").replace("\x00", "\\0")[:maximum]


def _is_link_or_reparse(path: Path) -> bool:
    """Return true for POSIX links and Windows reparse-backed paths."""
    try:
        metadata = path.lstat()
    except OSError:
        return False
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


def _claimed_line(value: Any) -> int:
    if isinstance(value, bool):
        raise TruthGuard41Error("finding line is not a positive integer")
    if isinstance(value, int):
        line = value
    elif isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value.strip()):
        line = int(value.strip())
    else:
        raise TruthGuard41Error("finding line is not a positive integer")
    if line < 1:
        raise TruthGuard41Error("finding line is not a positive integer")
    return line


def _root(document: Mapping[str, Any], supplied: str | os.PathLike[str] | None) -> Path:
    raw = supplied if supplied is not None else document.get("root")
    if not raw:
        raise TruthGuard41Error("source root is required for source-bound evidence")
    try:
        supplied = Path(os.fspath(raw)).expanduser()
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
                raise TruthGuard41Error(
                    "source root path cannot traverse a link or reparse point")
        lexical = Path(os.path.abspath(os.fspath(spelling)))
        resolved = lexical.resolve(strict=True)
    except TruthGuard41Error:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise TruthGuard41Error("source root is invalid") from exc
    if not resolved.exists() or not (resolved.is_file() or resolved.is_dir()):
        raise TruthGuard41Error("source root does not exist")
    return resolved


def _relative_path(root: Path, raw: Any) -> tuple[Path, str]:
    label = _safe_text(raw, 8_000).replace("\\", "/")
    if not label or label in {"workspace", ".", "<workspace>"}:
        raise TruthGuard41Error("finding has no concrete source path")
    base = root.parent if root.is_file() else root
    candidate = Path(label)
    lexical = Path(os.path.abspath(os.fspath(candidate if candidate.is_absolute() else base / candidate)))
    try:
        lexical_relative = lexical.relative_to(base)
    except ValueError as exc:
        raise TruthGuard41Error("finding source escapes the selected root") from exc
    current = base
    for part in lexical_relative.parts:
        current = current / part
        if _is_link_or_reparse(current):
            raise TruthGuard41Error("finding source traverses a link or reparse point")
    resolved = lexical.resolve()
    try:
        relative = resolved.relative_to(base).as_posix()
    except ValueError as exc:
        raise TruthGuard41Error("finding source escapes the selected root") from exc
    if root.is_file() and resolved != root:
        raise TruthGuard41Error("finding source does not match the selected file")
    if resolved.is_symlink() or not resolved.is_file():
        raise TruthGuard41Error("finding source is not a regular in-scope file")
    return resolved, relative


def _read(path: Path) -> bytes:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise TruthGuard41Error("finding source could not be read") from exc
    if len(raw) > MAX_FILE_BYTES:
        raise TruthGuard41Error("finding source exceeds the per-file evidence boundary")
    return raw


def _snapshot_file(path: Path) -> tuple[int, str]:
    """Hash one immutable regular file without retaining its full contents."""
    try:
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            if before.st_size > MAX_FILE_BYTES:
                raise TruthGuard41Error("source file exceeds the per-file snapshot boundary")
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_FILE_BYTES:
                    raise TruthGuard41Error("source file exceeds the per-file snapshot boundary")
                digest.update(chunk)
            after = os.fstat(stream.fileno())
    except TruthGuard41Error:
        raise
    except OSError as exc:
        raise TruthGuard41Error("selected source inventory could not be read") from exc
    identity_before = (before.st_size, before.st_mtime_ns, getattr(before, "st_ino", 0))
    identity_after = (after.st_size, after.st_mtime_ns, getattr(after, "st_ino", 0))
    if size != before.st_size or identity_before != identity_after:
        raise TruthGuard41Error("selected source changed while its inventory was hashed")
    return size, digest.hexdigest()


def _snapshot_manifest(root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Create a bounded, complete lexical inventory of the selected root.

    Directory entries and non-followed links are included so additions and
    removals change the manifest. Only regular files contribute content bytes.
    """
    entries: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    total_bytes = 0

    def add(entry: dict[str, Any]) -> None:
        if len(entries) >= MAX_MANIFEST_ENTRIES:
            raise TruthGuard41Error("selected source inventory exceeds the entry boundary")
        entries.append(entry)

    if root.is_file():
        size, digest = _snapshot_file(root)
        return [{"path": root.name, "kind": "file", "bytes": size,
                 "sha256": digest}], []

    stack: list[tuple[Path, Path]] = [(root, Path())]
    while stack:
        directory, prefix = stack.pop()
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise TruthGuard41Error("selected source inventory could not be enumerated") from exc
        pending_directories: list[tuple[Path, Path]] = []
        for child in children:
            path = Path(child.path)
            relative_path = prefix / child.name
            relative = relative_path.as_posix()
            if _is_link_or_reparse(path):
                try:
                    target = os.readlink(path)
                except OSError:
                    target = "unavailable"
                add({"path": relative, "kind": "link-or-reparse",
                     "target_sha256": _sha(os.fsencode(target))})
                gaps.append({"path": relative,
                             "reason": "link or reparse entry is inventoried but not followed"})
                continue
            try:
                if child.is_dir(follow_symlinks=False):
                    add({"path": relative, "kind": "directory"})
                    pending_directories.append((path, relative_path))
                elif child.is_file(follow_symlinks=False):
                    size, digest = _snapshot_file(path)
                    total_bytes += size
                    if total_bytes > MAX_TOTAL_BYTES:
                        raise TruthGuard41Error("selected source inventory exceeds the aggregate byte boundary")
                    add({"path": relative, "kind": "file", "bytes": size,
                         "sha256": digest})
                else:
                    add({"path": relative, "kind": "unsupported"})
                    gaps.append({"path": relative,
                                 "reason": "non-regular source entry is outside snapshot coverage"})
            except OSError as exc:
                raise TruthGuard41Error("selected source inventory entry could not be classified") from exc
        stack.extend(reversed(pending_directories))
    entries.sort(key=lambda item: (str(item.get("path", "")), str(item.get("kind", ""))))
    return entries, gaps


def _line_range(raw: bytes, line: int) -> tuple[int, int]:
    requested = _claimed_line(line)
    if not raw:
        if requested == 1:
            return 0, 0
        raise TruthGuard41Error("finding line is outside the source file")
    starts = [0]
    for index, value in enumerate(raw):
        if value == 10 and index + 1 < len(raw):
            starts.append(index + 1)
    if requested > len(starts):
        raise TruthGuard41Error("finding line is outside the source file")
    start = starts[requested - 1]
    newline = raw.find(b"\n", start)
    end = len(raw) if newline < 0 else newline + 1
    if end - start > MAX_SNIPPET_BYTES:
        end = start + MAX_SNIPPET_BYTES
    return start, end


def _rule_digest(finding: Mapping[str, Any]) -> str:
    explicit = finding.get("rule_sha256")
    if isinstance(explicit, str) and _HEX64.fullmatch(explicit):
        return explicit
    return _sha({
        "rule": _safe_text(finding.get("rule") or finding.get("rule_id"), 300),
        "category": _safe_text(finding.get("category"), 200),
        "cwe": _safe_text(finding.get("cwe"), 80),
        "severity": _safe_text(finding.get("severity"), 20).upper(),
        "source_engine": _safe_text(finding.get("source_engine") or finding.get("analyzer"), 200),
    })


def _descriptors(document: Mapping[str, Any], config: Mapping[str, Any] | None,
                 analyzer: Mapping[str, Any] | None) -> tuple[dict[str, Any], dict[str, Any]]:
    raw_config = config if config is not None else document.get("analysis_config")
    raw_analyzer = analyzer if analyzer is not None else document.get("analyzer")
    config_value = dict(raw_config) if isinstance(raw_config, Mapping) else {}
    analyzer_value = dict(raw_analyzer) if isinstance(raw_analyzer, Mapping) else {
        "name": "Attestor", "version": _safe_text(document.get("version", VERSION), 80),
        "schema": _safe_text(document.get("schema"), 200),
    }
    return _json_copy(config_value), _json_copy(analyzer_value)


def _collect_sources(document: Mapping[str, Any], root: Path) -> tuple[
        dict[str, tuple[Path, bytes]], list[dict[str, Any]], list[dict[str, Any]]]:
    findings = document.get("findings") if isinstance(document.get("findings"), list) else []
    if len(findings) > MAX_FINDINGS:
        raise TruthGuard41Error("finding count exceeds the Truth Guard boundary")
    loaded: dict[str, tuple[Path, bytes]] = {}
    manifest, gaps = _snapshot_manifest(root)
    manifest_files = {str(row.get("path")): row for row in manifest
                      if row.get("kind") == "file"}
    for index, finding in enumerate(findings):
        if not isinstance(finding, Mapping):
            gaps.append({"finding": index, "reason": "finding is not an evidence object"})
            continue
        try:
            path, relative = _relative_path(root, finding.get("path"))
            if relative not in loaded:
                raw = _read(path)
                snapshot = manifest_files.get(relative)
                if not snapshot or snapshot.get("bytes") != len(raw) or snapshot.get("sha256") != _sha(raw):
                    raise TruthGuard41Error("finding source changed after the root inventory was captured")
                loaded[relative] = (path, raw)
        except TruthGuard41Error as exc:
            gaps.append({"finding": index, "path": _safe_text(finding.get("path"), 1_000),
                         "reason": str(exc)})
    return loaded, manifest, gaps


def _finding_evidence(index: int, finding: Mapping[str, Any],
                      loaded: Mapping[str, tuple[Path, bytes]], root: Path,
                      *, config_sha256: str, analyzer_sha256: str,
                      manifest_sha256: str) -> dict[str, Any]:
    rule_sha256 = _rule_digest(finding)
    try:
        _path, relative = _relative_path(root, finding.get("path"))
        raw = loaded[relative][1]
        line = _claimed_line(finding.get("line", 1))
        start, end = _line_range(raw, line)
        snippet = raw[start:end]
        state, reason = "bound", "exact source bytes and producer inputs are content-addressed"
        source = {"path": relative, "file_sha256": _sha(raw), "file_bytes": len(raw),
                  "byte_start": start, "byte_end": end, "snippet_bytes": len(snippet),
                  "snippet_sha256": _sha(snippet)}
    except (KeyError, TypeError, ValueError, TruthGuard41Error) as exc:
        state, reason = "unbound", _safe_text(exc, 500)
        source = {"path": _safe_text(finding.get("path"), 1_000), "file_sha256": "",
                  "file_bytes": 0, "byte_start": 0, "byte_end": 0,
                  "snippet_bytes": 0, "snippet_sha256": ""}
    try:
        identity_line = _claimed_line(finding.get("line", 1))
    except TruthGuard41Error:
        identity_line = 0
    identity = {
        "index": index,
        "rule": _safe_text(finding.get("rule") or finding.get("rule_id"), 300),
        "path": _safe_text(finding.get("path"), 2_000).replace("\\", "/"),
        "line": identity_line,
        "severity": _safe_text(finding.get("severity", "MEDIUM"), 20).upper(),
    }
    body = {"state": state, "reason": reason, "finding": identity, "source": source,
            "rule_sha256": rule_sha256, "config_sha256": config_sha256,
            "analyzer_sha256": analyzer_sha256,
            "input_manifest_sha256": manifest_sha256}
    body["evidence_sha256"] = _sha(body)
    return body


def signing_capabilities() -> dict[str, Any]:
    return {
        "hmac_sha256": True,
        "public_key": False,
        "public_key_gap": (
            "This zero-dependency build has no audited public-key signing primitive. "
            "HMAC-SHA256 authenticates shared-key possession but does not provide non-repudiation."
        ),
    }


def _signature_payload(ledger: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in ledger.items() if key != "signature"}


def guard_document(document: Mapping[str, Any], *,
                   root: str | os.PathLike[str] | None = None,
                   config: Mapping[str, Any] | None = None,
                   analyzer: Mapping[str, Any] | None = None,
                   key: bytes | None = None, key_id: str = "") -> dict[str, Any]:
    """Return a JSON copy carrying a source-bound Truth Guard 3 ledger."""
    if not isinstance(document, Mapping):
        raise TruthGuard41Error("report must be a mapping")
    output = _json_copy(_clean_document(document))
    selected = _root(output, root)
    config_value, analyzer_value = _descriptors(output, config, analyzer)
    loaded, manifest, gaps = _collect_sources(output, selected)
    manifest_sha256 = _sha(manifest)
    config_sha256, analyzer_sha256 = _sha(config_value), _sha(analyzer_value)
    findings = output.get("findings") if isinstance(output.get("findings"), list) else []
    evidence = [_finding_evidence(index, finding, loaded, selected,
                                  config_sha256=config_sha256,
                                  analyzer_sha256=analyzer_sha256,
                                  manifest_sha256=manifest_sha256)
                for index, finding in enumerate(findings) if isinstance(finding, Mapping)]
    for item, binding in zip((row for row in findings if isinstance(row, dict)), evidence):
        item["source_evidence"] = {
            **binding["source"], "state": binding["state"],
            "evidence_sha256": binding["evidence_sha256"],
            "rule_sha256": binding["rule_sha256"],
            "config_sha256": config_sha256,
            "analyzer_sha256": analyzer_sha256,
            "input_manifest_sha256": manifest_sha256,
        }
    clean = _clean_document(output)
    capabilities = signing_capabilities()
    ledger = {
        "schema": SCHEMA, "version": VERSION,
        "status": "verified" if evidence and not gaps and all(row["state"] == "bound" for row in evidence)
                  else "partial",
        "report_sha256": _sha(clean),
        "selected_root_sha256": _sha(str(selected)),
        "input_manifest": manifest,
        "input_manifest_sha256": manifest_sha256,
        "input_manifest_scope": "complete-selected-root-inventory",
        "config_sha256": config_sha256,
        "analyzer_sha256": analyzer_sha256,
        "finding_evidence": evidence,
        "finding_evidence_sha256": _sha(evidence),
        "summary": {"findings": len(findings), "bound": sum(row["state"] == "bound" for row in evidence),
                    "unbound": sum(row["state"] != "bound" for row in evidence),
                    "source_files": len(manifest), "gaps": len(gaps)},
        "gaps": gaps[:2_000] + ([{"reason": capabilities["public_key_gap"]}] if not capabilities["public_key"] else []),
        "replay": {"mode": "deterministic-source-replay", "stale_inputs_refused": True,
                   "additions_and_removals_refused": True,
                   "full_selected_root_inventory": True,
                   "config_required_for_exact_replay": True,
                   "analyzer_required_for_exact_replay": True},
        "signing_capabilities": capabilities,
    }
    if key is not None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise TruthGuard41Error("HMAC key must contain at least 32 bytes")
        if not isinstance(key_id, str) or not 1 <= len(key_id) <= 128:
            raise TruthGuard41Error("authenticated ledgers require a bounded key id")
        value = hmac.new(key, _canonical(_signature_payload(ledger)), hashlib.sha256).hexdigest()
        ledger["signature"] = {"algorithm": "hmac-sha256", "key_id": key_id,
                               "value": value, "state": "authenticated-shared-key",
                               "non_repudiation": False}
    else:
        ledger["signature"] = {"algorithm": "none", "key_id": "", "value": "",
                               "state": "integrity-only", "non_repudiation": False}
    ledger["ledger_sha256"] = _sha({key: value for key, value in ledger.items()
                                      if key != "ledger_sha256"})
    output["truth_guard3"] = ledger
    if len(_canonical(output)) > MAX_PUBLIC_BYTES:
        raise TruthGuard41Error(
            "guarded report exceeds the 32 MiB Truth Guard boundary after evidence binding")
    return output


def _verify_binding(binding: Mapping[str, Any], root: Path,
                    manifest_sha256: str, config_sha256: str,
                    analyzer_sha256: str) -> tuple[list[str], bool]:
    errors: list[str] = []
    stale = False
    body = {key: value for key, value in binding.items() if key != "evidence_sha256"}
    if binding.get("evidence_sha256") != _sha(body):
        errors.append("finding evidence digest mismatch")
    for key, expected in (("input_manifest_sha256", manifest_sha256),
                          ("config_sha256", config_sha256),
                          ("analyzer_sha256", analyzer_sha256)):
        if binding.get(key) != expected:
            errors.append("finding %s mismatch" % key)
    if binding.get("state") != "bound":
        errors.append("finding evidence is not source-bound")
        return errors, stale
    source = binding.get("source") if isinstance(binding.get("source"), Mapping) else {}
    try:
        path, relative = _relative_path(root, source.get("path"))
        raw = _read(path)
        start, end = int(source.get("byte_start")), int(source.get("byte_end"))
        finding = binding.get("finding") if isinstance(binding.get("finding"), Mapping) else {}
        expected_start, expected_end = _line_range(raw, _claimed_line(finding.get("line")))
        if not 0 <= start <= end <= len(raw) or end - start > MAX_SNIPPET_BYTES:
            raise TruthGuard41Error("finding byte range is invalid")
        if (start, end) != (expected_start, expected_end) \
                or source.get("path") != relative or source.get("file_sha256") != _sha(raw) \
                or source.get("file_bytes") != len(raw) \
                or source.get("snippet_bytes") != end - start \
                or source.get("snippet_sha256") != _sha(raw[start:end]):
            stale = True
            errors.append("source evidence is stale")
    except (KeyError, TypeError, ValueError, TruthGuard41Error):
        stale = True
        errors.append("source evidence could not be replayed")
    return errors, stale


def verify_guarded(document: Mapping[str, Any], *,
                   root: str | os.PathLike[str] | None = None,
                   config: Mapping[str, Any] | None = None,
                   analyzer: Mapping[str, Any] | None = None,
                   key: bytes | None = None,
                   require_fresh: bool = True) -> dict[str, Any]:
    errors: list[str] = []
    stale_rows: list[int] = []
    if not isinstance(document, Mapping):
        return {"ok": False, "status": "invalid", "errors": ["report must be a mapping"],
                "authenticated": False, "fresh": False}
    try:
        if len(_canonical(document)) > MAX_PUBLIC_BYTES:
            errors.append("guarded report exceeds the Truth Guard byte boundary")
    except (TruthGuard41Error, TypeError, ValueError, OverflowError, RecursionError):
        errors.append("guarded report is not bounded deterministic JSON")
    ledger = document.get("truth_guard3")
    if not isinstance(ledger, Mapping) or ledger.get("schema") != SCHEMA or ledger.get("version") != VERSION:
        return {"ok": False, "status": "invalid", "errors": ["Truth Guard 3 ledger is absent"],
                "authenticated": False, "fresh": False}
    claimed_ledger = ledger.get("ledger_sha256")
    if claimed_ledger != _sha({k: v for k, v in ledger.items() if k != "ledger_sha256"}):
        errors.append("ledger digest mismatch")
    clean = _clean_document(document)
    if ledger.get("report_sha256") != _sha(clean):
        errors.append("guarded report digest mismatch")
    manifest = ledger.get("input_manifest") if isinstance(ledger.get("input_manifest"), list) else []
    manifest_sha256 = _sha(manifest)
    if ledger.get("input_manifest_scope") != "complete-selected-root-inventory":
        errors.append("input manifest scope is not a complete selected-root inventory")
    if ledger.get("input_manifest_sha256") != manifest_sha256:
        errors.append("input manifest digest mismatch")
    evidence = ledger.get("finding_evidence") if isinstance(ledger.get("finding_evidence"), list) else []
    if ledger.get("finding_evidence_sha256") != _sha(evidence):
        errors.append("finding evidence catalog digest mismatch")
    findings = document.get("findings") if isinstance(document.get("findings"), list) else []
    if len(evidence) != sum(isinstance(row, Mapping) for row in findings):
        errors.append("finding evidence count mismatch")
    config_value, analyzer_value = _descriptors(document, config, analyzer)
    config_sha256 = _sha(config_value) if config is not None else str(ledger.get("config_sha256", ""))
    analyzer_sha256 = _sha(analyzer_value) if analyzer is not None else str(ledger.get("analyzer_sha256", ""))
    if config is not None and config_sha256 != ledger.get("config_sha256"):
        errors.append("replay configuration is stale")
    if analyzer is not None and analyzer_sha256 != ledger.get("analyzer_sha256"):
        errors.append("replay analyzer identity is stale")
    selected: Path | None = None
    if require_fresh:
        try:
            selected = _root(document, root)
            if ledger.get("selected_root_sha256") != _sha(str(selected)):
                errors.append("selected source root changed")
            try:
                current_manifest, _current_gaps = _snapshot_manifest(selected)
                if current_manifest != manifest:
                    errors.append("input manifest is stale: selected-root entries or contents changed")
            except TruthGuard41Error as exc:
                errors.append("input manifest is stale: %s" % exc)
        except TruthGuard41Error as exc:
            errors.append(str(exc))
    for index, binding in enumerate(evidence):
        if not isinstance(binding, Mapping):
            errors.append("finding evidence entry is invalid")
            continue
        if selected is not None:
            row_errors, stale = _verify_binding(binding, selected, manifest_sha256,
                                                str(ledger.get("config_sha256", "")),
                                                str(ledger.get("analyzer_sha256", "")))
            errors.extend("finding %d: %s" % (index, value) for value in row_errors)
            if stale:
                stale_rows.append(index)
    signature = ledger.get("signature") if isinstance(ledger.get("signature"), Mapping) else {}
    algorithm = signature.get("algorithm")
    authenticated = False
    if algorithm == "hmac-sha256":
        if not isinstance(key, bytes) or len(key) < 32:
            errors.append("authenticated ledger key was not supplied")
        else:
            unsigned = {name: value for name, value in ledger.items()
                        if name not in {"signature", "ledger_sha256"}}
            expected = hmac.new(key, _canonical(unsigned), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(str(signature.get("value", "")), expected):
                errors.append("ledger authentication mismatch")
            else:
                authenticated = True
    elif algorithm != "none":
        errors.append("unsupported ledger signature algorithm")
    stale = bool(stale_rows or any("stale" in value or "source root" in value for value in errors))
    status = "stale" if stale else "invalid" if errors else str(ledger.get("status", "verified"))
    return {"ok": not errors, "status": status, "errors": errors[:2_000],
            "authenticated": authenticated, "fresh": require_fresh and not stale and not errors,
            "stale_findings": stale_rows, "public_key_authenticated": False,
            "authentication_gap": signing_capabilities()["public_key_gap"]}


def replay_verify(document: Mapping[str, Any], root: str | os.PathLike[str], *,
                  config: Mapping[str, Any] | None = None,
                  analyzer: Mapping[str, Any] | None = None,
                  key: bytes | None = None) -> dict[str, Any]:
    return verify_guarded(document, root=root, config=config, analyzer=analyzer,
                          key=key, require_fresh=True)


def deterministic_json(document: Mapping[str, Any]) -> str:
    return json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False,
                      allow_nan=False) + "\n"


__all__ = ["SCHEMA", "VERSION", "TruthGuard41Error", "guard_document",
           "verify_guarded", "replay_verify", "signing_capabilities",
           "deterministic_json"]
