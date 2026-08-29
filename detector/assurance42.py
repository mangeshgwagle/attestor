#!/usr/bin/env python3
"""Experimental, passive repository assurance over one captured byte view.

This compositor deliberately exposes a narrow surface.  It captures one
bounded snapshot, feeds only those captured bytes to fixed bundled analyzers,
normalizes non-source evidence, self-verifies the result, and never applies a
repair.  It is an experimental review aid, not an OS sandbox, penetration
test, proof of safety, or authorization to inspect somebody else's code.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Iterable, Mapping, Sequence
import unicodedata


# Standalone use must not create bytecode either.  This is set before sibling
# analyzers are imported; it describes application write requests, not possible
# operating-system access-time metadata changes caused by reads.
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve(strict=True).parent
HERE_TEXT = os.fspath(HERE)
if HERE_TEXT not in sys.path:
    sys.path.insert(0, HERE_TEXT)

import analysis_snapshot41 as snapshot41
import attack_surface413
import detect
import language_coverage42
import security_posture413
import semantic_graph41


SCHEMA = "attestor.assurance/4.2-experimental"
VERSION = "4.2"
COMPONENT_SCHEMA = "attestor.assurance-component/4.2"
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_INVALID = 2
EXIT_INCOMPLETE = 3
EXIT_OPERATIONAL = 4

# One profile no larger than any downstream analyzer.  A relatively small
# per-file ceiling also bounds the legacy detector, whose public scan function
# materializes each file's findings before returning them.
PROFILE_LIMITS = snapshot41.SnapshotLimits(
    max_files=2_000,
    max_file_bytes=128 * 1024,
    max_total_bytes=16 * 1024 * 1024,
    max_path_chars=4_096,
    max_gaps=10_000,
    max_entries_per_directory=10_000,
)
MAX_EVIDENCE = 5_000
MAX_GAPS = 20_000
MAX_TEXT = 1_024
MAX_REPORT_BYTES = 24 * 1024 * 1024
MAX_SEMANTIC_NODES = 25_000
HEX64 = re.compile(r"[0-9a-f]{64}")
SAFE_LABEL = re.compile(r"[^a-zA-Z0-9_.:/+-]+")
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

SNAPSHOT_CAPTURE_CONTRACT = {
    "captured_subject_code_executed": False,
    "snapshot_files_dynamically_imported_for_analysis": False,
    "engine_started_processes": False,
    "network_requests_made": False,
    "application_write_operations_requested": False,
    "symlinks_or_reparse_points_followed": False,
    "atomic_whole_tree_snapshot": False,
}

DETECT_STATIC_CONTRACT = {
    "captured_subject_code_executed": False,
    "snapshot_files_dynamically_imported_for_analysis": False,
    "engine_started_processes": False,
    "network_requests_made": False,
    "application_write_operations_requested": False,
}

SEMANTIC_STATIC_CONTRACT = {
    "target_code_executed": False,
    "target_modules_imported": False,
    "compiler_invoked": False,
    "processes_started": False,
    "network_accessed": False,
    "filesystem_writes": False,
}

ATTACK_STATIC_CONTRACT = {
    "target_code_executed": False,
    "target_modules_imported": False,
    "processes_started": False,
    "network_accessed": False,
    "target_files_written": False,
    "remediation_applied": False,
    "exploit_payloads_generated": False,
    "symlinks_followed": False,
}

POSTURE_STATIC_CONTRACT = {
    "target_code_executed": False,
    "network_accessed": False,
    "files_written": False,
    "git_invoked": False,
    "binary_mode": "metadata-and-bounded-printable-strings-only",
}

def _expected_engine_execution() -> dict[str, Any]:
    return {
        "captured_subject_code_executed": False,
        "snapshot_files_dynamically_imported_for_analysis": False,
        "engine_started_processes": False,
        "target_or_tool_processes_started": False,
        "network_requests_made": False,
        "target_content_or_directory_entries_written": False,
        "application_write_operations_requested": False,
        "remediation_applied": False,
        "exploit_payloads_generated": False,
        "outer_launcher_may_start_one_fixed_python_child": True,
    }


def _expected_cost_profile() -> dict[str, Any]:
    return {
        "paid_api_or_provider_used": False,
        "external_provider_charge_usd": 0,
        "network_service_charge_usd": 0,
        "new_runtime_dependency_charge_usd": 0,
        "local_compute_cost_usd": None,
        "scope_note": (
            "Local hardware, electricity, operating-system, storage, and staff costs "
            "are unmeasured; USD 0 applies only to external provider/network charges."
        ),
    }


def _expected_limitations() -> list[str]:
    return [
        "Static candidates and advisory repairs are not runtime proof or verified fixes.",
        "The capture uses per-file identity checks; it is not an atomic whole-tree snapshot.",
        "The fixed Python child provides import isolation, not an OS or syscall sandbox.",
        "SHA-256 supplies equality/integrity evidence, not authorship or authenticity.",
        "Analyzer source-file hashes are not attestation of the exact bytes loaded or executed.",
        "Reports expose relative paths and content hashes and must be treated as sensitive metadata.",
        "Full-file hashes are not encryption, redaction, or protection from dictionary confirmation.",
        "Missing history, provenance, executable-mode, lock, or language evidence keeps coverage incomplete.",
    ]


class AssuranceError(ValueError):
    """Base class for a bounded assurance failure."""


class AssuranceInputError(AssuranceError):
    """The requested directory cannot be accepted as an analysis input."""


class AssuranceOperationalError(AssuranceError):
    """A fixed analyzer failed or returned evidence that did not verify."""


def canonical_json(value: Any, *, pretty: bool = False) -> str:
    """Serialize bounded JSON deterministically."""
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2 if pretty else None,
            separators=None if pretty else (",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise AssuranceOperationalError("assurance evidence is not canonical JSON") from exc


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _seal(body: Mapping[str, Any], digest_field: str = "report_sha256") -> dict[str, Any]:
    result = dict(body)
    result[digest_field] = digest_json(result)
    return result


def _safe_text(value: Any, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str):
        return ""
    output: list[str] = []
    for character in value:
        code = ord(character)
        if character in "\n\r\t":
            output.append(" ")
        elif (code < 32 or 0x7F <= code <= 0x9F
              or unicodedata.category(character) == "Cf"):
            output.append("?")
        else:
            output.append(character)
        if len(output) >= maximum:
            break
    return "".join(output).strip()


def _label(value: Any, fallback: str = "unknown") -> str:
    clean = SAFE_LABEL.sub("-", _safe_text(value, 128)).strip("-._:/+").lower()
    return clean[:96] or fallback


def _line_count(content: bytes) -> int:
    return 1 if not content else content.count(b"\n") + (0 if content.endswith(b"\n") else 1)


def _snapshot_projection(snapshot: snapshot41.SourceSnapshot) -> dict[str, Any]:
    native = snapshot.report()
    valid, errors = snapshot41.verify_report(native)
    if not valid:
        raise AssuranceOperationalError(
            "snapshot report did not verify: " + ", ".join(errors[:3]))
    if snapshot.limits != PROFILE_LIMITS:
        raise AssuranceOperationalError("snapshot limits differ from the assurance profile")
    paths: list[str] = []
    manifest: list[dict[str, Any]] = []
    seen_casefold: set[str] = set()
    total = 0
    for item in snapshot.files:
        try:
            path = snapshot41.safe_relative(item.path)
        except snapshot41.SnapshotError as exc:
            raise AssuranceOperationalError("snapshot contains an unsafe path") from exc
        if path != item.path or path.casefold() in seen_casefold:
            raise AssuranceOperationalError("snapshot paths are not canonical and case-unique")
        if (len(path) > 1_024 or _safe_text(path, 4_096) != path
                or unicodedata.normalize("NFC", path) != path):
            raise AssuranceInputError(
                "a snapshot path cannot be represented safely in assurance evidence")
        seen_casefold.add(path.casefold())
        content = item.content
        if (not isinstance(content, bytes) or len(content) != item.size
                or hashlib.sha256(content).hexdigest() != item.sha256):
            raise AssuranceOperationalError("snapshot byte evidence mismatch")
        if snapshot.get(path) is not item:
            raise AssuranceOperationalError("snapshot index identity mismatch")
        paths.append(path)
        total += item.size
        manifest.append({
            "path": path,
            "language": item.language,
            "size": item.size,
            "line_count": _line_count(content),
            "sha256": item.sha256,
        })
    if paths != sorted(paths) or total > PROFILE_LIMITS.max_total_bytes:
        raise AssuranceOperationalError("snapshot ordering or total-byte boundary mismatch")
    if len(manifest) > PROFILE_LIMITS.max_files:
        raise AssuranceOperationalError("snapshot file boundary mismatch")
    body = {
        "schema": native["schema"],
        "version": native["version"],
        "analysis_level": native["analysis_level"],
        "root": ".",
        "snapshot_sha256": snapshot.snapshot_sha256,
        "native_report_sha256": native["report_sha256"],
        "file_count": len(manifest),
        "total_bytes": total,
        "files": manifest,
        "native_gaps": [
            {
                "path": _safe_text(row.get("path", ""), 4_096),
                "reason": _label(row.get("reason", "snapshot-gap")),
                "native_gap_sha256": digest_json(dict(row)),
            }
            for row in snapshot.gaps
        ],
        "limits": {name: getattr(PROFILE_LIMITS, name)
                   for name in PROFILE_LIMITS.__dataclass_fields__},
        "capture_contract": dict(SNAPSHOT_CAPTURE_CONTRACT),
    }
    body["projection_sha256"] = digest_json(body)
    return body


def _module_identity(module: Any) -> dict[str, str]:
    raw = getattr(module, "__file__", None)
    if not isinstance(raw, str):
        raise AssuranceOperationalError("analyzer module has no file identity")
    try:
        unresolved = Path(raw)
        if unresolved.is_symlink():
            raise AssuranceOperationalError("linked analyzer module is refused")
        resolved = unresolved.resolve(strict=True)
        resolved.relative_to(HERE)
        info = resolved.stat()
        if not stat.S_ISREG(info.st_mode):
            raise AssuranceOperationalError("analyzer module is not a regular file")
        data = resolved.read_bytes()
    except (OSError, ValueError) as exc:
        raise AssuranceOperationalError("analyzer module escaped the trusted detector root") from exc
    return {
        "module": str(getattr(module, "__name__", "")),
        "source_sha256": hashlib.sha256(data).hexdigest(),
    }


def _gap(analyzer: str, analyzer_schema: str, child_digest: str,
         path: Any, reason: Any, native: Any) -> dict[str, Any]:
    clean_path = _safe_text(path, 4_096)
    if clean_path == ".":
        clean_path = ""
    body = {
        "analyzer": analyzer,
        "analyzer_schema": analyzer_schema,
        "child_report_sha256": child_digest,
        "path": clean_path,
        "reason": _label(reason, "coverage-gap"),
        "native_gap_sha256": digest_json(native),
    }
    body["gap_id"] = "gap42-" + digest_json(body)[:24]
    return body


def _advisory(text: Any, *, safe_to_autofix: bool = False) -> dict[str, Any]:
    return {
        "kind": "preview-only",
        "text": _safe_text(text, 1_024),
        "safe_to_autofix": bool(safe_to_autofix),
        "applied": False,
        "verified": False,
    }


def _evidence(*, analyzer: str, analyzer_schema: str, child_digest: str,
              snapshot_sha256: str, source_sha256: str, native_id: Any,
              rule_id: Any, severity: Any, path: Any, line: Any,
              severity_basis: str, evidence_state: Any, confidence: Any, exploitability: Any,
              advisory: Mapping[str, Any], details: Mapping[str, Any]) -> dict[str, Any]:
    severity_text = str(severity).lower()
    if severity_text not in SEVERITY_ORDER:
        severity_text = "info"
    clean_line = line if type(line) is int and line >= 1 else 1
    body = {
        "analyzer": analyzer,
        "analyzer_schema": analyzer_schema,
        "child_report_sha256": child_digest,
        "snapshot_sha256": snapshot_sha256,
        "source_sha256": source_sha256,
        "native_id": _safe_text(native_id, 160),
        "rule_id": _label(rule_id, "unnamed-rule"),
        "severity": severity_text,
        "severity_basis": severity_basis,
        "path": _safe_text(path, 4_096),
        "line": clean_line,
        "evidence_state": _label(evidence_state, "unverified"),
        "confidence": confidence if type(confidence) in {int, float} else None,
        "exploitability": _safe_text(exploitability, 160),
        "advisory": dict(advisory),
        "details": dict(details),
    }
    body["evidence_id"] = "assure42-" + digest_json(body)[:24]
    return body


def _component(*, name: str, module: Any, native_schema: str,
               native_version: str, native_digest: str, native_status: str,
               self_consistency: str, snapshot_sha256: str,
               metrics: Mapping[str, Any], gaps: Sequence[Mapping[str, Any]],
               static_contract: Mapping[str, Any],
               verification_level: str) -> dict[str, Any]:
    identity = _module_identity(module)
    body = {
        "schema": COMPONENT_SCHEMA,
        "version": VERSION,
        "name": name,
        "module": identity["module"],
        "module_source_file_sha256": identity["source_sha256"],
        "native_schema": native_schema,
        "native_version": native_version,
        "input_snapshot_sha256": snapshot_sha256,
        "native_output_sha256": native_digest,
        "native_status": native_status,
        "native_self_consistency": self_consistency,
        "verification_level": verification_level,
        "metrics": dict(metrics),
        "coverage_gap_count": len({digest_json(row) for row in gaps}),
        "static_contract": dict(static_contract),
    }
    body["projection_sha256"] = digest_json(body)
    return body


def _line_is_valid(path: str, line: int, files: Mapping[str, Mapping[str, Any]]) -> bool:
    row = files.get(path.casefold())
    return bool(row and type(line) is int and 1 <= line <= row["line_count"])


def _language_projection(files: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    counts = language_coverage42.rule_counts()
    wildcard = language_coverage42.wildcard_rules()
    by_language: Counter[str] = Counter()
    uncovered: list[dict[str, Any]] = []
    file_rows = list(files)
    for item in file_rows:
        path = str(item["path"])
        source_sha256 = str(item["sha256"])
        language = detect.language_for(path)
        label = language if isinstance(language, str) and language else "unsupported"
        by_language[label] += 1
        if counts.get(label, 0) <= 0:
            uncovered.append({
                "path": path,
                "language": label,
                "source_sha256": source_sha256,
                "reason": "no-language-specific-core-rules",
            })
    body = {
        "schema": language_coverage42.SCHEMA,
        "version": language_coverage42.VERSION,
        "file_count": len(file_rows),
        "by_language": dict(sorted(by_language.items())),
        "covered_languages": sorted(counts),
        "specific_rule_counts": dict(sorted(counts.items())),
        "wildcard_rule_count": wildcard,
        "uncovered": uncovered,
    }
    body["report_sha256"] = digest_json(body)
    return body


def _language_report(snapshot: snapshot41.SourceSnapshot) -> dict[str, Any]:
    return _language_projection(
        {"path": item.path, "sha256": item.sha256}
        for item in snapshot.files)


def _run_detect(snapshot: snapshot41.SourceSnapshot,
                file_rows: Mapping[str, Mapping[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    sources: list[tuple[str, str, str, bool]] = []
    native_gaps: list[dict[str, Any]] = []
    for item in snapshot.files:
        language = detect.language_for(item.path)
        if language is None:
            continue
        text, replaced = item.text()
        if replaced:
            native_gaps.append({"path": item.path, "reason": "utf8-decoded-with-replacement"})
        sources.append((item.path, text, language, replaced))

    java_text = [text for path, text, language, _ in sources if language == "java"]
    java_seed = detect.java_cross_file_taint(java_text) if len(java_text) > 1 else detect.CrossFileTaint()
    accepted: list[Any] = []
    truncated = False
    for path, text, language, _ in sources:
        rows = detect.scan_source(
            text, path, language, deep=True,
            cross_file_taint=java_seed if language == "java" else detect.CrossFileTaint(),
        )
        remaining = MAX_EVIDENCE - len(accepted)
        if len(rows) > remaining:
            accepted.extend(rows[:max(0, remaining)])
            native_gaps.append({"path": path, "reason": "detect-finding-budget-reached"})
            truncated = True
            break
        accepted.extend(rows)

    public_rows: list[dict[str, Any]] = []
    for finding in accepted:
        path = _safe_text(getattr(finding, "path", ""), 4_096)
        line = getattr(finding, "line", 1)
        if not _line_is_valid(path, line, file_rows):
            native_gaps.append({"path": path, "reason": "detect-invalid-finding-location"})
            continue
        public_rows.append({
            "path": path,
            "line": line,
            "rule_id": _label(getattr(finding, "rule", "")),
            "severity": str(getattr(finding, "severity", "INFO")).lower(),
            "cwe": _safe_text(detect.RULE_CWE.get(getattr(finding, "rule", ""), ""), 32),
            "confidence": getattr(finding, "confidence", None),
            "exploitability": _safe_text(getattr(finding, "exploitability", ""), 160),
            "advisory": _advisory(
                getattr(finding, "fix", ""),
                safe_to_autofix=getattr(finding, "safe_to_autofix", False),
            ),
        })
    public_rows.sort(key=lambda row: (
        row["path"], row["line"], -SEVERITY_ORDER.get(row["severity"], 0), row["rule_id"]))
    adapter_body = {
        "schema": "attestor.detect-bounded-adapter/4.2",
        "version": VERSION,
        "snapshot_sha256": snapshot.snapshot_sha256,
        "files_scanned": len(sources),
        "finding_budget": MAX_EVIDENCE,
        "findings": public_rows,
        "gaps": native_gaps,
        "truncated": truncated,
    }
    adapter_digest = digest_json(adapter_body)
    component = _component(
        name="detect",
        module=detect,
        native_schema=adapter_body["schema"],
        native_version=VERSION,
        native_digest=adapter_digest,
        native_status="partial" if native_gaps else "complete",
        self_consistency="bounded-adapter-normalized",
        snapshot_sha256=snapshot.snapshot_sha256,
        metrics={
            "files_scanned": len(sources),
            "findings": len(public_rows),
            "normalized_evidence": len(public_rows),
            "specific_rules": sum(language_coverage42.rule_counts().values()),
            "finding_budget": MAX_EVIDENCE,
        },
        gaps=native_gaps,
        static_contract=DETECT_STATIC_CONTRACT,
        verification_level="bounded-local-normalization-no-native-report-verifier",
    )
    evidence = [
        _evidence(
            analyzer="detect",
            analyzer_schema=component["native_schema"],
            child_digest=component["native_output_sha256"],
            snapshot_sha256=snapshot.snapshot_sha256,
            source_sha256=file_rows[row["path"].casefold()]["sha256"],
            native_id="",
            rule_id=row["rule_id"],
            severity=row["severity"],
            severity_basis="native-rule-metadata",
            path=row["path"],
            line=row["line"],
            evidence_state="bounded-static-candidate",
            confidence=row["confidence"],
            exploitability=row["exploitability"],
            advisory=row["advisory"],
            details={"kind": "core-rule", "cwe": row["cwe"],
                     "runtime_exploitability": "unverified"},
        )
        for row in public_rows
    ]
    gaps = [
        _gap("detect", component["native_schema"], component["native_output_sha256"],
             row.get("path", ""), row.get("reason", "detect-gap"), row)
        for row in native_gaps
    ]
    return component, evidence, gaps


def _run_semantic(snapshot: snapshot41.SourceSnapshot,
                  file_rows: Mapping[str, Mapping[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    native = semantic_graph41.build(snapshot, max_nodes=MAX_SEMANTIC_NODES)
    valid, errors = semantic_graph41.verify_report(native)
    if not valid or native.get("snapshot_sha256") != snapshot.snapshot_sha256:
        raise AssuranceOperationalError(
            "semantic graph did not self-verify: " + ", ".join(errors[:3]))
    expected_contract = SEMANTIC_STATIC_CONTRACT
    if native.get("static_contract") != expected_contract:
        raise AssuranceOperationalError("semantic graph static contract was not passive")
    native_gaps = list(native.get("coverage", {}).get("gaps", []))
    witnesses = list(native.get("graph", {}).get("taint_witnesses", []))
    projected: list[dict[str, Any]] = []
    for witness in witnesses[:MAX_EVIDENCE]:
        source = witness.get("source", {})
        sink = witness.get("sink", {})
        source_path = _safe_text(source.get("path", ""), 4_096)
        sink_path = _safe_text(sink.get("path", ""), 4_096)
        source_line = source.get("line", 1)
        sink_line = sink.get("line", 1)
        if (not _line_is_valid(source_path, source_line, file_rows)
                or not _line_is_valid(sink_path, sink_line, file_rows)):
            native_gaps.append({"path": sink_path, "reason": "semantic-invalid-witness-location"})
            continue
        context = _label(witness.get("context", "dataflow"))
        advice = {
            "command": "Use an argument-vector API and strict allowlists; never compose a shell command from untrusted data.",
            "sql": "Use typed parameter binding and keep untrusted values out of SQL syntax.",
            "code": "Remove dynamic evaluation of untrusted data and use a constrained parser or dispatch table.",
        }.get(context, "Validate the trust boundary and replace the sensitive sink with a constrained API.")
        projected.append(_evidence(
            analyzer="semantic_graph41",
            analyzer_schema=native["schema"],
            child_digest=native["report_sha256"],
            snapshot_sha256=snapshot.snapshot_sha256,
            source_sha256=file_rows[sink_path.casefold()]["sha256"],
            native_id=witness.get("id", ""),
            rule_id="semantic-taint-" + context,
            severity="high",
            severity_basis="assurance-policy-default",
            path=sink_path,
            line=sink_line,
            evidence_state="bounded-parser-derived",
            confidence=None,
            exploitability="runtime-unverified",
            advisory=_advisory(advice),
            details={
                "kind": "semantic-taint-witness",
                "cwe": _safe_text(witness.get("cwe", ""), 32),
                "context": context,
                "source": {
                    "path": source_path,
                    "line": source_line,
                    "source_sha256": file_rows[source_path.casefold()]["sha256"],
                },
                "sink": {
                    "path": sink_path,
                    "line": sink_line,
                    "source_sha256": file_rows[sink_path.casefold()]["sha256"],
                },
                "cross_file": bool(witness.get("cross_file", False)),
                "precision": _label(witness.get("precision", "bounded-static")),
                "runtime_exploitability": "unverified",
            },
        ))
    if len(witnesses) > MAX_EVIDENCE:
        native_gaps.append({"path": "", "reason": "semantic-evidence-budget-reached"})
    component = _component(
        name="semantic_graph41",
        module=semantic_graph41,
        native_schema=native["schema"],
        native_version=native["version"],
        native_digest=native["report_sha256"],
        native_status="partial" if native_gaps else "complete",
        self_consistency="native-verifier-and-snapshot-binding-passed",
        snapshot_sha256=snapshot.snapshot_sha256,
        metrics={
            "symbols": len(native["graph"]["symbols"]),
            "calls": len(native["graph"]["calls"]),
            "data_flow": len(native["graph"]["data_flow"]),
            "taint_witnesses": len(witnesses),
            "normalized_evidence": len(projected),
            "selected_node_budget": MAX_SEMANTIC_NODES,
        },
        gaps=native_gaps,
        static_contract=expected_contract,
        verification_level="native-self-consistency-plus-shared-snapshot-binding",
    )
    gaps = [
        _gap("semantic_graph41", native["schema"], native["report_sha256"],
             row.get("path", ""), row.get("reason", "semantic-gap"), row)
        for row in native_gaps
    ]
    return component, projected, gaps


def _run_attack(snapshot: snapshot41.SourceSnapshot,
                file_rows: Mapping[str, Mapping[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    native = attack_surface413.analyze(".", snapshot_or_documents=snapshot)
    valid, errors = attack_surface413.verify_report(native)
    if not valid:
        raise AssuranceOperationalError(
            "attack-surface report did not self-verify: " + ", ".join(errors[:3]))
    expected_execution = ATTACK_STATIC_CONTRACT
    if native.get("execution") != expected_execution or native.get("status") == "failed":
        raise AssuranceOperationalError("attack-surface analyzer was not passive or failed")
    inventory = native.get("coverage", {}).get("inventory", {})
    if inventory.get("scope_kind") != "provided-snapshot":
        raise AssuranceOperationalError("attack-surface analyzer reread the target")
    native_gaps = list(native.get("coverage", {}).get("gaps", []))
    projected: list[dict[str, Any]] = []
    for row in list(native.get("findings", []))[:MAX_EVIDENCE]:
        path = _safe_text(row.get("path", ""), 4_096)
        line = row.get("line", 1)
        if not _line_is_valid(path, line, file_rows):
            native_gaps.append({"path": path, "reason": "attack-invalid-finding-location"})
            continue
        projected.append(_evidence(
            analyzer="attack_surface413",
            analyzer_schema=native["schema"],
            child_digest=native["report_sha256"],
            snapshot_sha256=snapshot.snapshot_sha256,
            source_sha256=file_rows[path.casefold()]["sha256"],
            native_id=row.get("id", ""),
            rule_id=row.get("rule", "attack-surface"),
            severity=row.get("severity", "info"),
            severity_basis="native-finding-metadata",
            path=path,
            line=line,
            evidence_state=row.get("evidence_state", "unverified"),
            confidence=None,
            exploitability=str(row.get("exploitability", {}).get("band", "unverified")),
            advisory=_advisory(row.get("remediation", "")),
            details={
                "kind": "attack-surface-finding",
                "category": _label(row.get("category", "attack-surface")),
                "cwe": _safe_text(row.get("cwe", ""), 32),
                "runtime_exploitability": "unverified",
            },
        ))
    if len(native.get("findings", [])) > MAX_EVIDENCE:
        native_gaps.append({"path": "", "reason": "attack-evidence-budget-reached"})
    component = _component(
        name="attack_surface413",
        module=attack_surface413,
        native_schema=native["schema"],
        native_version=native["version"],
        native_digest=native["report_sha256"],
        native_status=native["status"],
        self_consistency="native-verifier-and-provided-snapshot-mode-passed",
        snapshot_sha256=snapshot.snapshot_sha256,
        metrics={
            "findings": len(native["findings"]),
            "normalized_evidence": len(projected),
            "attack_paths": len(native["attack_paths"]),
            "entry_points": native["summary"]["entry_points"],
            "files_loaded": inventory.get("files_loaded", 0),
        },
        gaps=native_gaps,
        static_contract=expected_execution,
        verification_level="native-self-consistency-plus-provided-snapshot-mode",
    )
    gaps = [
        _gap("attack_surface413", native["schema"], native["report_sha256"],
             row.get("path", ""), row.get("reason", "attack-gap"), row)
        for row in native_gaps
    ]
    return component, projected, gaps


def _run_posture(snapshot: snapshot41.SourceSnapshot,
                 file_rows: Mapping[str, Mapping[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    artifacts = [security_posture413.Artifact(item.path, item.content, executable=False)
                 for item in snapshot.files]
    collection_gaps = [
        {"capability": "snapshot", "reason": _label(row.get("reason", "snapshot-gap")),
         "path": _safe_text(row.get("path", ""), 1_024)}
        for row in snapshot.gaps
    ]
    collection_gaps.append({
        "capability": "artifact-executable-metadata",
        "reason": "executable-mode-not-represented-by-shared-snapshot",
        "path": "",
    })
    native = security_posture413.scan_security_posture(
        artifacts, collection_gaps=collection_gaps)
    if not security_posture413.verify_report(native):
        raise AssuranceOperationalError("security-posture report did not self-verify")
    expected_execution = POSTURE_STATIC_CONTRACT
    if native.get("execution") != expected_execution:
        raise AssuranceOperationalError("security-posture analyzer was not passive")
    if (native.get("scope", {}).get("artifact_count") != len(snapshot.files)
            or native.get("scope", {}).get("input_bytes") != sum(item.size for item in snapshot.files)):
        raise AssuranceOperationalError("security-posture snapshot accounting mismatch")
    native_gaps = list(native.get("gaps", []))
    projected: list[dict[str, Any]] = []
    for row in list(native.get("findings", []))[:MAX_EVIDENCE]:
        path = _safe_text(row.get("path", ""), 4_096)
        line = row.get("line", 1)
        if not _line_is_valid(path, line, file_rows):
            native_gaps.append({"path": path, "reason": "posture-invalid-finding-location",
                                "capability": "finding-evidence"})
            continue
        projected.append(_evidence(
            analyzer="security_posture413",
            analyzer_schema=native["schema"],
            child_digest=native["report_sha256"],
            snapshot_sha256=snapshot.snapshot_sha256,
            source_sha256=file_rows[path.casefold()]["sha256"],
            native_id=row.get("finding_id", ""),
            rule_id=row.get("rule_id", "security-posture"),
            severity=row.get("severity", "info"),
            severity_basis="native-finding-metadata",
            path=path,
            line=line,
            evidence_state=row.get("evidence_state", "unverified"),
            confidence=None,
            exploitability="runtime-unverified",
            advisory=_advisory(row.get("remediation", "")),
            details={
                "kind": "security-posture-finding",
                "category": _label(row.get("category", "security-posture")),
                "source_kind": _label(row.get("source_kind", "snapshot-artifact")),
                "runtime_exploitability": "unverified",
            },
        ))
    if len(native.get("findings", [])) > MAX_EVIDENCE:
        native_gaps.append({"path": "", "reason": "posture-evidence-budget-reached",
                            "capability": "reporting"})
    component = _component(
        name="security_posture413",
        module=security_posture413,
        native_schema=native["schema"],
        native_version=native["version"],
        native_digest=native["report_sha256"],
        native_status=native["status"],
        self_consistency="native-verifier-and-artifact-accounting-passed",
        snapshot_sha256=snapshot.snapshot_sha256,
        metrics={
            "findings": len(native["findings"]),
            "normalized_evidence": len(projected),
            "sbom_components": native["sbom"]["component_count"],
            "artifacts": native["scope"]["artifact_count"],
            "current_secret_matches": native["secret_lifecycle"]["current_snapshot_match_count"],
        },
        gaps=native_gaps,
        static_contract=expected_execution,
        verification_level="native-self-consistency-plus-artifact-accounting",
    )
    gaps = [
        _gap("security_posture413", native["schema"], native["report_sha256"],
             row.get("path", ""), row.get("capability", row.get("reason", "posture-gap")), row)
        for row in native_gaps
    ]
    return component, projected, gaps


def _summary(snapshot_projection: Mapping[str, Any], analyzers: Mapping[str, Any],
             evidence: Sequence[Mapping[str, Any]], gaps: Sequence[Mapping[str, Any]],
             language_report: Mapping[str, Any]) -> dict[str, Any]:
    by_severity = {name: 0 for name in SEVERITY_ORDER}
    for row in evidence:
        by_severity[row["severity"]] += 1
    return {
        "file_count": snapshot_projection["file_count"],
        "total_bytes": snapshot_projection["total_bytes"],
        "language_count": len(language_report["by_language"]),
        "uncovered_files": len(language_report["uncovered"]),
        "core_rules": analyzers["detect"]["metrics"]["specific_rules"],
        "core_findings": analyzers["detect"]["metrics"]["findings"],
        "semantic_taint_witnesses": analyzers["semantic_graph41"]["metrics"]["taint_witnesses"],
        "attack_surface_findings": analyzers["attack_surface413"]["metrics"]["findings"],
        "attack_paths": analyzers["attack_surface413"]["metrics"]["attack_paths"],
        "posture_findings": analyzers["security_posture413"]["metrics"]["findings"],
        "sbom_components": analyzers["security_posture413"]["metrics"]["sbom_components"],
        "evidence_count": len(evidence),
        "gap_count": len(gaps),
        "by_severity": by_severity,
    }


def _native_has_findings(analyzers: Mapping[str, Any], evidence: Sequence[Any]) -> bool:
    if evidence:
        return True
    try:
        return any((
            analyzers["detect"]["metrics"]["findings"] > 0,
            analyzers["semantic_graph41"]["metrics"]["taint_witnesses"] > 0,
            analyzers["attack_surface413"]["metrics"]["findings"] > 0,
            analyzers["security_posture413"]["metrics"]["findings"] > 0,
        ))
    except (KeyError, TypeError):
        return False


def _status(evidence: Sequence[Any], gaps: Sequence[Any],
            analyzers: Mapping[str, Any]) -> str:
    has_findings = _native_has_findings(analyzers, evidence)
    if gaps:
        return "incomplete-findings" if has_findings else "incomplete"
    return "findings" if has_findings else "clean"


def run_assurance(root: str | os.PathLike[str]) -> dict[str, Any]:
    """Run the fixed passive assurance profile on one directory."""
    try:
        snapshot = snapshot41.capture(root, PROFILE_LIMITS)
    except (snapshot41.SnapshotError, TypeError, ValueError, OSError) as exc:
        raise AssuranceInputError("directory could not be captured by the assurance profile") from exc
    projection = _snapshot_projection(snapshot)
    file_rows = {row["path"].casefold(): row for row in projection["files"]}
    language_report = _language_report(snapshot)

    try:
        detect_component, detect_evidence, detect_gaps = _run_detect(snapshot, file_rows)
        semantic_component, semantic_evidence, semantic_gaps = _run_semantic(snapshot, file_rows)
        attack_component, attack_evidence, attack_gaps = _run_attack(snapshot, file_rows)
        posture_component, posture_evidence, posture_gaps = _run_posture(snapshot, file_rows)
    except AssuranceError:
        raise
    except (MemoryError, RecursionError) as exc:
        raise AssuranceOperationalError("analyzer resource boundary was exceeded") from exc
    except Exception as exc:
        raise AssuranceOperationalError(
            "a fixed analyzer failed: " + type(exc).__name__) from exc

    analyzers = {
        "attack_surface413": attack_component,
        "detect": detect_component,
        "security_posture413": posture_component,
        "semantic_graph41": semantic_component,
    }
    evidence = [*detect_evidence, *semantic_evidence, *attack_evidence, *posture_evidence]
    evidence.sort(key=lambda row: (
        -SEVERITY_ORDER[row["severity"]], row["path"], row["line"],
        row["analyzer"], row["rule_id"], row["evidence_id"]))
    gaps = [
        _gap("snapshot", projection["schema"], projection["native_report_sha256"],
             row["path"], row["reason"], row)
        for row in projection["native_gaps"]
    ]
    for row in language_report["uncovered"]:
        gaps.append(_gap(
            "language_coverage42", language_report["schema"],
            language_report["report_sha256"], row["path"], row["reason"], row))
    gaps.extend(detect_gaps)
    gaps.extend(semantic_gaps)
    gaps.extend(attack_gaps)
    gaps.extend(posture_gaps)
    unique_gaps = {row["gap_id"]: row for row in gaps}
    gaps = sorted(unique_gaps.values(), key=lambda row: (
        row["analyzer"], row["path"], row["reason"], row["gap_id"]))
    if len(gaps) > MAX_GAPS:
        gaps = gaps[:MAX_GAPS - 1]
        marker = _gap("assurance42", SCHEMA, "0" * 64, "",
                      "assurance-gap-budget-reached", {"limit": MAX_GAPS})
        gaps.append(marker)

    status = _status(evidence, gaps, analyzers)
    summary = _summary(projection, analyzers, evidence, gaps, language_report)
    body = {
        "schema": SCHEMA,
        "version": VERSION,
        "experimental": True,
        "status": status,
        "complete": status in {"clean", "findings"},
        "summary": summary,
        "snapshot": projection,
        "analyzers": analyzers,
        "evidence": evidence,
        "coverage": {
            "complete": not gaps,
            "gaps": gaps,
            "status_precedence": "incomplete-outranks-findings",
        },
        "language_coverage": language_report,
        "execution": _expected_engine_execution(),
        "cost_profile": _expected_cost_profile(),
        "limitations": _expected_limitations(),
    }
    report = _seal(body)
    if len(canonical_json(report).encode("utf-8")) > MAX_REPORT_BYTES:
        raise AssuranceOperationalError("assurance report exceeded its output boundary")
    valid, errors = verify_report(report)
    if not valid:
        raise AssuranceOperationalError(
            "generated assurance report did not self-verify: " + ", ".join(errors[:3]))
    return report


def _digest_valid(value: Any) -> bool:
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def _verify_report_impl(report: Any) -> tuple[bool, list[str]]:
    """Verify the exact projected evidence and all recomputable relationships."""
    errors: list[str] = []

    def error(message: str) -> None:
        if len(errors) < 100:
            errors.append(message)

    exact = {
        "schema", "version", "experimental", "status", "complete", "summary",
        "snapshot", "analyzers", "evidence", "coverage", "language_coverage",
        "execution", "cost_profile", "limitations", "report_sha256",
    }
    if type(report) is not dict:
        return False, ["report is not an object"]
    if set(report) != exact:
        error("top-level report shape mismatch")
    if report.get("schema") != SCHEMA or report.get("version") != VERSION:
        error("schema or version mismatch")
    if report.get("experimental") is not True:
        error("experimental marker mismatch")
    body = {key: value for key, value in report.items() if key != "report_sha256"}
    try:
        if report.get("report_sha256") != digest_json(body):
            error("report digest mismatch")
        if len(canonical_json(report).encode("utf-8")) > MAX_REPORT_BYTES:
            error("report exceeds output boundary")
    except AssuranceError:
        error("report is not bounded canonical JSON")
    if report.get("execution") != _expected_engine_execution():
        error("execution contract mismatch")
    if report.get("cost_profile") != _expected_cost_profile():
        error("cost profile mismatch")
    if report.get("limitations") != _expected_limitations():
        error("limitations mismatch")

    snapshot = report.get("snapshot")
    file_rows: dict[str, Mapping[str, Any]] = {}
    if type(snapshot) is not dict:
        error("snapshot projection is malformed")
        snapshot = {}
    else:
        snapshot_keys = {
            "schema", "version", "analysis_level", "root", "snapshot_sha256",
            "native_report_sha256", "file_count", "total_bytes", "files",
            "native_gaps", "limits", "capture_contract", "projection_sha256",
        }
        if set(snapshot) != snapshot_keys:
            error("snapshot projection shape mismatch")
        if (snapshot.get("schema") != snapshot41.SCHEMA
                or snapshot.get("version") != snapshot41.VERSION
                or snapshot.get("analysis_level") != "immutable-content-addressed-static-source"):
            error("snapshot native identity mismatch")
        if not _digest_valid(snapshot.get("native_report_sha256")):
            error("snapshot native report digest is invalid")
        if snapshot.get("capture_contract") != SNAPSHOT_CAPTURE_CONTRACT:
            error("snapshot capture contract mismatch")
        projection_digest = snapshot.get("projection_sha256")
        projection_body = {key: value for key, value in snapshot.items()
                           if key != "projection_sha256"}
        if projection_digest != digest_json(projection_body):
            error("snapshot projection digest mismatch")
        files = snapshot.get("files")
        if type(files) is not list or len(files) > PROFILE_LIMITS.max_files:
            error("snapshot file manifest is malformed")
            files = []
        paths: list[str] = []
        total = 0
        for row in files:
            if (type(row) is not dict or set(row) != {
                    "path", "language", "size", "line_count", "sha256"}):
                error("snapshot file row shape mismatch")
                continue
            try:
                path = snapshot41.safe_relative(row["path"])
            except (snapshot41.SnapshotError, TypeError):
                error("snapshot file path is unsafe")
                continue
            if (path != row["path"] or _safe_text(path, 4_096) != path or len(path) > 1_024
                    or unicodedata.normalize("NFC", path) != path):
                error("snapshot file path is unsafe to render")
                continue
            expected_snapshot_language = getattr(snapshot41, "_LANGUAGE", {}).get(
                Path(path).suffix.casefold(), "unknown")
            if (type(row["size"]) is not int or not 0 <= row["size"] <= PROFILE_LIMITS.max_file_bytes
                    or type(row["line_count"]) is not int or row["line_count"] < 1
                    or not _digest_valid(row["sha256"])
                    or row["language"] != expected_snapshot_language):
                error("snapshot file evidence is invalid")
                continue
            if path.casefold() in file_rows:
                error("snapshot paths collide")
                continue
            paths.append(path)
            total += row["size"]
            file_rows[path.casefold()] = row
        if paths != sorted(paths):
            error("snapshot paths are not sorted")
        if (type(snapshot.get("file_count")) is not int
                or type(snapshot.get("total_bytes")) is not int
                or snapshot.get("file_count") != len(files)
                or snapshot.get("total_bytes") != total
                or total > PROFILE_LIMITS.max_total_bytes):
            error("snapshot totals mismatch")
        if snapshot.get("root") != "." or not _digest_valid(snapshot.get("snapshot_sha256")):
            error("snapshot identity is invalid")
        expected_limits = {name: getattr(PROFILE_LIMITS, name)
                           for name in PROFILE_LIMITS.__dataclass_fields__}
        if snapshot.get("limits") != expected_limits:
            error("snapshot limits mismatch")
        native_gaps = snapshot.get("native_gaps")
        if type(native_gaps) is not list or len(native_gaps) > PROFILE_LIMITS.max_gaps:
            error("snapshot native gaps are malformed")
        else:
            for row in native_gaps:
                if (type(row) is not dict or set(row) != {
                        "path", "reason", "native_gap_sha256"}
                        or not _digest_valid(row.get("native_gap_sha256"))
                        or _safe_text(row.get("path", ""), 4_096) != row.get("path")
                        or _label(row.get("reason", "")) != row.get("reason")):
                    error("snapshot native gap evidence is invalid")

    analyzers = report.get("analyzers")
    expected_analyzers = {
        "attack_surface413", "detect", "security_posture413", "semantic_graph41"}
    if type(analyzers) is not dict or set(analyzers) != expected_analyzers:
        error("analyzer projection set mismatch")
        analyzers = {}
    else:
        component_keys = {
            "schema", "version", "name", "module", "module_source_file_sha256",
            "native_schema", "native_version", "input_snapshot_sha256",
            "native_output_sha256", "native_status", "native_self_consistency",
            "verification_level", "metrics", "coverage_gap_count",
            "static_contract", "projection_sha256",
        }
        component_specs = {
            "detect": {
                "module": detect,
                "native_schema": "attestor.detect-bounded-adapter/4.2",
                "native_version": VERSION,
                "statuses": {"complete", "partial"},
                "consistency": "bounded-adapter-normalized",
                "verification": "bounded-local-normalization-no-native-report-verifier",
                "contract": DETECT_STATIC_CONTRACT,
                "metric_keys": {"files_scanned", "findings", "normalized_evidence",
                                "specific_rules", "finding_budget"},
            },
            "semantic_graph41": {
                "module": semantic_graph41,
                "native_schema": semantic_graph41.SCHEMA,
                "native_version": semantic_graph41.VERSION,
                "statuses": {"complete", "partial"},
                "consistency": "native-verifier-and-snapshot-binding-passed",
                "verification": "native-self-consistency-plus-shared-snapshot-binding",
                "contract": SEMANTIC_STATIC_CONTRACT,
                "metric_keys": {"symbols", "calls", "data_flow", "taint_witnesses",
                                "normalized_evidence", "selected_node_budget"},
            },
            "attack_surface413": {
                "module": attack_surface413,
                "native_schema": attack_surface413.SCHEMA,
                "native_version": attack_surface413.VERSION,
                "statuses": {"clean", "findings", "partial", "partial-findings"},
                "consistency": "native-verifier-and-provided-snapshot-mode-passed",
                "verification": "native-self-consistency-plus-provided-snapshot-mode",
                "contract": ATTACK_STATIC_CONTRACT,
                "metric_keys": {"findings", "normalized_evidence", "attack_paths",
                                "entry_points", "files_loaded"},
            },
            "security_posture413": {
                "module": security_posture413,
                "native_schema": security_posture413.SCHEMA,
                "native_version": security_posture413.VERSION,
                "statuses": {"complete", "partial"},
                "consistency": "native-verifier-and-artifact-accounting-passed",
                "verification": "native-self-consistency-plus-artifact-accounting",
                "contract": POSTURE_STATIC_CONTRACT,
                "metric_keys": {"findings", "normalized_evidence", "sbom_components",
                                "artifacts", "current_secret_matches"},
            },
        }
        for name, row in analyzers.items():
            spec = component_specs[name]
            if (type(row) is not dict or set(row) != component_keys
                    or row.get("schema") != COMPONENT_SCHEMA
                    or row.get("version") != VERSION):
                error("analyzer component shape mismatch")
                continue
            body = {key: value for key, value in row.items() if key != "projection_sha256"}
            if row.get("projection_sha256") != digest_json(body):
                error("analyzer projection digest mismatch")
            if row.get("name") != name or row.get("input_snapshot_sha256") != snapshot.get("snapshot_sha256"):
                error("analyzer snapshot binding mismatch")
            if (row.get("module") != spec["module"].__name__
                    or row.get("native_schema") != spec["native_schema"]
                    or row.get("native_version") != spec["native_version"]
                    or row.get("native_status") not in spec["statuses"]
                    or row.get("native_self_consistency") != spec["consistency"]
                    or row.get("verification_level") != spec["verification"]
                    or row.get("static_contract") != spec["contract"]):
                error("analyzer identity or static contract mismatch")
            if not _digest_valid(row.get("native_output_sha256")):
                error("analyzer native output digest is invalid")
            try:
                expected_module = _module_identity(spec["module"])
            except AssuranceOperationalError:
                error("current analyzer module identity is unavailable")
                expected_module = {}
            if (not _digest_valid(row.get("module_source_file_sha256"))
                    or row.get("module_source_file_sha256") != expected_module.get("source_sha256")):
                error("analyzer module digest is invalid")
            if type(row.get("coverage_gap_count")) is not int or row["coverage_gap_count"] < 0:
                error("analyzer gap count is invalid")
            metrics = row.get("metrics")
            if (type(metrics) is not dict or set(metrics) != spec["metric_keys"]
                    or any(type(value) is not int or value < 0
                           for value in metrics.values())):
                error("analyzer metrics are invalid")
                continue
            if name == "detect" and (
                    metrics["finding_budget"] != MAX_EVIDENCE
                    or metrics["specific_rules"] != sum(language_coverage42.rule_counts().values())
                    or metrics["files_scanned"] > snapshot.get("file_count", 0)):
                error("detect metrics violate the fixed profile")
            if name == "semantic_graph41" and metrics["selected_node_budget"] != MAX_SEMANTIC_NODES:
                error("semantic metrics violate the fixed profile")
            if name == "security_posture413" and metrics["artifacts"] != snapshot.get("file_count"):
                error("posture artifact count does not match the snapshot")

    language = report.get("language_coverage")
    if type(language) is not dict:
        error("language coverage report is malformed")
        language = {}
    else:
        expected_language = _language_projection(
            {"path": row["path"], "sha256": row["sha256"]}
            for row in snapshot.get("files", []) if type(row) is dict
            and "path" in row and "sha256" in row)
        if language != expected_language:
            error("language coverage does not match the snapshot and fixed rule registry")

    evidence = report.get("evidence")
    if type(evidence) is not list or len(evidence) > 4 * MAX_EVIDENCE:
        error("evidence list is malformed")
        evidence = []
    evidence_keys = {
        "evidence_id", "analyzer", "analyzer_schema", "child_report_sha256",
        "snapshot_sha256", "source_sha256", "native_id", "rule_id", "severity",
        "severity_basis", "path", "line", "evidence_state", "confidence",
        "exploitability", "advisory", "details",
    }
    seen_evidence: set[str] = set()
    for row in evidence:
        if type(row) is not dict or set(row) != evidence_keys:
            error("evidence row is malformed")
            continue
        body = {key: value for key, value in row.items() if key != "evidence_id"}
        expected_id = "assure42-" + digest_json(body)[:24]
        if row.get("evidence_id") != expected_id or expected_id in seen_evidence:
            error("evidence digest or uniqueness mismatch")
        seen_evidence.add(expected_id)
        path = row.get("path")
        line = row.get("line")
        source = file_rows.get(path.casefold()) if isinstance(path, str) else None
        if (source is None or row.get("source_sha256") != source.get("sha256")
                or type(line) is not int or not 1 <= line <= source.get("line_count", 0)):
            error("evidence source binding mismatch")
        component = analyzers.get(row.get("analyzer"), {}) if isinstance(analyzers, dict) else {}
        if (row.get("child_report_sha256") != component.get("native_output_sha256")
                or row.get("analyzer_schema") != component.get("native_schema")
                or row.get("snapshot_sha256") != snapshot.get("snapshot_sha256")):
            error("evidence analyzer binding mismatch")
        expected_basis = {
            "detect": "native-rule-metadata",
            "semantic_graph41": "assurance-policy-default",
            "attack_surface413": "native-finding-metadata",
            "security_posture413": "native-finding-metadata",
        }.get(row.get("analyzer"))
        if (row.get("severity") not in SEVERITY_ORDER
                or row.get("severity_basis") != expected_basis
                or _label(row.get("rule_id", "")) != row.get("rule_id")
                or _label(row.get("evidence_state", "")) != row.get("evidence_state")
                or not _digest_valid(row.get("source_sha256"))
                or not _digest_valid(row.get("snapshot_sha256"))
                or not isinstance(row.get("native_id"), str)
                or not isinstance(row.get("exploitability"), str)
                or type(row.get("details")) is not dict
                or (row.get("confidence") is not None
                    and type(row.get("confidence")) not in {int, float})):
            error("evidence metadata is invalid")
        details = row.get("details") if type(row.get("details")) is dict else {}
        analyzer_name = row.get("analyzer")
        if analyzer_name == "detect":
            if (set(details) != {"kind", "cwe", "runtime_exploitability"}
                    or details.get("kind") != "core-rule"
                    or details.get("runtime_exploitability") != "unverified"
                    or not isinstance(details.get("cwe"), str)
                    or (details.get("cwe") and re.fullmatch(r"CWE-[0-9]+", details["cwe"]) is None)):
                error("detect evidence details are invalid")
        elif analyzer_name == "semantic_graph41":
            if set(details) != {
                    "kind", "cwe", "context", "source", "sink", "cross_file",
                    "precision", "runtime_exploitability"}:
                error("semantic evidence details shape mismatch")
            else:
                source_detail = details.get("source")
                sink_detail = details.get("sink")
                if (details.get("kind") != "semantic-taint-witness"
                        or details.get("runtime_exploitability") != "unverified"
                        or type(details.get("cross_file")) is not bool
                        or _label(details.get("context", "")) != details.get("context")
                        or _label(details.get("precision", "")) != details.get("precision")
                        or not isinstance(details.get("cwe"), str)
                        or type(source_detail) is not dict
                        or type(sink_detail) is not dict
                        or set(source_detail or {}) != {"path", "line", "source_sha256"}
                        or set(sink_detail or {}) != {"path", "line", "source_sha256"}):
                    error("semantic evidence details are invalid")
                else:
                    source_manifest = file_rows.get(str(source_detail["path"]).casefold())
                    sink_manifest = file_rows.get(str(sink_detail["path"]).casefold())
                    if (source_manifest is None or sink_manifest is None
                            or source_detail["source_sha256"] != source_manifest["sha256"]
                            or sink_detail["source_sha256"] != sink_manifest["sha256"]
                            or type(source_detail["line"]) is not int
                            or type(sink_detail["line"]) is not int
                            or not 1 <= source_detail["line"] <= source_manifest["line_count"]
                            or not 1 <= sink_detail["line"] <= sink_manifest["line_count"]
                            or details["cross_file"] is not (
                                source_detail["path"] != sink_detail["path"])
                            or sink_detail["path"] != row.get("path")
                            or sink_detail["line"] != row.get("line")):
                        error("semantic witness is not bound to the snapshot")
        elif analyzer_name == "attack_surface413":
            if (set(details) != {"kind", "category", "cwe", "runtime_exploitability"}
                    or details.get("kind") != "attack-surface-finding"
                    or details.get("runtime_exploitability") != "unverified"
                    or _label(details.get("category", "")) != details.get("category")
                    or not isinstance(details.get("cwe"), str)):
                error("attack-surface evidence details are invalid")
        elif analyzer_name == "security_posture413":
            if (set(details) != {"kind", "category", "source_kind", "runtime_exploitability"}
                    or details.get("kind") != "security-posture-finding"
                    or details.get("runtime_exploitability") != "unverified"
                    or _label(details.get("category", "")) != details.get("category")
                    or _label(details.get("source_kind", "")) != details.get("source_kind")):
                error("security-posture evidence details are invalid")
        advisory = row.get("advisory")
        if (type(advisory) is not dict or set(advisory) != {
                "kind", "text", "safe_to_autofix", "applied", "verified"}
                or advisory.get("applied") is not False
                or advisory.get("verified") is not False
                or advisory.get("kind") != "preview-only"
                or type(advisory.get("safe_to_autofix")) is not bool
                or not isinstance(advisory.get("text"), str)
                or _safe_text(advisory.get("text"), 1_024) != advisory.get("text")):
            error("advisory state mismatch")
    if evidence != sorted(evidence, key=lambda row: (
            -SEVERITY_ORDER.get(row.get("severity", "info"), 0), row.get("path", ""),
            row.get("line", 0), row.get("analyzer", ""), row.get("rule_id", ""),
            row.get("evidence_id", ""))):
        error("evidence ordering mismatch")

    coverage = report.get("coverage")
    if type(coverage) is not dict or set(coverage) != {
            "complete", "gaps", "status_precedence"}:
        error("coverage shape mismatch")
        gaps = []
    else:
        gaps = coverage.get("gaps")
        if type(gaps) is not list or len(gaps) > MAX_GAPS:
            error("gap list is malformed")
            gaps = []
        seen_gaps: set[str] = set()
        gap_keys = {"gap_id", "analyzer", "analyzer_schema",
                    "child_report_sha256", "path", "reason", "native_gap_sha256"}
        for row in gaps:
            if type(row) is not dict or set(row) != gap_keys:
                error("gap row is malformed")
                continue
            body = {key: value for key, value in row.items() if key != "gap_id"}
            expected = "gap42-" + digest_json(body)[:24]
            if row.get("gap_id") != expected or expected in seen_gaps:
                error("gap digest or uniqueness mismatch")
            seen_gaps.add(expected)
            analyzer = row.get("analyzer")
            if analyzer in analyzers:
                component = analyzers[analyzer]
                binding = (component.get("native_schema"), component.get("native_output_sha256"))
            elif analyzer == "snapshot":
                binding = (snapshot.get("schema"), snapshot.get("native_report_sha256"))
            elif analyzer == "language_coverage42":
                binding = (language.get("schema"), language.get("report_sha256"))
            elif analyzer == "assurance42":
                binding = (SCHEMA, "0" * 64)
            else:
                binding = (None, None)
            if (row.get("analyzer_schema"), row.get("child_report_sha256")) != binding:
                error("gap analyzer binding mismatch")
            if (not _digest_valid(row.get("native_gap_sha256"))
                    or _safe_text(row.get("path", ""), 4_096) != row.get("path")
                    or _label(row.get("reason", "")) != row.get("reason")):
                error("gap evidence is invalid")
            gap_path = row.get("path", "")
            if gap_path:
                try:
                    normalized_gap_path = snapshot41.safe_relative(gap_path)
                except (snapshot41.SnapshotError, TypeError):
                    error("gap path is outside the portable snapshot namespace")
                else:
                    if (normalized_gap_path != gap_path or len(gap_path) > 1_024
                            or unicodedata.normalize("NFC", gap_path) != gap_path):
                        error("gap path is not canonical")
        if coverage.get("complete") is not (not gaps):
            error("coverage completeness mismatch")
        if coverage.get("status_precedence") != "incomplete-outranks-findings":
            error("coverage precedence mismatch")
        if gaps != sorted(gaps, key=lambda row: (
                row.get("analyzer", ""), row.get("path", ""), row.get("reason", ""),
                row.get("gap_id", ""))):
            error("gap ordering mismatch")

    if analyzers:
        evidence_counts = Counter(row.get("analyzer") for row in evidence)
        gap_counts = Counter(row.get("analyzer") for row in gaps)
        for name, component in analyzers.items():
            if component.get("metrics", {}).get("normalized_evidence") != evidence_counts[name]:
                error("analyzer normalized evidence count mismatch")
            if component.get("coverage_gap_count") != gap_counts[name]:
                error("analyzer coverage gap count mismatch")
        expected_native_status = {
            "detect": "partial" if gap_counts["detect"] else "complete",
            "semantic_graph41": (
                "partial" if gap_counts["semantic_graph41"] else "complete"),
            "attack_surface413": (
                "partial-findings" if gap_counts["attack_surface413"]
                and analyzers["attack_surface413"]["metrics"]["findings"]
                else "partial" if gap_counts["attack_surface413"]
                else "findings" if analyzers["attack_surface413"]["metrics"]["findings"]
                else "clean"),
            "security_posture413": (
                "partial" if gap_counts["security_posture413"] else "complete"),
        }
        for name, expected in expected_native_status.items():
            if analyzers[name].get("native_status") != expected:
                error("analyzer native status contradicts projected gaps/findings")
    required_posture_gaps = {
        "artifact-executable-metadata", "git-secret-history", "signature-provenance"}
    actual_posture_reasons = {
        row.get("reason") for row in gaps
        if row.get("analyzer") == "security_posture413"
    }
    if not required_posture_gaps.issubset(actual_posture_reasons):
        error("mandatory snapshot-only posture gaps are missing")
    expected_language_gaps = {
        (row["path"], row["reason"]) for row in language.get("uncovered", [])
        if type(row) is dict and "path" in row and "reason" in row
    }
    actual_language_gaps = {
        (row.get("path"), row.get("reason")) for row in gaps
        if row.get("analyzer") == "language_coverage42"
    }
    if actual_language_gaps != expected_language_gaps:
        error("language coverage gaps are not exactly cross-linked")

    expected_status = _status(evidence, gaps, analyzers)
    if report.get("status") != expected_status:
        error("status mismatch")
    if report.get("complete") is not (expected_status in {"clean", "findings"}):
        error("top-level completeness mismatch")
    if analyzers and snapshot and language:
        try:
            expected_summary = _summary(snapshot, analyzers, evidence, gaps, language)
        except (KeyError, TypeError):
            error("summary inputs are malformed")
        else:
            if report.get("summary") != expected_summary:
                error("summary mismatch")
    return not errors, errors


def verify_report(report: Any) -> tuple[bool, list[str]]:
    """Fail-closed wrapper: adversarial JSON never escapes as an exception."""
    try:
        return _verify_report_impl(report)
    except (Exception, RecursionError) as exc:
        return False, ["report verification failed closed (%s)" % type(exc).__name__]


def exit_for_status(status_or_report: str | Mapping[str, Any]) -> int:
    status = status_or_report.get("status") if isinstance(status_or_report, Mapping) else status_or_report
    return {
        "clean": EXIT_CLEAN,
        "findings": EXIT_FINDINGS,
        "incomplete": EXIT_INCOMPLETE,
        "incomplete-findings": EXIT_INCOMPLETE,
    }.get(status, EXIT_OPERATIONAL)


def render_text(report: Mapping[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "Attestor 4.2 experimental assurance: %s" % report["status"],
        "files=%d bytes=%d evidence=%d gaps=%d" % (
            summary["file_count"], summary["total_bytes"],
            summary["evidence_count"], summary["gap_count"]),
        "core=%d semantic_taint=%d attack_surface=%d attack_paths=%d posture=%d sbom=%d" % (
            summary["core_findings"], summary["semantic_taint_witnesses"],
            summary["attack_surface_findings"], summary["attack_paths"],
            summary["posture_findings"], summary["sbom_components"]),
    ]
    for row in report["evidence"]:
        lines.append("%s:%d [%s/%s] %s" % (
            row["path"], row["line"], row["severity"], row["analyzer"], row["rule_id"]))
        if row["advisory"]["text"]:
            lines.append("  advisory (not applied or verified): " + row["advisory"]["text"])
    if report["coverage"]["gaps"]:
        lines.append("Coverage is incomplete; representative gaps:")
        for row in report["coverage"]["gaps"][:20]:
            suffix = (" (" + row["path"] + ")") if row["path"] else ""
            lines.append("  %s: %s%s" % (row["analyzer"], row["reason"], suffix))
        if len(report["coverage"]["gaps"]) > 20:
            lines.append("  ... %d additional gaps are present in JSON output" % (
                len(report["coverage"]["gaps"]) - 20))
    lines.append("report_sha256=" + report["report_sha256"])
    lines.append("No repair was applied; static advice requires human review and separate verification.")
    return "\n".join(lines)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attestor assure",
        description="Experimental passive assurance for one authorized directory.",
        allow_abbrev=False,
    )
    parser.add_argument("directory")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def _diagnostic(message: str) -> None:
    print("attestor assure: " + _safe_text(message, 400), file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        report = run_assurance(args.directory)
        valid, errors = verify_report(report)
        if not valid:
            raise AssuranceOperationalError(
                "report verification failed: " + ", ".join(errors[:3]))
        print(canonical_json(report, pretty=True) if args.format == "json" else render_text(report))
        return exit_for_status(report)
    except AssuranceInputError as exc:
        _diagnostic(str(exc))
        return EXIT_INVALID
    except AssuranceOperationalError as exc:
        _diagnostic(str(exc))
        return EXIT_OPERATIONAL
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:
        _diagnostic("operational failure (%s); no report was accepted" % type(exc).__name__)
        return EXIT_OPERATIONAL


if __name__ == "__main__":
    raise SystemExit(main())
