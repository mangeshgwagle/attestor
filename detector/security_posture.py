#!/usr/bin/env python3
"""Attestor 3.0 defensive cybersecurity posture engine.

The posture engine fuses multi-language findings, repository reachability,
redacted secret analysis, STRIDE attack paths, attack-surface inventory,
supply-chain checks, and a local CycloneDX inventory.  It is offline-safe: no
exploitation, network probing, dependency resolution, installation, or target
code execution is performed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import tempfile
from dataclasses import asdict
from datetime import date
from pathlib import Path
from typing import Any

import advanced_rules
import detect
import multilang
import nativescan
import qualitygate
import precision_catalog
import repo_intel
import scanengine
import secmax
import security_intelligence
import security_taxonomy


SCHEMA = "attestor-security-posture/3.0"
BASELINE_SCHEMA = "attestor-security-baseline/1"
SUPPRESSION_SCHEMA = "attestor-security-suppressions/1"
MAX_POLICY_BYTES = 1024 * 1024
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_WEIGHT = {"CRITICAL": 10.0, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.5, "INFO": 1.0}
SECURITY_CATEGORIES = {
    "access", "archive", "auth", "browser", "cloud", "command", "container",
    "credential", "crypto", "cross-site", "data-protection", "database",
    "deserialization", "external-call", "file", "host", "identity", "injection",
    "memory-safety", "random", "secret", "security", "supply", "transport",
    "web", "workflow", "xml", "mobile", "ci-cd", "iac",
}


def _security_issue(issue: scanengine.Issue) -> bool:
    text = " ".join((issue.category, issue.rule, issue.cwe, issue.owasp)).lower()
    return bool(issue.cwe or issue.owasp or any(word in text for word in SECURITY_CATEGORIES))


def _relative(root: Path, value: str) -> str:
    try:
        return Path(value).resolve().relative_to(root).as_posix()
    except (OSError, ValueError):
        return str(value).replace("\\", "/")


def _from_scan(issue: scanengine.Issue, root: Path) -> dict[str, Any]:
    return {
        "path": _relative(root, issue.path), "line": max(1, int(issue.line)),
        "rule": issue.rule, "severity": issue.severity,
        "category": issue.category or "code-security", "cwe": issue.cwe,
        "owasp": issue.owasp, "confidence": round(issue.confidence or 0.75, 2),
        "message": issue.message, "fix": issue.fix,
        "source": issue.source or "scanengine", "pack": issue.pack or "core",
        "catalog_fingerprint": issue.fingerprint,
        "asvs": list(issue.asvs),
        "cwe_top25_2025_rank": issue.cwe_top25_2025_rank,
    }


def _from_secmax(item, root: Path) -> dict[str, Any]:
    return {
        "path": _relative(root, str(item.path)), "line": max(1, int(item.line)),
        "rule": item.rule, "severity": item.severity, "category": item.category,
        "cwe": "", "owasp": item.owasp, "confidence": float(item.confidence),
        "message": item.detail, "fix": item.fix, "source": "securitymax",
        "pack": "securitymax", "exploitability_hint": item.exploitability,
    }


def _deduplicate(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    chosen: dict[tuple[str, int, str], dict[str, Any]] = {}
    for original in rows:
        row = dict(original)
        key = (row["path"].lower(), int(row["line"]), row["rule"])
        previous = chosen.get(key)
        if previous is None:
            chosen[key] = row
            continue
        preferred = row if row.get("confidence", 0) > previous.get("confidence", 0) else previous
        other = previous if preferred is row else row
        preferred["asvs"] = sorted(set(preferred.get("asvs", [])) | set(other.get("asvs", [])))
        preferred["nist_ssdf"] = sorted(set(preferred.get("nist_ssdf", [])) | set(other.get("nist_ssdf", [])))
        evidence = preferred.get("evidence", []) + other.get("evidence", [])
        evidence_keys = set()
        preferred["evidence"] = []
        for item in evidence:
            marker = (item.get("kind"), item.get("path"), item.get("line"), item.get("description"))
            if marker not in evidence_keys:
                evidence_keys.add(marker)
                preferred["evidence"].append(item)
        chosen[key] = preferred
    return sorted(chosen.values(), key=lambda row: (
        -float(row.get("risk_score", 0)), -SEVERITY_RANK.get(row["severity"], 0),
        -row["confidence"], row["path"].lower(), row["line"], row["rule"]))


def _risk(findings: list[dict[str, Any]]) -> tuple[int, str]:
    if not findings:
        return 0, "no-findings"
    values = [float(row.get("risk_score") or
                    (SEVERITY_WEIGHT.get(row["severity"], 4.0)
                     * security_taxonomy.cwe_priority_factor(str(row.get("cwe") or ""))))
              for row in findings]
    weighted = sum(value * (0.65 + 0.35 * float(row.get("confidence", 0.75)))
                   for value, row in zip(values, findings))
    score = min(100, round(max(values) * 7.5 + 25 * (1 - math.exp(-weighted / 35))))
    if any(row["severity"] == "CRITICAL" for row in findings) or score >= 85:
        label = "critical"
    elif any(row["severity"] == "HIGH" for row in findings) or score >= 65:
        label = "high"
    elif score >= 35:
        label = "elevated"
    else:
        label = "guarded"
    return score, label


def _counts(findings: list[dict[str, Any]], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in findings:
        value = row.get(key) or "unmapped"
        value = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
        out[value] = out.get(value, 0) + 1
    return dict(sorted(out.items(), key=lambda item: (-item[1], item[0])))


def _multi_counts(findings: list[dict[str, Any]], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in findings:
        for value in row.get(key, []) or []:
            out[str(value)] = out.get(str(value), 0) + 1
    return dict(sorted(out.items(), key=lambda item: (-item[1], item[0])))


def finding_fingerprint(row: dict[str, Any]) -> str:
    """Return a value-independent, deterministic finding identity."""
    payload = json.dumps([
        "attestor-finding/v1", str(row.get("rule", "")),
        str(row.get("path", "")).replace("\\", "/").lower(),
        max(1, int(row.get("line", 1))), str(row.get("cwe", "")),
    ], ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _load_policy(path: str, label: str) -> tuple[Any, list[str]]:
    if not path:
        return None, []
    target = Path(path).expanduser()
    try:
        if not target.is_file():
            return None, ["%s file is not readable: %s" % (label, target)]
        if target.stat().st_size > MAX_POLICY_BYTES:
            return None, ["%s file exceeds %d bytes: %s" % (label, MAX_POLICY_BYTES, target)]
        return json.loads(target.read_text(encoding="utf-8")), []
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, ["%s file could not be loaded (%s): %s" % (label, type(exc).__name__, target)]


def _apply_baseline(findings: list[dict[str, Any]], path: str) -> tuple[dict[str, Any], list[str]]:
    document, errors = _load_policy(path, "baseline")
    values: list[Any] = []
    invalid = 0
    if document is not None:
        if isinstance(document, dict):
            if document.get("schema") not in {None, BASELINE_SCHEMA}:
                errors.append("baseline schema is not supported")
            values = document.get("fingerprints", [])
        elif isinstance(document, list):
            values = document
        if not isinstance(values, list):
            errors.append("baseline fingerprints must be a JSON array")
            values = []
    fingerprints = set()
    for value in values:
        fingerprint = value.get("fingerprint") if isinstance(value, dict) else value
        if isinstance(fingerprint, str) and len(fingerprint) == 64 and all(
                char in "0123456789abcdefABCDEF" for char in fingerprint):
            fingerprints.add(fingerprint.lower())
        else:
            invalid += 1
    current = {row["fingerprint"] for row in findings}
    for row in findings:
        row["baseline_state"] = "unchanged" if row["fingerprint"] in fingerprints else "new"
    return {
        "schema": BASELINE_SCHEMA, "provided": bool(path), "path": str(path) if path else "",
        "entries": len(fingerprints), "matched": len(current & fingerprints),
        "new": len(current - fingerprints), "stale": len(fingerprints - current),
        "invalid_entries": invalid,
    }, errors


def _apply_suppressions(findings: list[dict[str, Any]], path: str) -> tuple[dict[str, Any], list[str]]:
    document, errors = _load_policy(path, "suppression")
    entries: list[Any] = []
    if document is not None:
        if isinstance(document, dict) and document.get("schema") not in {None, SUPPRESSION_SCHEMA}:
            errors.append("suppression schema is not supported")
        entries = document.get("suppressions", []) if isinstance(document, dict) else document
        if not isinstance(entries, list):
            errors.append("suppression entries must be a JSON array")
            entries = []
    today = date.today()
    active: dict[str, dict[str, str]] = {}
    expired: list[dict[str, str]] = []
    invalid: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            invalid.append({"index": index, "reason": "entry is not an object"})
            continue
        fingerprint = entry.get("fingerprint")
        reason = entry.get("reason")
        expires = entry.get("expires")
        if not isinstance(fingerprint, str) or len(fingerprint) != 64 or not all(
                char in "0123456789abcdefABCDEF" for char in fingerprint):
            invalid.append({"index": index, "reason": "fingerprint must be 64 hexadecimal characters"})
            continue
        if not isinstance(reason, str) or len(reason.strip()) < 8 or len(reason) > 500 or any(
                ord(char) < 32 for char in reason):
            invalid.append({"index": index, "reason": "reason must be 8-500 printable characters"})
            continue
        try:
            expiry = date.fromisoformat(expires) if isinstance(expires, str) else None
        except ValueError:
            expiry = None
        if expiry is None:
            invalid.append({"index": index, "reason": "expires must be an ISO date (YYYY-MM-DD)"})
            continue
        record = {"fingerprint": fingerprint.lower(), "reason": reason.strip(), "expires": expiry.isoformat()}
        if expiry < today:
            expired.append(record)
        else:
            active[fingerprint.lower()] = record
    matched = set()
    for row in findings:
        record = active.get(row["fingerprint"])
        row["suppressed"] = bool(record)
        if record:
            matched.add(row["fingerprint"])
            row["suppression"] = {"reason": record["reason"], "expires": record["expires"]}
    return {
        "schema": SUPPRESSION_SCHEMA, "provided": bool(path), "path": str(path) if path else "",
        "active_entries": len(active), "matched": len(matched),
        "unmatched": len(set(active) - matched), "expired": expired,
        "expired_count": len(expired), "invalid": invalid, "invalid_count": len(invalid),
        "requirement": "every suppression requires an exact fingerprint, reason, and non-expired date",
    }, errors


def baseline_document(report: dict[str, Any]) -> dict[str, Any]:
    """Build a baseline document suitable for a future ``--baseline`` scan."""
    return {
        "schema": BASELINE_SCHEMA,
        "fingerprints": sorted({row["fingerprint"] for row in report.get("findings", [])}),
        "note": "Fingerprints contain rule/location metadata only; no matched secret material.",
    }


def _attack_surface(root: Path, scan: scanengine.WorkspaceResult,
                    intelligence: dict, inventory: qualitygate.DependencyInventory) -> dict[str, Any]:
    paths = [Path(row.path) for row in scan.files]
    suffixes = {path.suffix.lower() for path in paths}
    names = {path.name.lower() for path in paths}
    return {
        "entrypoints": list(intelligence.get("entrypoints", [])),
        "routes": sorted(route for meta in intelligence.get("definitions", {}).values()
                         for route in meta.get("routes", [])),
        "dependency_count": len(inventory.dependencies), "manifests": list(inventory.manifests),
        "containers": sorted(_relative(root, str(path)) for path in paths
                             if path.name.lower().startswith(("dockerfile", "containerfile"))),
        "ci_cd": sorted(_relative(root, str(path)) for path in paths
                        if ".github" in {part.lower() for part in path.parts}
                        or path.name.lower() in {"jenkinsfile", ".gitlab-ci.yml"}),
        "infrastructure_as_code": bool({".tf", ".tfvars", ".hcl"} & suffixes),
        "database_assets": bool({".sql"} & suffixes or {"alembic.ini"} & names),
        "unsafe_source_to_sink_flows": list(intelligence.get("unsafe_flows", [])),
        "import_cycles": list(intelligence.get("import_cycles", [])),
    }


def _recommendations(findings: list[dict[str, Any]], scan: scanengine.WorkspaceResult,
                     inventory: qualitygate.DependencyInventory) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for row in findings:
        fix = row.get("fix") or "Perform a focused manual security review and add a regression check."
        key = (row["category"], fix)
        group = groups.setdefault(key, {
            "priority": row["severity"], "category": row["category"], "fix": fix,
            "findings": 0, "rules": set(), "affected_paths": set(),
            "fingerprints": [], "max_risk_score": 0.0, "evidence_chains": 0,
        })
        group["findings"] += 1
        group["rules"].add(row["rule"])
        group["affected_paths"].add(row["path"])
        group["fingerprints"].append(row["fingerprint"])
        group["max_risk_score"] = max(group["max_risk_score"], float(row.get("risk_score", 0)))
        group["evidence_chains"] += bool(row.get("evidence"))
        if SEVERITY_RANK.get(row["severity"], 0) > SEVERITY_RANK.get(group["priority"], 0):
            group["priority"] = row["severity"]
    rows = []
    for group in groups.values():
        group["rules"] = sorted(group["rules"])
        group["affected_paths"] = sorted(group["affected_paths"])[:20]
        group["fingerprints"] = sorted(set(group["fingerprints"]))[:20]
        rows.append(group)
    unverified = sum(1 for row in scan.files if row.verification == "unverified"
                     and row.language not in {"text", "sql", "terraform", "yaml", "docker", "nginx"})
    if unverified:
        rows.append({"priority": "MEDIUM", "category": "verification",
                     "fix": "Run the opt-in syntax/compiler adapters in CI for available toolchains.",
                     "findings": unverified, "rules": ["unverified-source"],
                     "affected_paths": [], "fingerprints": [], "max_risk_score": 0,
                     "evidence_chains": 0})
    if inventory.dependencies:
        rows.append({"priority": "MEDIUM", "category": "dependency-assurance",
                     "fix": "Feed the CycloneDX inventory to a current advisory scanner; offline Attestor does not invent CVE status.",
                     "findings": len(inventory.dependencies), "rules": ["advisory-resolution-not-run"],
                     "affected_paths": list(inventory.manifests)[:20], "fingerprints": [],
                     "max_risk_score": 0, "evidence_chains": 0})
    return sorted(rows, key=lambda row: (-SEVERITY_RANK.get(row["priority"], 0),
                                         -row["max_risk_score"], -row["findings"],
                                         row["category"]))[:40]


def assess(root: str | Path, *, jobs: int = scanengine.DEFAULT_JOBS,
           deep: bool = True, external_tools: bool = False,
           use_cache: bool = True, cache_path: str = "",
           baseline_path: str = "", suppressions_path: str = "") -> dict[str, Any]:
    base = Path(root).expanduser().resolve()
    if base.is_file():
        requested = base
        try:
            with tempfile.TemporaryDirectory(prefix="attestor-security-file-") as folder:
                isolated = Path(folder) / requested.name
                shutil.copyfile(requested, isolated)
                report = assess(
                    isolated.parent, jobs=jobs, deep=deep,
                    external_tools=external_tools, use_cache=use_cache,
                    cache_path=cache_path, baseline_path=baseline_path,
                    suppressions_path=suppressions_path)
        except OSError as exc:
            return {"schema": SCHEMA, "root": str(requested), "status": "failed",
                    "risk": {"score": 0, "label": "unknown"},
                    "errors": ["file scope could not be isolated (%s): %s" %
                               (type(exc).__name__, exc)], "findings": []}
        report["root"] = str(requested)
        report.setdefault("coverage", {}).update({
            "scope_kind": "file", "scope_target": str(requested),
        })
        report.get("sbom", {}).get("metadata", {}).get("component", {})["name"] = requested.name
        report.setdefault("assurance_notes", []).append(
            "Single-file scope was analyzed in isolation; sibling files were not read or included.")
        return report
    if not base.is_dir():
        return {"schema": SCHEMA, "root": str(base), "status": "failed",
                "risk": {"score": 0, "label": "unknown"},
                "errors": ["workspace is not a readable directory"], "findings": []}
    scan = scanengine.scan([str(base)], jobs=max(1, min(int(jobs), 32)), deep=deep,
                           tools=external_tools, use_cache=use_cache, cache_path=cache_path)
    security_max = secmax.scan([str(base)])
    intelligence = repo_intel.analyze(str(base))
    inventory = qualitygate.inventory_dependencies(base)
    sbom = qualitygate.build_sbom(base, inventory)
    contextual = security_intelligence.analyze(base, repo_report=intelligence)

    rows = [_from_scan(issue, base) for issue in scan.issues if _security_issue(issue)]
    # Security Max remains a standalone compatibility surface and contributes
    # its coarse threat-model vocabulary below. Its line-oriented heuristic
    # findings are intentionally not promoted into the 3.0 posture: the unified
    # scanner plus contextual engine cover those classes with code/string
    # awareness, redaction, reachability, and stronger negative guards.
    rows.extend(contextual.get("findings", []))
    findings = _deduplicate(security_intelligence.enrich_findings(rows, contextual, intelligence))
    for row in findings:
        row["fingerprint"] = finding_fingerprint(row)
        row["fingerprint_algorithm"] = "attestor-finding/v1-sha256"
    baseline, baseline_errors = _apply_baseline(findings, baseline_path)
    suppressions, suppression_errors = _apply_suppressions(findings, suppressions_path)
    actionable = [row for row in findings if not row.get("suppressed")]
    score, label = _risk(actionable)
    inherent_score, inherent_label = _risk(findings)
    severity = {name: 0 for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    total_severity = dict(severity)
    for row in findings:
        total_severity[row["severity"]] = total_severity.get(row["severity"], 0) + 1
    for row in actionable:
        severity[row["severity"]] = severity.get(row["severity"], 0) + 1

    errors = list(scan.errors) + list(inventory.errors) + list(contextual.get("errors", []))
    errors += baseline_errors + suppression_errors
    if intelligence.get("parse_errors"):
        errors.extend("%s: %s" % (row["path"], row["message"])
                      for row in intelligence["parse_errors"])
    failed = scan.status in {"failed", "unsupported"} or contextual.get("status") == "failed" or bool(errors)
    surface = _attack_surface(base, scan, intelligence, inventory)
    surface.update(contextual.get("attack_surface", {}))
    legacy_model = security_max["threat_model"]
    threat_model = {
        "method": "STRIDE", "nist_ssdf": ["PW.1.1"],
        "assets": legacy_model.get("assets", []),
        "attack_surfaces": legacy_model.get("attack_surfaces", []),
        "trust_boundaries": contextual.get("trust_boundaries", []),
        "attack_paths": contextual.get("attack_paths", []),
        "legacy_boundary_descriptions": legacy_model.get("trust_boundaries", []),
        "top_risks": [row["rule"] for row in actionable[:10]],
    }
    return {
        "schema": SCHEMA, "root": str(base),
        "status": "failed" if failed else ("findings" if actionable else "clean"),
        "risk": {"score": score, "label": label,
                 "inherent_score": inherent_score, "inherent_label": inherent_label,
                 "model": "severity + confidence + static reachability + CWE Top 25:2025 rank"},
        "summary": {
            "files_scanned": scan.files_scanned, "findings": len(findings),
            "actionable_findings": len(actionable),
            "suppressed_findings": len(findings) - len(actionable),
            "new_findings": sum(row.get("baseline_state") == "new" for row in findings),
            "severity": severity, "total_severity": total_severity,
            "categories": _counts(actionable, "category"), "cwe": _counts(actionable, "cwe"),
            "owasp": _counts(actionable, "owasp_2025"),
            "owasp_2025": _counts(actionable, "owasp_2025"),
            "owasp_2021": _counts(actionable, "owasp_2021"),
            "asvs_5_0_0": _multi_counts(actionable, "asvs"),
            "nist_ssdf_1_1": _multi_counts(actionable, "nist_ssdf"),
            "secret_findings": sum(1 for row in actionable if any(
                word in (row["rule"] + " " + row["category"]).lower()
                for word in ("secret", "token", "credential", "password", "api-key"))),
        },
        "coverage": {
            "workspace_status": scan.status, "files_discovered": scan.files_discovered,
            "files_scanned": scan.files_scanned, "cache_hits": scan.cache_hits,
            "verified": sum(1 for row in scan.files if row.verification == "verified"),
            "unverified": sum(1 for row in scan.files if row.verification == "unverified"),
            "failed_verification": sum(1 for row in scan.files if row.verification == "failed"),
            "advanced_rules": len(advanced_rules.RULES),
            "precision_flow_rules": len(precision_catalog.RULES),
            "total_explicit_rules": (
                len(detect.RULES) + len(nativescan.LINE_RULES)
                + sum(len(rows) for rows in multilang.RULES.values())
                + len(advanced_rules.RULES) + len(precision_catalog.RULES)),
            # Which weakness classes the catalog can express at all.  Reported
            # every run so a class nobody wrote a rule for surfaces as a named
            # gap rather than as silence.
            "cwe_top25": security_taxonomy.top25_coverage(
                {getattr(fn, "cwe", "") for fn in detect.RULES}
                | {str(getattr(item, "cwe", "") or "")
                   for item in advanced_rules.RULES}),
            "external_tools": bool(external_tools),
            "legacy_secmax_findings_observed": len(security_max.get("findings", [])),
            "legacy_secmax_findings_promoted": 0,
            "contextual_security": contextual.get("coverage", {}),
        },
        "standards": {
            "primary_application_taxonomy": "OWASP Top 10:2025",
            "legacy_application_taxonomy": "OWASP Top 10:2021 (preserved when supplied)",
            "weakness_priority": "CWE Top 25:2025",
            "verification_standard": "OWASP ASVS 5.0.0 (versioned IDs only)",
            "development_framework": "NIST SSDF 1.1",
        },
        "threat_model": threat_model, "attack_surface": surface,
        "supply_chain": contextual.get("supply_chain", {}),
        "recommendations": _recommendations(actionable, scan, inventory),
        "findings": findings, "dependency_inventory": asdict(inventory), "sbom": sbom,
        "governance": {"baseline": baseline, "suppressions": suppressions},
        "errors": errors, "skipped": list(scan.skipped),
        "assurance_notes": [
            "Defensive local analysis only; no exploitation, target execution, or network probing was performed.",
            "Dependency versions were inventoried locally; vulnerability/advisory status was not guessed offline.",
            "A clean static result is not proof of absence; coverage and verification counts are separate.",
            "Secret candidates are discarded after matching; reports contain no value, prefix, suffix, or value hash.",
            "Suppressions never hide findings: accepted, expired, invalid, and unmatched entries remain auditable.",
            "Reachability and exploitability are conservative static estimates, not proof of practical exploitation.",
            "Legacy Security Max heuristic findings are not promoted into the 3.0 posture; its standalone CLI remains available for compatibility.",
        ],
    }


def to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    results = []
    rules: dict[str, dict[str, Any]] = {}
    for row in report.get("findings", []):
        properties = {
            "category": row.get("category", ""), "cwe": row.get("cwe", ""),
            "owasp_2025": row.get("owasp_2025", ""), "owasp_2021": row.get("owasp_2021", ""),
            "asvs": row.get("asvs", []), "nist_ssdf": row.get("nist_ssdf", []),
            "precision": row.get("precision", ""), "tags": row.get("stride", []),
            "security-severity": str(row.get("risk_score", 0)),
            "cwe_top25_2025_rank": row.get("cwe_top25_2025_rank"),
        }
        rule = {"id": row["rule"], "name": row["rule"],
                "shortDescription": {"text": row["message"]}, "properties": properties}
        if str(row.get("cwe", "")).startswith("CWE-"):
            rule["helpUri"] = "https://cwe.mitre.org/data/definitions/%s.html" % row["cwe"].split("-", 1)[1]
        rules[row["rule"]] = rule
        result: dict[str, Any] = {
            "ruleId": row["rule"],
            "level": "error" if row["severity"] in {"CRITICAL", "HIGH"} else (
                "warning" if row["severity"] == "MEDIUM" else "note"),
            "message": {"text": row["message"] + (" Fix: " + row["fix"] if row.get("fix") else "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": row["path"]},
                                                  "region": {"startLine": row["line"]}}}],
            "baselineState": row.get("baseline_state", "new"),
            "partialFingerprints": {"attestorFindingFingerprint/v1": row.get("fingerprint", "")},
            "properties": {**properties, "confidence": row.get("confidence", 0),
                           "source": row.get("source", ""),
                           "reachability": row.get("reachability", {}),
                           "exploitability": row.get("exploitability", {}),
                           "suppressed": bool(row.get("suppressed"))},
        }
        if row.get("suppressed"):
            suppression = row.get("suppression", {})
            result["suppressions"] = [{"kind": "external", "status": "accepted",
                                       "justification": "%s (expires %s)" % (
                                           suppression.get("reason", "accepted risk"),
                                           suppression.get("expires", "unknown"))}]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Attestor 3.0 Cybersecurity Mayhem",
                                         "semanticVersion": "3.0.0",
                                         "informationUri": "https://owasp.org/Top10/2025/",
                                         "rules": list(rules.values())}}, "results": results,
                  "properties": {"posture_schema": report.get("schema", SCHEMA)}}],
    }


def render_markdown(report: dict[str, Any]) -> str:
    if report.get("status") == "failed" and "summary" not in report:
        return "# Attestor 3.0 cybersecurity posture\n\nStatus: **failed**\n\n" + "\n".join(
            "- " + error for error in report.get("errors", [])) + "\n"
    summary = report["summary"]
    lines = [
        "# Attestor 3.0 cybersecurity posture", "",
        "- Status: **%s**" % report["status"],
        "- Active risk: **%s / 100 (%s)**" % (report["risk"]["score"], report["risk"]["label"]),
        "- Files scanned: **%d**" % summary["files_scanned"],
        "- Findings: **%d total / %d actionable / %d suppressed**" % (
            summary["findings"], summary["actionable_findings"], summary["suppressed_findings"]),
        "- Critical / high actionable: **%d / %d**" % (
            summary["severity"].get("CRITICAL", 0), summary["severity"].get("HIGH", 0)),
        "- Dependencies inventoried: **%d**" % len(report["dependency_inventory"]["dependencies"]),
        "", "## Fix first", "",
    ]
    if report["recommendations"]:
        for row in report["recommendations"][:12]:
            lines.append("- **%s - %s** (%d findings, risk %.1f): %s" % (
                row["priority"], row["category"], row["findings"], row["max_risk_score"], row["fix"]))
    else:
        lines.append("- No remediation groups were generated from actionable findings.")
    attack_paths = report.get("threat_model", {}).get("attack_paths", [])
    lines += ["", "## STRIDE attack paths", ""]
    if attack_paths:
        for path in attack_paths[:10]:
            lines.append("- **%s** (risk %.1f, %s): %s" % (
                path.get("rule", "attack-path"), path.get("risk_score", 0),
                ", ".join(path.get("stride", [])), " -> ".join(path.get("nodes", []))))
    else:
        lines.append("- No supported attack path was established from available static evidence.")
    lines += ["", "## Highest-priority evidence", ""]
    for row in report["findings"][:30]:
        metadata = " - ".join(item for item in (
            row["category"], row.get("cwe", ""), row.get("owasp_2025", "")) if item)
        disposition = "SUPPRESSED until %s" % row.get("suppression", {}).get("expires", "unknown") if row.get("suppressed") else row.get("baseline_state", "new").upper()
        lines += [
            "### %s - %s" % (row["severity"], row["rule"]), "",
            "`%s:%d` - %s" % (row["path"], row["line"], row["message"]), "",
            "%s  Confidence: %.0f%% - Risk: %.1f - %s" % (
                metadata, row["confidence"] * 100, row.get("risk_score", 0), disposition), "",
            "Fix: " + (row.get("fix") or "manual security review required"), "",
        ]
    governance = report.get("governance", {})
    baseline = governance.get("baseline", {})
    suppression = governance.get("suppressions", {})
    lines += [
        "## Baseline and suppressions", "",
        "- Baseline: %d matched, %d new, %d stale, %d invalid." % (
            baseline.get("matched", 0), baseline.get("new", 0), baseline.get("stale", 0),
            baseline.get("invalid_entries", 0)),
        "- Suppressions: %d active, %d matched, %d expired, %d invalid." % (
            suppression.get("active_entries", 0), suppression.get("matched", 0),
            suppression.get("expired_count", 0), suppression.get("invalid_count", 0)),
        "", "## Coverage and honesty", "",
    ] + ["- " + note for note in report["assurance_notes"]]
    if report["errors"]:
        lines += ["", "## Analysis errors", ""] + ["- " + error for error in report["errors"]]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--jobs", type=int, default=scanengine.DEFAULT_JOBS)
    parser.add_argument("--tools", action="store_true")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--cache", default="")
    parser.add_argument("--baseline", default="", help="existing Attestor baseline JSON")
    parser.add_argument("--suppressions", default="", help="explicit suppression JSON; reason and expiry required")
    parser.add_argument("--format", choices=("markdown", "json", "sarif", "sbom", "baseline"), default="markdown")
    args = parser.parse_args(argv)
    report = assess(args.root, jobs=args.jobs, external_tools=args.tools,
                    use_cache=not args.no_cache, cache_path=args.cache,
                    baseline_path=args.baseline, suppressions_path=args.suppressions)
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    elif args.format == "sarif":
        print(json.dumps(to_sarif(report), indent=2))
    elif args.format == "sbom":
        print(json.dumps(report.get("sbom", {}), indent=2, sort_keys=True))
    elif args.format == "baseline":
        print(json.dumps(baseline_document(report), indent=2, sort_keys=True))
    else:
        print(render_markdown(report), end="")
    if report.get("status") == "failed":
        return 2
    return min(report.get("summary", {}).get("actionable_findings", 0), 250)


if __name__ == "__main__":
    raise SystemExit(main())
