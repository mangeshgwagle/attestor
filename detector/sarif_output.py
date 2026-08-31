#!/usr/bin/env python3
"""SARIF 2.1.0 output -- industry-standard format for static analysis results.

Converts ANY Attestor finding format (dataflow, js_scanner, secret_scanner, etc.)
into SARIF JSON consumable by GitHub Code Scanning, VS Code, Azure DevOps, and
any CI pipeline that speaks SARIF. Evidence traces become SARIF codeFlows.

Usage:
    # from dataflow findings:
    sarif = sarif_output.from_findings(dataflow.to_dict(findings))
    sarif_output.write(findings_dict, "results.sarif")

    # from js_scanner / secret_scanner findings:
    sarif = sarif_output.generate_sarif(scanner_findings)
    sarif_output.write_sarif(scanner_findings, "results.sarif")

    # round-trip import:
    findings = sarif_output.from_sarif(sarif)
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

VERSION = "4.3"
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"

_SEV_LEVEL = {
    "CRITICAL": "error", "HIGH": "error",
    "MEDIUM": "warning", "LOW": "note", "INFO": "note",
}
_SEV_RANK = {
    "CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.0, "INFO": 0.5,
}
_CWE_URL = "https://cwe.mitre.org/data/definitions/{}.html"


def _severity_to_level(severity: str) -> str:
    return _SEV_LEVEL.get(severity.upper(), "warning")


def _severity_to_rank(severity: str) -> float:
    return _SEV_RANK.get(severity.upper(), 5.0)


def _cwe_num(cwe: str) -> int | None:
    if not cwe:
        return None
    digits = "".join(c for c in cwe if c.isdigit())
    return int(digits) if digits else None


def _build_rule(rule_id: str, description: str, severity: str,
                cwe: str = "", category: str = "") -> dict:
    rule: dict[str, Any] = {
        "id": rule_id,
        "shortDescription": {"text": description},
        "defaultConfiguration": {"level": _severity_to_level(severity)},
        "properties": {
            "security-severity": str(_severity_to_rank(severity)),
            "tags": ["security"],
        },
    }
    if cwe:
        rule["properties"]["tags"].append(cwe)
        num = _cwe_num(cwe)
        if num:
            rule["helpUri"] = _CWE_URL.format(num)
    if category:
        rule["properties"]["category"] = category
    return rule


def _make_location(file: str, line: int, code: str = "") -> dict:
    loc: dict = {
        "physicalLocation": {
            "artifactLocation": {
                "uri": file.replace("\\", "/"),
                "uriBaseId": "%SRCROOT%",
            },
            "region": {"startLine": max(line, 1)},
        },
    }
    if code:
        loc["physicalLocation"]["region"]["snippet"] = {"text": code[:500]}
    return loc


def _make_codeflow(trace: list[dict], fallback_file: str) -> dict | None:
    if not trace:
        return None
    locs = []
    for step in trace:
        sfile = step.get("file", fallback_file) or fallback_file
        sline = step.get("line", 1) or 1
        note = step.get("note", "")
        code = step.get("code", "")
        loc = _make_location(sfile, sline, code)
        loc["message"] = {"text": note}
        locs.append({"location": loc})
    if not locs:
        return None
    return {"threadFlows": [{"locations": locs}]}


def _normalize(f: dict) -> dict:
    """Normalize any Attestor finding format to a common shape."""
    return {
        "vuln_type": (f.get("sink_type") or f.get("category") or
                      f.get("vulnerability") or "unknown"),
        "cwe": f.get("cwe") or f.get("sink_cwe") or "",
        "severity": (f.get("severity") or "MEDIUM").upper(),
        "file": f.get("sink_file") or f.get("file") or f.get("path") or "",
        "line": int(f.get("sink_line") or f.get("line") or 1),
        "code": f.get("sink_code") or f.get("matched_text") or "",
        "source_type": f.get("source_type") or "",
        "confidence": f.get("confidence") or "high",
        "interproc": f.get("interprocedural", False),
        "language": f.get("language") or "python",
        "trace": f.get("trace") or [],
        "rule_id": f.get("rule_id") or "",
        "description": f.get("description") or "",
    }


def from_findings(findings: list[dict], tool_name: str = "Attestor",
                  src_root: str = "") -> dict:
    """Convert any Attestor findings into SARIF, including evidence traces."""
    rules: dict[str, dict] = {}
    rule_order: list[str] = []
    results = []

    for f in findings:
        n = _normalize(f)
        vuln = n["vuln_type"]
        cwe = n["cwe"]
        rule_id = n["rule_id"] or (f"{cwe}/{vuln}" if cwe else vuln)

        if rule_id not in rules:
            desc = n["description"] or vuln.replace("_", " ").title()
            rules[rule_id] = _build_rule(rule_id, desc, n["severity"], cwe)
            rule_order.append(rule_id)

        file = n["file"]
        if src_root and file.startswith(src_root):
            file = os.path.relpath(file, src_root)

        msg_parts = [vuln.replace("_", " ").title()]
        if cwe:
            msg_parts.append(f"({cwe})")
        if n["source_type"]:
            msg_parts.append(f"from {n['source_type']}")
        if n["interproc"]:
            msg_parts.append("[cross-function]")

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_order.index(rule_id),
            "level": _severity_to_level(n["severity"]),
            "message": {"text": " ".join(msg_parts)},
            "locations": [_make_location(file, n["line"], n["code"])],
            "properties": {
                "severity": n["severity"],
                "confidence": n["confidence"],
                "language": n["language"],
            },
        }

        cf = _make_codeflow(n["trace"], file)
        if cf:
            result["codeFlows"] = [cf]

        cwe_id = _cwe_num(cwe)
        if cwe_id:
            result["taxa"] = [{
                "id": str(cwe_id),
                "toolComponent": {"name": "CWE"},
            }]

        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": VERSION,
                    "semanticVersion": VERSION,
                    "informationUri": "https://github.com/mangeshgwagle/attestor",
                    "rules": list(rules.values()),
                },
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(timezone.utc).isoformat(),
            }],
        }],
    }


# --- Backward-compatible API for js_scanner / secret_scanner findings ---

def generate_sarif(findings: list[dict], tool_name: str = "Attestor",
                   tool_version: str = VERSION, root: str = "") -> dict:
    sarif = from_findings(findings, tool_name)
    sarif["runs"][0]["tool"]["driver"]["version"] = tool_version
    sarif["runs"][0]["tool"]["driver"]["semanticVersion"] = tool_version
    if root:
        sarif["runs"][0]["originalUriBaseIds"] = {
            "%SRCROOT%": {
                "uri": (f"file:///{root.replace(os.sep, '/')}/"
                        if os.path.isabs(root) else root + "/"),
            },
        }
    return sarif


def write_sarif(findings: list[dict], output_path: str,
                tool_name: str = "Attestor", tool_version: str = VERSION,
                root: str = ""):
    sarif = generate_sarif(findings, tool_name, tool_version, root)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)
        f.write("\n")


def write(findings: list[dict], output: str = "attestor.sarif",
          tool_name: str = "Attestor", src_root: str = "") -> str:
    sarif = from_findings(findings, tool_name, src_root)
    with open(output, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
    return output


# --- Merge and import ---

def merge_sarif_runs(*sarif_docs: dict) -> dict:
    merged_runs = []
    for doc in sarif_docs:
        merged_runs.extend(doc.get("runs", []))
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": merged_runs}


def from_sarif(sarif: dict) -> list[dict]:
    """Parse SARIF back into Attestor-style findings (for import)."""
    findings = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            locs = result.get("locations", [])
            ploc = locs[0].get("physicalLocation", {}) if locs else {}
            aloc = ploc.get("artifactLocation", {})
            region = ploc.get("region", {})
            props = result.get("properties", {})

            finding: dict = {
                "sink_type": rule_id.split("/")[-1] if "/" in rule_id else rule_id,
                "cwe": rule_id.split("/")[0] if "/" in rule_id else "",
                "sink_file": aloc.get("uri", ""),
                "sink_line": region.get("startLine", 0),
                "sink_code": region.get("snippet", {}).get("text", ""),
                "severity": props.get("severity", "MEDIUM"),
                "confidence": props.get("confidence", "medium"),
                "language": props.get("language", "python"),
                "source_type": "",
                "interprocedural": False,
                "trace": [],
            }

            cfs = result.get("codeFlows", [])
            if cfs:
                for tf in cfs[0].get("threadFlows", []):
                    for loc_wrap in tf.get("locations", []):
                        inner = loc_wrap.get("location", {})
                        pl = inner.get("physicalLocation", {})
                        finding["trace"].append({
                            "file": pl.get("artifactLocation", {}).get("uri", ""),
                            "line": pl.get("region", {}).get("startLine", 0),
                            "code": pl.get("region", {}).get("snippet", {}).get("text", ""),
                            "note": inner.get("message", {}).get("text", ""),
                        })

            findings.append(finding)
    return findings


def summary(sarif: dict) -> str:
    lines = []
    for i, run in enumerate(sarif.get("runs", [])):
        tool = run.get("tool", {}).get("driver", {})
        name = tool.get("name", "unknown")
        results = run.get("results", [])
        rules_list = tool.get("rules", [])
        lines.append(f"\n  Run {i+1}: {name}")
        lines.append(f"    Rules:   {len(rules_list)}")
        lines.append(f"    Results: {len(results)}")
        by_level: dict[str, int] = {}
        for r in results:
            level = r.get("level", "warning")
            by_level[level] = by_level.get(level, 0) + 1
        for level in ("error", "warning", "note"):
            count = by_level.get(level, 0)
            if count:
                lines.append(f"    {level}: {count}")
    return "\n".join(lines)
