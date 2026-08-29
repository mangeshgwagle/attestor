#!/usr/bin/env python3
"""SARIF 2.1.0 output formatter -- generates GitHub Code Scanning compatible
SARIF output from Attestor findings."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"


def _severity_to_level(severity: str) -> str:
    return {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }.get(severity.upper(), "warning")


def _severity_to_rank(severity: str) -> float:
    return {
        "CRITICAL": 9.5,
        "HIGH": 8.0,
        "MEDIUM": 5.0,
        "LOW": 2.0,
        "INFO": 0.5,
    }.get(severity.upper(), 5.0)


def _build_rule(rule_id: str, description: str, severity: str,
                cwe: str = "", category: str = "") -> dict:
    rule: dict[str, Any] = {
        "id": rule_id,
        "shortDescription": {"text": description},
        "defaultConfiguration": {
            "level": _severity_to_level(severity),
        },
        "properties": {
            "security-severity": str(_severity_to_rank(severity)),
        },
    }
    if cwe:
        rule["properties"]["tags"] = ["security", cwe]
        rule["relationships"] = [{
            "target": {
                "id": cwe,
                "guid": "",
                "toolComponent": {"name": "CWE", "index": 0},
            },
            "kinds": ["superset"],
        }]
    else:
        rule["properties"]["tags"] = ["security"]
    if category:
        rule["properties"]["category"] = category
    return rule


def _build_result(finding: dict, rule_index: int) -> dict:
    severity = finding.get("severity", "MEDIUM")
    result: dict[str, Any] = {
        "ruleId": finding.get("rule_id", "UNKNOWN"),
        "ruleIndex": rule_index,
        "level": _severity_to_level(severity),
        "message": {
            "text": finding.get("description", finding.get("message", "")),
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": finding.get("path", "").replace("\\", "/"),
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {
                    "startLine": max(1, finding.get("line", 1)),
                },
            },
        }],
    }
    if finding.get("matched_text"):
        result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
            "text": finding["matched_text"][:500],
        }
    if finding.get("remediation"):
        result["fixes"] = [{
            "description": {"text": finding["remediation"]},
        }]
    return result


def generate_sarif(
    findings: list[dict],
    tool_name: str = "Attestor",
    tool_version: str = "4.2",
    root: str = "",
) -> dict:
    rules = {}
    rule_indices = {}
    results = []

    for finding in findings:
        rule_id = finding.get("rule_id", "UNKNOWN")
        if rule_id not in rules:
            idx = len(rules)
            rules[rule_id] = _build_rule(
                rule_id,
                finding.get("description", ""),
                finding.get("severity", "MEDIUM"),
                cwe=finding.get("cwe", ""),
                category=finding.get("category", ""),
            )
            rule_indices[rule_id] = idx
        results.append(_build_result(finding, rule_indices[rule_id]))

    sarif: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "semanticVersion": tool_version,
                    "informationUri": "https://github.com/attestor",
                    "rules": list(rules.values()),
                },
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": datetime.now(timezone.utc).isoformat(),
            }],
        }],
    }

    if root:
        sarif["runs"][0]["originalUriBaseIds"] = {
            "%SRCROOT%": {
                "uri": f"file:///{root.replace(os.sep, '/')}/" if os.path.isabs(root) else root + "/",
            },
        }

    return sarif


def write_sarif(
    findings: list[dict],
    output_path: str,
    tool_name: str = "Attestor",
    tool_version: str = "4.2",
    root: str = "",
):
    sarif = generate_sarif(findings, tool_name, tool_version, root)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)
        f.write("\n")


def merge_sarif_runs(*sarif_docs: dict) -> dict:
    merged_runs = []
    for doc in sarif_docs:
        merged_runs.extend(doc.get("runs", []))
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": merged_runs,
    }


def summary(sarif: dict) -> str:
    lines = []
    for i, run in enumerate(sarif.get("runs", [])):
        tool = run.get("tool", {}).get("driver", {})
        name = tool.get("name", "unknown")
        results = run.get("results", [])
        rules = tool.get("rules", [])
        lines.append(f"\n  Run {i+1}: {name}")
        lines.append(f"    Rules:   {len(rules)}")
        lines.append(f"    Results: {len(results)}")
        by_level = {}
        for r in results:
            level = r.get("level", "warning")
            by_level[level] = by_level.get(level, 0) + 1
        for level in ("error", "warning", "note"):
            count = by_level.get(level, 0)
            if count:
                lines.append(f"    {level}: {count}")
    return "\n".join(lines)
