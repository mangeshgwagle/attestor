#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping, Sequence

VERSION = "4.3"
SCHEMA = "attestor-sigma-export/4.3"

class SigmaExportError(ValueError):
    pass

_HEX = re.compile(r"[0-9a-f]{64}")
_SAFE_RULE = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_MAX_NEGATIVE = 10_000
_MAX_POSITIVE = 1_000
_MAX_SAMPLE_LEN = 64 * 1024

def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)

def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()

def _escape_sigma(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')

def _escape_yara(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

def _normalize_finding(finding: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(finding, Mapping):
        raise SigmaExportError("finding must be a mapping")
    rule = str(finding.get("rule") or finding.get("rule_id") or "").strip()
    if not rule or not _SAFE_RULE.fullmatch(rule):
        raise SigmaExportError("finding rule is missing or invalid")
    snippet = str(finding.get("snippet") or finding.get("message") or finding.get("pattern") or "").strip()
    if not snippet:
        snippet = rule
    if len(snippet) > 512:
        snippet = snippet[:512]
    path = str(finding.get("path") or "unknown").strip()[:1024]
    line = finding.get("line")
    try:
        line_no = max(1, int(line)) if line is not None else 1
    except (TypeError, ValueError):
        line_no = 1
    severity = str(finding.get("severity") or "MEDIUM").upper()
    if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        severity = "MEDIUM"
    return {"rule": rule, "snippet": snippet, "path": path, "line": line_no, "severity": severity, "cwe": str(finding.get("cwe") or "")[:32]}

def finding_to_sigma(finding: Mapping[str, Any]) -> dict[str, Any]:
    f = _normalize_finding(finding)
    rule_id = _digest({"rule": f["rule"], "snippet": f["snippet"]})[:16]
    title = "Attestor detection for %s" % f["rule"]
    level = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "informational"}[f["severity"]]
    pattern = f["snippet"]
    sigma = {
        "title": title,
        "id": rule_id,
        "status": "experimental",
        "description": "Generated from Attestor finding %s at %s:%d" % (f["rule"], f["path"], f["line"]),
        "author": "Attestor 4.3",
        "logsource": {"category": "application", "product": "attestor"},
        "detection": {
            "selection": {"msg|contains": pattern} if len(pattern) < 128 else {"msg|re": re.escape(pattern[:64])},
            "condition": "selection"
        },
        "level": level,
        "tags": ([f["cwe"]] if f["cwe"] else []) + ["attestor.%s" % f["rule"]],
        "_finding": f,
        "_pattern": pattern,
    }
    return sigma

def sigma_to_yaml(sigma: Mapping[str, Any]) -> str:
    f = sigma.get("_finding") or {}
    pattern = sigma.get("_pattern") or ""
    lines = [
        "title: %s" % sigma.get("title", ""),
        "id: %s" % sigma.get("id", ""),
        "status: %s" % sigma.get("status", "experimental"),
        "description: \"%s\"" % _escape_sigma(str(sigma.get("description", ""))),
        "logsource:",
        "    category: application",
        "detection:",
        "    selection:",
        "        msg|contains: \"%s\"" % _escape_sigma(pattern[:256]),
        "    condition: selection",
        "level: %s" % sigma.get("level", "medium"),
    ]
    return "\n".join(lines) + "\n"

def finding_to_yara(finding: Mapping[str, Any]) -> str:
    f = _normalize_finding(finding)
    rule_name = "Attestor_" + re.sub(r"[^A-Za-z0-9_]", "_", f["rule"])[:64]
    snippet_esc = _escape_yara(f["snippet"][:256])
    meta = [
        '    description = "Attestor finding %s at %s:%d"' % (f["rule"], f["path"], f["line"]),
        '    rule_id = "%s"' % f["rule"],
        '    version = "%s"' % VERSION,
    ]
    if f["cwe"]:
        meta.append('    cwe = "%s"' % f["cwe"])
    return "rule %s {\n  meta:\n%s\n  strings:\n    $a = \"%s\"\n  condition:\n    $a\n}\n" % (rule_name, "\n".join(meta), snippet_esc)

def _rule_matches(rule: Mapping[str, Any] | str, sample: str) -> bool:
    if len(sample) > _MAX_SAMPLE_LEN:
        sample = sample[:_MAX_SAMPLE_LEN]
    pattern = ""
    if isinstance(rule, Mapping):
        pattern = str(rule.get("_pattern") or "")
        if not pattern:
            det = rule.get("detection") or {}
            sel = det.get("selection") or {}
            for v in sel.values():
                if isinstance(v, str):
                    pattern = v
                    break
        if not pattern:
            f = rule.get("_finding") or {}
            pattern = str(f.get("snippet") or "")
    else:
        m = re.search(r'\$a\s*=\s*"([^"]*)"', rule)
        if m:
            pattern = m.group(1).encode("utf-8").decode("unicode_escape")
        else:
            pattern = str(rule)
    if not pattern:
        return False
    return pattern.lower() in sample.lower() or re.search(re.escape(pattern), sample, re.IGNORECASE) is not None

def test_fires_on_positive(rule: Mapping[str, Any] | str, positives: Sequence[str]) -> dict[str, Any]:
    if not positives:
        raise SigmaExportError("positive corpus is empty")
    if len(positives) > _MAX_POSITIVE:
        raise SigmaExportError("positive corpus exceeds limit")
    results = []
    for idx, sample in enumerate(positives):
        if not isinstance(sample, str):
            raise SigmaExportError("positive sample %d is not a string" % idx)
        fired = _rule_matches(rule, sample)
        results.append({"index": idx, "fired": fired})
    all_fired = all(r["fired"] for r in results)
    return {"total": len(results), "fired": sum(1 for r in results if r["fired"]), "all_fired": all_fired, "details": results}

def test_silent_on_negative(rule: Mapping[str, Any] | str, negatives: Sequence[str]) -> dict[str, Any]:
    if len(negatives) > _MAX_NEGATIVE:
        raise SigmaExportError("negative corpus exceeds limit")
    results = []
    for idx, sample in enumerate(negatives):
        if not isinstance(sample, str):
            raise SigmaExportError("negative sample %d is not a string" % idx)
        fired = _rule_matches(rule, sample)
        results.append({"index": idx, "fired": fired})
    silent = all(not r["fired"] for r in results)
    false_positives = sum(1 for r in results if r["fired"])
    return {"total": len(results), "false_positives": false_positives, "silent": silent, "details": results}

def export_sigma(finding: Mapping[str, Any], positives: Sequence[str], negatives: Sequence[str]) -> dict[str, Any]:
    sigma = finding_to_sigma(finding)
    pos = test_fires_on_positive(sigma, positives)
    if not pos["all_fired"]:
        raise SigmaExportError("sigma rule did not fire on all positive samples (%d/%d)" % (pos["fired"], pos["total"]))
    neg = test_silent_on_negative(sigma, negatives)
    if not neg["silent"]:
        raise SigmaExportError("sigma rule fired on %d negative samples; gate refuses export" % neg["false_positives"])
    return {"rule_type": "sigma", "rule": sigma, "yaml": sigma_to_yaml(sigma), "positive_test": pos, "negative_test": neg, "exported": True}

def export_yara(finding: Mapping[str, Any], positives: Sequence[str], negatives: Sequence[str]) -> dict[str, Any]:
    yara = finding_to_yara(finding)
    pos = test_fires_on_positive(yara, positives)
    if not pos["all_fired"]:
        raise SigmaExportError("yara rule did not fire on all positive samples (%d/%d)" % (pos["fired"], pos["total"]))
    neg = test_silent_on_negative(yara, negatives)
    if not neg["silent"]:
        raise SigmaExportError("yara rule fired on %d negative samples; gate refuses export" % neg["false_positives"])
    return {"rule_type": "yara", "rule": yara, "positive_test": pos, "negative_test": neg, "exported": True}

def export_rule(finding: Mapping[str, Any], positives: Sequence[str], negatives: Sequence[str], rule_type: str = "sigma") -> dict[str, Any]:
    if rule_type == "sigma":
        return export_sigma(finding, positives, negatives)
    if rule_type == "yara":
        return export_yara(finding, positives, negatives)
    raise SigmaExportError("rule_type must be sigma or yara")
