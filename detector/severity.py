#!/usr/bin/env python3
"""CVSS-like severity scoring engine -- assigns numeric scores to findings based
on CWE base scores, exposure context, confidence, and environmental factors.
Maps findings to OWASP Top 10 (2021) and MITRE ATT&CK categories."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

CWE_BASE_SCORES: dict[str, float] = {
    "CWE-78": 9.8,   # OS Command Injection
    "CWE-89": 9.8,   # SQL Injection
    "CWE-94": 9.8,   # Code Injection
    "CWE-95": 9.0,   # Eval Injection
    "CWE-79": 6.1,   # XSS
    "CWE-22": 7.5,   # Path Traversal
    "CWE-77": 9.8,   # Command Injection
    "CWE-502": 8.1,  # Deserialization
    "CWE-918": 7.5,  # SSRF
    "CWE-611": 7.5,  # XXE
    "CWE-434": 8.8,  # Unrestricted Upload
    "CWE-352": 8.0,  # CSRF
    "CWE-601": 6.1,  # Open Redirect
    "CWE-209": 5.3,  # Error Information Leak
    "CWE-532": 5.5,  # Log Injection / Info Leak
    "CWE-327": 5.9,  # Broken Crypto
    "CWE-328": 5.3,  # Weak Hash
    "CWE-330": 5.3,  # Insufficient Randomness
    "CWE-798": 7.5,  # Hardcoded Credentials
    "CWE-259": 7.5,  # Hardcoded Password
    "CWE-321": 7.5,  # Hardcoded Cryptographic Key
    "CWE-200": 5.3,  # Information Exposure
    "CWE-287": 9.8,  # Improper Authentication
    "CWE-306": 9.8,  # Missing Authentication
    "CWE-862": 8.6,  # Missing Authorization
    "CWE-863": 8.6,  # Incorrect Authorization
    "CWE-269": 8.8,  # Improper Privilege Management
    "CWE-250": 7.8,  # Exec with Unnecessary Privileges
    "CWE-732": 7.5,  # Incorrect Permission Assignment
    "CWE-1321": 8.6, # Prototype Pollution
    "CWE-1333": 7.5, # ReDoS
    "CWE-942": 5.3,  # Permissive CORS
    "CWE-693": 5.3,  # Protection Mechanism Failure
    "CWE-1004": 5.3, # Sensitive Cookie Without HttpOnly
    "CWE-120": 9.8,  # Buffer Overflow
    "CWE-125": 7.5,  # Out-of-bounds Read
    "CWE-787": 9.8,  # Out-of-bounds Write
    "CWE-416": 8.1,  # Use After Free
    "CWE-190": 7.5,  # Integer Overflow
    "CWE-476": 7.5,  # NULL Pointer Dereference
    "CWE-134": 9.8,  # Format String
    "CWE-362": 8.1,  # Race Condition
}

SEVERITY_LABEL_BASE: dict[str, float] = {
    "CRITICAL": 9.0,
    "HIGH": 7.0,
    "MEDIUM": 4.5,
    "LOW": 2.0,
    "INFO": 0.5,
}

OWASP_2021: dict[str, tuple[str, str]] = {
    "CWE-78": ("A03", "Injection"),
    "CWE-89": ("A03", "Injection"),
    "CWE-77": ("A03", "Injection"),
    "CWE-94": ("A03", "Injection"),
    "CWE-95": ("A03", "Injection"),
    "CWE-79": ("A03", "Injection"),
    "CWE-611": ("A03", "Injection"),
    "CWE-917": ("A03", "Injection"),
    "CWE-502": ("A08", "Software and Data Integrity Failures"),
    "CWE-287": ("A07", "Identification and Authentication Failures"),
    "CWE-306": ("A07", "Identification and Authentication Failures"),
    "CWE-798": ("A07", "Identification and Authentication Failures"),
    "CWE-259": ("A07", "Identification and Authentication Failures"),
    "CWE-862": ("A01", "Broken Access Control"),
    "CWE-863": ("A01", "Broken Access Control"),
    "CWE-22": ("A01", "Broken Access Control"),
    "CWE-601": ("A01", "Broken Access Control"),
    "CWE-918": ("A10", "Server-Side Request Forgery"),
    "CWE-327": ("A02", "Cryptographic Failures"),
    "CWE-328": ("A02", "Cryptographic Failures"),
    "CWE-330": ("A02", "Cryptographic Failures"),
    "CWE-321": ("A02", "Cryptographic Failures"),
    "CWE-209": ("A04", "Insecure Design"),
    "CWE-532": ("A09", "Security Logging and Monitoring Failures"),
    "CWE-942": ("A05", "Security Misconfiguration"),
    "CWE-693": ("A05", "Security Misconfiguration"),
    "CWE-1004": ("A05", "Security Misconfiguration"),
    "CWE-352": ("A01", "Broken Access Control"),
    "CWE-434": ("A04", "Insecure Design"),
    "CWE-1321": ("A08", "Software and Data Integrity Failures"),
    "CWE-1333": ("A06", "Vulnerable and Outdated Components"),
}

MITRE_MAPPING: dict[str, str] = {
    "CWE-78": "T1059 (Command and Scripting Interpreter)",
    "CWE-89": "T1190 (Exploit Public-Facing Application)",
    "CWE-79": "T1189 (Drive-by Compromise)",
    "CWE-22": "T1083 (File and Directory Discovery)",
    "CWE-502": "T1055 (Process Injection)",
    "CWE-798": "T1078 (Valid Accounts)",
    "CWE-918": "T1090 (Proxy)",
    "CWE-120": "T1203 (Exploitation for Client Execution)",
    "CWE-787": "T1203 (Exploitation for Client Execution)",
    "CWE-416": "T1203 (Exploitation for Client Execution)",
}

EXPOSURE_MULTIPLIER = {
    "internet": 1.0,
    "internal": 0.7,
    "local": 0.4,
    "test": 0.1,
}

CONFIDENCE_MULTIPLIER = {
    "high": 1.0,
    "medium": 0.8,
    "low": 0.5,
}


@dataclass
class ScoredFinding:
    rule_id: str
    path: str
    line: int
    severity_label: str
    base_score: float
    adjusted_score: float
    cwe: str
    owasp_id: str
    owasp_name: str
    mitre: str
    exposure: str
    confidence: str
    description: str = ""


def score_finding(
    finding: dict,
    exposure: str = "internet",
    confidence: str = "high",
) -> ScoredFinding:
    cwe = finding.get("cwe", "")
    severity_label = finding.get("severity", "MEDIUM").upper()
    rule_id = finding.get("rule_id", "")

    base_score = CWE_BASE_SCORES.get(cwe, SEVERITY_LABEL_BASE.get(severity_label, 4.5))

    exp_mult = EXPOSURE_MULTIPLIER.get(exposure, 0.7)
    conf_mult = CONFIDENCE_MULTIPLIER.get(confidence, 0.8)
    adjusted = round(min(10.0, base_score * exp_mult * conf_mult), 1)

    if adjusted >= 9.0:
        label = "CRITICAL"
    elif adjusted >= 7.0:
        label = "HIGH"
    elif adjusted >= 4.0:
        label = "MEDIUM"
    elif adjusted >= 0.1:
        label = "LOW"
    else:
        label = "INFO"

    owasp = OWASP_2021.get(cwe, ("", ""))
    mitre = MITRE_MAPPING.get(cwe, "")

    return ScoredFinding(
        rule_id=rule_id,
        path=finding.get("path", ""),
        line=finding.get("line", 0),
        severity_label=label,
        base_score=base_score,
        adjusted_score=adjusted,
        cwe=cwe,
        owasp_id=owasp[0],
        owasp_name=owasp[1],
        mitre=mitre,
        exposure=exposure,
        confidence=confidence,
        description=finding.get("description", ""),
    )


def score_findings(
    findings: list[dict],
    exposure: str = "internet",
    confidence: str = "high",
) -> list[ScoredFinding]:
    scored = [score_finding(f, exposure, confidence) for f in findings]
    scored.sort(key=lambda s: -s.adjusted_score)
    return scored


def render(scored: list[ScoredFinding]) -> str:
    if not scored:
        return "  No findings to score."
    lines = []
    lines.append(f"\n  Scored Findings ({len(scored)} total)")
    lines.append(f"  {'='*60}")
    for s in scored:
        cwe_str = f" ({s.cwe})" if s.cwe else ""
        owasp_str = f" OWASP:{s.owasp_id}" if s.owasp_id else ""
        mitre_str = f" MITRE:{s.mitre.split('(')[0].strip()}" if s.mitre else ""
        lines.append(
            f"  [{s.severity_label:8s}] {s.adjusted_score:4.1f}  "
            f"{s.path}:{s.line}  {s.rule_id}{cwe_str}{owasp_str}{mitre_str}"
        )
        if s.description:
            lines.append(f"           {s.description[:100]}")

    by_owasp = {}
    for s in scored:
        if s.owasp_id:
            by_owasp.setdefault(s.owasp_id, []).append(s)
    if by_owasp:
        lines.append(f"\n  OWASP Top 10 (2021) Summary:")
        for oid in sorted(by_owasp):
            group = by_owasp[oid]
            name = group[0].owasp_name
            max_score = max(s.adjusted_score for s in group)
            lines.append(f"    {oid} {name}: {len(group)} finding(s), max score {max_score}")

    avg = sum(s.adjusted_score for s in scored) / len(scored)
    max_s = max(s.adjusted_score for s in scored)
    lines.append(f"\n  Risk Summary: avg={avg:.1f}, max={max_s:.1f}, total={len(scored)}")
    return "\n".join(lines)


def to_dict(scored: list[ScoredFinding]) -> list[dict]:
    return [
        {
            "rule_id": s.rule_id,
            "path": s.path,
            "line": s.line,
            "severity": s.severity_label,
            "base_score": s.base_score,
            "adjusted_score": s.adjusted_score,
            "cwe": s.cwe,
            "owasp_id": s.owasp_id,
            "owasp_name": s.owasp_name,
            "mitre": s.mitre,
            "exposure": s.exposure,
            "confidence": s.confidence,
            "description": s.description,
        }
        for s in scored
    ]
