#!/usr/bin/env python3
"""Versioned security taxonomy helpers for Attestor's posture reports.

The mappings in this module are deliberately small and auditable.  OWASP Top
10:2025 is the primary application-risk taxonomy, the older OWASP 2021 value is
retained when an upstream detector supplied one, and CWE Top 25:2025 rank is a
bounded prioritization input rather than a claim that a static finding is a CVE.
"""
from __future__ import annotations

import re
from typing import Any


OWASP_2025 = {
    "A01": "A01:2025 Broken Access Control",
    "A02": "A02:2025 Security Misconfiguration",
    "A03": "A03:2025 Software Supply Chain Failures",
    "A04": "A04:2025 Cryptographic Failures",
    "A05": "A05:2025 Injection",
    "A06": "A06:2025 Insecure Design",
    "A07": "A07:2025 Authentication Failures",
    "A08": "A08:2025 Software or Data Integrity Failures",
    "A09": "A09:2025 Security Logging & Alerting Failures",
    "A10": "A10:2025 Mishandling of Exceptional Conditions",
}

# Official 2025 list order.  Rank is used as a modest multiplier only; it does
# not replace severity, confidence, reachability, or human triage.
CWE_TOP25_2025_RANK = {
    "CWE-79": 1, "CWE-89": 2, "CWE-352": 3, "CWE-862": 4,
    "CWE-787": 5, "CWE-22": 6, "CWE-416": 7, "CWE-125": 8,
    "CWE-78": 9, "CWE-94": 10, "CWE-120": 11, "CWE-434": 12,
    "CWE-476": 13, "CWE-121": 14, "CWE-502": 15, "CWE-122": 16,
    "CWE-863": 17, "CWE-20": 18, "CWE-284": 19, "CWE-200": 20,
    "CWE-306": 21, "CWE-918": 22, "CWE-77": 23, "CWE-639": 24,
    "CWE-770": 25,
}

LEGACY_TO_2025 = {
    "A01": "A01",  # Broken Access Control; SSRF also moved here from A10.
    "A02": "A04",
    "A03": "A05",
    "A04": "A06",
    "A05": "A02",
    "A06": "A03",
    "A07": "A07",
    "A08": "A08",
    "A09": "A09",
    "A10": "A01",
}

CWE_TO_OWASP_2025 = {
    "CWE-22": "A01", "CWE-73": "A01", "CWE-200": "A01",
    "CWE-276": "A01", "CWE-284": "A01", "CWE-306": "A07",
    "CWE-352": "A01", "CWE-601": "A01", "CWE-639": "A01",
    "CWE-732": "A01", "CWE-862": "A01", "CWE-863": "A01",
    "CWE-918": "A01", "CWE-209": "A02", "CWE-489": "A02",
    "CWE-611": "A02", "CWE-16": "A02", "CWE-295": "A04",
    "CWE-319": "A04", "CWE-321": "A04", "CWE-326": "A04",
    "CWE-327": "A04", "CWE-328": "A04", "CWE-330": "A04",
    "CWE-331": "A04", "CWE-798": "A07", "CWE-259": "A07",
    "CWE-287": "A07", "CWE-20": "A06", "CWE-242": "A06",
    "CWE-362": "A06", "CWE-400": "A06", "CWE-770": "A06",
    "CWE-78": "A05", "CWE-79": "A05", "CWE-89": "A05",
    "CWE-94": "A05", "CWE-95": "A05", "CWE-77": "A05",
    "CWE-347": "A08", "CWE-502": "A08", "CWE-353": "A08",
    "CWE-754": "A10", "CWE-755": "A10", "CWE-703": "A10",
}

OWASP_CODE_RX = re.compile(r"\b(A\d{2})(?::(20\d{2}))?\b", re.I)


def top25_coverage(covered: Any) -> dict[str, Any]:
    """Which CWE Top 25:2025 classes the supplied rule catalog can express.

    This reports the presence of a *rule*, never the absence of a defect.  A
    listed gap means Attestor is not looking for that class at all, which is a
    strictly stronger statement than a clean scan -- and the more useful one,
    because a named gap gets closed and a silent one does not.
    """
    tagged = {str(item).upper() for item in (covered or ()) if item}
    present: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    for cwe, rank in sorted(CWE_TOP25_2025_RANK.items(), key=lambda kv: kv[1]):
        row = {"cwe": cwe, "rank": rank,
               "owasp_2025": CWE_TO_OWASP_2025.get(cwe, "")}
        (present if cwe in tagged else missing).append(row)
    return {
        "taxonomy": "CWE Top 25:2025",
        "classes": len(CWE_TOP25_2025_RANK),
        "with_rules": len(present),
        "without_rules": len(missing),
        "covered": present,
        "uncovered": missing,
        "limitations": [
            "presence of a rule is not proof that the rule is complete",
            "an uncovered class is not searched for at all, so a clean scan "
            "says nothing about it",
            "rules carrying no honest weakness class are untagged and are not "
            "counted here even though they run",
        ],
    }


def cwe_rank(cwe: str) -> int | None:
    """Return the official CWE Top 25:2025 rank when mapped exactly."""
    return CWE_TOP25_2025_RANK.get((cwe or "").upper())


def cwe_priority_factor(cwe: str) -> float:
    """Return a conservative 1.00..1.25 risk multiplier for Top-25 CWEs."""
    rank = cwe_rank(cwe)
    return 1.0 if rank is None else round(1.0 + ((26 - rank) / 25.0) * 0.25, 3)


def primary_owasp(*, cwe: str = "", category: str = "", rule: str = "",
                  legacy: str = "") -> str:
    """Map a finding to OWASP Top 10:2025 without overstating weak evidence."""
    text = " ".join((category, rule)).lower()
    # Prefer an exact weakness mapping.  Broad terms such as "secret" and
    # "supply" are only fallbacks for findings without a mapped CWE.
    code = CWE_TO_OWASP_2025.get((cwe or "").upper())
    if code:
        return OWASP_2025[code]
    if any(word in text for word in ("supply", "dependency", "lockfile", "package",
                                      "github-action", "build-pipeline", "install-hook")):
        return OWASP_2025["A03"]
    if any(word in text for word in ("crypto", "cipher", "tls", "certificate", "secret")):
        return OWASP_2025["A04"]
    if any(word in text for word in ("exception", "error-handling", "fail-open")):
        return OWASP_2025["A10"]
    if any(word in text for word in ("logging", "alerting", "audit-log")):
        return OWASP_2025["A09"]
    match = OWASP_CODE_RX.search(legacy or "")
    if match:
        old_code, year = match.group(1).upper(), match.group(2)
        if year == "2025":
            return OWASP_2025.get(old_code, legacy)
        return OWASP_2025.get(LEGACY_TO_2025.get(old_code, ""), "")
    return ""


def stride_for(category: str, rule: str = "") -> list[str]:
    """Return applicable STRIDE threat classes, ordered and deduplicated."""
    text = " ".join((category, rule)).lower()
    values: list[str] = []
    if any(word in text for word in ("auth", "identity", "credential", "token")):
        values += ["Spoofing", "Elevation of Privilege"]
    if any(word in text for word in ("access", "authorization", "privilege", "admin")):
        values += ["Elevation of Privilege"]
    if any(word in text for word in ("injection", "integrity", "supply", "dependency",
                                      "workflow", "ci", "iac", "cloud")):
        values += ["Tampering"]
    if any(word in text for word in ("secret", "data", "exposure", "leak", "cors", "cookie")):
        values += ["Information Disclosure"]
    if any(word in text for word in ("logging", "audit")):
        values += ["Repudiation"]
    if any(word in text for word in ("availability", "resource", "dos", "limit")):
        values += ["Denial of Service"]
    return list(dict.fromkeys(values or ["Tampering"]))


def enrich_taxonomy(row: dict[str, Any]) -> dict[str, Any]:
    """Attach versioned mappings while preserving any upstream legacy value."""
    legacy = str(row.get("owasp") or row.get("owasp_2021") or "")
    primary = primary_owasp(cwe=str(row.get("cwe") or ""),
                            category=str(row.get("category") or ""),
                            rule=str(row.get("rule") or ""), legacy=legacy)
    row["owasp"] = primary
    row["owasp_2025"] = primary
    legacy_2021 = str(row.get("owasp_2021") or "")
    if ":2021" in legacy:
        legacy_2021 = legacy
    else:
        match = OWASP_CODE_RX.search(legacy)
        if match and match.group(2) is None:
            legacy_2021 = (legacy[:match.start()] + match.group(1).upper() + ":2021" +
                           legacy[match.end():])
    row["owasp_2021"] = legacy_2021
    row["cwe_top25_2025_rank"] = cwe_rank(str(row.get("cwe") or ""))
    row["cwe_priority_factor"] = cwe_priority_factor(str(row.get("cwe") or ""))
    row.setdefault("asvs", [])
    row.setdefault("nist_ssdf", [])
    row["stride"] = stride_for(str(row.get("category") or ""), str(row.get("rule") or ""))
    return row
