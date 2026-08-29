#!/usr/bin/env python3
"""Finding triage: rule confidence x file weight -> priority -> action.

The core `confidence.py` scores an individual finding's severity/exploitability.
This module answers the operational question that actually reduces noise: given
everything the aggregate scanners emitted, WHICH findings does a human look at?

It multiplies a per-rule confidence (how often this rule is right) by the
vendored-code weight (is this even the user's code?) to get a single priority,
then buckets into report / review / suppress. Tune the per-rule numbers from
measured precision with `evaluate.py` -- they are meant to be earned."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

try:
    import vendored
except ImportError:  # pragma: no cover
    from . import vendored  # type: ignore

DEFAULT_CONFIDENCE = 0.6

# Confidence per rule-id PREFIX (longest match wins). Seeded from expert priors;
# overwrite with evaluate.py --calibrate once you have measured precision.
RULE_CONFIDENCE: dict[str, float] = {
    # near-certain literal patterns
    "SEC-PRIVKEY": 0.97, "SEC-AWS": 0.98, "SEC-GITHUB": 0.98, "SEC-SLACK": 0.95,
    "SEC-STRIPE": 0.95, "SEC-GCP": 0.9, "SEC-AZURE": 0.9,
    "BIN-STR-PRIVKEY": 0.97, "BIN-STR-AWSKEY": 0.95, "BIN-STR-GHTOKEN": 0.95,
    "GIT-SECRET": 0.9, "GIT-DELETED-SECRET": 0.9,
    # data-flow: strong when a real source reaches a real sink
    "TAINT": 0.8,
    # CWE-mapped JS rules
    "JS-SQLI": 0.8, "JS-CMDI": 0.85, "JS-XSS": 0.7, "JS-SSRF": 0.7, "JS-PROTO": 0.65,
    # infra / pipeline: config facts
    "IAC": 0.8, "CICD-GHA-INJECT": 0.85, "CICD-GHA-BRANCH": 0.85, "CICD": 0.7,
    # supply chain
    "SC-TYPOSQUAT-XFORM": 0.85, "SC-SETUP-EXEC": 0.85, "SC-TYPOSQUAT-SIM": 0.55,
    # exploit detector -- noisy by nature; these are the self-scan flooders
    "EXP-ROOTKIT": 0.15, "EXP-OBFUSCATION": 0.35, "EXP-BACKDOOR": 0.4,
    "EXP-REVSHELL": 0.45, "EXP-C2": 0.3, "EXP-EVASION": 0.3,
    "EXP-CREDACCESS": 0.4, "EXP-PRIVESC": 0.4, "EXP-LATERAL": 0.4,
    "EXP-KEYLOGGER": 0.45, "EXP-EXFIL": 0.4, "EXP-MINER": 0.5, "EXP-WEBSHELL": 0.55,
    # heuristics
    "CVE-": 0.45, "SEC-ENTROPY": 0.35,
}

_SEVERITY_BOOST = {"CRITICAL": 1.0, "HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}
_CONFIG_FILE = ".attestor-triage.json"


@dataclass
class Triaged:
    finding: dict
    rule_confidence: float
    file_weight: float
    priority: float
    action: str          # "report" | "review" | "suppress"


def rule_confidence(rule_id: str) -> float:
    best_len, best_val = -1, DEFAULT_CONFIDENCE
    for prefix, val in RULE_CONFIDENCE.items():
        if rule_id.startswith(prefix) and len(prefix) > best_len:
            best_len, best_val = len(prefix), val
    return best_val


def triage_one(finding: dict, sniff_content: bool = True,
               _cache: dict | None = None) -> Triaged:
    rid = finding.get("rule_id", "")
    sev = finding.get("severity", "MEDIUM")
    path = finding.get("path") or finding.get("file") or finding.get("source_file") or ""

    rc = rule_confidence(rid)
    if _cache is not None and path in _cache:
        fw = _cache[path]
    else:
        fw = vendored.weight_for(path, sniff_content) if path else 1.0
        if _cache is not None:
            _cache[path] = fw
    priority = round(rc * fw * _SEVERITY_BOOST.get(sev, 0.7), 4)
    action = "report" if priority >= 0.5 else "review" if priority >= 0.2 else "suppress"
    return Triaged(finding, rc, fw, priority, action)


def triage_all(findings: list[dict], sniff_content: bool = True) -> list[Triaged]:
    cache: dict[str, float] = {}
    out = [triage_one(f, sniff_content, cache) for f in findings]
    out.sort(key=lambda t: -t.priority)
    return out


def counts(triaged: list[Triaged]) -> dict[str, int]:
    c = {"report": 0, "review": 0, "suppress": 0}
    for t in triaged:
        c[t.action] += 1
    return c


def load_overrides(path: str = _CONFIG_FILE) -> None:
    if not os.path.exists(path):
        return
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for k, v in data.get("rule_confidence", {}).items():
            RULE_CONFIDENCE[k] = float(v)
    except (OSError, json.JSONDecodeError, ValueError):
        pass


def save_overrides(path: str = _CONFIG_FILE) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"rule_confidence": RULE_CONFIDENCE}, f, indent=2, sort_keys=True)


def render(triaged: list[Triaged], limit: int = 40) -> str:
    c = counts(triaged)
    total = len(triaged)
    reduction = (c["suppress"] / total * 100) if total else 0.0
    lines = [
        f"\n  Triage ({total} findings)",
        "  " + "=" * 55,
        f"  report: {c['report']}   review: {c['review']}   suppress: {c['suppress']}",
        f"  noise removed: {c['suppress']}/{total} ({reduction:.1f}%) "
        f"vendored/low-confidence\n",
    ]
    shown = [t for t in triaged if t.action != "suppress"][:limit]
    for t in shown:
        f = t.finding
        p = f.get("path") or f.get("file") or "?"
        ln = f.get("line") or f.get("line_start") or "?"
        lines.append(f"  [{t.action:7s}] p={t.priority:.2f} "
                     f"(rule={t.rule_confidence:.2f} file={t.file_weight:.2f})  "
                     f"{f.get('rule_id','?')}  {p}:{ln}")
    if not shown:
        lines.append("  (nothing above suppression threshold)")
    return "\n".join(lines)


def to_dict(triaged: list[Triaged]) -> list[dict]:
    return [
        {**t.finding, "rule_confidence": t.rule_confidence,
         "file_weight": t.file_weight, "priority": t.priority, "action": t.action}
        for t in triaged
    ]
