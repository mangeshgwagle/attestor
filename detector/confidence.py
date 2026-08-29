#!/usr/bin/env python3
"""Confidence metadata for Attestor findings.

The detector already assigns severity. This module adds the operational labels a
repair pipeline needs: confidence, exploitability, and whether the issue is safe
to autofix mechanically.
"""
from __future__ import annotations

SECURITY_RULES = {
    "hardcoded-secret", "py-empty-secret-default", "py-sql-injection",
    "tls-verify-disabled", "weak-hash", "dangerous-eval", "py-yaml-load",
    "py-subprocess-shell", "py-insecure-deserialize", "debug-enabled",
    "js-client-secret-storage", "js-innerhtml", "js-settimeout-string",
    "js-prototype-pollution", "insecure-http-url", "unsafe-libc",
    "command-exec", "format-string", "scanf-unbounded",
}

SAFE_AUTOFIX_RULES = {
    "py-eq-none",
    "py-bare-except",
    "tls-verify-disabled",
    "weak-hash",
    "debug-enabled",
}

HIGH_SIGNAL_RULES = {
    "syntax-error", "tls-verify-disabled", "weak-hash", "dangerous-eval",
    "py-yaml-load", "py-subprocess-shell", "py-insecure-deserialize",
    "py-dict-fromkeys-mutable", "dataclass-mutable-default",
    "list-multiply-alias", "return-value-in-init", "c-realloc-leak",
    "c-return-local-address", "c-free-stack-address", "cpp-delete-array-mismatch",
}

LOW_SIGNAL_RULES = {
    "todo-fixme", "js-var", "py-bind-all-interfaces", "rangefor-copy",
    "float-equality", "weak-rng",
}

BASE_CONFIDENCE = {"HIGH": 0.86, "MEDIUM": 0.76, "LOW": 0.62}


def exploitability(rule: str, severity: str) -> str:
    if rule in SECURITY_RULES or severity == "HIGH":
        return "HIGH"
    if severity == "MEDIUM":
        return "MEDIUM"
    return "LOW"


def confidence(rule: str, severity: str, snippet: str = "") -> float:
    score = BASE_CONFIDENCE.get(severity, 0.60)
    if rule in HIGH_SIGNAL_RULES:
        score += 0.09
    if rule in LOW_SIGNAL_RULES:
        score -= 0.10
    if snippet and len(snippet.strip()) >= 6:
        score += 0.02
    return round(max(0.35, min(0.99, score)), 2)


def safe_to_autofix(rule: str) -> bool:
    return rule in SAFE_AUTOFIX_RULES


def score(rule: str, severity: str, fix: str = "", message: str = "", snippet: str = "") -> dict:
    """Return the confidence packet attached to every detector finding."""
    return {
        "confidence": confidence(rule, severity, snippet),
        "exploitability": exploitability(rule, severity),
        "safe_to_autofix": safe_to_autofix(rule),
    }


def enrich(finding):
    """Mutate a Finding-like object with confidence metadata and return it."""
    meta = score(
        getattr(finding, "rule", ""),
        getattr(finding, "severity", ""),
        getattr(finding, "fix", ""),
        getattr(finding, "message", ""),
        getattr(finding, "snippet", ""),
    )
    finding.confidence = meta["confidence"]
    finding.exploitability = meta["exploitability"]
    finding.safe_to_autofix = meta["safe_to_autofix"]
    return finding
