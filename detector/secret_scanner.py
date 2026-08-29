#!/usr/bin/env python3
"""Secret and credential scanner -- detects hardcoded secrets, API keys, tokens,
passwords, private keys, and high-entropy strings in source code."""
from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".lib",
    ".pyc", ".pyo", ".class", ".jar", ".war", ".zip", ".tar", ".gz",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".avi",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
}

SKIP_DIRS = {
    ".git", ".svn", "node_modules", "__pycache__", ".tox", ".venv",
    "venv", "env", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".eggs", "*.egg-info",
}


@dataclass
class SecretFinding:
    path: str
    line: int
    rule_id: str
    description: str
    severity: str
    matched_text: str
    redacted: str


SECRET_PATTERNS: list[tuple[str, str, str, str]] = [
    # (rule_id, description, regex_pattern, severity)

    # AWS
    ("SEC-AWS-KEY", "AWS Access Key ID",
     r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", "CRITICAL"),
    ("SEC-AWS-SECRET", "AWS Secret Access Key",
     r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s]*[=:]+[\s]*['\"]?([A-Za-z0-9/+=]{40})['\"]?", "CRITICAL"),

    # GitHub
    ("SEC-GH-PAT", "GitHub Personal Access Token",
     r"ghp_[A-Za-z0-9]{36}", "CRITICAL"),
    ("SEC-GH-OAUTH", "GitHub OAuth Access Token",
     r"gho_[A-Za-z0-9]{36}", "CRITICAL"),
    ("SEC-GH-FINE", "GitHub Fine-Grained Token",
     r"github_pat_[A-Za-z0-9_]{82}", "CRITICAL"),

    # GitLab
    ("SEC-GL-PAT", "GitLab Personal Access Token",
     r"glpat-[A-Za-z0-9\-]{20,}", "CRITICAL"),

    # Slack
    ("SEC-SLACK-TOKEN", "Slack Bot/User Token",
     r"xox[bporas]-[A-Za-z0-9\-]{10,250}", "CRITICAL"),
    ("SEC-SLACK-WEBHOOK", "Slack Webhook URL",
     r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}", "HIGH"),

    # Google
    ("SEC-GCP-KEY", "Google API Key",
     r"AIza[A-Za-z0-9_\-]{35}", "HIGH"),
    ("SEC-GCP-OAUTH", "Google OAuth Client Secret",
     r"(?i)client[_\-]?secret[\s]*[=:]+[\s]*['\"]?([A-Za-z0-9_\-]{24})['\"]?", "HIGH"),

    # Azure
    ("SEC-AZURE-SUB", "Azure Subscription Key",
     r"(?i)(?:subscription[_\-]?key|azure[_\-]?key)[\s]*[=:]+[\s]*['\"]?([A-Fa-f0-9]{32})['\"]?", "HIGH"),

    # Stripe
    ("SEC-STRIPE-SK", "Stripe Secret Key",
     r"sk_live_[A-Za-z0-9]{24,}", "CRITICAL"),
    ("SEC-STRIPE-RK", "Stripe Restricted Key",
     r"rk_live_[A-Za-z0-9]{24,}", "CRITICAL"),

    # Twilio
    ("SEC-TWILIO", "Twilio API Key",
     r"SK[a-f0-9]{32}", "HIGH"),

    # SendGrid
    ("SEC-SENDGRID", "SendGrid API Key",
     r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}", "CRITICAL"),

    # Mailgun
    ("SEC-MAILGUN", "Mailgun API Key",
     r"key-[A-Za-z0-9]{32}", "HIGH"),

    # NPM
    ("SEC-NPM", "NPM Token",
     r"npm_[A-Za-z0-9]{36}", "CRITICAL"),

    # PyPI
    ("SEC-PYPI", "PyPI API Token",
     r"pypi-[A-Za-z0-9_\-]{50,}", "CRITICAL"),

    # Generic tokens
    ("SEC-JWT", "JSON Web Token",
     r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "HIGH"),
    ("SEC-BEARER", "Bearer Token in Code",
     r"(?i)(?:bearer|authorization)[\s]*[=:]+[\s]*['\"]?bearer\s+[A-Za-z0-9_\-\.]{20,}['\"]?", "HIGH"),

    # Private keys
    ("SEC-PRIVKEY", "Private Key",
     r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", "CRITICAL"),
    ("SEC-PRIVKEY-PKCS8", "PKCS8 Private Key",
     r"-----BEGIN ENCRYPTED PRIVATE KEY-----", "HIGH"),

    # Passwords
    ("SEC-PASSWORD", "Hardcoded Password",
     r"(?i)(?:password|passwd|pwd|secret)[\s]*[=:]+[\s]*['\"][^'\"]{8,}['\"]", "HIGH"),

    # Connection strings
    ("SEC-CONNSTR", "Database Connection String",
     r"(?i)(?:mongodb|postgres|mysql|mssql|redis|amqp)://[^\s'\"]{10,}", "HIGH"),
    ("SEC-DSN", "DSN with Credentials",
     r"(?i)(?:mysql|pgsql|sqlite|oracle)://[^:]+:[^@]+@[^\s'\"]+", "CRITICAL"),

    # Generic high-entropy hex
    ("SEC-GENERIC-HEX", "Generic Secret (hex, 32+ chars)",
     r"(?i)(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token|api[_\-]?secret)[\s]*[=:]+[\s]*['\"]?([A-Fa-f0-9]{32,})['\"]?", "MEDIUM"),

    # Heroku
    ("SEC-HEROKU", "Heroku API Key",
     r"(?i)heroku[\s]*[=:]+[\s]*['\"]?[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}['\"]?", "HIGH"),

    # Discord
    ("SEC-DISCORD", "Discord Bot Token",
     r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}", "CRITICAL"),

    # Telegram
    ("SEC-TELEGRAM", "Telegram Bot Token",
     r"\d{8,10}:[A-Za-z0-9_-]{35}", "HIGH"),
]

_compiled_patterns: list[tuple[str, str, re.Pattern, str]] = []


def _get_patterns():
    global _compiled_patterns
    if not _compiled_patterns:
        _compiled_patterns = [
            (rid, desc, re.compile(pat), sev)
            for rid, desc, pat, sev in SECRET_PATTERNS
        ]
    return _compiled_patterns


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _redact(text: str) -> str:
    if len(text) <= 8:
        return "***"
    return text[:4] + "*" * (len(text) - 8) + text[-4:]


ENTROPY_THRESHOLD = 4.5
ENTROPY_MIN_LENGTH = 20

ALLOWLIST_PATTERNS = [
    re.compile(r"(?i)example|placeholder|dummy|test|sample|changeme|fixme|todo|your[_\-]?key"),
    re.compile(r"^[0]{16,}$"),
    re.compile(r"^[x]{16,}$"),
    re.compile(r"^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$"),
]


def _is_allowlisted(text: str) -> bool:
    return any(p.search(text) for p in ALLOWLIST_PATTERNS)


def _is_test_file(path: str) -> bool:
    p = path.lower()
    return ("test" in p or "spec" in p or "mock" in p or
            "fixture" in p or "fake" in p or "__tests__" in p)


def scan_line(line: str, lineno: int, path: str) -> list[SecretFinding]:
    findings = []
    if line.strip().startswith(("#", "//", "/*", "*")):
        return findings

    for rule_id, desc, pattern, severity in _get_patterns():
        for m in pattern.finditer(line):
            matched = m.group(0)
            actual_secret = m.group(1) if m.lastindex else matched
            if _is_allowlisted(actual_secret):
                continue
            if _is_test_file(path) and severity != "CRITICAL":
                severity = "LOW"
            findings.append(SecretFinding(
                path=path,
                line=lineno,
                rule_id=rule_id,
                description=desc,
                severity=severity,
                matched_text=matched,
                redacted=_redact(matched),
            ))
    return findings


def scan_entropy(line: str, lineno: int, path: str) -> list[SecretFinding]:
    findings = []
    tokens = re.findall(r"['\"]([A-Za-z0-9+/=_\-]{20,})['\"]", line)
    for token in tokens:
        if len(token) < ENTROPY_MIN_LENGTH:
            continue
        ent = shannon_entropy(token)
        if ent >= ENTROPY_THRESHOLD:
            if _is_allowlisted(token):
                continue
            findings.append(SecretFinding(
                path=path,
                line=lineno,
                rule_id="SEC-ENTROPY",
                description=f"High-entropy string (entropy={ent:.2f})",
                severity="MEDIUM",
                matched_text=token,
                redacted=_redact(token),
            ))
    return findings


def scan_file(path: str, entropy: bool = True) -> list[SecretFinding]:
    ext = Path(path).suffix.lower()
    if ext in BINARY_EXTENSIONS:
        return []
    findings = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                findings.extend(scan_line(line, lineno, path))
                if entropy:
                    findings.extend(scan_entropy(line, lineno, path))
    except (OSError, PermissionError):
        pass
    return findings


def scan_directory(root: str, entropy: bool = True) -> list[SecretFinding]:
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            findings.extend(scan_file(fpath, entropy=entropy))
    return findings


def render(findings: list[SecretFinding]) -> str:
    if not findings:
        return "  No secrets detected."
    lines = []
    by_sev = {}
    for f in findings:
        by_sev.setdefault(f.severity, []).append(f)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        group = by_sev.get(sev, [])
        if not group:
            continue
        lines.append(f"\n  [{sev}] ({len(group)} finding{'s' if len(group) > 1 else ''})")
        for f in group:
            lines.append(f"    {f.path}:{f.line}  {f.rule_id}")
            lines.append(f"      {f.description}")
            lines.append(f"      Matched: {f.redacted}")
    total = len(findings)
    crit = len(by_sev.get("CRITICAL", []))
    lines.append(f"\n  Total: {total} secret(s) found ({crit} critical)")
    return "\n".join(lines)


def to_dict(findings: list[SecretFinding]) -> list[dict]:
    return [
        {
            "path": f.path,
            "line": f.line,
            "rule_id": f.rule_id,
            "description": f.description,
            "severity": f.severity,
            "redacted": f.redacted,
        }
        for f in findings
    ]
