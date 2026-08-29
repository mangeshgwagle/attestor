#!/usr/bin/env python3
"""Threat intelligence IOC scanner -- detects indicators of compromise (IOCs)
in source code: known malicious IPs, suspicious domains, malware hashes,
C2 server patterns, cryptocurrency addresses, and Tor/proxy indicators."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {
    ".git", ".svn", "node_modules", "__pycache__", ".tox", ".venv",
    "venv", "dist", "build",
}

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".pyc",
    ".png", ".jpg", ".gif", ".zip", ".tar", ".gz", ".pdf",
}


@dataclass
class IOCFinding:
    path: str
    line: int
    ioc_type: str
    value: str
    description: str
    severity: str
    rule_id: str


KNOWN_MALICIOUS_SUBNETS = [
    r"(?:185\.220\.10[0-3])\.\d{1,3}",    # Known Tor exit / abuse
    r"(?:45\.33\.32\.156)",                 # scanme.nmap.org (not malicious but recon indicator)
    r"(?:198\.51\.100)\.\d{1,3}",          # Documentation range (shouldn't appear in prod code)
    r"(?:203\.0\.113)\.\d{1,3}",           # Documentation range
]

SUSPICIOUS_DOMAIN_PATTERNS = [
    (r"(?:pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.co)/\w+", "Pastebin URL (potential C2 or data hosting)"),
    (r"(?:ngrok\.io|serveo\.net|localhost\.run|localtunnel\.me)", "Tunnel service domain (potential C2)"),
    (r"(?:\.onion)\b", "Tor hidden service domain"),
    (r"(?:\.i2p)\b", "I2P network domain"),
    (r"(?:discord(?:app)?\.com/api/webhooks/\d+/[\w\-]+)", "Discord webhook (potential C2/exfil)"),
    (r"(?:telegram\.(?:org|me)|api\.telegram\.org)/bot", "Telegram bot API (potential C2)"),
    (r"(?:raw\.githubusercontent\.com|gist\.githubusercontent\.com)/[^\s'\"]+", "Raw GitHub content (potential payload hosting)"),
    (r"(?:iplogger\.org|grabify\.link|iplogger\.com)", "IP logger / tracking service"),
    (r"(?:temp-mail|guerrillamail|throwaway\.email|mailinator)", "Disposable email service"),
]

HASH_PATTERNS = [
    ("MD5", r"\b[a-fA-F0-9]{32}\b"),
    ("SHA1", r"\b[a-fA-F0-9]{40}\b"),
    ("SHA256", r"\b[a-fA-F0-9]{64}\b"),
]

CRYPTO_WALLET_PATTERNS = [
    ("Bitcoin", r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    ("Bitcoin Bech32", r"\bbc1[a-zA-HJ-NP-Z0-9]{39,59}\b"),
    ("Ethereum", r"\b0x[a-fA-F0-9]{40}\b"),
    ("Monero", r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
]

PROXY_SOCKS_PATTERNS = [
    (r"(?:socks[45]?|proxy)://[^\s'\"]+", "SOCKS/proxy URL"),
    (r"(?:tor_proxy|socks_proxy|http_proxy)\s*=\s*['\"]?(?:socks|http)", "Proxy configuration for anonymization"),
    (r"(?:ProxyChains|proxychains|tsocks|torsocks)", "Proxy chaining tool reference"),
]

EXPLOIT_DB_PATTERNS = [
    (r"(?:exploit-db\.com|sploitus\.com|0day\.today|packetstormsecurity)", "Exploit database reference"),
    (r"CVE-\d{4}-\d{4,7}", "CVE reference in code"),
    (r"(?:EDB-ID|exploit/\d+)", "Exploit-DB ID reference"),
]

SUSPICIOUS_USERAGENT = [
    (r"(?:User-Agent|useragent)\s*[:=]\s*['\"](?:Mozilla|curl|wget|python-requests|Go-http-client|Nikto|sqlmap|nmap|dirbuster|gobuster)",
     "Hardcoded User-Agent string (potential recon/attack tool)"),
]

_compiled_domain_patterns: list[tuple[re.Pattern, str]] = []
_compiled_proxy_patterns: list[tuple[re.Pattern, str]] = []
_compiled_exploit_patterns: list[tuple[re.Pattern, str]] = []
_compiled_ua_patterns: list[tuple[re.Pattern, str]] = []
_compiled_subnet_patterns: list[re.Pattern] = []


def _compile_all():
    global _compiled_domain_patterns, _compiled_proxy_patterns
    global _compiled_exploit_patterns, _compiled_ua_patterns, _compiled_subnet_patterns
    if _compiled_domain_patterns:
        return
    _compiled_domain_patterns = [(re.compile(p, re.I), d) for p, d in SUSPICIOUS_DOMAIN_PATTERNS]
    _compiled_proxy_patterns = [(re.compile(p, re.I), d) for p, d in PROXY_SOCKS_PATTERNS]
    _compiled_exploit_patterns = [(re.compile(p, re.I), d) for p, d in EXPLOIT_DB_PATTERNS]
    _compiled_ua_patterns = [(re.compile(p, re.I), d) for p, d in SUSPICIOUS_USERAGENT]
    _compiled_subnet_patterns = [re.compile(p) for p in KNOWN_MALICIOUS_SUBNETS]


def scan_line(line: str, lineno: int, path: str) -> list[IOCFinding]:
    _compile_all()
    findings = []
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", "//", "/*", "*")):
        return findings

    for pat in _compiled_subnet_patterns:
        for m in pat.finditer(stripped):
            findings.append(IOCFinding(
                path=path, line=lineno, ioc_type="suspicious_ip",
                value=m.group(0),
                description="Suspicious/known-malicious IP range",
                severity="HIGH", rule_id="IOC-IP",
            ))

    for pat, desc in _compiled_domain_patterns:
        for m in pat.finditer(stripped):
            findings.append(IOCFinding(
                path=path, line=lineno, ioc_type="suspicious_domain",
                value=m.group(0),
                description=desc,
                severity="HIGH", rule_id="IOC-DOMAIN",
            ))

    for pat, desc in _compiled_proxy_patterns:
        for m in pat.finditer(stripped):
            findings.append(IOCFinding(
                path=path, line=lineno, ioc_type="proxy_tunnel",
                value=m.group(0),
                description=desc,
                severity="MEDIUM", rule_id="IOC-PROXY",
            ))

    for pat, desc in _compiled_exploit_patterns:
        for m in pat.finditer(stripped):
            findings.append(IOCFinding(
                path=path, line=lineno, ioc_type="exploit_reference",
                value=m.group(0),
                description=desc,
                severity="MEDIUM", rule_id="IOC-EXPLOIT-REF",
            ))

    for pat, desc in _compiled_ua_patterns:
        for m in pat.finditer(stripped):
            findings.append(IOCFinding(
                path=path, line=lineno, ioc_type="suspicious_useragent",
                value=m.group(0)[:100],
                description=desc,
                severity="LOW", rule_id="IOC-UA",
            ))

    for crypto_name, crypto_pat in CRYPTO_WALLET_PATTERNS:
        for m in re.finditer(crypto_pat, stripped):
            val = m.group(0)
            if len(val) >= 26:
                findings.append(IOCFinding(
                    path=path, line=lineno, ioc_type="crypto_wallet",
                    value=val,
                    description=f"{crypto_name} wallet address",
                    severity="MEDIUM", rule_id="IOC-CRYPTO",
                ))

    return findings


def scan_file(path: str) -> list[IOCFinding]:
    ext = Path(path).suffix.lower()
    if ext in BINARY_EXTENSIONS:
        return []
    findings = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                findings.extend(scan_line(line, lineno, path))
    except (OSError, PermissionError):
        pass
    return findings


def scan_directory(root: str) -> list[IOCFinding]:
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            findings.extend(scan_file(fpath))
    return findings


def render(findings: list[IOCFinding]) -> str:
    if not findings:
        return "  No threat intelligence indicators detected."
    lines = []
    by_type = {}
    for f in findings:
        by_type.setdefault(f.ioc_type, []).append(f)

    for ioc_type in ("suspicious_ip", "suspicious_domain", "proxy_tunnel",
                     "crypto_wallet", "exploit_reference", "suspicious_useragent"):
        group = by_type.pop(ioc_type, [])
        if not group:
            continue
        label = ioc_type.replace("_", " ").title()
        lines.append(f"\n  [{label}] ({len(group)} indicator{'s' if len(group) > 1 else ''})")
        for f in group:
            lines.append(f"    [{f.severity}] {f.path}:{f.line}  {f.rule_id}")
            lines.append(f"      {f.description}: {f.value[:80]}")

    total = len(findings)
    lines.append(f"\n  Total: {total} IOC(s) detected")
    return "\n".join(lines)


def to_dict(findings: list[IOCFinding]) -> list[dict]:
    return [
        {
            "path": f.path,
            "line": f.line,
            "ioc_type": f.ioc_type,
            "value": f.value,
            "description": f.description,
            "severity": f.severity,
            "rule_id": f.rule_id,
        }
        for f in findings
    ]
