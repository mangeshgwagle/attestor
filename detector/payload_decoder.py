#!/usr/bin/env python3
"""Payload decoder -- detects and decodes obfuscated payloads in source code.
Supports base64, hex, ROT13, XOR, URL encoding, PowerShell encoded commands,
gzip/zlib compressed blobs, and nested encodings."""
from __future__ import annotations

import base64
import binascii
import codecs
import os
import re
import string
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".pyc",
    ".png", ".jpg", ".gif", ".zip", ".tar", ".gz", ".pdf",
}

SKIP_DIRS = {
    ".git", ".svn", "node_modules", "__pycache__", ".tox", ".venv",
    "venv", "dist", "build",
}

SUSPICIOUS_DECODED_PATTERNS = [
    re.compile(r"(?:eval|exec|system|passthru|shell_exec|popen|proc_open)", re.I),
    re.compile(r"(?:/bin/(?:sh|bash)|cmd\.exe|powershell)", re.I),
    re.compile(r"(?:socket|connect|bind|listen|accept)", re.I),
    re.compile(r"(?:wget|curl)\s+http", re.I),
    re.compile(r"(?:rm\s+-rf|del\s+/[sfq]|format\s+c:)", re.I),
    re.compile(r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\s+", re.I),
    re.compile(r"(?:<script|javascript:|onerror|onload)", re.I),
    re.compile(r"(?:import\s+os|import\s+subprocess|__import__)", re.I),
    re.compile(r"(?:net\s+user|net\s+localgroup|whoami|id\b)", re.I),
    re.compile(r"(?:chmod|chown|passwd|shadow|sudoers)", re.I),
    re.compile(r"(?:mimikatz|lazagne|rubeus|sharphound)", re.I),
]


@dataclass
class DecodedPayload:
    path: str
    line: int
    encoding: str
    original: str
    decoded: str
    severity: str
    is_suspicious: bool
    rule_id: str


def _is_printable(s: str, threshold: float = 0.8) -> bool:
    if not s:
        return False
    printable_count = sum(1 for c in s if c in string.printable)
    return (printable_count / len(s)) >= threshold


def _check_suspicious(decoded: str) -> bool:
    return any(p.search(decoded) for p in SUSPICIOUS_DECODED_PATTERNS)


def decode_base64(data: str) -> Optional[str]:
    data = data.strip()
    if len(data) < 16:
        return None
    try:
        decoded = base64.b64decode(data, validate=True).decode("utf-8", errors="replace")
        if _is_printable(decoded):
            return decoded
    except Exception:
        pass
    try:
        decoded = base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
        if _is_printable(decoded):
            return decoded
    except Exception:
        pass
    return None


def decode_hex(data: str) -> Optional[str]:
    data = data.strip().replace("\\x", "").replace("0x", "").replace(" ", "")
    if len(data) < 16 or len(data) % 2 != 0:
        return None
    try:
        decoded = binascii.unhexlify(data).decode("utf-8", errors="replace")
        if _is_printable(decoded):
            return decoded
    except Exception:
        pass
    return None


def decode_rot13(data: str) -> Optional[str]:
    if len(data) < 10:
        return None
    decoded = codecs.decode(data, "rot_13")
    if _check_suspicious(decoded) and not _check_suspicious(data):
        return decoded
    return None


def decode_xor_single_byte(data: bytes, key: int) -> Optional[str]:
    decoded = bytes(b ^ key for b in data)
    try:
        text = decoded.decode("utf-8", errors="strict")
        if _is_printable(text):
            return text
    except Exception:
        pass
    return None


def decode_url(data: str) -> Optional[str]:
    if "%" not in data or len(data) < 10:
        return None
    try:
        from urllib.parse import unquote
        decoded = unquote(data)
        if decoded != data and _is_printable(decoded):
            return decoded
    except Exception:
        pass
    return None


def decode_powershell_encoded(data: str) -> Optional[str]:
    data = data.strip()
    if len(data) < 16:
        return None
    try:
        decoded = base64.b64decode(data).decode("utf-16-le", errors="replace")
        if _is_printable(decoded):
            return decoded
    except Exception:
        pass
    return None


def try_decompress(data: bytes) -> Optional[str]:
    for func in (zlib.decompress, lambda d: zlib.decompress(d, -15), lambda d: zlib.decompress(d, 16 + 15)):
        try:
            result = func(data)
            text = result.decode("utf-8", errors="replace")
            if _is_printable(text):
                return text
        except Exception:
            continue
    return None


B64_PATTERN = re.compile(r"[A-Za-z0-9+/=]{40,}")
B64_URL_PATTERN = re.compile(r"[A-Za-z0-9_\-]{40,}")
HEX_PATTERN = re.compile(r"(?:0x)?(?:[0-9a-fA-F]{2}(?:\\x|0x|\s)?){20,}")
HEX_INLINE_PATTERN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){10,}")
URL_ENCODED_PATTERN = re.compile(r"(?:%[0-9a-fA-F]{2}){10,}")
PS_ENCODED_PATTERN = re.compile(r"(?i)-(?:enc(?:oded)?(?:c(?:ommand)?)?)\s+([A-Za-z0-9+/=]{20,})")
CHARCODE_PATTERN = re.compile(r"(?:chr\s*\(\s*\d+\s*\)[\s.+]*){5,}", re.I)
FROMCHARCODE_PATTERN = re.compile(r"String\.fromCharCode\s*\(([^)]+)\)", re.I)


def scan_line(line: str, lineno: int, path: str) -> list[DecodedPayload]:
    findings = []

    for m in PS_ENCODED_PATTERN.finditer(line):
        blob = m.group(1)
        decoded = decode_powershell_encoded(blob)
        if decoded:
            suspicious = _check_suspicious(decoded)
            findings.append(DecodedPayload(
                path=path, line=lineno, encoding="powershell_encoded",
                original=blob[:100], decoded=decoded[:500],
                severity="CRITICAL" if suspicious else "MEDIUM",
                is_suspicious=suspicious,
                rule_id="PAY-PS-ENC",
            ))

    for m in B64_PATTERN.finditer(line):
        blob = m.group(0)
        if any(f.original.startswith(blob[:50]) for f in findings):
            continue
        decoded = decode_base64(blob)
        if decoded:
            suspicious = _check_suspicious(decoded)
            findings.append(DecodedPayload(
                path=path, line=lineno, encoding="base64",
                original=blob[:100], decoded=decoded[:500],
                severity="HIGH" if suspicious else "LOW",
                is_suspicious=suspicious,
                rule_id="PAY-BASE64",
            ))

    for m in HEX_INLINE_PATTERN.finditer(line):
        blob = m.group(0)
        decoded = decode_hex(blob)
        if decoded:
            suspicious = _check_suspicious(decoded)
            findings.append(DecodedPayload(
                path=path, line=lineno, encoding="hex",
                original=blob[:100], decoded=decoded[:500],
                severity="HIGH" if suspicious else "LOW",
                is_suspicious=suspicious,
                rule_id="PAY-HEX",
            ))

    for m in URL_ENCODED_PATTERN.finditer(line):
        blob = m.group(0)
        decoded = decode_url(blob)
        if decoded:
            suspicious = _check_suspicious(decoded)
            findings.append(DecodedPayload(
                path=path, line=lineno, encoding="url",
                original=blob[:100], decoded=decoded[:500],
                severity="HIGH" if suspicious else "LOW",
                is_suspicious=suspicious,
                rule_id="PAY-URL",
            ))

    for m in FROMCHARCODE_PATTERN.finditer(line):
        try:
            nums = [int(x.strip()) for x in m.group(1).split(",") if x.strip().isdigit()]
            decoded = "".join(chr(n) for n in nums if 0 < n < 0x10FFFF)
            if decoded and _is_printable(decoded):
                suspicious = _check_suspicious(decoded)
                findings.append(DecodedPayload(
                    path=path, line=lineno, encoding="charcode",
                    original=m.group(0)[:100], decoded=decoded[:500],
                    severity="HIGH" if suspicious else "LOW",
                    is_suspicious=suspicious,
                    rule_id="PAY-CHARCODE",
                ))
        except (ValueError, OverflowError):
            pass

    return findings


def scan_file(path: str) -> list[DecodedPayload]:
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


def scan_directory(root: str) -> list[DecodedPayload]:
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            findings.extend(scan_file(fpath))
    return findings


def render(findings: list[DecodedPayload]) -> str:
    if not findings:
        return "  No encoded payloads detected."
    lines = []
    suspicious = [f for f in findings if f.is_suspicious]
    benign = [f for f in findings if not f.is_suspicious]

    if suspicious:
        lines.append(f"\n  SUSPICIOUS PAYLOADS ({len(suspicious)} found)")
        for f in suspicious:
            lines.append(f"    [{f.severity}] {f.path}:{f.line}  {f.rule_id}")
            lines.append(f"      Encoding: {f.encoding}")
            lines.append(f"      Decoded:  {f.decoded[:120]}...")
    if benign:
        lines.append(f"\n  Encoded strings ({len(benign)} found, possibly benign)")
        for f in benign[:10]:
            lines.append(f"    {f.path}:{f.line}  {f.encoding} -> {f.decoded[:80]}...")
        if len(benign) > 10:
            lines.append(f"    ... and {len(benign) - 10} more")

    total = len(findings)
    lines.append(f"\n  Total: {total} encoded payload(s) ({len(suspicious)} suspicious)")
    return "\n".join(lines)


def to_dict(findings: list[DecodedPayload]) -> list[dict]:
    return [
        {
            "path": f.path,
            "line": f.line,
            "encoding": f.encoding,
            "original": f.original,
            "decoded": f.decoded[:500],
            "severity": f.severity,
            "is_suspicious": f.is_suspicious,
            "rule_id": f.rule_id,
        }
        for f in findings
    ]
