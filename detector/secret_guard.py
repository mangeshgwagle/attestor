#!/usr/bin/env python3
"""High-precision, value-redacting secret analysis for Attestor.

Candidates exist only while a line is being inspected.  Findings contain the
location, credential family, and remediation evidence, but never the candidate
value, a prefix/suffix, or a hash of the value.  This makes the module safe to
feed into JSON, SARIF, CI logs, and baselines without creating a second leak.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import PurePath
from typing import Any, Iterable


MAX_LINE_CHARS = 16 * 1024
MAX_FINDINGS = 500

PLACEHOLDER_WORDS = {
    "changeme", "change-me", "change_me", "placeholder", "redacted",
    "replace-me", "replace_me", "replace-with-real-value", "not-a-secret",
    "not_a_secret", "dummy", "example", "sample", "fake", "your-token",
    "your_token", "your-secret", "your_secret", "todo", "unset", "none",
    "null", "password", "secret", "token", "hunter2",
}
PLACEHOLDER_PARTS = re.compile(
    r"(?:^|[_./:-])(?:example|sample|dummy|fake|placeholder|redacted|changeme|"
    r"replace(?:me)?|your|testonly|notasecret|do[_-]?not[_-]?echo)(?:$|[_./:-])",
    re.I,
)
REFERENCE_RX = re.compile(
    r"^(?:\$\{|\{\{|<[^>]+>|%\(|env\b|process\.env\b|os\.(?:getenv|environ)\b|"
    r"vault:|keyvault:|ssm:|secretKeyRef\b)", re.I,
)
SECRET_NAME_RX = re.compile(
    r"(?i)\b(?P<name>(?:(?:api|access|auth|client|private|signing|session|db|database|"
    r"service|webhook)[_-]?)?(?:key|secret|token|password|passwd|pwd|credential))\b"
    r"['\"]?\s*(?::|=|=>)\s*(?P<quote>['\"]?)(?P<value>[^'\"\s#,;}{]{6,512})(?P=quote)"
)
URL_CREDENTIAL_RX = re.compile(
    r"(?i)\b(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://"
    r"[^\s:/@]{1,128}:(?P<value>[^\s/@]{6,256})@"
)
PRIVATE_KEY_RX = re.compile(
    r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) PRIVATE KEY|PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----"
)
NPM_TOKEN_RX = re.compile(r"(?i)^\s*//[^:]+/:_authToken\s*=\s*(?P<value>\S{12,512})")
PYPI_PASSWORD_RX = re.compile(r"(?i)^\s*(?:password|token)\s*=\s*(?P<value>\S{8,512})")

# Provider formats are intentionally conservative.  They are useful precision
# anchors, not an exhaustive list and not a reason to print any matched bytes.
PROVIDER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github-token", re.compile(r"\b(?:gh[opusr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,255}\b")),
    ("stripe-live-key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,255}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,255}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("sendgrid-key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{20,}\b")),
    ("openai-project-key", re.compile(r"\bsk-proj-[A-Za-z0-9_-]{40,255}\b")),
    ("openai-service-key", re.compile(r"\bsk-svcacct-[A-Za-z0-9_-]{40,255}\b")),
    ("jwt-bearer", re.compile(r"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b")),
)

AWS_ACCESS_ID_RX = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
AWS_SECRET_RX = re.compile(
    r"(?i)\baws_secret_access_key\b\s*(?::|=)\s*['\"]?(?P<value>[A-Za-z0-9/+=]{40,128})"
)
TWILIO_ACCOUNT_RX = re.compile(r"\bAC[0-9a-fA-F]{32}\b")
TWILIO_SECRET_RX = re.compile(
    r"(?i)\bTWILIO_AUTH_TOKEN\b\s*(?::|=)\s*['\"]?(?P<value>[0-9a-f]{32})"
)
GCP_SERVICE_ACCOUNT_RX = re.compile(r"[\"']type[\"']\s*:\s*[\"']service_account[\"']", re.I)
AZURE_STORAGE_RX = re.compile(
    r"(?i)\bAccountName\s*=\s*[^;\s]{3,128};[^\n]{0,500}?\bAccountKey\s*=\s*(?P<value>[A-Za-z0-9+/]{40,}={0,2})"
)
CONTEXT_PROVIDER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("datadog-api-key", re.compile(
        r"(?i)\b(?:DD|DATADOG)_API_KEY\b\s*(?::|=)\s*['\"]?(?P<value>[0-9a-f]{32})")),
    ("datadog-application-key", re.compile(
        r"(?i)\b(?:DD|DATADOG)_(?:APP|APPLICATION)_KEY\b\s*(?::|=)\s*['\"]?(?P<value>[0-9a-f]{40})")),
    ("cloudflare-api-token", re.compile(
        r"(?i)\b(?:CF|CLOUDFLARE)_(?:API_)?TOKEN\b\s*(?::|=)\s*['\"]?(?P<value>[A-Za-z0-9_-]{32,80})")),
    ("azure-client-secret", re.compile(
        r"(?i)\b(?:AZURE|ARM)_CLIENT_SECRET\b\s*(?::|=)\s*['\"]?(?P<value>[A-Za-z0-9_~.-]{24,160})")),
)

TEST_PATH_PARTS = {"test", "tests", "testing", "fixture", "fixtures", "examples", "samples", "docs"}
EXAMPLE_NAMES = {".env.example", ".env.sample", "example.env", "sample.env"}


def shannon_entropy(value: str) -> float:
    """Calculate Shannon entropy per character for an ephemeral candidate."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = float(len(value))
    return -sum((count / length) * math.log2(count / length)
                for count in counts.values())


def _placeholder(value: str) -> bool:
    value = value.strip().strip("'\"")
    lower = value.lower()
    if not value or lower in PLACEHOLDER_WORDS or REFERENCE_RX.match(value):
        return True
    if PLACEHOLDER_PARTS.search(lower):
        return True
    if lower.startswith(("p@ssword", "password", "opensesame", "letmein", "admin123", "secret123")):
        return True
    if len(set(value)) <= 2 or re.fullmatch(r"(?:x+|0+|1+|-+|\.+)", lower):
        return True
    if re.fullmatch(r"(?:abc|123|qwerty|asdf)+", lower):
        return True
    return False


def _example_context(path: str) -> bool:
    pure = PurePath(path.replace("\\", "/"))
    return pure.name.lower() in EXAMPLE_NAMES or any(
        part.lower() in TEST_PATH_PARTS for part in pure.parts)


def _character_classes(value: str) -> int:
    return sum(bool(re.search(pattern, value)) for pattern in
               (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))


def _evidence(path: str, line: int, description: str) -> list[dict[str, Any]]:
    return [{"kind": "redacted-static-match", "path": path, "line": line,
             "description": description, "secret_material_redacted": True}]


def _finding(path: str, line: int, rule: str, severity: str, confidence: float,
             kind: str, message: str) -> dict[str, Any]:
    return {
        "path": path, "line": max(1, int(line)), "rule": rule,
        "severity": severity, "category": "secrets/credential-exposure",
        "cwe": "CWE-798", "owasp": "A07:2025 Authentication Failures",
        "owasp_2025": "A07:2025 Authentication Failures",
        "owasp_2021": "A07:2021 Identification and Authentication Failures",
        "confidence": round(max(0.0, min(float(confidence), 1.0)), 2),
        "message": message,
        "fix": ("Revoke or rotate the credential, remove it from repository history, "
                "and load the replacement from a least-privilege secrets manager."),
        "source": "secret-guard", "pack": "contextual-security-2.3",
        "precision": "very-high" if confidence >= 0.94 else "high",
        "secret_kind": kind, "secret_material_redacted": True,
        "asvs": ["v5.0.0-13.3.1"], "nist_ssdf": ["PW.7.2"],
        "evidence": _evidence(path, line, message),
    }


def _generic_candidates(line: str, *, allow_unquoted: bool) -> Iterable[tuple[str, str]]:
    for match in SECRET_NAME_RX.finditer(line):
        name, value = match.group("name"), match.group("value")
        if name.lower().startswith("public"):
            continue
        # In source languages a non-quoted right-hand side is an expression,
        # not a literal secret.  Config/shell formats legitimately use bare
        # credential values, so callers opt in for those files.
        if not match.group("quote") and not allow_unquoted:
            continue
        yield name.lower(), value


def scan_text(text: str, path: str = "<memory>", *,
              max_findings: int = MAX_FINDINGS) -> list[dict[str, Any]]:
    """Return redacted secret findings for UTF-8 text.

    The scan is line-bounded and output-bounded.  ``text`` is never retained in
    a finding.  Placeholder/reference suppression happens before entropy or
    provider classification.
    """
    limit = max(1, min(int(max_findings), MAX_FINDINGS))
    findings: list[dict[str, Any]] = []
    seen: set[tuple[int, str, str]] = set()
    example = _example_context(path)

    def add(row: dict[str, Any]) -> None:
        key = (row["line"], row["rule"], row["secret_kind"])
        if key not in seen and len(findings) < limit:
            seen.add(key)
            findings.append(row)

    lines = text.splitlines()
    pure = PurePath(path.replace("\\", "/"))
    allow_unquoted = (pure.suffix.lower() in {
        ".env", ".ini", ".cfg", ".conf", ".toml", ".yaml", ".yml",
        ".properties", ".sh", ".bash", ".zsh", ".ps1",
    } or pure.name.lower() in {".env", ".npmrc", ".pypirc", "dockerfile", "containerfile"})
    specialized_lines: set[int] = set()
    aws_ids = [index for index, line in enumerate(lines, start=1) if AWS_ACCESS_ID_RX.search(line)]
    for index, line in enumerate(lines, start=1):
        match = AWS_SECRET_RX.search(line)
        if (match and not _placeholder(match.group("value"))
                and any(abs(index - identifier_line) <= 40 for identifier_line in aws_ids)):
            specialized_lines.add(index)
            add(_finding(path, index, "secctx-aws-credential-pair", "CRITICAL",
                         0.99 if not example else 0.90, "aws-access-key-pair",
                         "an AWS access-key identifier and matching secret setting are stored together"))
    twilio_ids = [index for index, line in enumerate(lines, start=1) if TWILIO_ACCOUNT_RX.search(line)]
    for index, line in enumerate(lines, start=1):
        match = TWILIO_SECRET_RX.search(line)
        if (match and not _placeholder(match.group("value"))
                and any(abs(index - identifier_line) <= 40 for identifier_line in twilio_ids)):
            specialized_lines.add(index)
            add(_finding(path, index, "secctx-twilio-credential-pair", "CRITICAL",
                         0.99 if not example else 0.90, "twilio-account-token-pair",
                         "a Twilio account identifier and authentication token are stored together"))

    gcp_service_account = bool(GCP_SERVICE_ACCOUNT_RX.search(text))
    for line_no, raw in enumerate(lines, start=1):
        if len(findings) >= limit:
            break
        line = raw[:MAX_LINE_CHARS]
        if PRIVATE_KEY_RX.search(line):
            kind = "gcp-service-account-private-key" if gcp_service_account else "private-key"
            rule = "secctx-gcp-service-account-key" if gcp_service_account else "secctx-private-key-material"
            specialized_lines.add(line_no)
            add(_finding(path, line_no, rule, "CRITICAL", 0.99 if not example else 0.92,
                         kind, "service-account private key material is present in text"
                         if gcp_service_account else "private key material is present in a text file"))

        for family, pattern in PROVIDER_PATTERNS:
            for match in pattern.finditer(line):
                value = match.group(0)
                if _placeholder(value):
                    continue
                confidence = 0.94 if example else 0.99
                severity = "MEDIUM" if example else "CRITICAL"
                add(_finding(path, line_no, "secctx-provider-credential", severity,
                             confidence, family,
                             "a provider-formatted credential is embedded in text"))

        for family, pattern in CONTEXT_PROVIDER_PATTERNS:
            match = pattern.search(line)
            if match and not _placeholder(match.group("value")):
                specialized_lines.add(line_no)
                add(_finding(path, line_no, "secctx-contextual-provider-credential",
                             "MEDIUM" if example else "CRITICAL",
                             0.89 if example else 0.98, family,
                             "a provider credential is assigned to its provider-specific setting"))
        azure = AZURE_STORAGE_RX.search(line)
        if azure and not _placeholder(azure.group("value")):
            specialized_lines.add(line_no)
            add(_finding(path, line_no, "secctx-azure-storage-credential", "CRITICAL",
                         0.99 if not example else 0.90, "azure-storage-account-key",
                         "an Azure storage account name and account key are stored together"))

        for name, value in _generic_candidates(line, allow_unquoted=allow_unquoted):
            if line_no in specialized_lines:
                continue
            if _placeholder(value):
                continue
            password_like = any(word in name for word in ("password", "passwd", "pwd"))
            strong_shape = (len(value) >= 16 and shannon_entropy(value) >= 3.1
                            and _character_classes(value) >= 2)
            if not (strong_shape or (password_like and len(value) >= 8)):
                continue
            confidence = 0.82 if example else (0.94 if strong_shape else 0.90)
            severity = "MEDIUM" if example else "HIGH"
            add(_finding(path, line_no, "secctx-hardcoded-credential", severity,
                         confidence, "password" if password_like else "named-secret",
                         "a literal credential is assigned to a security-sensitive setting"))

        for match in URL_CREDENTIAL_RX.finditer(line):
            if not _placeholder(match.group("value")):
                add(_finding(path, line_no, "secctx-credential-in-url", "HIGH",
                             0.97 if not example else 0.86, "url-password",
                             "a URL contains embedded authentication material"))

        name = PurePath(path.replace("\\", "/")).name.lower()
        special = NPM_TOKEN_RX.search(line) if name == ".npmrc" else (
            PYPI_PASSWORD_RX.search(line) if name in {".pypirc", "pip.conf"} else None)
        if special and not _placeholder(special.group("value")):
            add(_finding(path, line_no, "secctx-package-registry-credential", "CRITICAL",
                         0.98 if not example else 0.88, "package-registry-token",
                         "a package-registry credential is stored in repository configuration"))

    return sorted(findings, key=lambda row: (row["line"], row["rule"], row["secret_kind"]))
