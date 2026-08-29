#!/usr/bin/env python3
"""secmax.py -- Attestor 2's defensive Security Max.

Security Max layers extra project-level security review on top of cyber.py:

  - Secrets Hunter Max: entropy + token assignment detection.
  - Dependency Sentinel: lockfile, floating dependency, risky lifecycle checks.
  - Web/API Security Brain: CORS, CSRF, cookie, redirect, SSRF-shaped risks.
  - Taint Flow Tracker: request/input sources near SQL, shell, eval, and fetch sinks.
  - IaC/DevOps Scanner: Dockerfile and GitHub Actions hardening checks.
  - Crypto Checker: weak hashes, weak randomness, ECB/static IV patterns.
  - Supply Chain Guard: unpinned actions, remote installer scripts, install hooks.
  - Defensive Reproducer: tiny safe proof snippets for findings.
  - SARIF/CI Mode: machine-readable security results for code-scanning tools.
  - Security Patch Forge: ranked fix guidance, never blind mutation.
  - OWASP Mode: maps findings to broad OWASP-style buckets.
  - Threat Model Generator: assets, trust boundaries, and attack surfaces.

It reads local files only. It does not exploit, scan networks, brute-force, or
modify the target project.
"""
from __future__ import annotations

import argparse
import json
import math
import re
from dataclasses import asdict, dataclass
from pathlib import Path

import cyber

MAX_BYTES = 768 * 1024
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SHA_REF = re.compile(r"@[0-9a-fA-F]{40}(?:\s+#.*)?\s*$")
ACTION_REF = re.compile(r"\buses\s*:\s*[^@\s]+@([^\s#]+)", re.I)
ASSIGNMENT = re.compile(
    r"(?i)\b(?:secret|token|api[_-]?key|private[_-]?key|password|client[_-]?secret)"
    r"\b['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_./+=:-]{18,})"
)
REGEX_PATTERN_DECLARATION = re.compile(
    r"^\s*\(?\s*(?:r|u|b|br|rb)?[\"']\(\?[A-Za-z-]+[):]",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    category: str
    rule: str
    severity: str
    confidence: float
    exploitability: str
    safe_to_autofix: bool
    detail: str
    fix: str
    owasp: str = "A05 Security Misconfiguration"

    def sort_key(self):
        return (SEVERITY_RANK.get(self.severity, 9), -self.confidence,
                self.path, self.line, self.rule)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {ch: value.count(ch) for ch in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value))
                for count in counts.values())


def _placeholder(value: str) -> bool:
    low = value.strip("'\"").lower()
    return low in {"changeme", "placeholder", "example", "dummy"} or \
        low.startswith(("your_", "replace_", "${", "<"))


def _read(path: Path) -> str:
    if path.stat().st_size > MAX_BYTES:
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _line(path: str, no: int, category: str, rule: str, severity: str,
          confidence: float, exploitability: str, safe: bool, detail: str,
          fix: str, owasp: str) -> Finding:
    return Finding(path, no, category, rule, severity, round(confidence, 2),
                   exploitability, safe, detail, fix, owasp)


def _text_files(paths) -> list[Path]:
    return cyber.collect_paths(paths)


def _scan_entropy(text: str, path: str) -> list[Finding]:
    findings = []
    for no, raw in enumerate(text.splitlines(), start=1):
        candidates = [m.group(1) for m in ASSIGNMENT.finditer(raw)]
        for value in candidates:
            if _placeholder(value) or len(value) < 24:
                continue
            score = _entropy(value)
            if score >= 3.6:
                findings.append(_line(
                    path, no, "Secrets Hunter Max", "secmax-high-entropy-secret",
                    "HIGH", min(0.99, score / 5.0), "high", False,
                    "high-entropy credential-like value appears in source",
                    "Rotate the value, move it to a secrets manager, and keep only an example.",
                    "A02 Cryptographic Failures"))
    return findings


def _scan_dependency_sentinel(text: str, path: Path) -> list[Finding]:
    findings = []
    name = path.name.lower()
    folder = path.parent
    if name == "package.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {}
        if data and not any((folder / lock).exists()
                            for lock in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")):
            findings.append(_line(
                str(path), 1, "Dependency Sentinel", "secmax-node-lockfile-missing",
                "MEDIUM", 0.86, "medium", True,
                "package.json exists without a committed Node lockfile nearby",
                "Commit a lockfile so installs are reproducible.",
                "A08 Software and Data Integrity Failures"))
        scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
        if isinstance(scripts, dict):
            for script_name, command in scripts.items():
                low = str(command).lower()
                if script_name in ("preinstall", "install", "postinstall") and low.strip():
                    findings.append(_line(
                        str(path), 1, "Supply Chain Guard", "secmax-install-hook",
                        "MEDIUM", 0.80, "medium", False,
                        "package lifecycle install hook can run code during dependency install",
                        "Keep install hooks minimal, pinned, reviewed, and documented.",
                        "A08 Software and Data Integrity Failures"))
                if "curl" in low and "|" in low and ("sh" in low or "bash" in low):
                    findings.append(_line(
                        str(path), 1, "Supply Chain Guard", "secmax-remote-script-install",
                        "HIGH", 0.88, "high", False,
                        "script downloads remote code and pipes it into a shell",
                        "Pin, checksum, and review downloaded scripts before execution.",
                        "A08 Software and Data Integrity Failures"))
    if name == "requirements.txt":
        for no, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "git+" in line and "@" not in line.rsplit("#", 1)[0]:
                findings.append(_line(
                    str(path), no, "Supply Chain Guard", "secmax-unpinned-git-dependency",
                    "MEDIUM", 0.84, "medium", True,
                    "git dependency is not pinned to an immutable revision",
                    "Pin VCS dependencies to a commit hash.",
                    "A08 Software and Data Integrity Failures"))
    return findings


def _scan_web_api(text: str, path: str) -> list[Finding]:
    findings = []
    all_low = text.lower()
    for no, raw in enumerate(text.splitlines(), start=1):
        low = raw.lower()
        post_route = "methods" in low and "post" in low and "route" in low
        if post_route and not any(word in all_low for word in ("csrf", "xsrf", "csrfprotect")):
            findings.append(_line(
                path, no, "Web/API Security Brain", "secmax-post-route-without-csrf-shape",
                "MEDIUM", 0.72, "medium", False,
                "POST route is present but no CSRF protection marker was found in the file",
                "Add CSRF protection for browser session routes or prove token-based auth is used.",
                "A01 Broken Access Control"))
        if "allow_origins" in low and "*" in raw:
            findings.append(_line(
                path, no, "Web/API Security Brain", "secmax-wide-cors-origin",
                "MEDIUM", 0.84, "medium", False,
                "CORS allow_origins appears to include every origin",
                "Restrict CORS origins and avoid wildcard credentials.",
                "A05 Security Misconfiguration"))
        if "redirect(" in low and any(src in low for src in ("request.", "next", "return_to")):
            findings.append(_line(
                path, no, "Web/API Security Brain", "secmax-open-redirect-candidate",
                "MEDIUM", 0.78, "medium", False,
                "redirect destination appears user-influenced",
                "Use relative redirects or validate against an allowlist.",
                "A01 Broken Access Control"))
    return findings


def _scan_crypto_iac_supply(text: str, path: Path) -> list[Finding]:
    findings = []
    name = path.name.lower()
    normalized = str(path).replace("\\", "/").lower()
    shell_word = "sh"
    for no, raw in enumerate(text.splitlines(), start=1):
        if REGEX_PATTERN_DECLARATION.match(raw):
            continue
        low = raw.lower()
        if "mode_ecb" in low or ".ecb" in low:
            findings.append(_line(
                str(path), no, "Crypto Checker", "secmax-ecb-mode",
                "HIGH", 0.88, "medium", False,
                "ECB mode leaks plaintext structure",
                "Use an authenticated mode such as AES-GCM or ChaCha20-Poly1305.",
                "A02 Cryptographic Failures"))
        if re.search(r"\biv\s*=\s*(b?['\"]|[0-9a-f]{16,})", low):
            findings.append(_line(
                str(path), no, "Crypto Checker", "secmax-static-iv-candidate",
                "MEDIUM", 0.74, "medium", False,
                "static IV/nonce-shaped assignment found",
                "Generate a fresh nonce/IV per encryption operation.",
                "A02 Cryptographic Failures"))
        if "uses:" in low and ACTION_REF.search(raw) and not SHA_REF.search(raw):
            findings.append(_line(
                str(path), no, "IaC/DevOps Scanner", "secmax-unpinned-github-action",
                "MEDIUM", 0.82, "medium", True,
                "GitHub Action is pinned by tag/branch rather than commit SHA",
                "Pin third-party actions to full commit SHAs.",
                "A08 Software and Data Integrity Failures"))
        if "curl" in low and "|" in raw and (" bash" in low or (" " + shell_word) in low):
            findings.append(_line(
                str(path), no, "Supply Chain Guard", "secmax-curl-pipe-shell",
                "HIGH", 0.88, "high", False,
                "remote script is piped into a shell",
                "Download, verify checksum/signature, then execute deliberately.",
                "A08 Software and Data Integrity Failures"))
    if name == "dockerfile" and "healthcheck" not in text.lower():
        findings.append(_line(
            str(path), 1, "IaC/DevOps Scanner", "secmax-docker-missing-healthcheck",
            "LOW", 0.65, "low", True,
            "Dockerfile has no HEALTHCHECK instruction",
            "Add a lightweight HEALTHCHECK for long-running services.",
            "A05 Security Misconfiguration"))
    if "/.github/workflows/" in normalized and "permissions:" not in text.lower():
        findings.append(_line(
            str(path), 1, "IaC/DevOps Scanner", "secmax-actions-permissions-missing",
            "MEDIUM", 0.76, "medium", True,
            "workflow does not declare least-privilege permissions",
            "Set top-level permissions and grant only what each job needs.",
            "A05 Security Misconfiguration"))
    return findings


def _from_cyber(item: cyber.Finding) -> Finding:
    owasp = {
        "Secrets Hunter": "A02 Cryptographic Failures",
        "Crypto Doctor": "A02 Cryptographic Failures",
        "Taint Flow Scanner": "A03 Injection",
        "Auth & Session Auditor": "A07 Identification and Authentication Failures",
        "Dependency Guardian": "A08 Software and Data Integrity Failures",
        "Container & Config Hardener": "A05 Security Misconfiguration",
        "Web/API Security Review": "A01 Broken Access Control",
    }.get(item.category, "A05 Security Misconfiguration")
    return Finding(item.path, item.line, item.category, item.rule, item.severity,
                   item.confidence, item.exploitability, item.safe_to_autofix,
                   item.detail, item.fix, owasp)


def _extra_scan(paths) -> list[Finding]:
    findings = []
    for path in _text_files(paths):
        try:
            text = _read(path)
        except OSError:
            continue
        if not text:
            continue
        label = str(path)
        findings.extend(_scan_entropy(text, label))
        findings.extend(_scan_dependency_sentinel(text, path))
        findings.extend(_scan_web_api(text, label))
        findings.extend(_scan_crypto_iac_supply(text, path))
    return findings


def scan(paths) -> dict:
    base = cyber.scan(paths)
    findings = [_from_cyber(item) for item in base["findings"]]
    findings.extend(_extra_scan(paths))
    findings.sort(key=Finding.sort_key)
    return {
        "paths": list(paths),
        "scanned_files": base["scanned_files"],
        "findings": findings,
        "threat_model": threat_model(paths, findings),
    }


def threat_model(paths, findings: list[Finding]) -> dict:
    files = _text_files(paths)
    names = [p.name.lower() for p in files]
    return {
        "assets": [
            "credentials and API tokens",
            "dependency manifests and install scripts",
            "web/API handlers and session cookies",
            "container/CI configuration",
        ],
        "trust_boundaries": [
            "HTTP request data entering handlers",
            "environment/config values entering runtime",
            "third-party packages and CI actions entering builds",
        ],
        "attack_surfaces": [
            "web routes" if any(p.suffix == ".py" for p in files) else "source files",
            "Node dependencies" if "package.json" in names else "dependency files",
            "container build" if "dockerfile" in names else "runtime config",
            "CI workflows" if any(".yml" in p.name.lower() or ".yaml" in p.name.lower()
                                  for p in files) else "local scripts",
        ],
        "top_risks": [item.rule for item in findings[:5]],
    }


def defensive_reproducer(item: Finding) -> str:
    return "\n".join([
        "# Defensive proof for %s" % item.rule,
        "# File: %s:%d" % (item.path, item.line),
        "# This is a safe regression-test idea, not an exploit.",
        "def test_security_regression():",
        "    finding = %r" % item.rule,
        "    assert finding",
        "    # Add a project-specific assertion proving the unsafe pattern is gone.",
    ])


def to_sarif(report: dict) -> dict:
    rules = {}
    results = []
    for item in report["findings"]:
        rules[item.rule] = {
            "id": item.rule,
            "name": item.rule,
            "shortDescription": {"text": item.detail},
            "properties": {"category": item.category, "owasp": item.owasp},
        }
        results.append({
            "ruleId": item.rule,
            "level": {"CRITICAL": "error", "HIGH": "error",
                      "MEDIUM": "warning", "LOW": "note", "INFO": "note"}.get(
                          item.severity, "warning"),
            "message": {"text": item.detail + " Fix: " + item.fix},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": item.path},
                    "region": {"startLine": item.line},
                }
            }],
            "properties": {
                "confidence": item.confidence,
                "exploitability": item.exploitability,
                "safe_to_autofix": item.safe_to_autofix,
                "owasp": item.owasp,
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name": "Attestor 2 Security Max",
            "rules": list(rules.values()),
        }}, "results": results}],
    }


def _counts(findings: list[Finding]) -> dict:
    counts = {key: 0 for key in SEVERITY_RANK}
    categories = {}
    for item in findings:
        counts[item.severity] = counts.get(item.severity, 0) + 1
        categories[item.category] = categories.get(item.category, 0) + 1
    return {"severity": counts, "categories": categories}


def render(report: dict) -> str:
    findings = report["findings"]
    counts = _counts(findings)
    model = report["threat_model"]
    lines = [
        "Attestor 2 Security Max",
        "=" * 72,
        "scanned files: %d" % report["scanned_files"],
        "findings: %d" % len(findings),
        "severity: " + ", ".join("%s=%d" % (key, counts["severity"].get(key, 0))
                                  for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")),
        "",
        "Threat model generator:",
        "  assets: " + "; ".join(model["assets"]),
        "  trust boundaries: " + "; ".join(model["trust_boundaries"]),
        "  attack surfaces: " + "; ".join(model["attack_surfaces"]),
        "",
    ]
    if not findings:
        lines.append("No Security Max findings.")
        return "\n".join(lines)
    lines.append("Findings and Security Patch Forge guidance:")
    for item in findings[:40]:
        lines += [
            "[%s] %s:%d  %s" % (item.severity, item.path, item.line, item.rule),
            "  category: %s  owasp: %s" % (item.category, item.owasp),
            "  confidence: %.2f  exploitability: %s  safe_autofix: %s" % (
                item.confidence, item.exploitability, "yes" if item.safe_to_autofix else "no"),
            "  detail: " + item.detail,
            "  patch guidance: " + item.fix,
            "  defensive reproducer:",
            "    " + defensive_reproducer(item).replace("\n", "\n    "),
            "",
        ]
    return "\n".join(lines).rstrip()


def to_json(report: dict) -> str:
    return json.dumps({
        "scanned_files": report["scanned_files"],
        "summary": _counts(report["findings"]),
        "threat_model": report["threat_model"],
        "findings": [asdict(item) for item in report["findings"]],
    }, indent=2)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="+", help="files or folders to review defensively")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--sarif", action="store_true")
    args = parser.parse_args(argv)
    report = scan(args.paths)
    if args.sarif:
        print(json.dumps(to_sarif(report), indent=2))
    elif args.json:
        print(to_json(report))
    else:
        print(render(report))
    return min(len(report["findings"]), 250)


if __name__ == "__main__":
    raise SystemExit(main())
