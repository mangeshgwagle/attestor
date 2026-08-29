#!/usr/bin/env python3
"""cyber.py -- Attestor's defensive Cyber Sentinel scanner.

Offline, local, and safe: it reads files you point it at and reports defensive
security risks. It does not exploit anything, make network requests, or mutate a
project. Each finding carries severity, confidence, exploitability, and whether
it is safe to auto-fix.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path

MAX_BYTES = 512 * 1024
SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    "node_modules", ".venv", "venv", "env", "dist", "build", "target",
}
TEXT_SUFFIXES = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".toml", ".yaml", ".yml",
    ".env", ".ini", ".cfg", ".conf", ".txt", ".md", ".sh", ".ps1", ".bat",
    ".dockerfile", ".lock",
}
TEXT_NAMES = {
    "dockerfile", "makefile", "requirements.txt", "package.json",
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "pyproject.toml",
}
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


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

    def sort_key(self):
        return (
            SEVERITY_RANK.get(self.severity, 9),
            -self.confidence,
            self.path,
            self.line,
            self.rule,
        )


def _is_placeholder(value: str) -> bool:
    low = value.strip().strip("'\"").lower()
    if len(low) < 8:
        return True
    return low in {"changeme", "change-me", "example", "placeholder", "dummy"} or \
        low.startswith(("your_", "your-", "replace_", "replace-", "<", "${"))


def _line_no(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _confidence(path: str, line: str, base: float) -> float:
    low_path = path.lower()
    low_line = line.lower()
    if ".example" in low_path or low_path.endswith(".sample"):
        return min(base, 0.45)
    if any(word in low_line for word in ("example", "placeholder", "changeme")):
        return min(base, 0.50)
    return base


def _finding(path: str, line: int, category: str, rule: str, severity: str,
             confidence: float, exploitability: str, autofix: bool,
             detail: str, fix: str) -> Finding:
    return Finding(path, line, category, rule, severity, round(confidence, 2),
                   exploitability, autofix, detail, fix)


_CRED_ASSIGN = re.compile(
    r"(?i)\b(?:[A-Za-z0-9]+[_-])?(?:pass(?:word|wd)?|api[_-]?key|access[_-]?key|auth[_-]?token|"
    r"client[_-]?secret|private[_-]?key|db[_-]?pass\w*)\b\s*[:=]\s*"
    r"['\"]?([A-Za-z0-9_./+=:-]{12,})"
)
_CRED_PATTERNS = [
    ("cyber-aws-key", "HIGH", 0.98, re.compile(r"\b" + "AKIA" + r"[0-9A-Z]{16}\b"),
     "AWS-style access key id committed in plaintext",
     "Move the credential to a secrets manager and rotate it immediately."),
    ("cyber-github-token", "HIGH", 0.96, re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
     "GitHub-style token committed in plaintext",
     "Revoke the token, move it to the environment, and remove it from history."),
    ("cyber-openai-key", "HIGH", 0.94, re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
     "API key-shaped token committed in plaintext",
     "Rotate the key and load it from the environment or a secrets manager."),
    ("cyber-private-key-block", "CRITICAL", 0.99,
     re.compile("-----BEGIN " + r"(?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
     "private key material appears to be committed",
     "Remove the key, rotate it, and scrub repository history."),
]
_SQL_CALL = "." + "execute("
_F_DOUBLE = "f" + '"'
_F_SINGLE = "f" + "'"


def _scan_credentials(text: str, path: str) -> list[Finding]:
    findings = []
    for name, severity, conf, rx, detail, fix in _CRED_PATTERNS:
        for match in rx.finditer(text):
            line_no = _line_no(text, match.start())
            line = text.splitlines()[line_no - 1] if text.splitlines() else ""
            findings.append(_finding(path, line_no, "Secrets Hunter", name, severity,
                                     _confidence(path, line, conf), "high", False,
                                     detail, fix))
    for idx, line in enumerate(text.splitlines(), start=1):
        match = _CRED_ASSIGN.search(line)
        if match and not _is_placeholder(match.group(1)):
            findings.append(_finding(
                path, idx, "Secrets Hunter", "cyber-hardcoded-credential",
                "HIGH", _confidence(path, line, 0.90), "high", False,
                "credential-looking value is assigned directly in source or config",
                "Load it from the environment, keep only an example placeholder, and rotate leaks."))
    return findings


def _scan_auth_and_crypto(text: str, path: str) -> list[Finding]:
    findings = []
    for idx, line in enumerate(text.splitlines(), start=1):
        low = line.lower()
        if ("hashlib." + "md5" + "(") in low or ("hashlib." + "sha1" + "(") in low:
            findings.append(_finding(
                path, idx, "Crypto Doctor", "cyber-weak-hash", "HIGH", 0.95,
                "medium", True,
                "fast legacy hash used where security code often needs stronger primitives",
                "Use SHA-256+ for integrity; use bcrypt, scrypt, or Argon2 for passwords."))
        if "random." in low and any(word in low for word in ("token", "nonce", "session", "key")):
            findings.append(_finding(
                path, idx, "Crypto Doctor", "cyber-weak-random-token", "HIGH", 0.92,
                "medium", True,
                "predictable PRNG appears to feed a security-sensitive value",
                "Use secrets.token_urlsafe, secrets.token_bytes, or os.urandom."))
        if "jwt.decode" in low and ("verify_signature" in low or "verify=false" in low):
            findings.append(_finding(
                path, idx, "Auth & Session Auditor", "cyber-jwt-verification-disabled",
                "CRITICAL", 0.96, "high", False,
                "JWT verification appears disabled",
                "Require signature verification, expected algorithms, issuer, and audience."))
        if "set_cookie" in low:
            missing = [flag for flag in ("httponly", "secure", "samesite") if flag not in low]
            if missing:
                findings.append(_finding(
                    path, idx, "Auth & Session Auditor", "cyber-weak-cookie-flags",
                    "MEDIUM", 0.86, "medium", True,
                    "cookie is set without " + ", ".join(missing),
                    "Set HttpOnly, Secure, and SameSite for session cookies."))
        if "cors" in low and ("*" in line or "allow_all" in low):
            findings.append(_finding(
                path, idx, "Web/API Security Review", "cyber-open-cors",
                "MEDIUM", 0.82, "medium", False,
                "CORS appears open to every origin",
                "Restrict origins to trusted domains and avoid wildcard credentials."))
    return findings


def _scan_taint_and_web(text: str, path: str) -> list[Finding]:
    findings = []
    user_words = ("request.", "req.", "input(", "argv", "query", "params")
    for idx, line in enumerate(text.splitlines(), start=1):
        low = line.lower()
        userish = any(word in low for word in user_words)
        if _SQL_CALL in low and (_F_DOUBLE in line or _F_SINGLE in line
                                 or " + " in line or "% " in line):
            findings.append(_finding(
                path, idx, "Taint Flow Scanner", "cyber-sql-string-built",
                "CRITICAL", 0.91, "high", False,
                "SQL appears built with string formatting or concatenation",
                "Use parameterized queries and whitelist dynamic identifiers."))
        if (("os" + ".system(") in low or ("shell=true" in low and "subprocess" in low)):
            findings.append(_finding(
                path, idx, "Taint Flow Scanner", "cyber-command-injection-sink",
                "HIGH", 0.88, "high", False,
                "command execution sink can become injection if user input reaches it",
                "Pass an argument list, keep shell disabled, and validate inputs."))
        if userish and (("e" + "val(") in low or ("e" + "xec(") in low):
            findings.append(_finding(
                path, idx, "Taint Flow Scanner", "cyber-code-injection-sink",
                "CRITICAL", 0.94, "high", False,
                "user-controlled data appears able to reach dynamic code execution",
                "Replace dynamic execution with explicit parsing and dispatch."))
        if userish and (("requests" + ".get(") in low or ("urlopen(" in low)):
            findings.append(_finding(
                path, idx, "Web/API Security Review", "cyber-ssrf-shape",
                "HIGH", 0.78, "high", False,
                "user-controlled URL appears to reach a server-side fetch",
                "Validate scheme/host, block private ranges, and use allowlists."))
        if "redirect(" in low and userish:
            findings.append(_finding(
                path, idx, "Web/API Security Review", "cyber-open-redirect-shape",
                "MEDIUM", 0.78, "medium", False,
                "redirect target appears influenced by request input",
                "Use relative routes or validate targets against an allowlist."))
        if "debug" in low and re.search(r"[:=]\s*(true|1|yes)\b", low):
            findings.append(_finding(
                path, idx, "Container & Config Hardener", "cyber-debug-enabled",
                "MEDIUM", 0.84, "medium", True,
                "debug mode appears enabled",
                "Disable debug mode outside local development."))
        if "verify=false" in low or "rejectunauthorized" in low and "false" in low:
            findings.append(_finding(
                path, idx, "Container & Config Hardener", "cyber-tls-verification-disabled",
                "HIGH", 0.90, "medium", True,
                "TLS certificate verification appears disabled",
                "Keep TLS verification enabled and install trusted CA roots when needed."))
    return findings


def _scan_dependency_file(text: str, path: str) -> list[Finding]:
    findings = []
    name = Path(path).name.lower()
    if name == "requirements.txt":
        for idx, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            if "==" not in line and " @ " not in line:
                findings.append(_finding(
                    path, idx, "Dependency Guardian", "cyber-unpinned-python-dependency",
                    "LOW", 0.82, "low", True,
                    "Python dependency is not pinned",
                    "Pin versions and refresh them through a controlled update process."))
    if name == "package.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {}
        for block in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(block, {})
            if isinstance(deps, dict):
                for dep, version in deps.items():
                    if str(version).strip().lower() in {"*", "latest", ""}:
                        findings.append(_finding(
                            path, 1, "Dependency Guardian", "cyber-floating-node-dependency",
                            "MEDIUM", 0.86, "medium", True,
                            f"{dep} uses a floating version in {block}",
                            "Pin to a reviewed version and commit a lockfile."))
    return findings


def _scan_container_and_ci(text: str, path: str) -> list[Finding]:
    findings = []
    low_path = path.lower().replace("\\", "/")
    lines = text.splitlines()
    if Path(path).name.lower() == "dockerfile":
        has_user = any(line.strip().lower().startswith("user ") for line in lines)
        if not has_user:
            findings.append(_finding(
                path, 1, "Container & Config Hardener", "cyber-docker-missing-user",
                "MEDIUM", 0.80, "medium", True,
                "Dockerfile does not switch away from the root user",
                "Create a non-root user and set USER before the runtime command."))
        for idx, line in enumerate(lines, start=1):
            low = line.strip().lower()
            if low.startswith("user root"):
                findings.append(_finding(
                    path, idx, "Container & Config Hardener", "cyber-docker-root-user",
                    "MEDIUM", 0.88, "medium", True,
                    "container explicitly runs as root",
                    "Run the service as a dedicated non-root user."))
            if low.startswith("add http"):
                findings.append(_finding(
                    path, idx, "Container & Config Hardener", "cyber-docker-remote-add",
                    "LOW", 0.76, "low", True,
                    "Docker ADD pulls from a remote URL",
                    "Download with pinned checksums in a build step or vendor the artifact."))
    if "/.github/workflows/" in low_path or low_path.endswith((".yml", ".yaml")):
        for idx, line in enumerate(lines, start=1):
            low = line.lower()
            if "pull_request_target" in low:
                findings.append(_finding(
                    path, idx, "Container & Config Hardener", "cyber-risky-ci-trigger",
                    "HIGH", 0.78, "medium", False,
                    "workflow uses pull_request_target, which can expose privileged tokens",
                    "Use pull_request for untrusted code or isolate privileged steps."))
            if "curl" in low and "|" in low and (" sh" in low or " bash" in low):
                findings.append(_finding(
                    path, idx, "Container & Config Hardener", "cyber-curl-pipe-shell",
                    "MEDIUM", 0.82, "medium", False,
                    "CI executes a remote script through a shell pipeline",
                    "Pin and verify downloaded scripts before execution."))
    return findings


def is_text_path(path: Path) -> bool:
    name = path.name.lower()
    return name in TEXT_NAMES or path.suffix.lower() in TEXT_SUFFIXES


def collect_paths(paths) -> list[Path]:
    out = []
    for raw in paths:
        root = Path(raw)
        if root.is_file() and is_text_path(root):
            out.append(root)
        elif root.is_dir():
            for current, dirs, files in os.walk(root):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for name in files:
                    path = Path(current) / name
                    if is_text_path(path):
                        out.append(path)
    return sorted(out, key=lambda p: str(p).lower())


def scan_file(path: Path) -> list[Finding]:
    try:
        if path.stat().st_size > MAX_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    label = str(path)
    findings = []
    findings.extend(_scan_credentials(text, label))
    findings.extend(_scan_auth_and_crypto(text, label))
    findings.extend(_scan_taint_and_web(text, label))
    findings.extend(_scan_dependency_file(text, label))
    findings.extend(_scan_container_and_ci(text, label))
    return findings


def scan(paths) -> dict:
    files = collect_paths(paths)
    findings = []
    for path in files:
        findings.extend(scan_file(path))
    findings.sort(key=Finding.sort_key)
    return {"scanned_files": len(files), "findings": findings}


def summary(findings: list[Finding]) -> dict:
    counts = {key: 0 for key in SEVERITY_RANK}
    categories = {}
    for item in findings:
        counts[item.severity] = counts.get(item.severity, 0) + 1
        categories[item.category] = categories.get(item.category, 0) + 1
    return {"severity": counts, "categories": categories}


def render(report: dict) -> str:
    findings = report["findings"]
    totals = summary(findings)
    lines = [
        "Cyber Sentinel report",
        "=" * 64,
        "Scanned files: %d" % report["scanned_files"],
        "Findings: %d" % len(findings),
        "Severity: " + ", ".join("%s=%d" % (k, totals["severity"].get(k, 0))
                                  for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")),
        "",
    ]
    if not findings:
        lines.append("No cybersecurity findings from Cyber Sentinel.")
        return "\n".join(lines)
    for item in findings:
        lines.extend([
            "[%s] %s:%d  %s" % (item.severity, item.path, item.line, item.rule),
            "  category: %s" % item.category,
            "  confidence: %.2f  exploitability: %s  safe_to_autofix: %s" % (
                item.confidence, item.exploitability, item.safe_to_autofix),
            "  detail: " + item.detail,
            "  fix: " + item.fix,
            "",
        ])
    return "\n".join(lines).rstrip()


def to_json(report: dict) -> str:
    payload = {
        "scanned_files": report["scanned_files"],
        "summary": summary(report["findings"]),
        "findings": [asdict(item) for item in report["findings"]],
    }
    return json.dumps(payload, indent=2)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="files or folders to scan defensively")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    report = scan(args.paths)
    print(to_json(report) if args.json else render(report))
    return min(len(report["findings"]), 250)


if __name__ == "__main__":
    raise SystemExit(main())
