#!/usr/bin/env python3
"""Git history analysis -- scans commit history for vulnerability introduction,
secret leaks in past commits, dangerous file patterns, and security-relevant
changes over time. Works without network access (local repo only)."""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

SECRET_PATTERNS = [
    (re.compile(r"(?:AKIA|AGPA|AIDA|AROA|AIPA)[A-Z0-9]{16}"), "AWS Access Key", "CRITICAL"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub PAT", "CRITICAL"),
    (re.compile(r"gho_[A-Za-z0-9]{36}"), "GitHub OAuth", "CRITICAL"),
    (re.compile(r"glpat-[A-Za-z0-9\-]{20,}"), "GitLab PAT", "CRITICAL"),
    (re.compile(r"sk-[A-Za-z0-9]{32,}"), "OpenAI API Key", "CRITICAL"),
    (re.compile(r"xox[bpors]-[A-Za-z0-9\-]{10,}"), "Slack Token", "CRITICAL"),
    (re.compile(r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----"), "Private Key", "CRITICAL"),
    (re.compile(r"(?:password|passwd|secret|api_key|apikey|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]", re.I),
     "Hardcoded Secret", "HIGH"),
    (re.compile(r"(?:mongodb|postgres|mysql|redis)://\S+:\S+@\S+", re.I),
     "Database Connection String", "CRITICAL"),
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.I), "Bearer Token", "HIGH"),
]

DANGEROUS_FILE_PATTERNS = [
    (re.compile(r"\.env$"), "Environment file committed", "HIGH"),
    (re.compile(r"\.pem$"), "PEM certificate committed", "HIGH"),
    (re.compile(r"\.key$"), "Key file committed", "HIGH"),
    (re.compile(r"\.p12$|\.pfx$"), "PKCS12 certificate committed", "HIGH"),
    (re.compile(r"id_rsa|id_ed25519|id_ecdsa"), "SSH private key committed", "CRITICAL"),
    (re.compile(r"\.keystore$|\.jks$"), "Java keystore committed", "HIGH"),
    (re.compile(r"credentials\.json|service.account\.json"), "Cloud credentials committed", "CRITICAL"),
    (re.compile(r"\.htpasswd$"), "Apache password file committed", "HIGH"),
    (re.compile(r"shadow$|passwd$"), "System password file committed", "CRITICAL"),
    (re.compile(r"wp-config\.php$"), "WordPress config committed", "HIGH"),
]

SECURITY_CHANGE_PATTERNS = [
    (re.compile(r"\beval\s*\("), "eval() introduced", "HIGH"),
    (re.compile(r"\bexec\s*\("), "exec() introduced", "HIGH"),
    (re.compile(r"os\.system\s*\("), "os.system() introduced", "CRITICAL"),
    (re.compile(r"subprocess\.\w+\s*\(.*shell\s*=\s*True", re.I),
     "Shell=True subprocess introduced", "CRITICAL"),
    (re.compile(r"pickle\.loads?\s*\("), "Pickle deserialization introduced", "HIGH"),
    (re.compile(r"yaml\.(?:unsafe_)?load\s*\((?!.*Loader)"), "Unsafe YAML load introduced", "HIGH"),
    (re.compile(r"(?:disable|skip|bypass|no).*(?:auth|csrf|cors|ssl|tls|verify)", re.I),
     "Security control disabled", "HIGH"),
    (re.compile(r"TODO.*(?:security|vuln|hack|fix|danger)", re.I),
     "Security TODO left in code", "MEDIUM"),
    (re.compile(r"(?:chmod|chown)\s+(?:777|666|a\+rwx)", re.I),
     "Insecure permissions set", "HIGH"),
]


@dataclass
class GitHistoryFinding:
    commit_hash: str
    commit_date: str
    author: str
    message: str
    file_path: str
    rule_id: str
    description: str
    severity: str
    category: str
    line_content: str = ""
    still_present: bool = False


def _run_git(args: list[str], cwd: str) -> str:
    try:
        result = subprocess.run(
            ["git"] + args,
            capture_output=True, text=True, timeout=60,
            cwd=cwd, encoding="utf-8", errors="replace",
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def _is_git_repo(path: str) -> bool:
    return bool(_run_git(["rev-parse", "--git-dir"], path).strip())


def scan_history(
    repo_path: str,
    max_commits: int = 200,
    scan_diffs: bool = True,
) -> list[GitHistoryFinding]:
    if not _is_git_repo(repo_path):
        return []

    findings = []

    log_output = _run_git([
        "log", f"-{max_commits}", "--pretty=format:%H|%aI|%an|%s",
        "--diff-filter=ACMR", "--name-only",
    ], repo_path)

    if not log_output:
        return []

    current_commit = None
    for line in log_output.split("\n"):
        line = line.strip()
        if not line:
            continue

        if "|" in line and len(line.split("|")) >= 4:
            parts = line.split("|", 3)
            current_commit = {
                "hash": parts[0][:12],
                "date": parts[1][:10],
                "author": parts[2],
                "message": parts[3][:100],
            }
            continue

        if current_commit and line:
            for pat, desc, sev in DANGEROUS_FILE_PATTERNS:
                if pat.search(line):
                    findings.append(GitHistoryFinding(
                        commit_hash=current_commit["hash"],
                        commit_date=current_commit["date"],
                        author=current_commit["author"],
                        message=current_commit["message"],
                        file_path=line,
                        rule_id="GIT-FILE",
                        description=desc,
                        severity=sev,
                        category="dangerous_file",
                    ))

    if scan_diffs:
        diff_output = _run_git([
            "log", f"-{min(max_commits, 100)}", "-p", "--diff-filter=ACMR",
            "--pretty=format:COMMIT:%H|%aI|%an|%s",
            "--", "*.py", "*.js", "*.ts", "*.java", "*.go", "*.rb",
            "*.php", "*.yaml", "*.yml", "*.json", "*.xml", "*.env",
        ], repo_path)

        current_commit = None
        current_file = ""
        for line in diff_output.split("\n"):
            if line.startswith("COMMIT:"):
                parts = line[7:].split("|", 3)
                current_commit = {
                    "hash": parts[0][:12],
                    "date": parts[1][:10] if len(parts) > 1 else "",
                    "author": parts[2] if len(parts) > 2 else "",
                    "message": parts[3][:100] if len(parts) > 3 else "",
                }
                continue

            if line.startswith("+++ b/"):
                current_file = line[6:]
                continue

            if line.startswith("+") and not line.startswith("+++") and current_commit:
                added_line = line[1:]

                for pat, desc, sev in SECRET_PATTERNS:
                    if pat.search(added_line):
                        findings.append(GitHistoryFinding(
                            commit_hash=current_commit["hash"],
                            commit_date=current_commit["date"],
                            author=current_commit["author"],
                            message=current_commit["message"],
                            file_path=current_file,
                            rule_id="GIT-SECRET",
                            description=f"Secret leaked in commit: {desc}",
                            severity=sev,
                            category="secret_leak",
                            line_content=added_line[:120],
                        ))

                for pat, desc, sev in SECURITY_CHANGE_PATTERNS:
                    if pat.search(added_line):
                        findings.append(GitHistoryFinding(
                            commit_hash=current_commit["hash"],
                            commit_date=current_commit["date"],
                            author=current_commit["author"],
                            message=current_commit["message"],
                            file_path=current_file,
                            rule_id="GIT-SECCHANGE",
                            description=desc,
                            severity=sev,
                            category="security_change",
                            line_content=added_line[:120],
                        ))

    return findings


def scan_deleted_secrets(repo_path: str, max_commits: int = 100) -> list[GitHistoryFinding]:
    if not _is_git_repo(repo_path):
        return []

    findings = []
    diff_output = _run_git([
        "log", f"-{max_commits}", "-p", "--diff-filter=D",
        "--pretty=format:COMMIT:%H|%aI|%an|%s",
        "--", "*.env", "*.pem", "*.key", "*.p12", "*.pfx",
    ], repo_path)

    current_commit = None
    for line in diff_output.split("\n"):
        if line.startswith("COMMIT:"):
            parts = line[7:].split("|", 3)
            current_commit = {
                "hash": parts[0][:12],
                "date": parts[1][:10] if len(parts) > 1 else "",
                "author": parts[2] if len(parts) > 2 else "",
                "message": parts[3][:100] if len(parts) > 3 else "",
            }
        elif line.startswith("-") and not line.startswith("---") and current_commit:
            removed_line = line[1:]
            for pat, desc, sev in SECRET_PATTERNS:
                if pat.search(removed_line):
                    findings.append(GitHistoryFinding(
                        commit_hash=current_commit["hash"],
                        commit_date=current_commit["date"],
                        author=current_commit["author"],
                        message=current_commit["message"],
                        file_path="(deleted file)",
                        rule_id="GIT-DELETED-SECRET",
                        description=f"Secret in deleted file still in history: {desc}",
                        severity="CRITICAL",
                        category="deleted_secret",
                        line_content=removed_line[:80],
                        still_present=True,
                    ))

    return findings


def scan(repo_path: str, max_commits: int = 200) -> list[GitHistoryFinding]:
    findings = []
    findings.extend(scan_history(repo_path, max_commits))
    findings.extend(scan_deleted_secrets(repo_path, min(max_commits, 100)))

    seen = set()
    deduped = []
    for f in findings:
        key = (f.commit_hash, f.rule_id, f.file_path, f.description)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


def render(findings: list[GitHistoryFinding]) -> str:
    if not findings:
        return "  No git history security issues found."
    lines = []
    by_cat = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)

    lines.append(f"\n  Git History Analysis ({len(findings)} finding{'s' if len(findings) != 1 else ''})")
    lines.append(f"  {'='*55}")

    for cat in ("secret_leak", "deleted_secret", "dangerous_file", "security_change"):
        group = by_cat.get(cat, [])
        if not group:
            continue
        label = cat.replace("_", " ").title()
        lines.append(f"\n  [{label}] ({len(group)} finding{'s' if len(group) != 1 else ''})")
        for f in sorted(group, key=lambda x: ("CRITICAL", "HIGH", "MEDIUM", "LOW").index(x.severity)):
            lines.append(f"    [{f.severity}] {f.commit_hash}  {f.commit_date}  by {f.author}")
            lines.append(f"      {f.description}")
            lines.append(f"      File: {f.file_path}")
            if f.line_content:
                redacted = re.sub(r"(['\"])[^'\"]{8,}(['\"])", r"\1***REDACTED***\2", f.line_content)
                lines.append(f"      Content: {redacted[:80]}")
            if f.still_present:
                lines.append(f"      WARNING: Still accessible in git history!")

    crit = sum(1 for f in findings if f.severity == "CRITICAL")
    lines.append(f"\n  Total: {len(findings)} finding(s) ({crit} critical)")
    return "\n".join(lines)


def to_dict(findings: list[GitHistoryFinding]) -> list[dict]:
    return [
        {
            "commit_hash": f.commit_hash,
            "commit_date": f.commit_date,
            "author": f.author,
            "message": f.message,
            "file_path": f.file_path,
            "rule_id": f.rule_id,
            "description": f.description,
            "severity": f.severity,
            "category": f.category,
            "still_present": f.still_present,
        }
        for f in findings
    ]
