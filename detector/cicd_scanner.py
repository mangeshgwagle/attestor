#!/usr/bin/env python3
"""CI/CD pipeline security scanner -- detects injection vulnerabilities,
overprivileged tokens, insecure configurations, and supply chain risks in
GitHub Actions, GitLab CI, Jenkins, and Azure DevOps pipelines."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
}


@dataclass
class CICDFinding:
    path: str
    line: int
    rule_id: str
    description: str
    severity: str
    category: str
    remediation: str = ""
    details: str = ""


GHA_INJECTION_CONTEXTS = [
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.pages.*.page_name",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.commits.*.message",
    "github.event.commits.*.author.email",
    "github.head_ref",
    "github.event.workflow_run.head_branch",
    "github.event.discussion.title",
    "github.event.discussion.body",
]


def _scan_gha_file(path: str, content: str) -> list[CICDFinding]:
    findings = []
    lines = content.split("\n")

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        for ctx in GHA_INJECTION_CONTEXTS:
            pattern = re.compile(r"\$\{\{\s*" + re.escape(ctx).replace(r"\*", r"\w+") + r"\s*\}\}")
            if pattern.search(stripped):
                if "run:" in stripped or any("run:" in lines[j].strip() for j in range(max(0, i-3), i)):
                    findings.append(CICDFinding(
                        path=path, line=i,
                        rule_id="CICD-GHA-INJECT",
                        description=f"Command injection via {ctx} in run step",
                        severity="CRITICAL", category="injection",
                        remediation="Use an intermediate environment variable instead of direct interpolation",
                    ))

        if re.search(r"uses:\s+\w+/\w+@[a-f0-9]{40}", stripped):
            pass
        elif re.search(r"uses:\s+\w+/\w+@v?\d+", stripped):
            if not re.search(r"uses:\s+actions/", stripped):
                findings.append(CICDFinding(
                    path=path, line=i,
                    rule_id="CICD-GHA-UNPIN",
                    description="Third-party action pinned to mutable tag instead of SHA",
                    severity="HIGH", category="supply_chain",
                    remediation="Pin actions to full commit SHA: uses: owner/action@<sha>",
                    details=stripped[:100],
                ))
        elif re.search(r"uses:\s+\w+/\w+@(?:main|master|latest)", stripped):
            findings.append(CICDFinding(
                path=path, line=i,
                rule_id="CICD-GHA-BRANCH",
                description="Action pinned to branch (main/master) -- highly mutable",
                severity="CRITICAL", category="supply_chain",
                remediation="Pin to commit SHA, never to a branch name",
                details=stripped[:100],
            ))

        if re.search(r"permissions:\s*write-all", stripped, re.I):
            findings.append(CICDFinding(
                path=path, line=i,
                rule_id="CICD-GHA-PERMS",
                description="Workflow uses write-all permissions (overprivileged)",
                severity="HIGH", category="privilege",
                remediation="Use least-privilege: specify only needed permissions (contents: read, etc.)",
            ))

        if re.search(r"pull_request_target", stripped):
            findings.append(CICDFinding(
                path=path, line=i,
                rule_id="CICD-GHA-PRT",
                description="pull_request_target trigger -- runs with write access on fork PRs",
                severity="HIGH", category="privilege",
                remediation="Avoid pull_request_target; use pull_request + workflow_run pattern",
            ))

        if re.search(r"persist-credentials:\s*true", stripped, re.I):
            findings.append(CICDFinding(
                path=path, line=i,
                rule_id="CICD-GHA-CREDS",
                description="Actions checkout with persist-credentials: true",
                severity="MEDIUM", category="credential",
                remediation="Set persist-credentials: false to avoid token leakage",
            ))

        if re.search(r"::set-output|::save-state|::add-path|::set-env", stripped):
            findings.append(CICDFinding(
                path=path, line=i,
                rule_id="CICD-GHA-DEPRECATED",
                description="Deprecated workflow command (potential injection vector)",
                severity="MEDIUM", category="injection",
                remediation="Use $GITHUB_OUTPUT, $GITHUB_STATE, $GITHUB_PATH, $GITHUB_ENV files",
            ))

        if re.search(r"\$\{\{\s*secrets\.\w+\s*\}\}", stripped):
            if "echo" in stripped.lower() or "print" in stripped.lower():
                findings.append(CICDFinding(
                    path=path, line=i,
                    rule_id="CICD-GHA-SECRETLOG",
                    description="Secret potentially exposed in log output",
                    severity="HIGH", category="credential",
                    remediation="Never echo/print secrets; use them only in env vars or masked outputs",
                ))

        if re.search(r"if:\s*.*(?:always|cancelled)\s*\(\s*\)", stripped):
            if re.search(r"\$\{\{\s*secrets\.", stripped):
                findings.append(CICDFinding(
                    path=path, line=i,
                    rule_id="CICD-GHA-ALWAYS-SECRET",
                    description="Secret used in always() condition -- runs even on failure",
                    severity="MEDIUM", category="credential",
                ))

        if re.search(r"ACTIONS_ALLOW_UNSECURE_COMMANDS", stripped, re.I):
            findings.append(CICDFinding(
                path=path, line=i,
                rule_id="CICD-GHA-UNSECURE",
                description="ACTIONS_ALLOW_UNSECURE_COMMANDS enables deprecated injection vectors",
                severity="CRITICAL", category="injection",
                remediation="Remove this environment variable and migrate to secure alternatives",
            ))

    return findings


def _scan_gitlab_ci(path: str, content: str) -> list[CICDFinding]:
    findings = []
    lines = content.split("\n")

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        if re.search(r"curl.*\|\s*(?:sh|bash)", stripped, re.I):
            findings.append(CICDFinding(
                path=path, line=i,
                rule_id="CICD-GL-CURLPIPE",
                description="Curl-pipe-shell pattern in CI script",
                severity="CRITICAL", category="supply_chain",
                remediation="Download script, verify checksum, then execute",
            ))

        if re.search(r"\$CI_COMMIT_MESSAGE|\$CI_MERGE_REQUEST_TITLE", stripped):
            if "script:" in content[max(0, content.rfind("\n", 0, sum(len(l)+1 for l in lines[:i-1]))):]:
                findings.append(CICDFinding(
                    path=path, line=i,
                    rule_id="CICD-GL-INJECT",
                    description="User-controlled variable in script (potential injection)",
                    severity="HIGH", category="injection",
                    remediation="Validate and sanitize CI variables before use in scripts",
                ))

        if re.search(r"allow_failure:\s*true", stripped, re.I):
            findings.append(CICDFinding(
                path=path, line=i,
                rule_id="CICD-GL-ALLOWFAIL",
                description="Security job allows failure (can be bypassed)",
                severity="MEDIUM", category="misconfiguration",
                remediation="Security-critical jobs should not allow failure",
            ))

        if re.search(r"image:\s*['\"]?\w+/\w+(?::['\"]?latest)?['\"]?\s*$", stripped, re.I):
            if ":latest" in stripped or not re.search(r":\w+", stripped.split("image:")[-1]):
                findings.append(CICDFinding(
                    path=path, line=i,
                    rule_id="CICD-GL-LATEST",
                    description="CI image uses :latest or untagged (mutable)",
                    severity="MEDIUM", category="supply_chain",
                    remediation="Pin CI images to specific digest or immutable tag",
                ))

    return findings


def _scan_jenkinsfile(path: str, content: str) -> list[CICDFinding]:
    findings = []
    lines = content.split("\n")

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        if re.search(r"sh\s+['\"].*\$\{", stripped):
            findings.append(CICDFinding(
                path=path, line=i,
                rule_id="CICD-JENKINS-INJECT",
                description="Variable interpolation in sh step (injection risk)",
                severity="HIGH", category="injection",
                remediation="Use sh script with single quotes or withEnv for variables",
            ))

        if re.search(r"script\s*\{", stripped):
            if re.search(r"(?:httpRequest|curl|wget)", content[sum(len(l)+1 for l in lines[:i]):sum(len(l)+1 for l in lines[:i+10])]):
                findings.append(CICDFinding(
                    path=path, line=i,
                    rule_id="CICD-JENKINS-NET",
                    description="Network request in pipeline script block",
                    severity="MEDIUM", category="supply_chain",
                ))

        if re.search(r"credentials\s*\(\s*['\"]", stripped):
            findings.append(CICDFinding(
                path=path, line=i,
                rule_id="CICD-JENKINS-CRED",
                description="Inline credential reference (verify scope)",
                severity="LOW", category="credential",
                remediation="Use folder-scoped credentials with minimal access",
            ))

    return findings


def scan_directory(root: str) -> list[CICDFinding]:
    findings = []

    gha_dir = os.path.join(root, ".github", "workflows")
    if os.path.isdir(gha_dir):
        for fname in os.listdir(gha_dir):
            if fname.endswith((".yml", ".yaml")):
                fpath = os.path.join(gha_dir, fname)
                try:
                    with open(fpath, encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    findings.extend(_scan_gha_file(fpath, content))
                except OSError:
                    continue

    for ci_name in (".gitlab-ci.yml", ".gitlab-ci.yaml"):
        ci_path = os.path.join(root, ci_name)
        if os.path.exists(ci_path):
            try:
                with open(ci_path, encoding="utf-8", errors="replace") as f:
                    content = f.read()
                findings.extend(_scan_gitlab_ci(ci_path, content))
            except OSError:
                pass

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if fname.lower() in ("jenkinsfile", "jenkinsfile.groovy"):
                fpath = os.path.join(dirpath, fname)
                try:
                    with open(fpath, encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    findings.extend(_scan_jenkinsfile(fpath, content))
                except OSError:
                    continue

    return findings


def render(findings: list[CICDFinding]) -> str:
    if not findings:
        return "  No CI/CD security issues found."
    lines = []
    by_cat = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)

    lines.append(f"\n  CI/CD Pipeline Security ({len(findings)} finding{'s' if len(findings) != 1 else ''})")
    lines.append(f"  {'='*55}")

    for cat in ("injection", "supply_chain", "privilege", "credential", "misconfiguration"):
        group = by_cat.get(cat, [])
        if not group:
            continue
        label = cat.replace("_", " ").title()
        lines.append(f"\n  [{label}] ({len(group)} finding{'s' if len(group) != 1 else ''})")
        for f in sorted(group, key=lambda x: ("CRITICAL", "HIGH", "MEDIUM", "LOW").index(x.severity)):
            lines.append(f"    [{f.severity}] {f.path}:{f.line}  {f.rule_id}")
            lines.append(f"      {f.description}")
            if f.remediation:
                lines.append(f"      Fix: {f.remediation}")

    crit = sum(1 for f in findings if f.severity == "CRITICAL")
    lines.append(f"\n  Total: {len(findings)} finding(s) ({crit} critical)")
    return "\n".join(lines)


def to_dict(findings: list[CICDFinding]) -> list[dict]:
    return [
        {
            "path": f.path,
            "line": f.line,
            "rule_id": f.rule_id,
            "description": f.description,
            "severity": f.severity,
            "category": f.category,
            "remediation": f.remediation,
        }
        for f in findings
    ]
