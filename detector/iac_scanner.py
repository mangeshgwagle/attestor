#!/usr/bin/env python3
"""Infrastructure-as-Code (IaC) security scanner -- detects misconfigurations in
Dockerfiles, docker-compose, Kubernetes manifests, Terraform, GitHub Actions,
Helm charts, and .env files."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

SKIP_DIRS = {
    ".git", ".svn", "node_modules", "__pycache__", ".tox", ".venv",
    "venv", "dist", "build",
}


@dataclass
class IaCFinding:
    path: str
    line: int
    rule_id: str
    description: str
    severity: str
    category: str
    remediation: str = ""


# Dockerfile rules
DOCKERFILE_RULES: list[tuple[str, str, str, str, str]] = [
    ("IAC-DOCKER-ROOT", "Container runs as root (no USER directive)",
     r"^(?!.*\bUSER\b)", "HIGH",
     "Add 'USER nonroot' before CMD/ENTRYPOINT"),
    ("IAC-DOCKER-LATEST", "Using ':latest' tag (non-reproducible builds)",
     r"(?i)FROM\s+\S+:latest\b", "MEDIUM",
     "Pin to a specific image tag or digest"),
    ("IAC-DOCKER-ADD", "ADD used instead of COPY (may extract archives unexpectedly)",
     r"(?i)^ADD\s+(?!https?://)", "LOW",
     "Use COPY unless you need archive extraction"),
    ("IAC-DOCKER-CURL-PIPE", "Curl piped to shell (supply chain risk)",
     r"(?:curl|wget)\s+.*\|\s*(?:sh|bash|python)", "HIGH",
     "Download first, verify checksum, then execute"),
    ("IAC-DOCKER-SECRETS", "Secrets in Dockerfile (ENV with password/key/token)",
     r"(?i)ENV\s+\S*(?:PASSWORD|SECRET|KEY|TOKEN|API_KEY)\s*=\s*\S+", "CRITICAL",
     "Use Docker secrets or build args with --secret"),
    ("IAC-DOCKER-EXPOSE-ALL", "Exposing all ports with 0.0.0.0",
     r"EXPOSE\s+0\.0\.0\.0", "MEDIUM",
     "Bind to specific interface"),
    ("IAC-DOCKER-SUDO", "sudo in container (already running as root means no isolation)",
     r"(?:RUN|CMD|ENTRYPOINT).*\bsudo\b", "LOW",
     "Use USER directive instead of sudo"),
    ("IAC-DOCKER-NOCOPY-CHOWN", "COPY without --chown (files owned by root)",
     r"^COPY\s+(?!--chown)", "LOW",
     "Use COPY --chown=user:group"),
    ("IAC-DOCKER-APT-NOCLEAN", "apt-get without cleanup (bloated image layer)",
     r"apt-get\s+install(?!.*&&\s*(?:apt-get\s+clean|rm\s+-rf))", "LOW",
     "Chain apt-get install with apt-get clean && rm -rf /var/lib/apt/lists/*"),
]

COMPOSE_RULES: list[tuple[str, str, str, str, str]] = [
    ("IAC-COMPOSE-PRIV", "Privileged container (full host access)",
     r"(?i)privileged\s*:\s*true", "CRITICAL",
     "Remove privileged: true unless absolutely needed"),
    ("IAC-COMPOSE-HOSTNET", "Host network mode (no network isolation)",
     r"(?i)network_mode\s*:\s*['\"]?host", "HIGH",
     "Use bridge or overlay network"),
    ("IAC-COMPOSE-HOSTPID", "Host PID namespace (can see host processes)",
     r"(?i)pid\s*:\s*['\"]?host", "HIGH",
     "Remove pid: host"),
    ("IAC-COMPOSE-HOSTPATH", "Sensitive host path mounted",
     r"(?i)volumes:.*(?:/etc/shadow|/etc/passwd|/var/run/docker\.sock|/root)", "CRITICAL",
     "Avoid mounting sensitive host paths"),
    ("IAC-COMPOSE-NOREAD", "Volume not mounted read-only where possible",
     r"volumes:.*(?:/etc|/var/log|/opt)(?!:ro)", "LOW",
     "Mount with :ro for read-only access"),
    ("IAC-COMPOSE-CAPSYS", "SYS_ADMIN capability added",
     r"(?i)cap_add:.*SYS_ADMIN", "HIGH",
     "Only add minimal required capabilities"),
    ("IAC-COMPOSE-ENV-SECRET", "Secret in environment variable",
     r"(?i)environment:.*(?:PASSWORD|SECRET|KEY|TOKEN)\s*[:=]\s*[^\$]", "HIGH",
     "Use Docker secrets or external secret manager"),
]

K8S_RULES: list[tuple[str, str, str, str, str]] = [
    ("IAC-K8S-PRIV", "Privileged container in pod spec",
     r"(?i)privileged\s*:\s*true", "CRITICAL",
     "Set privileged: false"),
    ("IAC-K8S-ROOT", "Running as root (runAsNonRoot not set)",
     r"(?i)runAsUser\s*:\s*0", "HIGH",
     "Set runAsNonRoot: true and runAsUser to non-zero UID"),
    ("IAC-K8S-NOLIMITS", "No resource limits set",
     r"(?i)containers:(?!.*(?:limits|resources))", "MEDIUM",
     "Set resource requests and limits"),
    ("IAC-K8S-HOSTPATH", "hostPath volume (access to host filesystem)",
     r"(?i)hostPath\s*:", "HIGH",
     "Use emptyDir, configMap, or PVC instead"),
    ("IAC-K8S-HOSTNET", "Host network enabled",
     r"(?i)hostNetwork\s*:\s*true", "HIGH",
     "Set hostNetwork: false"),
    ("IAC-K8S-HOSTPID", "Host PID namespace",
     r"(?i)hostPID\s*:\s*true", "HIGH",
     "Set hostPID: false"),
    ("IAC-K8S-NODEPORT", "NodePort service (exposes port on all nodes)",
     r"(?i)type\s*:\s*NodePort", "MEDIUM",
     "Use ClusterIP with Ingress or LoadBalancer"),
    ("IAC-K8S-DEFAULT-SA", "Default service account used",
     r"(?i)serviceAccountName\s*:\s*default", "MEDIUM",
     "Create a dedicated service account with minimal RBAC"),
    ("IAC-K8S-ALLCAPS", "All capabilities not dropped",
     r"(?i)capabilities:(?!.*drop.*ALL)", "MEDIUM",
     "Add drop: [ALL] under securityContext.capabilities"),
    ("IAC-K8S-SECRET-ENV", "Secret in plain-text env var",
     r"(?i)value\s*:\s*['\"]?(?:password|secret|key|token)['\"]?", "HIGH",
     "Use secretKeyRef or external secrets operator"),
    ("IAC-K8S-READONLY", "Root filesystem not read-only",
     r"(?i)readOnlyRootFilesystem\s*:\s*false", "MEDIUM",
     "Set readOnlyRootFilesystem: true"),
]

TERRAFORM_RULES: list[tuple[str, str, str, str, str]] = [
    ("IAC-TF-PUBLIC-S3", "S3 bucket with public access",
     r"(?i)acl\s*=\s*\"public-(?:read|read-write)\"", "CRITICAL",
     "Set acl = 'private' and use bucket policy for access control"),
    ("IAC-TF-PUBLIC-SG", "Security group allowing 0.0.0.0/0 ingress",
     r"(?i)cidr_blocks\s*=\s*\[\"0\.0\.0\.0/0\"\]", "HIGH",
     "Restrict CIDR to specific IP ranges"),
    ("IAC-TF-NO-ENCRYPT", "Storage without encryption",
     r"(?i)encrypted\s*=\s*false", "HIGH",
     "Set encrypted = true"),
    ("IAC-TF-HARDCODED", "Hardcoded secret in Terraform",
     r"(?i)(?:password|secret_key|access_key)\s*=\s*\"[^${}\"]{8,}\"", "CRITICAL",
     "Use variables with sensitive = true or vault"),
    ("IAC-TF-NO-LOGGING", "No access logging enabled",
     r"(?i)(?:logging|access_logs)\s*\{[^}]*enabled\s*=\s*false", "MEDIUM",
     "Enable access logging"),
    ("IAC-TF-WILDCARD-IAM", "Wildcard (*) in IAM policy",
     r"\"Action\"\s*:\s*\[?\s*\"\*\"", "CRITICAL",
     "Follow least-privilege principle"),
    ("IAC-TF-HTTP", "HTTP instead of HTTPS",
     r"(?i)protocol\s*=\s*\"HTTP\"", "MEDIUM",
     "Use HTTPS with TLS"),
    ("IAC-TF-OLD-TLS", "Outdated TLS version",
     r"(?i)(?:ssl_policy|tls_version|minimum_tls_version)\s*=\s*\"(?:TLSv1|TLSv1\.0|TLSv1\.1)\"", "HIGH",
     "Use TLS 1.2 or 1.3 minimum"),
]

GH_ACTIONS_RULES: list[tuple[str, str, str, str, str]] = [
    ("IAC-GHA-INJECTION", "Potential command injection via github context",
     r"\$\{\{\s*github\.event\.(?:issue|pull_request|comment)\.(?:title|body|label)", "CRITICAL",
     "Use environment variables or intermediate files for user-controlled input"),
    ("IAC-GHA-UNPINNED", "Unpinned third-party action (supply chain risk)",
     r"uses:\s+[^@\s]+@(?:main|master|latest|v\d+)\b", "HIGH",
     "Pin actions to a specific commit SHA"),
    ("IAC-GHA-SECRET-LOG", "Secret potentially logged",
     r"(?:echo|print|console\.log).*\$\{\{\s*secrets\.", "CRITICAL",
     "Never echo secrets; use environment variables"),
    ("IAC-GHA-PERSIST-CREDS", "persist-credentials not disabled for checkout",
     r"actions/checkout.*(?!persist-credentials:\s*false)", "MEDIUM",
     "Set persist-credentials: false in checkout step"),
    ("IAC-GHA-WRITE-ALL", "Overly permissive workflow permissions",
     r"permissions\s*:\s*write-all", "HIGH",
     "Use granular permissions (contents: read, etc.)"),
    ("IAC-GHA-PULL-TARGET", "pull_request_target with checkout of PR head",
     r"(?i)pull_request_target.*checkout.*\$\{\{\s*github\.event\.pull_request\.head", "CRITICAL",
     "Never checkout PR head in pull_request_target; use pull_request event"),
]

ENV_RULES: list[tuple[str, str, str, str, str]] = [
    ("IAC-ENV-SECRET", "Hardcoded secret in .env file",
     r"(?i)(?:PASSWORD|SECRET|KEY|TOKEN|API_KEY|PRIVATE_KEY)\s*=\s*[^\s$]{4,}", "HIGH",
     "Use a secret manager instead of .env files"),
    ("IAC-ENV-DEBUG", "Debug mode enabled in production .env",
     r"(?i)DEBUG\s*=\s*(?:true|1|yes)", "MEDIUM",
     "Set DEBUG=false in production"),
    ("IAC-ENV-ADMIN", "Default admin credentials",
     r"(?i)(?:ADMIN_PASSWORD|ROOT_PASSWORD|DB_PASSWORD)\s*=\s*(?:admin|password|123456|root)", "CRITICAL",
     "Use strong, unique passwords"),
]

_compiled_cache: dict[str, list[tuple[str, str, re.Pattern, str, str]]] = {}


def _compile_rules(rules):
    key = id(rules)
    if key not in _compiled_cache:
        _compiled_cache[key] = [
            (rid, desc, re.compile(pat), sev, rem)
            for rid, desc, pat, sev, rem in rules
        ]
    return _compiled_cache[key]


def _scan_with_rules(path: str, rules, category: str) -> list[IaCFinding]:
    findings = []
    compiled = _compile_rules(rules)
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except (OSError, PermissionError):
        return []

    for lineno, line in enumerate(lines, 1):
        for rule_id, desc, pattern, severity, remediation in compiled:
            if pattern.search(line):
                findings.append(IaCFinding(
                    path=path, line=lineno,
                    rule_id=rule_id, description=desc,
                    severity=severity, category=category,
                    remediation=remediation,
                ))
    return findings


def _check_dockerfile_no_user(path: str) -> list[IaCFinding]:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except (OSError, PermissionError):
        return []
    if "USER " not in content and "FROM " in content:
        return [IaCFinding(
            path=path, line=1,
            rule_id="IAC-DOCKER-ROOT",
            description="Container runs as root (no USER directive)",
            severity="HIGH", category="dockerfile",
            remediation="Add 'USER nonroot' before CMD/ENTRYPOINT",
        )]
    return []


def scan_file(path: str) -> list[IaCFinding]:
    fname = os.path.basename(path).lower()
    findings = []

    if fname == "dockerfile" or fname.startswith("dockerfile."):
        findings.extend(_scan_with_rules(path, DOCKERFILE_RULES[1:], "dockerfile"))
        findings.extend(_check_dockerfile_no_user(path))
    elif fname in ("docker-compose.yml", "docker-compose.yaml") or fname.startswith("compose."):
        findings.extend(_scan_with_rules(path, COMPOSE_RULES, "docker_compose"))
    elif fname.endswith((".yml", ".yaml")):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                head = f.read(2000)
        except OSError:
            head = ""
        if "apiVersion:" in head and "kind:" in head:
            findings.extend(_scan_with_rules(path, K8S_RULES, "kubernetes"))
        if "on:" in head and ("jobs:" in head or "steps:" in head):
            findings.extend(_scan_with_rules(path, GH_ACTIONS_RULES, "github_actions"))
    elif fname.endswith((".tf", ".tf.json")):
        findings.extend(_scan_with_rules(path, TERRAFORM_RULES, "terraform"))
    elif fname == ".env" or fname.startswith(".env."):
        findings.extend(_scan_with_rules(path, ENV_RULES, "dotenv"))

    return findings


def scan_directory(root: str) -> list[IaCFinding]:
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            findings.extend(scan_file(fpath))
    return findings


def render(findings: list[IaCFinding]) -> str:
    if not findings:
        return "  No IaC misconfigurations detected."
    lines = []
    by_cat = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)

    for cat in ("dockerfile", "docker_compose", "kubernetes", "terraform",
                "github_actions", "dotenv"):
        group = by_cat.pop(cat, [])
        if not group:
            continue
        label = cat.replace("_", " ").title()
        lines.append(f"\n  [{label}] ({len(group)} finding{'s' if len(group) > 1 else ''})")
        for f in sorted(group, key=lambda x: ("CRITICAL", "HIGH", "MEDIUM", "LOW").index(x.severity)):
            lines.append(f"    [{f.severity}] {f.path}:{f.line}  {f.rule_id}")
            lines.append(f"      {f.description}")
            if f.remediation:
                lines.append(f"      Fix: {f.remediation}")

    total = len(findings)
    crit = sum(1 for f in findings if f.severity == "CRITICAL")
    lines.append(f"\n  Total: {total} IaC issue(s) ({crit} critical)")
    return "\n".join(lines)


def to_dict(findings: list[IaCFinding]) -> list[dict]:
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
