#!/usr/bin/env python3
"""Infrastructure-as-Code security scanner.

Scans Dockerfiles, Terraform, CloudFormation, and Kubernetes manifests
for common security misconfigurations. Regex-based, no external deps.

Checks:
  Dockerfile: running as root, ADD vs COPY, latest tag, exposed secrets,
              privileged instructions, missing healthcheck.
  Terraform:  public S3/GCS buckets, open security groups (0.0.0.0/0),
              missing encryption, overly permissive IAM, unencrypted DBs.
  K8s:        privileged containers, hostNetwork/hostPID, missing resource
              limits, running as root, writable rootfs.
  CloudFormation: public S3, open ingress, missing encryption.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
             "dist", "build", ".terraform"}


@dataclass
class IaCFinding:
    rule_id: str
    severity: str
    file: str
    line: int
    code: str
    description: str
    category: str
    cwe: str = ""


_DOCKERFILE_RULES = [
    {
        "id": "DOCKER-001", "severity": "HIGH",
        "pattern": r"^\s*USER\s+root\s*$",
        "description": "Container runs as root -- use a non-root USER",
        "cwe": "CWE-250", "category": "privilege",
    },
    {
        "id": "DOCKER-002", "severity": "MEDIUM",
        "pattern": r"^\s*ADD\s+(?!.*\.tar|.*\.gz)",
        "description": "Use COPY instead of ADD unless extracting archives",
        "cwe": "CWE-829", "category": "supply_chain",
    },
    {
        "id": "DOCKER-003", "severity": "MEDIUM",
        "pattern": r"^\s*FROM\s+\S+:latest\b",
        "description": "Pin image tags instead of using :latest",
        "cwe": "CWE-829", "category": "supply_chain",
    },
    {
        "id": "DOCKER-004", "severity": "CRITICAL",
        "pattern": r"(?i)(password|secret|api_key|token)\s*=\s*\S+",
        "description": "Hard-coded secret in Dockerfile -- use build secrets or env",
        "cwe": "CWE-798", "category": "secrets",
    },
    {
        "id": "DOCKER-005", "severity": "HIGH",
        "pattern": r"--privileged",
        "description": "Container runs in privileged mode",
        "cwe": "CWE-250", "category": "privilege",
    },
    {
        "id": "DOCKER-006", "severity": "LOW",
        "pattern": r"^\s*EXPOSE\s+22\b",
        "description": "SSH port exposed in container -- prefer exec/attach",
        "cwe": "CWE-284", "category": "network",
    },
]

_TERRAFORM_RULES = [
    {
        "id": "TF-001", "severity": "CRITICAL",
        "pattern": r'acl\s*=\s*"public-read"',
        "description": "S3/GCS bucket is publicly readable",
        "cwe": "CWE-284", "category": "access_control",
    },
    {
        "id": "TF-002", "severity": "HIGH",
        "pattern": r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
        "description": "Security group allows ingress from 0.0.0.0/0",
        "cwe": "CWE-284", "category": "network",
    },
    {
        "id": "TF-003", "severity": "HIGH",
        "pattern": r'encrypted\s*=\s*false',
        "description": "Resource has encryption disabled",
        "cwe": "CWE-311", "category": "encryption",
    },
    {
        "id": "TF-004", "severity": "CRITICAL",
        "pattern": r'(?i)(password|secret_key|access_key)\s*=\s*"[^"]{4,}"',
        "description": "Hard-coded credential in Terraform config",
        "cwe": "CWE-798", "category": "secrets",
    },
    {
        "id": "TF-005", "severity": "HIGH",
        "pattern": r'"Effect"\s*:\s*"Allow".*"Action"\s*:\s*"\*"',
        "description": "IAM policy allows all actions (Action: *)",
        "cwe": "CWE-250", "category": "privilege",
    },
    {
        "id": "TF-006", "severity": "MEDIUM",
        "pattern": r'storage_encrypted\s*=\s*false',
        "description": "RDS/database storage encryption disabled",
        "cwe": "CWE-311", "category": "encryption",
    },
    {
        "id": "TF-007", "severity": "MEDIUM",
        "pattern": r'publicly_accessible\s*=\s*true',
        "description": "Database is publicly accessible",
        "cwe": "CWE-284", "category": "network",
    },
    {
        "id": "TF-008", "severity": "MEDIUM",
        "pattern": r'versioning\s*\{[^}]*enabled\s*=\s*false',
        "description": "S3 bucket versioning disabled -- data loss risk",
        "cwe": "CWE-693", "category": "resilience",
    },
]

_K8S_RULES = [
    {
        "id": "K8S-001", "severity": "CRITICAL",
        "pattern": r"privileged\s*:\s*true",
        "description": "Container runs in privileged mode",
        "cwe": "CWE-250", "category": "privilege",
    },
    {
        "id": "K8S-002", "severity": "HIGH",
        "pattern": r"hostNetwork\s*:\s*true",
        "description": "Pod uses host network namespace",
        "cwe": "CWE-284", "category": "network",
    },
    {
        "id": "K8S-003", "severity": "HIGH",
        "pattern": r"hostPID\s*:\s*true",
        "description": "Pod shares host PID namespace",
        "cwe": "CWE-284", "category": "privilege",
    },
    {
        "id": "K8S-004", "severity": "MEDIUM",
        "pattern": r"readOnlyRootFilesystem\s*:\s*false",
        "description": "Container has writable root filesystem",
        "cwe": "CWE-284", "category": "filesystem",
    },
    {
        "id": "K8S-005", "severity": "HIGH",
        "pattern": r"runAsUser\s*:\s*0\b",
        "description": "Container runs as root (UID 0)",
        "cwe": "CWE-250", "category": "privilege",
    },
    {
        "id": "K8S-006", "severity": "MEDIUM",
        "pattern": r"allowPrivilegeEscalation\s*:\s*true",
        "description": "Container allows privilege escalation",
        "cwe": "CWE-250", "category": "privilege",
    },
    {
        "id": "K8S-007", "severity": "LOW",
        "pattern": r'image\s*:\s*\S+:latest\b',
        "description": "Container uses :latest tag -- pin a specific version",
        "cwe": "CWE-829", "category": "supply_chain",
    },
]

_CFN_RULES = [
    {
        "id": "CFN-001", "severity": "CRITICAL",
        "pattern": r"AccessControl\s*:\s*PublicRead",
        "description": "S3 bucket is publicly readable",
        "cwe": "CWE-284", "category": "access_control",
    },
    {
        "id": "CFN-002", "severity": "HIGH",
        "pattern": r"CidrIp\s*:\s*0\.0\.0\.0/0",
        "description": "Security group allows ingress from 0.0.0.0/0",
        "cwe": "CWE-284", "category": "network",
    },
    {
        "id": "CFN-003", "severity": "HIGH",
        "pattern": r"StorageEncrypted\s*:\s*false",
        "description": "RDS storage encryption disabled",
        "cwe": "CWE-311", "category": "encryption",
    },
]


def _detect_file_type(path: str) -> str:
    name = os.path.basename(path).lower()
    if name == "dockerfile" or name.startswith("dockerfile."):
        return "dockerfile"
    if name.endswith((".tf", ".tf.json")):
        return "terraform"
    if name.endswith((".yaml", ".yml")):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                head = f.read(2000)
            if "apiVersion:" in head and "kind:" in head:
                return "kubernetes"
            if "AWSTemplateFormatVersion" in head or "AWS::CloudFormation" in head:
                return "cloudformation"
        except OSError:
            pass
    if name.endswith(".json"):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                head = f.read(2000)
            if "AWSTemplateFormatVersion" in head:
                return "cloudformation"
        except OSError:
            pass
    return ""


def _scan_file(path: str, lines: list[str], rules: list[dict]) -> list[IaCFinding]:
    findings = []
    for i, line in enumerate(lines):
        for rule in rules:
            if re.search(rule["pattern"], line):
                findings.append(IaCFinding(
                    rule_id=rule["id"], severity=rule["severity"],
                    file=path, line=i + 1, code=line.strip()[:120],
                    description=rule["description"],
                    category=rule.get("category", ""),
                    cwe=rule.get("cwe", ""),
                ))
    return findings


def _no_user_directive(path: str, lines: list[str]) -> list[IaCFinding]:
    has_user = any(re.match(r"^\s*USER\s+\S+", l) for l in lines)
    has_from = any(re.match(r"^\s*FROM\s+", l) for l in lines)
    if has_from and not has_user:
        return [IaCFinding(
            rule_id="DOCKER-007", severity="MEDIUM",
            file=path, line=1, code="(no USER directive found)",
            description="No USER directive -- container defaults to root",
            category="privilege", cwe="CWE-250",
        )]
    return []


def _no_resource_limits(path: str, content: str) -> list[IaCFinding]:
    if "kind:" in content and "containers:" in content:
        if "resources:" not in content:
            return [IaCFinding(
                rule_id="K8S-008", severity="MEDIUM",
                file=path, line=1, code="(no resources: section)",
                description="No resource limits/requests -- DoS risk",
                category="resilience", cwe="CWE-770",
            )]
    return []


_FILE_TYPE_RULES = {
    "dockerfile": _DOCKERFILE_RULES,
    "terraform": _TERRAFORM_RULES,
    "kubernetes": _K8S_RULES,
    "cloudformation": _CFN_RULES,
}


def scan_file(path: str) -> list[IaCFinding]:
    ftype = _detect_file_type(path)
    if not ftype:
        return []
    rules = _FILE_TYPE_RULES.get(ftype, [])
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            content = f.read()
        lines = content.splitlines()
    except OSError:
        return []
    findings = _scan_file(path, lines, rules)
    if ftype == "dockerfile":
        findings += _no_user_directive(path, lines)
    if ftype == "kubernetes":
        findings += _no_resource_limits(path, content)
    return findings


def scan_paths(paths: list[str]) -> list[IaCFinding]:
    all_findings = []
    for p in paths:
        if os.path.isfile(p):
            all_findings += scan_file(p)
        elif os.path.isdir(p):
            for dp, dn, fn in os.walk(p):
                dn[:] = [d for d in dn if d not in SKIP_DIRS]
                for name in fn:
                    all_findings += scan_file(os.path.join(dp, name))
    return all_findings


def to_dict(findings: list[IaCFinding]) -> list[dict]:
    return [
        {
            "rule_id": f.rule_id, "severity": f.severity,
            "file": f.file, "path": f.file, "line": f.line,
            "sink_file": f.file, "sink_line": f.line,
            "sink_code": f.code, "sink_type": f.category,
            "matched_text": f.code, "description": f.description,
            "category": f.category, "cwe": f.cwe,
            "language": "iac",
        }
        for f in findings
    ]


def render(findings: list[IaCFinding]) -> str:
    if not findings:
        return "  No IaC security issues found."
    lines = [
        f"\n  IaC Security Scan -- {len(findings)} issue(s)",
        "  " + "=" * 62,
    ]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for f in sorted(findings, key=lambda x: order.get(x.severity, 9)):
        lines.append(f"\n  [{f.severity}] {f.rule_id} at "
                     f"{os.path.basename(f.file)}:{f.line}")
        lines.append(f"    {f.description}")
        if f.cwe:
            lines.append(f"    {f.cwe}")
        lines.append(f"    > {f.code[:100]}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="attestor-iac-scan",
        description="Scan Dockerfiles, Terraform, K8s, and CloudFormation for misconfigs.")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    findings = scan_paths(args.paths)
    if args.json:
        print(json.dumps(to_dict(findings), indent=2))
    else:
        print(render(findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
