#!/usr/bin/env python3
"""Conservative security/correctness checks for Attestor 3.0's extended languages.

These rules complement real compilers and existing language-specific engines.
They never execute project code and only report patterns with useful evidence.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    language: str
    rule: str
    severity: str
    message: str
    fix: str
    confidence: float = 0.85


EXT_LANGUAGE = {
    ".rs": "rust", ".go": "go", ".java": "java", ".cs": "csharp",
    ".sql": "sql", ".tf": "terraform", ".tfvars": "terraform",
    ".yaml": "yaml", ".yml": "yaml", ".gradle": "gradle",
}


RULES = {
    "rust": [
        ("rust-unsafe-block", "MEDIUM", r"\bunsafe\s*\{",
         "unsafe Rust bypasses compiler safety guarantees",
         "isolate and document the invariant; prefer a safe abstraction."),
        ("rust-transmute", "HIGH", r"\b(?:std::mem::)?transmute\s*(?:::|\()",
         "transmute can violate layout, lifetime, and validity invariants",
         "use explicit conversions or a reviewed representation-safe wrapper."),
        ("rust-command-shell", "HIGH", r"Command::new\s*\(\s*[\"'](?:sh|bash|cmd|powershell)",
         "spawning a command shell creates an injection boundary",
         "invoke the target executable directly with a fixed argument vector."),
    ],
    "go": [
        ("go-insecure-tls", "HIGH", r"InsecureSkipVerify\s*:\s*true",
         "TLS verification is disabled",
         "use the system/custom trust store and leave verification enabled."),
        ("go-command-shell", "HIGH", r"exec\.Command\s*\(\s*[\"'](?:sh|bash|cmd|powershell)",
         "spawning a shell around data can enable command injection",
         "invoke the intended executable directly and pass validated arguments."),
        ("go-world-writable", "MEDIUM", r"os\.(?:WriteFile|MkdirAll?)\s*\([^\n]*0?777\b",
         "world-writable filesystem permissions are requested",
         "use the least permissions required, commonly 0600/0700."),
    ],
    "java": [
        ("java-insecure-deserialization", "HIGH", r"\bObjectInputStream\s*\(",
         "native Java deserialization can instantiate attacker-controlled object graphs",
         "use a schema-based format and strict type allowlists."),
        ("java-runtime-exec", "HIGH", r"Runtime\.getRuntime\(\)\.exec\s*\(",
         "Runtime.exec is a command-injection boundary",
         "use ProcessBuilder with a fixed executable and validated arguments."),
        ("java-weak-random", "MEDIUM", r"\bnew\s+Random\s*\(",
         "java.util.Random is predictable for security tokens",
         "use SecureRandom for security-sensitive values."),
    ],
    "csharp": [
        ("csharp-binaryformatter", "HIGH", r"\bBinaryFormatter\b",
         "BinaryFormatter is unsafe for untrusted input",
         "use a safe schema-based serializer with explicit types."),
        ("csharp-process-shell", "HIGH", r"UseShellExecute\s*=\s*true|Process\.Start\s*\(",
         "shell/process launch is an injection boundary",
         "disable shell execution and pass a fixed executable/argument list."),
        ("csharp-async-void", "MEDIUM", r"\basync\s+void\s+\w+\s*\(",
         "async void exceptions cannot be awaited or reliably observed",
         "return Task except for framework event handlers."),
    ],
    "sql": [
        ("sql-dynamic-exec", "HIGH", r"\bEXEC(?:UTE)?\s*\(\s*[@:]?\w+",
         "dynamic SQL execution can turn data into executable SQL",
         "use parameterized statements and an allowlist for identifiers."),
        ("sql-delete-without-where", "HIGH", r"^\s*DELETE\s+FROM\s+[\w.]+\s*;?\s*$",
         "DELETE without a WHERE clause removes every row",
         "add an intentional predicate or an explicit audited truncate operation."),
        ("sql-select-star", "LOW", r"\bSELECT\s+\*\s+FROM\b",
         "SELECT * creates unstable, over-broad data contracts",
         "select the required columns explicitly."),
    ],
    "terraform": [
        ("tf-public-ingress", "HIGH", r"[\"']0\.0\.0\.0/0[\"']",
         "a resource permits traffic from the entire IPv4 internet",
         "restrict the CIDR to the required trusted networks."),
        ("tf-public-acl", "HIGH", r"acl\s*=\s*[\"']public-(?:read|read-write)[\"']",
         "a cloud storage ACL is public",
         "use private ACLs and grant access through explicit identities."),
        ("tf-secret-value", "HIGH", r"(?i)\b(?:password|secret|api_key)\s*=\s*[\"'][^${][^\"']{7,}[\"']",
         "a secret-looking value is hardcoded in Terraform",
         "use a sensitive variable sourced from a secret manager."),
    ],
    "yaml": [
        ("k8s-privileged", "HIGH", r"^\s*privileged\s*:\s*true\s*$",
         "a container is granted privileged host access",
         "remove privileged mode and grant only required capabilities."),
        ("k8s-host-network", "HIGH", r"^\s*hostNetwork\s*:\s*true\s*$",
         "a workload shares the host network namespace",
         "use the pod network unless host networking is strictly required."),
        ("k8s-latest-tag", "MEDIUM", r"^\s*image\s*:\s*[^\s]+:latest\s*$",
         "the mutable latest image tag makes deployments non-reproducible",
         "pin an immutable digest or versioned tag."),
        ("ci-pull-request-target", "HIGH", r"^\s*pull_request_target\s*:",
         "pull_request_target runs with base-repository privileges",
         "never execute or checkout untrusted PR code in this workflow."),
        ("ci-curl-pipe-shell", "HIGH", r"\bcurl\b[^\n|]*\|\s*(?:sh|bash)\b",
         "downloaded network content is executed directly as shell code",
         "download, verify a pinned checksum/signature, then execute locally."),
    ],
}


def language_for(path: str) -> str:
    name = os.path.basename(path).lower()
    if name in ("dockerfile", "containerfile") or name.startswith("dockerfile."):
        return "docker"
    return EXT_LANGUAGE.get(os.path.splitext(name)[1], "")


def _docker_findings(text: str, path: str) -> list[Finding]:
    findings = []
    has_nonroot_user = False
    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if re.match(r"(?i)^USER\s+(?!0\b|root\b)\S+", stripped):
            has_nonroot_user = True
        if re.match(r"(?i)^FROM\s+\S+:latest(?:\s|$)", stripped):
            findings.append(Finding(path, line_no, "docker", "docker-latest-tag", "MEDIUM",
                                    "the base image uses the mutable latest tag",
                                    "pin a version and preferably an immutable digest."))
        if re.match(r"(?i)^ADD\s+https?://", stripped):
            findings.append(Finding(path, line_no, "docker", "docker-remote-add", "MEDIUM",
                                    "ADD downloads remote content without an integrity check",
                                    "download with a pinned checksum in a build step, then COPY it."))
    if text.strip() and not has_nonroot_user:
        findings.append(Finding(path, 1, "docker", "docker-root-default", "MEDIUM",
                                "the final image does not select a non-root user",
                                "create and select a dedicated unprivileged USER."))
    return findings


def analyze(text: str, path: str) -> list[Finding]:
    language = language_for(path)
    if language == "docker":
        return _docker_findings(text, path)
    findings = []
    for rule, severity, pattern, message, fix in RULES.get(language, []):
        regex = re.compile(pattern, re.I if language in {"sql", "terraform"} else 0)
        for line_no, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("//", "#", "--")):
                continue
            if regex.search(line):
                findings.append(Finding(path, line_no, language, rule, severity, message, fix))
    return findings
