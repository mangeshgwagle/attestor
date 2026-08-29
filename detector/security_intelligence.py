#!/usr/bin/env python3
"""Bounded, offline security-context analysis for Attestor.

This layer complements language rules with repository-wide evidence: attack
surfaces, STRIDE trust boundaries, source-to-sink attack paths, supply-chain
controls, secrets, CI, containers, cloud/IaC, web/API, mobile, crypto, and auth.
It never resolves packages, contacts a registry, probes a host, executes target
code, or includes matched secret material in its output.
"""
from __future__ import annotations

import ast
import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable

import secret_guard
import security_taxonomy


SCHEMA = "attestor-security-intelligence/1"
MAX_FILES = 6000
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 48 * 1024 * 1024
MAX_FINDINGS = 3000
MAX_COMPONENTS = 1500
MAX_ATTACK_PATHS = 200
SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", ".venv", "venv", "node_modules", "vendor",
    "dist", "build", "target", ".stack-work", ".terraform", ".next",
    ".gradle", "bin", "obj", "coverage", "generated_service",
}
TEXT_SUFFIXES = {
    ".py", ".pyw", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".java", ".kt", ".kts", ".go", ".rs", ".rb", ".php", ".cs",
    ".swift", ".c", ".cc", ".cpp", ".h", ".hpp", ".sh", ".bash",
    ".zsh", ".ps1", ".sql", ".tf", ".tfvars", ".hcl", ".yaml",
    ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".xml",
    ".plist", ".properties", ".gradle", ".env", ".md", ".txt",
}
TEXT_NAMES = {
    "dockerfile", "containerfile", "jenkinsfile", "makefile", ".env",
    ".npmrc", ".pypirc", ".gitmodules", "gemfile", "gemfile.lock",
    "procfile", "nginx.conf", "go.mod", "go.sum", "cargo.toml",
    "cargo.lock", "package.json", "package-lock.json", "pnpm-lock.yaml",
    "yarn.lock", "composer.json", "composer.lock", "pipfile", "pipfile.lock",
}
MANIFESTS = {
    "package.json", "pyproject.toml", "requirements.txt", "pipfile",
    "cargo.toml", "go.mod", "gemfile", "composer.json", "pom.xml",
    "build.gradle", "build.gradle.kts", "packages.config",
}
LOCKFILES = {
    "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock",
    "bun.lock", "bun.lockb", "poetry.lock", "uv.lock", "pipfile.lock",
    "cargo.lock", "go.sum", "gemfile.lock", "composer.lock", "packages.lock.json",
}
LOCK_EXPECTATIONS = {
    "package.json": ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml",
                     "yarn.lock", "bun.lock", "bun.lockb"),
    "pyproject.toml": ("poetry.lock", "uv.lock", "pdm.lock"),
    "pipfile": ("pipfile.lock",), "cargo.toml": ("cargo.lock",),
    "go.mod": ("go.sum",), "gemfile": ("gemfile.lock",),
    "composer.json": ("composer.lock",),
}
SEVERITY_VALUE = {"CRITICAL": 9.7, "HIGH": 8.0, "MEDIUM": 5.4, "LOW": 3.0, "INFO": 1.0}
REACHABILITY_FACTOR = {
    "internet-facing": 1.0, "client-facing": 0.92, "build-time": 0.92,
    "deployment-time": 0.88, "reachable-entrypoint": 0.90,
    "local": 0.68, "unknown": 0.76,
}

ROUTE_PATTERNS = (
    re.compile(r"(?m)^\s*@(?:\w+\.)?(?:route|get|post|put|patch|delete|websocket)\s*\("),
    re.compile(r"\b(?:app|router)\.(?:get|post|put|patch|delete|use)\s*\("),
    re.compile(r"@(?:Request|Get|Post|Put|Patch|Delete)Mapping\s*\("),
    re.compile(r"\b(?:Handle|HandleFunc)\s*\("),
    re.compile(r"\[(?:HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete|Route)\b"),
)
AUTH_MARKERS = re.compile(
    r"(?i)\b(?:oauth2?|openid|oidc|jwt|bearer|authentication|authorization|"
    r"login_required|require_auth|authorize|passport|spring security)\b"
)
DATA_MARKERS = re.compile(
    r"(?i)\b(?:postgres|mysql|sqlite|mongodb|redis|dynamodb|database|sqlalchemy|"
    r"entityframework|prisma|mongoose|jdbc:)\b"
)


def _relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except (OSError, ValueError):
        return path.as_posix()


def _line_for(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _read_text(path: Path) -> tuple[str | None, str]:
    try:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            return None, "oversized"
        data = path.read_bytes()
    except OSError as exc:
        return None, "read-error:%s" % type(exc).__name__
    if b"\x00" in data[:8192]:
        return None, "binary"
    try:
        return data.decode("utf-8"), "read"
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace"), "decoded-with-replacement"


def _discover(root: Path) -> tuple[list[Path], dict[str, Any]]:
    paths: list[Path] = []
    skipped: list[dict[str, str]] = []
    total_bytes = 0
    truncated = False
    for current, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = sorted(name for name in directories
                                if name.lower() not in SKIP_DIRS
                                and not (Path(current) / name).is_symlink())
        for filename in sorted(filenames):
            path = Path(current) / filename
            if path.is_symlink():
                skipped.append({"path": _relative(root, path), "reason": "symlink"})
                continue
            if path.suffix.lower() not in TEXT_SUFFIXES and filename.lower() not in TEXT_NAMES:
                continue
            try:
                size = path.stat().st_size
            except OSError:
                skipped.append({"path": _relative(root, path), "reason": "stat-error"})
                continue
            if size > MAX_FILE_BYTES:
                skipped.append({"path": _relative(root, path), "reason": "oversized"})
                continue
            if len(paths) >= MAX_FILES or total_bytes + size > MAX_TOTAL_BYTES:
                truncated = True
                break
            paths.append(path)
            total_bytes += size
        if truncated:
            break
    return paths, {
        "files_considered": len(paths), "bytes_considered": total_bytes,
        "max_files": MAX_FILES, "max_file_bytes": MAX_FILE_BYTES,
        "max_total_bytes": MAX_TOTAL_BYTES, "truncated": truncated,
        "skipped": skipped[:200], "skipped_count": len(skipped),
    }


def _finding(path: str, line: int, rule: str, severity: str, category: str,
             cwe: str, message: str, fix: str, confidence: float, *,
             asvs: Iterable[str] = (), ssdf: Iterable[str] = (),
             precision: str = "high") -> dict[str, Any]:
    row: dict[str, Any] = {
        "path": path, "line": max(1, int(line)), "rule": rule,
        "severity": severity, "category": category, "cwe": cwe,
        "owasp": "", "confidence": round(max(0.0, min(confidence, 1.0)), 2),
        "message": message, "fix": fix, "source": "security-intelligence",
        "pack": "contextual-security-2.3", "precision": precision,
        "asvs": list(asvs), "nist_ssdf": list(ssdf),
        "evidence": [{"kind": "static-configuration", "path": path, "line": max(1, int(line)),
                      "description": message}],
    }
    return security_taxonomy.enrich_taxonomy(row)


def _component(components: list[dict[str, Any]], kind: str, path: str, line: int,
               exposure: str, evidence: str) -> None:
    if len(components) >= MAX_COMPONENTS:
        return
    key = (kind, path, line)
    if any((row["kind"], row["path"], row["line"]) == key for row in components[-100:]):
        return
    components.append({"kind": kind, "path": path, "line": max(1, line),
                       "exposure": exposure, "evidence": evidence})


def _surface_file(path: Path, relative: str, text: str,
                  components: list[dict[str, Any]], route_files: set[str]) -> None:
    name = path.name.lower()
    normalized = "/" + relative.lower()
    for pattern in ROUTE_PATTERNS:
        for match in list(pattern.finditer(text))[:100]:
            _component(components, "web-or-api-route", relative, _line_for(text, match.start()),
                       "internet-facing", "framework route declaration")
            route_files.add(relative)
    if name in {"openapi.json", "openapi.yaml", "openapi.yml", "swagger.json", "swagger.yaml"}:
        _component(components, "api-contract", relative, 1, "internet-facing", "API contract file")
    if name.startswith(("dockerfile", "containerfile")) or name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
        _component(components, "container", relative, 1, "deployment-time", "container build/runtime configuration")
    if "/.github/workflows/" in normalized or name in {"jenkinsfile", ".gitlab-ci.yml", "azure-pipelines.yml"}:
        _component(components, "ci-cd-workflow", relative, 1, "build-time", "automation workflow")
    if path.suffix.lower() in {".tf", ".tfvars", ".hcl"} or name in {"serverless.yml", "serverless.yaml", "template.yaml"}:
        _component(components, "infrastructure-as-code", relative, 1, "deployment-time", "infrastructure declaration")
    if name == "androidmanifest.xml" or (name == "info.plist" and "ios" in normalized):
        _component(components, "mobile-application", relative, 1, "client-facing", "mobile application manifest")
    if name in MANIFESTS:
        _component(components, "dependency-manifest", relative, 1, "build-time", "third-party component declaration")
    if AUTH_MARKERS.search(text):
        _component(components, "identity-control", relative, 1, "reachable-entrypoint", "authentication/authorization implementation marker")
    if path.suffix.lower() == ".sql" or DATA_MARKERS.search(text):
        _component(components, "data-store", relative, 1, "reachable-entrypoint", "data persistence implementation marker")


def _scan_ci(text: str, path: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    lower = text.lower()
    workflow = "/.github/workflows/" in ("/" + path.lower())
    if workflow:
        event = re.search(r"(?m)^\s*pull_request_target\s*:", text)
        untrusted_ref = re.search(
            r"github\.event\.pull_request\.head|github\.head_ref|pull_request\.head\.repo", text)
        executable = re.search(r"(?m)^\s*-?\s*(?:run|uses)\s*:", text)
        secrets = re.search(r"\$\{\{\s*secrets\.", text)
        if event and untrusted_ref and executable:
            severity = "CRITICAL" if secrets else "HIGH"
            rows.append(_finding(
                path, _line_for(text, event.start()), "secctx-pr-target-untrusted-execution",
                severity, "ci-cd/supply-chain", "CWE-829",
                "pull_request_target combines privileged context with untrusted pull-request content",
                "Do not execute pull-request code in pull_request_target; split validation from a separately approved privileged workflow.",
                0.98, ssdf=("PO.5.1", "PS.1.1")))
        write_all = re.search(r"(?mi)^\s*permissions\s*:\s*write-all\s*$", text)
        if write_all:
            rows.append(_finding(
                path, _line_for(text, write_all.start()), "secctx-actions-write-all",
                "HIGH", "ci-cd/permissions", "CWE-250",
                "GitHub Actions grants write-all permissions to the workflow token",
                "Set read-only defaults and grant narrowly scoped write permissions only to the job that requires them.",
                0.99, ssdf=("PO.5.1", "PS.1.1")))
        persist = re.search(r"(?mi)^\s*persist-credentials\s*:\s*true\s*$", text)
        if persist:
            rows.append(_finding(
                path, _line_for(text, persist.start()), "secctx-actions-persist-credentials",
                "MEDIUM", "ci-cd/credential-boundary", "CWE-522",
                "checkout explicitly leaves workflow credentials available to later steps",
                "Set persist-credentials to false and pass a least-privilege token only to the step that needs it.",
                0.97, ssdf=("PO.5.1", "PS.1.1")))
        if re.search(r"(?m)^\s*pull_request\s*:", text) and "self-hosted" in lower and re.search(r"(?m)^\s*run\s*:", text):
            match = re.search(r"self-hosted", text, re.I)
            rows.append(_finding(
                path, _line_for(text, match.start()) if match else 1,
                "secctx-untrusted-pr-self-hosted-runner", "HIGH", "ci-cd/runner-boundary", "CWE-250",
                "pull-request code can execute on a self-hosted runner",
                "Use an isolated ephemeral runner with no persistent credentials or network trust for untrusted contributions.",
                0.94, ssdf=("PO.5.1",)))
    if path.lower().endswith(".gitlab-ci.yml") and "docker:dind" in lower and re.search(r"(?mi)^\s*privileged\s*:\s*true", text):
        match = re.search(r"(?mi)^\s*privileged\s*:\s*true", text)
        rows.append(_finding(
            path, _line_for(text, match.start()), "secctx-gitlab-privileged-dind", "HIGH",
            "ci-cd/runner-boundary", "CWE-250",
            "CI combines Docker-in-Docker with privileged runner execution",
            "Use rootless isolated builders or a dedicated remote build service without privileged runner access.",
            0.96, ssdf=("PO.5.1",)))
    return rows


def _scan_container(text: str, path: str, name: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    lower_name = name.lower()
    if lower_name.startswith(("dockerfile", "containerfile")):
        for match in re.finditer(r"(?mi)^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)", text):
            image = match.group("image")
            if image.lower() == "scratch" or "@sha256:" in image or "$" in image:
                continue
            if ":" not in image or image.rsplit(":", 1)[-1].lower() == "latest":
                rows.append(_finding(
                    path, _line_for(text, match.start()), "secctx-container-mutable-base",
                    "MEDIUM", "container/supply-chain", "CWE-829",
                    "container base image is selected by a mutable reference",
                    "Pin the reviewed base image by digest and use automated, reviewed digest updates.",
                    0.93, ssdf=("PW.4.1", "PW.4.4")))
        for match in re.finditer(r"(?mi)^\s*ADD\s+https?://", text):
            rows.append(_finding(
                path, _line_for(text, match.start()), "secctx-container-remote-add", "HIGH",
                "container/supply-chain", "CWE-494", "container build downloads an unverified remote artifact with ADD",
                "Download a pinned artifact in a controlled step, verify its signature or digest, then copy it into the image.",
                0.97, ssdf=("PW.4.1", "PW.4.4")))
        for match in re.finditer(r"(?mi)^\s*USER\s+(?:root|0)(?:\s|$)", text):
            rows.append(_finding(
                path, _line_for(text, match.start()), "secctx-container-explicit-root", "MEDIUM",
                "container/least-privilege", "CWE-250", "container runtime user is explicitly root",
                "Create a dedicated non-root account and switch to it before the final entrypoint.",
                0.97, ssdf=("PW.9.1",)))
    normalized = path.lower()
    if lower_name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"} or "k8s" in normalized or "kubernetes" in normalized:
        checks = (
            (r"(?mi)^\s*privileged\s*:\s*true\s*$", "secctx-container-privileged", "HIGH", "CWE-250",
             "workload explicitly enables privileged container execution",
             "Remove privileged mode and grant only the specific Linux capabilities the workload requires."),
            (r"(?mi)^\s*(?:hostNetwork|hostPID)\s*:\s*true\s*$", "secctx-k8s-host-namespace", "HIGH", "CWE-250",
             "Kubernetes workload joins a host namespace",
             "Use isolated pod namespaces unless a documented, tightly controlled system workload requires host access."),
            (r"(?mi)^\s*allowPrivilegeEscalation\s*:\s*true\s*$", "secctx-k8s-privilege-escalation", "MEDIUM", "CWE-250",
             "Kubernetes workload explicitly allows privilege escalation",
             "Set allowPrivilegeEscalation to false and apply a restricted security context."),
            (r"(?mi)^\s*-?\s*/var/run/docker\.sock\s*:", "secctx-container-docker-socket", "CRITICAL", "CWE-250",
             "container mounts the host Docker control socket",
             "Remove the Docker socket mount; use a narrowly scoped build or orchestration API instead."),
        )
        for pattern, rule, severity, cwe, message, fix in checks:
            for match in re.finditer(pattern, text):
                rows.append(_finding(path, _line_for(text, match.start()), rule, severity,
                                     "container/isolation", cwe, message, fix, 0.97,
                                     ssdf=("PW.9.1",)))
    return rows


def _scan_iac_cloud(text: str, path: str, suffix: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if suffix in {".tf", ".tfvars", ".hcl"}:
        lines = text.splitlines()
        for index, raw in enumerate(lines):
            if "0.0.0.0/0" not in raw and "::/0" not in raw:
                continue
            window = "\n".join(lines[max(0, index - 12):index + 13])
            if re.search(r"(?i)\b(?:from_port|to_port|port)\s*=\s*(?:22|23|2375|2376|3389|5432|3306|6379|6443|9200)\b", window):
                rows.append(_finding(
                    path, index + 1, "secctx-tf-public-admin-service", "CRITICAL",
                    "cloud/network-exposure", "CWE-284",
                    "infrastructure exposes an administrative or data-service port to the public internet",
                    "Restrict ingress to explicit trusted networks or private connectivity and require strong service authentication.",
                    0.98, ssdf=("PW.9.1",)))
        patterns = (
            (r"(?i)\bacl\s*=\s*[\"']public-(?:read|read-write)[\"']", "secctx-cloud-public-storage", "HIGH", "CWE-732",
             "cloud object storage is configured with a public ACL",
             "Enable public-access blocking and grant access through narrowly scoped identities."),
            (r"(?i)\b(?:allow_blob_public_access|public_network_access_enabled)\s*=\s*true", "secctx-cloud-public-data-access", "HIGH", "CWE-732",
             "cloud data service explicitly enables public access",
             "Disable public access and use private endpoints plus least-privilege identities."),
            (r"(?i)\bmembers\s*=\s*\[[^\]]*[\"'](?:allUsers|allAuthenticatedUsers)[\"']", "secctx-gcp-public-iam", "HIGH", "CWE-732",
             "cloud IAM binding grants access to a public principal",
             "Replace the public principal with explicit workload or user identities."),
        )
        for pattern, rule, severity, cwe, message, fix in patterns:
            for match in re.finditer(pattern, text):
                rows.append(_finding(path, _line_for(text, match.start()), rule, severity,
                                     "cloud/access-control", cwe, message, fix, 0.96,
                                     ssdf=("PW.9.1",)))
    if path.lower().endswith((".json", ".yaml", ".yml", ".tf")):
        paired_offsets: list[int] = []
        if path.lower().endswith(".json"):
            try:
                document = json.loads(text)
            except (json.JSONDecodeError, TypeError):
                document = None

            def wildcard(value: Any) -> bool:
                return value == "*" or isinstance(value, list) and "*" in value

            def walk(value: Any) -> None:
                if isinstance(value, dict):
                    effect = str(value.get("Effect", "Allow")).lower()
                    if effect == "allow" and wildcard(value.get("Action")) and wildcard(value.get("Resource")):
                        paired_offsets.append(0)
                    for child in value.values():
                        walk(child)
                elif isinstance(value, list):
                    for child in value:
                        walk(child)

            if document is not None:
                walk(document)
        else:
            key = r"[\"']?%s[\"']?\s*[:=]\s*[\"']\*[\"']"
            pattern = r"(?is)(?:%s.{0,600}%s|%s.{0,600}%s)" % (
                key % "Action", key % "Resource", key % "Resource", key % "Action")
            paired_offsets = [match.start() for match in re.finditer(pattern, text)]
        for offset in paired_offsets:
            rows.append(_finding(
                path, _line_for(text, offset), "secctx-cloud-wildcard-iam", "HIGH",
                "cloud/identity-policy", "CWE-250", "cloud policy grants wildcard actions over wildcard resources",
                "Replace wildcard actions and resources with the smallest required operations and resource identifiers.",
                0.97, ssdf=("PW.9.1",)))
    return rows


def _scan_web_api(text: str, path: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    lower = text.lower()
    wildcard = re.search(r"(?i)(?:allow_origins|access-control-allow-origin|origin)\s*[:=]\s*(?:\[[^\]]*)?[\"']\*[\"']", text)
    credentials = re.search(r"(?i)(?:allow_credentials|access-control-allow-credentials|credentials)\s*[:=]\s*true", text)
    if wildcard and credentials and abs(wildcard.start() - credentials.start()) < 1000:
        rows.append(_finding(
            path, _line_for(text, min(wildcard.start(), credentials.start())), "secctx-cors-wildcard-credentials",
            "HIGH", "web/cors", "CWE-942", "CORS combines credentialed requests with an unrestricted origin",
            "Use an exact allowlist of trusted origins and reject credentials for all other origins.",
            0.98, asvs=("v5.0.0-3.4.2",), ssdf=("PW.7.2",)))
    if Path(path).suffix.lower() in {".py", ".pyw"}:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            tree = None
        if tree is not None:
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = node.func.attr if isinstance(node.func, ast.Attribute) else (
                    node.func.id if isinstance(node.func, ast.Name) else "")
                if name == "set_cookie":
                    disabled = [keyword.arg for keyword in node.keywords
                                if keyword.arg in {"secure", "httponly"}
                                and isinstance(keyword.value, ast.Constant)
                                and keyword.value.value is False]
                    if not disabled:
                        continue
                    rows.append(_finding(
                        path, getattr(node, "lineno", 1), "secctx-insecure-auth-cookie", "HIGH",
                        "web/session", "CWE-614", "cookie creation explicitly disables a session-cookie security attribute",
                        "Set Secure and HttpOnly for session cookies and choose a purpose-appropriate SameSite policy.",
                        0.99, asvs=("v5.0.0-3.3.1", "v5.0.0-3.3.4"), ssdf=("PW.7.2",)))
                elif name == "run":
                    keywords = {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg}
                    host = keywords.get("host")
                    debug = keywords.get("debug")
                    public_host = (isinstance(host, ast.Constant) and host.value in {"0.0.0.0", "::"})
                    debug_on = isinstance(debug, ast.Constant) and debug.value is True
                    if public_host and debug_on:
                        rows.append(_finding(
                            path, getattr(node, "lineno", 1), "secctx-public-debug-server", "CRITICAL",
                            "web/debug-exposure", "CWE-489", "development debugger is enabled on a publicly bound application server",
                            "Disable debug mode outside isolated local development and run behind a hardened production server.",
                            0.99, asvs=("v5.0.0-13.4.2",), ssdf=("PW.9.1",)))
    for match in re.finditer(r"(?i)\bssl_protocols\b[^;\n]*TLSv1(?:\.0|\.1)?(?!\.\d)(?=\s|;|$)", text):
        rows.append(_finding(
            path, _line_for(text, match.start()), "secctx-legacy-tls-protocol", "HIGH",
            "transport/cryptography", "CWE-326", "server configuration enables an obsolete TLS protocol version",
            "Permit TLS 1.2 and TLS 1.3 only, with current cipher configuration.",
            0.98, asvs=("v5.0.0-12.1.1",), ssdf=("PW.9.1",)))
    if ("openapi" in lower or "swagger" in lower or path.lower().endswith(("openapi.yaml", "openapi.yml", "swagger.yaml"))):
        for match in re.finditer(r"(?is)\btype\s*:\s*apiKey\b.{0,300}?\bin\s*:\s*query\b", text):
            rows.append(_finding(
                path, _line_for(text, match.start()), "secctx-api-key-in-query", "HIGH",
                "api/credential-transport", "CWE-598", "API contract sends an API credential in the URL query string",
                "Carry credentials in an Authorization header over TLS and prevent them from entering URL logs and history.",
                0.98, asvs=("v5.0.0-13.2.1",), ssdf=("PW.7.2",)))
    return rows


def _scan_mobile(text: str, path: str, name: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if name.lower() == "androidmanifest.xml":
        checks = (
            (r"android:debuggable\s*=\s*[\"']true[\"']", "secctx-android-debuggable", "HIGH", "CWE-489",
             "Android application manifest enables debugging",
             "Disable debuggable in release manifests and enforce the release setting in the build pipeline."),
            (r"android:usesCleartextTraffic\s*=\s*[\"']true[\"']", "secctx-android-cleartext", "HIGH", "CWE-319",
             "Android application explicitly permits cleartext network traffic",
             "Disable cleartext traffic and define a restrictive network security configuration."),
            (r"android:allowBackup\s*=\s*[\"']true[\"']", "secctx-android-unrestricted-backup", "MEDIUM", "CWE-200",
             "Android application explicitly permits platform backup",
             "Disable backup for sensitive applications or define precise data extraction rules."),
        )
        for pattern, rule, severity, cwe, message, fix in checks:
            for match in re.finditer(pattern, text, re.I):
                rows.append(_finding(path, _line_for(text, match.start()), rule, severity,
                                     "mobile/platform-security", cwe, message, fix, 0.98,
                                     ssdf=("PW.9.1",)))
        try:
            root = ET.fromstring(text)
            android = "{http://schemas.android.com/apk/res/android}"
            application = root.find("application")
            application_permission = (application.attrib.get(android + "permission", "")
                                      if application is not None else "")
            for tag in ("service", "provider", "receiver"):
                for node in root.findall(".//" + tag):
                    protected = application_permission or any(node.attrib.get(android + attribute, "")
                                                              for attribute in ("permission", "readPermission", "writePermission"))
                    if node.attrib.get(android + "exported", "").lower() == "true" and not protected:
                        rows.append(_finding(
                            path, 1, "secctx-android-exported-component", "HIGH",
                            "mobile/component-access", "CWE-926",
                            "Android %s is exported without an enforcing permission" % tag,
                            "Set exported=false or require a signature-level permission and validate every incoming request.",
                            0.97, ssdf=("PW.9.1",)))
        except ET.ParseError:
            pass
    if name.lower() == "info.plist":
        match = re.search(r"(?is)<key>NSAllowsArbitraryLoads</key>\s*<true\s*/>", text)
        if match:
            rows.append(_finding(
                path, _line_for(text, match.start()), "secctx-ios-arbitrary-network-loads", "HIGH",
                "mobile/transport-security", "CWE-319", "iOS App Transport Security allows arbitrary network loads",
                "Remove the global exception and add only narrowly scoped, documented domain exceptions if unavoidable.",
                0.99, ssdf=("PW.9.1",)))
    return rows


def _scan_crypto_auth(text: str, path: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    patterns = (
        (r"(?i)\b(?:bcrypt\.)?(?:gensalt|hashpw|hash)\s*\([^\n]{0,200}?\b(?:rounds|cost)\s*=\s*([4-9])\b",
         "secctx-weak-bcrypt-cost", "HIGH", "CWE-916", "password hashing uses a bcrypt cost below 10",
         "Raise the bcrypt cost to at least 10 and tune it upward for the deployment's latency budget.", ("v5.0.0-11.4.2",)),
        (r"(?i)\balgorithms?\s*[:=]\s*\[[^\]]*[\"']none[\"']",
         "secctx-jwt-none-algorithm", "CRITICAL", "CWE-347", "JWT verification accepts the unsigned none algorithm",
         "Allowlist one expected asymmetric signing algorithm and validate issuer, audience, type, and lifetime.", ("v5.0.0-9.2.2",)),
        (r"(?i)[\"']verify_signature[\"']\s*:\s*false",
         "secctx-jwt-signature-disabled", "CRITICAL", "CWE-347", "JWT signature verification is explicitly disabled",
         "Enable signature validation and strictly validate token issuer, audience, type, and lifetime.", ("v5.0.0-9.2.2",)),
        (r"(?i)\bredirect_uris?\s*[:=]\s*(?:\[[^\]]*)?[\"'](?:\*|https?://\*)[\"']",
         "secctx-oauth-wildcard-redirect", "HIGH", "CWE-601", "OAuth redirect configuration contains a wildcard destination",
         "Register exact client-specific redirect URIs and compare them using exact string matching.", ("v5.0.0-10.4.1",)),
    )
    for pattern, rule, severity, cwe, message, fix, asvs in patterns:
        for match in re.finditer(pattern, text):
            rows.append(_finding(path, _line_for(text, match.start()), rule, severity,
                                 "auth/cryptography", cwe, message, fix, 0.97,
                                 asvs=asvs, ssdf=("PW.7.2",)))
    if Path(path).suffix.lower() in {".py", ".pyw"}:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            tree = None
        if tree is not None:
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = ""
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                iterations = None
                for keyword in node.keywords:
                    if keyword.arg == "iterations" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, int):
                        iterations = keyword.value.value
                if name == "pbkdf2_hmac" and iterations is None and len(node.args) >= 4:
                    value = node.args[3]
                    if isinstance(value, ast.Constant) and isinstance(value.value, int):
                        iterations = value.value
                if name == "PBKDF2HMAC" and iterations is None:
                    continue
                if name not in {"pbkdf2_hmac", "PBKDF2HMAC"} or iterations is None or iterations >= 10_000:
                    continue
                rows.append(_finding(
                    path, getattr(node, "lineno", 1), "secctx-weak-pbkdf2-iterations", "HIGH",
                    "auth/cryptography", "CWE-916",
                    "password derivation uses fewer than 10,000 PBKDF2 iterations",
                    "Use current algorithm-specific guidance and calibrate a substantially stronger iteration count.",
                    0.99, asvs=("v5.0.0-11.4.2",), ssdf=("PW.7.2",)))
    return rows


def _parse_package_json(text: str, path: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return rows
    if not isinstance(data, dict):
        return rows
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        dependencies = data.get(section, {})
        if not isinstance(dependencies, dict):
            continue
        for _package, spec in dependencies.items():
            if not isinstance(spec, str):
                continue
            lower = spec.lower().strip()
            if lower.startswith("http://"):
                rows.append(_finding(
                    path, 1, "secctx-insecure-dependency-transport", "HIGH",
                    "supply-chain/dependency-source", "CWE-494",
                    "dependency artifact is fetched over unauthenticated cleartext transport",
                    "Use a trusted HTTPS registry and verify the resolved artifact's integrity.",
                    0.99, asvs=("v5.0.0-15.2.4",), ssdf=("PW.4.1", "PW.4.4")))
            if ("git+" in lower or lower.startswith(("github:", "gitlab:", "git://"))):
                revision = lower.rsplit("#", 1)[-1] if "#" in lower else ""
                if not re.fullmatch(r"[0-9a-f]{40,64}", revision):
                    rows.append(_finding(
                        path, 1, "secctx-mutable-vcs-dependency", "MEDIUM",
                        "supply-chain/dependency-source", "CWE-829",
                        "VCS dependency is not pinned to an immutable commit identifier",
                        "Pin the reviewed VCS dependency to a full commit hash and retain lockfile integrity metadata.",
                        0.96, asvs=("v5.0.0-15.2.4",), ssdf=("PW.4.1", "PW.4.4")))
    scripts = data.get("scripts", {})
    if isinstance(scripts, dict):
        for hook in ("preinstall", "install", "postinstall"):
            command = scripts.get(hook)
            if isinstance(command, str) and re.search(r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b", command):
                rows.append(_finding(
                    path, 1, "secctx-install-hook-remote-shell", "CRITICAL",
                    "supply-chain/install-hook", "CWE-494",
                    "package install hook downloads content directly into a shell",
                    "Remove the remote installer; vendor or pin the artifact and verify its signature or digest before controlled execution.",
                    0.99, asvs=("v5.0.0-15.2.4",), ssdf=("PW.4.1", "PW.4.4")))
    return rows


def _scan_dependency_file(text: str, path: str, name: str) -> list[dict[str, Any]]:
    rows = _parse_package_json(text, path) if name.lower() == "package.json" else []
    if name.lower() in {"package-lock.json", "npm-shrinkwrap.json"}:
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            data = {}
        packages = data.get("packages", {}) if isinstance(data, dict) else {}
        if isinstance(packages, dict):
            for info in packages.values():
                if isinstance(info, dict) and str(info.get("resolved", "")).lower().startswith("http://"):
                    rows.append(_finding(
                        path, 1, "secctx-lockfile-cleartext-artifact", "HIGH",
                        "supply-chain/lockfile", "CWE-494",
                        "lockfile resolves a package artifact over cleartext HTTP",
                        "Regenerate the lockfile from a trusted HTTPS registry and verify package integrity.",
                        0.99, asvs=("v5.0.0-15.2.4",), ssdf=("PW.4.1", "PW.4.4")))
                    break
    if name.lower() == ".gitmodules":
        for match in re.finditer(r"(?mi)^\s*url\s*=\s*(?:http://|git://)", text):
            rows.append(_finding(
                path, _line_for(text, match.start()), "secctx-submodule-insecure-transport", "HIGH",
                "supply-chain/source", "CWE-494", "Git submodule uses an unauthenticated transport",
                "Use HTTPS or SSH from a trusted host and pin/review the submodule commit.",
                0.98, ssdf=("PW.4.1", "PW.4.4")))
    if name.lower() == "cargo.toml":
        for match in re.finditer(r"(?mi)^\s*[^#\n=]+\s*=\s*\{[^}\n]*\bgit\s*=\s*[\"'][^\"']+[\"'][^}\n]*\}", text):
            declaration = match.group(0)
            if not re.search(r"\brev\s*=\s*[\"'][0-9a-fA-F]{40,64}[\"']", declaration):
                rows.append(_finding(
                    path, _line_for(text, match.start()), "secctx-cargo-mutable-git-dependency", "MEDIUM",
                    "supply-chain/dependency-source", "CWE-829", "Cargo git dependency lacks an immutable revision",
                    "Set rev to a reviewed full commit identifier and commit Cargo.lock for deployable applications.",
                    0.96, asvs=("v5.0.0-15.2.4",), ssdf=("PW.4.1", "PW.4.4")))
    return rows


def _lock_coverage(paths: list[Path], root: Path) -> dict[str, Any]:
    by_directory: dict[Path, set[str]] = {}
    for path in paths:
        by_directory.setdefault(path.parent, set()).add(path.name.lower())
    rows = []
    for directory, names in sorted(by_directory.items(), key=lambda item: str(item[0]).lower()):
        for manifest, expected in LOCK_EXPECTATIONS.items():
            if manifest not in names:
                continue
            present = sorted(set(expected) & names)
            rows.append({
                "manifest": _relative(root, directory / manifest),
                "status": "present" if present else "missing",
                "lockfiles": [_relative(root, directory / item) for item in present],
                "expected_any_of": list(expected),
            })
    return {
        "manifests_with_lock_expectation": len(rows),
        "with_lockfile": sum(row["status"] == "present" for row in rows),
        "without_lockfile": sum(row["status"] == "missing" for row in rows),
        "coverage": rows[:500],
    }


def _reachability(path: str, route_files: set[str], repo_report: dict[str, Any]) -> tuple[str, str, float]:
    lower = "/" + path.lower()
    name = Path(path).name.lower()
    if path in route_files:
        return "internet-facing", "file declares a web/API route", 0.94
    if "/.github/workflows/" in lower or path.lower().endswith(("jenkinsfile", ".gitlab-ci.yml", "azure-pipelines.yml")):
        return "build-time", "file executes in an automation boundary", 0.96
    if Path(path).suffix.lower() in {".tf", ".tfvars", ".hcl"} or "docker" in Path(path).name.lower():
        return "deployment-time", "file controls deployment/runtime isolation", 0.90
    if Path(path).name.lower() in {"androidmanifest.xml", "info.plist"}:
        return "client-facing", "file controls a distributed client application", 0.94
    if name.startswith(".env") or name in {".npmrc", ".pypirc", "application.properties", "appsettings.json"}:
        return "deployment-time", "configuration is consumed at build or runtime", 0.90
    if name in MANIFESTS | LOCKFILES:
        return "build-time", "file participates in dependency resolution", 0.92
    reachable_paths = {
        str(meta.get("path", "")).replace("\\", "/")
        for name, meta in repo_report.get("definitions", {}).items()
        if name in set(repo_report.get("reachable", []))
    }
    if any(candidate.endswith("/" + path) or candidate == path for candidate in reachable_paths):
        return "reachable-entrypoint", "repository call graph reaches a definition in this file", 0.84
    return "unknown", "no reliable static entrypoint relationship was established", 0.55


def _enrich_risk(row: dict[str, Any], route_files: set[str],
                 repo_report: dict[str, Any]) -> dict[str, Any]:
    state, basis, confidence = _reachability(row["path"], route_files, repo_report)
    score = (SEVERITY_VALUE.get(row["severity"], 4.0)
             * float(row.get("confidence", 0.75))
             * REACHABILITY_FACTOR.get(state, 0.76)
             * security_taxonomy.cwe_priority_factor(str(row.get("cwe") or "")))
    score = round(max(0.1, min(10.0, score)), 1)
    row["reachability"] = {"state": state, "basis": basis, "confidence": confidence}
    row["exploitability"] = {"score": score, "level": (
        "critical" if score >= 9 else "high" if score >= 7 else
        "moderate" if score >= 4 else "low")}
    row["risk_score"] = score
    row.setdefault("evidence", []).append({
        "kind": "reachability-context", "path": row["path"], "line": row["line"],
        "description": basis,
    })
    return row


def enrich_findings(findings: Iterable[dict[str, Any]], context: dict[str, Any],
                    repo_report: dict[str, Any]) -> list[dict[str, Any]]:
    """Attach uniform taxonomy, evidence, reachability, and risk metadata."""
    components = context.get("attack_surface", {}).get("components", [])
    route_files = {row["path"] for row in components
                   if row.get("kind") == "web-or-api-route"}
    rows = []
    for original in findings:
        row = security_taxonomy.enrich_taxonomy(dict(original))
        row.setdefault("precision", "high" if row.get("confidence", 0) >= 0.85 else "medium")
        row.setdefault("evidence", [{
            "kind": "static-detector", "path": row.get("path", ""),
            "line": max(1, int(row.get("line", 1))),
            "description": row.get("message", "static security evidence"),
        }])
        if not isinstance(row.get("reachability"), dict) or "risk_score" not in row:
            row = _enrich_risk(row, route_files, repo_report)
        rows.append(row)
    return rows


def _trust_boundaries(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    kinds = {row["kind"] for row in components}
    specifications = (
        ("TB-HTTP", "Untrusted network to application", "external requester", "web/API handlers",
         {"web-or-api-route", "api-contract"}, ["Spoofing", "Tampering", "Information Disclosure"]),
        ("TB-IDENTITY", "Identity provider to authorization decisions", "identity/token issuer", "protected operations",
         {"identity-control"}, ["Spoofing", "Elevation of Privilege"]),
        ("TB-DATA", "Application to persistent data", "application process", "data store",
         {"data-store"}, ["Tampering", "Information Disclosure"]),
        ("TB-SUPPLY", "Third-party code to build", "package/action publisher", "build and release pipeline",
         {"dependency-manifest", "ci-cd-workflow"}, ["Tampering", "Elevation of Privilege"]),
        ("TB-DEPLOY", "Build artifact to runtime control plane", "build/deployment identity", "container or cloud runtime",
         {"container", "infrastructure-as-code"}, ["Tampering", "Elevation of Privilege", "Denial of Service"]),
        ("TB-MOBILE", "Untrusted device/application boundary", "other apps and networks", "mobile application data/components",
         {"mobile-application"}, ["Spoofing", "Information Disclosure", "Elevation of Privilege"]),
    )
    rows = []
    for identifier, name, source, destination, required, stride in specifications:
        evidence = [row for row in components if row["kind"] in required][:12]
        if not evidence:
            continue
        rows.append({"id": identifier, "name": name, "source": source,
                     "destination": destination, "stride": stride,
                     "evidence": [{"path": row["path"], "line": row["line"],
                                   "kind": row["kind"]} for row in evidence]})
    return rows


def _attack_paths(findings: list[dict[str, Any]], components: list[dict[str, Any]],
                  repo_report: dict[str, Any]) -> list[dict[str, Any]]:
    paths: list[dict[str, Any]] = []
    route_by_file = {row["path"] for row in components if row["kind"] == "web-or-api-route"}
    for flow in repo_report.get("unsafe_flows", [])[:MAX_ATTACK_PATHS]:
        path = str(flow.get("path", "")).replace("\\", "/")
        paths.append({
            "id": "AP-%04d" % (len(paths) + 1), "stride": ["Tampering", "Elevation of Privilege"],
            "risk_score": round(8.8 * float(flow.get("confidence", 0.8)), 1),
            "nodes": ["untrusted request", "web/API route" if any(path.endswith(item) for item in route_by_file) else "application entrypoint",
                      "request-derived data", "dangerous sink: " + str(flow.get("sink", "unknown"))],
            "rule": "repo-confirmed-unsafe-flow",
            "evidence": [{"path": path, "line": int(flow.get("line", 1)),
                          "description": str(flow.get("message", "source-to-sink flow"))}],
        })
    path_templates = {
        "secrets": ["source repository", "build/runtime consumer", "credential-protected service"],
        "ci": ["untrusted contribution or third party", "CI runner", "release artifact or repository token"],
        "supply": ["third-party package/action", "dependency resolver or build", "distributed artifact"],
        "cloud": ["untrusted network or identity", "cloud control plane", "deployed resource or data"],
        "container": ["container process", "runtime isolation boundary", "host or neighboring workload"],
        "mobile": ["untrusted app/network", "mobile platform component", "application/user data"],
        "auth": ["unauthenticated actor", "identity/session boundary", "protected operation"],
        "web": ["untrusted browser/request", "web/API boundary", "session or application data"],
    }
    for row in sorted(findings, key=lambda item: -item.get("risk_score", 0)):
        if len(paths) >= MAX_ATTACK_PATHS:
            break
        category = row["category"].lower()
        key = next((name for name in path_templates if name in category), None)
        if not key or row.get("risk_score", 0) < 5.0:
            continue
        paths.append({
            "id": "AP-%04d" % (len(paths) + 1), "stride": list(row.get("stride", [])),
            "risk_score": row["risk_score"], "nodes": path_templates[key],
            "rule": row["rule"], "evidence": list(row.get("evidence", []))[:4],
        })
    return paths


def analyze(root: str | Path, *, repo_report: dict[str, Any] | None = None) -> dict[str, Any]:
    """Analyze repository security context without network or target execution."""
    base = Path(root).expanduser().resolve()
    if not base.is_dir():
        return {"schema": SCHEMA, "status": "failed", "root": str(base),
                "findings": [], "errors": ["workspace is not a readable directory"]}
    repository = repo_report or {}
    paths, coverage = _discover(base)
    findings: list[dict[str, Any]] = []
    components: list[dict[str, Any]] = []
    route_files: set[str] = set()
    errors: list[str] = []
    read_files = 0
    replacement_files = 0
    action_refs = {"immutable": 0, "mutable": 0}

    for path in paths:
        relative = _relative(base, path)
        text, status = _read_text(path)
        if text is None:
            coverage["skipped_count"] += 1
            if len(coverage["skipped"]) < 200:
                coverage["skipped"].append({"path": relative, "reason": status})
            continue
        read_files += 1
        replacement_files += status == "decoded-with-replacement"
        _surface_file(path, relative, text, components, route_files)
        additions: list[dict[str, Any]] = []
        additions.extend(secret_guard.scan_text(text, relative,
                                                max_findings=min(500, MAX_FINDINGS - len(findings))))
        additions.extend(_scan_ci(text, relative))
        additions.extend(_scan_container(text, relative, path.name))
        additions.extend(_scan_iac_cloud(text, relative, path.suffix.lower()))
        additions.extend(_scan_web_api(text, relative))
        additions.extend(_scan_mobile(text, relative, path.name))
        additions.extend(_scan_crypto_auth(text, relative))
        additions.extend(_scan_dependency_file(text, relative, path.name))
        if "/.github/workflows/" in ("/" + relative.lower()):
            for match in re.finditer(r"(?mi)^\s*-?\s*uses\s*:\s*[^\s#]+@([^\s#]+)", text):
                if re.fullmatch(r"[0-9a-fA-F]{40}", match.group(1)):
                    action_refs["immutable"] += 1
                else:
                    action_refs["mutable"] += 1
        for row in additions:
            if len(findings) >= MAX_FINDINGS:
                coverage["findings_truncated"] = True
                break
            findings.append(security_taxonomy.enrich_taxonomy(row))

    # Stable IDs make attack-surface evidence addressable without exposing code.
    components.sort(key=lambda row: (row["kind"], row["path"], row["line"]))
    for index, component in enumerate(components, start=1):
        component["id"] = "AS-%04d" % index
    enriched = [_enrich_risk(row, route_files, repository) for row in findings]
    chosen: dict[tuple[str, int, str], dict[str, Any]] = {}
    for row in enriched:
        key = (row["path"].lower(), row["line"], row["rule"])
        previous = chosen.get(key)
        if previous is None or row["confidence"] > previous["confidence"]:
            chosen[key] = row
    findings = sorted(chosen.values(), key=lambda row: (
        -row["risk_score"], row["path"].lower(), row["line"], row["rule"]))
    lock = _lock_coverage(paths, base)
    boundaries = _trust_boundaries(components)
    attack_paths = _attack_paths(findings, components, repository)
    kind_counts: dict[str, int] = {}
    for row in components:
        kind_counts[row["kind"]] = kind_counts.get(row["kind"], 0) + 1
    coverage.update({"files_read": read_files,
                     "decoded_with_replacement": replacement_files,
                     "findings_truncated": bool(coverage.get("findings_truncated", False))})
    return {
        "schema": SCHEMA, "status": "findings" if findings else "clean",
        "root": str(base), "findings": findings,
        "attack_surface": {"components": components,
                           "counts": dict(sorted(kind_counts.items())),
                           "total": len(components)},
        "trust_boundaries": boundaries, "attack_paths": attack_paths,
        "supply_chain": {**lock, "github_action_refs": action_refs,
                         "manifest_count": sum(path.name.lower() in MANIFESTS for path in paths),
                         "lockfile_count": sum(path.name.lower() in LOCKFILES for path in paths)},
        "coverage": coverage, "errors": errors,
        "assurance": {
            "offline_only": True, "target_execution": False, "network_probing": False,
            "package_resolution": False, "raw_secret_material_in_output": False,
            "threat_model_method": "STRIDE", "threat_model_control": "NIST SSDF 1.1 PW.1.1",
        },
    }
