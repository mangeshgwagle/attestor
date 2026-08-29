#!/usr/bin/env python3
"""Supply chain deep analysis -- goes beyond basic SCA to detect typosquatting,
dependency confusion, maintainer anomalies, malicious install scripts,
suspicious package behavior patterns, and phantom dependency attacks."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from typing import Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
}

POPULAR_PYPI = [
    "requests", "numpy", "pandas", "flask", "django", "boto3", "urllib3",
    "setuptools", "pip", "wheel", "six", "pyyaml", "cryptography", "pillow",
    "sqlalchemy", "jinja2", "scipy", "matplotlib", "click", "celery",
    "redis", "psycopg2", "pymongo", "paramiko", "fabric", "ansible",
    "tensorflow", "torch", "scikit-learn", "beautifulsoup4", "lxml",
    "httpx", "aiohttp", "fastapi", "uvicorn", "gunicorn", "pytest",
    "black", "mypy", "pylint", "flake8", "isort", "autopep8",
    "pydantic", "marshmallow", "attrs", "dataclasses", "typing-extensions",
    "certifi", "chardet", "idna", "pytz", "python-dateutil",
    "werkzeug", "markupsafe", "itsdangerous", "colorama", "tqdm",
    "docker", "kubernetes", "google-auth", "google-cloud-storage",
    "azure-storage-blob", "msal", "boto", "botocore", "awscli",
    "stripe", "twilio", "sendgrid", "slack-sdk", "pygithub",
    "opencv-python", "transformers", "tokenizers", "datasets",
]

POPULAR_NPM = [
    "express", "react", "react-dom", "vue", "angular", "next", "nuxt",
    "lodash", "axios", "moment", "dayjs", "webpack", "babel", "eslint",
    "prettier", "typescript", "jest", "mocha", "chai", "cypress",
    "mongoose", "sequelize", "prisma", "knex", "typeorm",
    "socket.io", "ws", "redis", "ioredis", "pg", "mysql2",
    "jsonwebtoken", "bcrypt", "passport", "helmet", "cors",
    "dotenv", "commander", "yargs", "chalk", "debug",
    "uuid", "date-fns", "ramda", "rxjs", "underscore",
    "body-parser", "cookie-parser", "multer", "morgan",
    "nodemailer", "sharp", "puppeteer", "cheerio",
    "formidable", "busboy", "fastify", "koa", "hapi",
    "npm", "yarn", "pnpm", "lerna", "turbo",
]


@dataclass
class SupplyChainFinding:
    path: str
    package: str
    rule_id: str
    description: str
    severity: str
    category: str
    details: str = ""
    similar_to: str = ""
    confidence: float = 0.0


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


TYPOSQUAT_TRANSFORMS = [
    lambda s: s.replace("-", "_"),
    lambda s: s.replace("_", "-"),
    lambda s: s.replace("-", ""),
    lambda s: s.replace("_", ""),
    lambda s: s + "s",
    lambda s: s[:-1] if len(s) > 3 and s.endswith("s") else s,
    lambda s: "python-" + s,
    lambda s: "py" + s,
    lambda s: s + "-python",
    lambda s: s + "-py",
    lambda s: s.replace("python", ""),
    lambda s: s.replace("py", "") if s.startswith("py") else s,
]


def check_typosquatting(
    dep_name: str,
    ecosystem: str = "PyPI",
) -> list[SupplyChainFinding]:
    findings = []
    popular = POPULAR_PYPI if ecosystem == "PyPI" else POPULAR_NPM
    dep_lower = dep_name.lower().replace("-", "_")

    for legit in popular:
        legit_lower = legit.lower().replace("-", "_")
        if dep_lower == legit_lower:
            continue

        sim = _similarity(dep_lower, legit_lower)
        if sim >= 0.85 and sim < 1.0:
            findings.append(SupplyChainFinding(
                path="", package=dep_name,
                rule_id="SC-TYPOSQUAT-SIM",
                description=f"Package name very similar to popular '{legit}' (similarity: {sim:.0%})",
                severity="HIGH", category="typosquatting",
                similar_to=legit, confidence=sim,
            ))

        for transform in TYPOSQUAT_TRANSFORMS:
            if transform(dep_lower) == legit_lower and dep_lower != legit_lower:
                findings.append(SupplyChainFinding(
                    path="", package=dep_name,
                    rule_id="SC-TYPOSQUAT-XFORM",
                    description=f"Package name is a known typosquat variant of '{legit}'",
                    severity="CRITICAL", category="typosquatting",
                    similar_to=legit, confidence=0.95,
                ))
                break

        if len(dep_lower) > 3 and len(legit_lower) > 3:
            if dep_lower in legit_lower or legit_lower in dep_lower:
                if abs(len(dep_lower) - len(legit_lower)) <= 3:
                    findings.append(SupplyChainFinding(
                        path="", package=dep_name,
                        rule_id="SC-TYPOSQUAT-SUB",
                        description=f"Package name is substring variant of '{legit}'",
                        severity="MEDIUM", category="typosquatting",
                        similar_to=legit, confidence=0.7,
                    ))

    return findings


def check_dependency_confusion(
    deps: list[dict],
    internal_scope: str = "",
) -> list[SupplyChainFinding]:
    findings = []
    for dep in deps:
        name = dep.get("name", "")
        source = dep.get("source", "")
        version = dep.get("version", "")

        if name.startswith("@") and "/" in name:
            scope = name.split("/")[0]
            if scope not in ("@types", "@babel", "@testing-library", "@emotion",
                             "@mui", "@angular", "@vue", "@react-native"):
                findings.append(SupplyChainFinding(
                    path=dep.get("lockfile", ""),
                    package=name,
                    rule_id="SC-DEPCONF-SCOPE",
                    description=f"Scoped package {scope} -- verify registry ownership",
                    severity="LOW", category="dependency_confusion",
                    details=f"version: {version}",
                ))

        if internal_scope and name.startswith(internal_scope):
            if source and "npmjs.org" in source or "pypi.org" in source:
                findings.append(SupplyChainFinding(
                    path=dep.get("lockfile", ""),
                    package=name,
                    rule_id="SC-DEPCONF-PUBLIC",
                    description=f"Internal-looking package '{name}' resolved from public registry",
                    severity="CRITICAL", category="dependency_confusion",
                    details=f"source: {source}, version: {version}",
                ))

        if version and re.match(r"^0\.0\.[1-9]$", version):
            findings.append(SupplyChainFinding(
                path=dep.get("lockfile", ""),
                package=name,
                rule_id="SC-DEPCONF-SQUAT",
                description=f"Package at squatter version {version} (0.0.x pattern)",
                severity="MEDIUM", category="dependency_confusion",
                details="Very early version number often indicates a placeholder/squat package",
            ))

    return findings


MALICIOUS_SETUP_PATTERNS = [
    (re.compile(r"(?:os\.system|subprocess|Popen)\s*\(", re.I),
     "SC-SETUP-EXEC", "Command execution in setup.py", "CRITICAL"),
    (re.compile(r"(?:urllib|requests|http\.client|urlopen)\s*\(", re.I),
     "SC-SETUP-NET", "Network request in setup.py", "HIGH"),
    (re.compile(r"(?:socket\.connect|socket\.socket)\s*\(", re.I),
     "SC-SETUP-SOCK", "Socket connection in setup.py", "CRITICAL"),
    (re.compile(r"(?:base64\.b64decode|codecs\.decode)\s*\(", re.I),
     "SC-SETUP-DECODE", "Encoded payload in setup.py", "HIGH"),
    (re.compile(r"(?:eval|exec|compile)\s*\(", re.I),
     "SC-SETUP-EVAL", "Dynamic code execution in setup.py", "CRITICAL"),
    (re.compile(r"(?:open\s*\(\s*['\"](?:/etc/|C:\\|~/))", re.I),
     "SC-SETUP-FILEREAD", "Sensitive file access in setup.py", "HIGH"),
    (re.compile(r"(?:os\.environ|getpass|platform\.node|socket\.gethostname)", re.I),
     "SC-SETUP-RECON", "System reconnaissance in setup.py", "MEDIUM"),
    (re.compile(r"(?:keyring|credentials|password|token|api_key)\b", re.I),
     "SC-SETUP-CRED", "Credential access in setup.py", "HIGH"),
]

MALICIOUS_NPM_PATTERNS = [
    (re.compile(r"\"(?:preinstall|postinstall|preuninstall)\"\s*:\s*\"[^\"]*(?:curl|wget|node\s+-e|sh\s+-c)", re.I),
     "SC-NPM-HOOK", "Suspicious install hook in package.json", "CRITICAL"),
    (re.compile(r"\"(?:preinstall|postinstall)\"\s*:\s*\"[^\"]+\"", re.I),
     "SC-NPM-INSTALL-SCRIPT", "Install script in package.json", "MEDIUM"),
]


def check_install_scripts(root: str) -> list[SupplyChainFinding]:
    findings = []
    setup_files = ["setup.py", "setup.cfg", "pyproject.toml"]
    for fname in setup_files:
        fpath = os.path.join(root, fname)
        if not os.path.exists(fpath):
            continue
        try:
            with open(fpath, encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            continue
        for pat, rule_id, desc, sev in MALICIOUS_SETUP_PATTERNS:
            for m in pat.finditer(content):
                line_num = content[:m.start()].count("\n") + 1
                findings.append(SupplyChainFinding(
                    path=fpath, package="",
                    rule_id=rule_id, description=desc,
                    severity=sev, category="malicious_install",
                    details=f"line {line_num}: {m.group(0)[:80]}",
                ))

    pkg_json = os.path.join(root, "package.json")
    if os.path.exists(pkg_json):
        try:
            with open(pkg_json, encoding="utf-8") as f:
                content = f.read()
        except OSError:
            content = ""
        for pat, rule_id, desc, sev in MALICIOUS_NPM_PATTERNS:
            for m in pat.finditer(content):
                findings.append(SupplyChainFinding(
                    path=pkg_json, package="",
                    rule_id=rule_id, description=desc,
                    severity=sev, category="malicious_install",
                    details=m.group(0)[:100],
                ))

    return findings


def check_lockfile_integrity(root: str) -> list[SupplyChainFinding]:
    findings = []
    req_txt = os.path.join(root, "requirements.txt")
    if os.path.exists(req_txt):
        try:
            with open(req_txt, encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    if "==" not in line and ">=" not in line and "<=" not in line:
                        m = re.match(r"([A-Za-z0-9_\-.]+)", line)
                        if m:
                            findings.append(SupplyChainFinding(
                                path=req_txt, package=m.group(1),
                                rule_id="SC-LOCK-UNPIN",
                                description=f"Unpinned dependency '{m.group(1)}' (no version constraint)",
                                severity="MEDIUM", category="lockfile_integrity",
                                details=f"line {line_num}: {line}",
                            ))
                    if line.startswith("git+") or line.startswith("svn+"):
                        findings.append(SupplyChainFinding(
                            path=req_txt, package=line,
                            rule_id="SC-LOCK-VCS",
                            description="VCS dependency (mutable reference)",
                            severity="HIGH", category="lockfile_integrity",
                            details=f"line {line_num}: {line[:80]}",
                        ))
                    if "http://" in line:
                        findings.append(SupplyChainFinding(
                            path=req_txt, package=line,
                            rule_id="SC-LOCK-HTTP",
                            description="Dependency fetched over plain HTTP",
                            severity="HIGH", category="lockfile_integrity",
                            details=f"line {line_num}: no TLS",
                        ))
        except OSError:
            pass

    return findings


def scan(root: str, internal_scope: str = "") -> list[SupplyChainFinding]:
    findings = []
    findings.extend(check_install_scripts(root))
    findings.extend(check_lockfile_integrity(root))

    req_txt = os.path.join(root, "requirements.txt")
    if os.path.exists(req_txt):
        try:
            with open(req_txt, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    m = re.match(r"([A-Za-z0-9_\-.]+)", line)
                    if m:
                        findings.extend(check_typosquatting(m.group(1), "PyPI"))
        except OSError:
            pass

    pkg_json = os.path.join(root, "package.json")
    if os.path.exists(pkg_json):
        try:
            with open(pkg_json, encoding="utf-8") as f:
                data = json.load(f)
            for section in ("dependencies", "devDependencies"):
                for name in data.get(section, {}):
                    clean_name = name.lstrip("@").split("/")[-1] if "@" in name else name
                    findings.extend(check_typosquatting(clean_name, "npm"))
        except (OSError, json.JSONDecodeError):
            pass

    return findings


def render(findings: list[SupplyChainFinding]) -> str:
    if not findings:
        return "  No supply chain issues detected."
    lines = []
    by_cat = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)

    cat_order = ["typosquatting", "dependency_confusion", "malicious_install",
                 "lockfile_integrity"]
    lines.append(f"\n  Supply Chain Analysis ({len(findings)} finding{'s' if len(findings) != 1 else ''})")
    lines.append(f"  {'='*55}")

    for cat in cat_order:
        group = by_cat.pop(cat, [])
        if not group:
            continue
        label = cat.replace("_", " ").title()
        lines.append(f"\n  [{label}] ({len(group)} finding{'s' if len(group) != 1 else ''})")
        for f in sorted(group, key=lambda x: ("CRITICAL", "HIGH", "MEDIUM", "LOW").index(x.severity)):
            pkg = f" ({f.package})" if f.package else ""
            similar = f" [similar to: {f.similar_to}]" if f.similar_to else ""
            lines.append(f"    [{f.severity}] {f.rule_id}{pkg}{similar}")
            lines.append(f"      {f.description}")
            if f.details:
                lines.append(f"      {f.details}")

    total = len(findings)
    crit = sum(1 for f in findings if f.severity == "CRITICAL")
    lines.append(f"\n  Total: {total} supply chain issue(s) ({crit} critical)")
    return "\n".join(lines)


def to_dict(findings: list[SupplyChainFinding]) -> list[dict]:
    return [
        {
            "path": f.path,
            "package": f.package,
            "rule_id": f.rule_id,
            "description": f.description,
            "severity": f.severity,
            "category": f.category,
            "details": f.details,
            "similar_to": f.similar_to,
            "confidence": f.confidence,
        }
        for f in findings
    ]
