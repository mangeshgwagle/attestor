#!/usr/bin/env python3
"""Dependency CVE scanner for Owen.

Parses dependency manifests (requirements.txt, package.json, pom.xml, etc.),
resolves version ranges, and checks against a built-in advisory database
of known CVEs. No network calls required — the advisory DB ships with Owen.

Usage:
    scanner = DepScanner()
    scanner.scan_project("/path/to/project")
    print(scanner.report())
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

VERSION = "4.2"


# =========================================================================== #
#  DATA TYPES                                                                  #
# =========================================================================== #

class Ecosystem(Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    JAVA = "java"
    RUBY = "ruby"
    GO = "go"
    RUST = "rust"
    DOTNET = "dotnet"
    PHP = "php"


class RiskLevel(Enum):
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()


RISK_CVSS = {
    RiskLevel.CRITICAL: (9.0, 10.0),
    RiskLevel.HIGH: (7.0, 8.9),
    RiskLevel.MEDIUM: (4.0, 6.9),
    RiskLevel.LOW: (0.1, 3.9),
    RiskLevel.INFO: (0.0, 0.0),
}


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: Ecosystem
    source_file: str = ""
    is_dev: bool = False

    @property
    def key(self) -> str:
        return "%s:%s" % (self.ecosystem.value, self.name.lower())


@dataclass
class Advisory:
    cve_id: str
    package: str
    ecosystem: Ecosystem
    affected_versions: str
    fixed_version: str
    severity: RiskLevel
    cvss: float
    title: str
    description: str = ""
    cwe: int = 0
    references: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return "%s:%s" % (self.ecosystem.value, self.package.lower())


@dataclass
class VulnMatch:
    dependency: Dependency
    advisory: Advisory
    is_fixable: bool = True

    @property
    def upgrade_action(self) -> str:
        if self.advisory.fixed_version:
            return "Upgrade %s to >= %s" % (
                self.dependency.name, self.advisory.fixed_version)
        return "No known fix — consider replacing %s" % self.dependency.name


# =========================================================================== #
#  VERSION COMPARISON                                                          #
# =========================================================================== #

def parse_version(v: str) -> tuple:
    parts = re.split(r"[.\-+]", v.strip().lstrip("vV=^~><!"))
    result = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            result.append(p)
    return tuple(result) if result else (0,)


def version_lt(a: str, b: str) -> bool:
    return parse_version(a) < parse_version(b)


def version_lte(a: str, b: str) -> bool:
    return parse_version(a) <= parse_version(b)


def version_gte(a: str, b: str) -> bool:
    return parse_version(a) >= parse_version(b)


def version_in_range(version: str, range_spec: str) -> bool:
    """Check if version falls within a range specification.

    Supports: "< 2.0", ">= 1.0, < 2.0", "1.0 - 2.0", "< 3.0.1", "*".
    """
    if not range_spec or range_spec.strip() == "*":
        return True

    range_spec = range_spec.strip()

    if " - " in range_spec:
        lo, hi = range_spec.split(" - ", 1)
        return version_gte(version, lo.strip()) and version_lte(version, hi.strip())

    parts = [p.strip() for p in range_spec.split(",")]
    for part in parts:
        m = re.match(r"^([<>=!]+)\s*(.+)$", part)
        if not m:
            continue
        op, val = m.group(1), m.group(2)
        if op == "<" and not version_lt(version, val):
            return False
        elif op == "<=" and not version_lte(version, val):
            return False
        elif op == ">=" and not version_gte(version, val):
            return False
        elif op == ">" and not (not version_lte(version, val)):
            return False
        elif op == "!=" and parse_version(version) == parse_version(val):
            return False
    return True


# =========================================================================== #
#  MANIFEST PARSERS                                                            #
# =========================================================================== #

def parse_requirements_txt(content: str, source: str) -> list[Dependency]:
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_\-.]+)\s*([=<>!~]+)\s*([^\s;#,]+)", line)
        if m:
            deps.append(Dependency(
                name=m.group(1), version=m.group(3),
                ecosystem=Ecosystem.PYTHON, source_file=source))
        else:
            m2 = re.match(r"^([A-Za-z0-9_\-.]+)\s*$", line)
            if m2:
                deps.append(Dependency(
                    name=m2.group(1), version="*",
                    ecosystem=Ecosystem.PYTHON, source_file=source))
    return deps


def parse_package_json(content: str, source: str) -> list[Dependency]:
    deps = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return deps

    for section, is_dev in [("dependencies", False), ("devDependencies", True)]:
        for name, ver in data.get(section, {}).items():
            clean = re.sub(r"^[\^~>=<! ]+", "", ver)
            deps.append(Dependency(
                name=name, version=clean,
                ecosystem=Ecosystem.JAVASCRIPT, source_file=source,
                is_dev=is_dev))
    return deps


def parse_gemfile(content: str, source: str) -> list[Dependency]:
    deps = []
    for line in content.splitlines():
        m = re.match(r"""^\s*gem\s+['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]""", line)
        if m:
            deps.append(Dependency(
                name=m.group(1),
                version=re.sub(r"^[~>=<! ]+", "", m.group(2)),
                ecosystem=Ecosystem.RUBY, source_file=source))
        else:
            m2 = re.match(r"""^\s*gem\s+['"]([^'"]+)['"]""", line)
            if m2:
                deps.append(Dependency(
                    name=m2.group(1), version="*",
                    ecosystem=Ecosystem.RUBY, source_file=source))
    return deps


def parse_go_mod(content: str, source: str) -> list[Dependency]:
    deps = []
    in_require = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if in_require or line.startswith("require "):
            parts = line.replace("require ", "").strip().split()
            if len(parts) >= 2:
                deps.append(Dependency(
                    name=parts[0],
                    version=parts[1].lstrip("v"),
                    ecosystem=Ecosystem.GO, source_file=source))
    return deps


def parse_cargo_toml(content: str, source: str) -> list[Dependency]:
    deps = []
    in_deps = False
    for line in content.splitlines():
        if re.match(r"^\[.*dependencies.*\]", line):
            in_deps = True
            continue
        if line.startswith("[") and in_deps:
            in_deps = False
            continue
        if in_deps:
            m = re.match(r'^([A-Za-z0-9_-]+)\s*=\s*"([^"]+)"', line)
            if m:
                deps.append(Dependency(
                    name=m.group(1),
                    version=re.sub(r"^[~^>=< ]+", "", m.group(2)),
                    ecosystem=Ecosystem.RUST, source_file=source))
    return deps


def parse_pom_xml(content: str, source: str) -> list[Dependency]:
    deps = []
    for m in re.finditer(
            r"<dependency>\s*"
            r"<groupId>([^<]+)</groupId>\s*"
            r"<artifactId>([^<]+)</artifactId>\s*"
            r"(?:<version>([^<]+)</version>)?",
            content, re.DOTALL):
        name = "%s:%s" % (m.group(1), m.group(2))
        ver = m.group(3) or "*"
        deps.append(Dependency(
            name=name, version=ver,
            ecosystem=Ecosystem.JAVA, source_file=source))
    return deps


def parse_csproj(content: str, source: str) -> list[Dependency]:
    deps = []
    for m in re.finditer(
            r'<PackageReference\s+Include="([^"]+)"\s+'
            r'Version="([^"]+)"', content):
        deps.append(Dependency(
            name=m.group(1), version=m.group(2),
            ecosystem=Ecosystem.DOTNET, source_file=source))
    return deps


def parse_composer_json(content: str, source: str) -> list[Dependency]:
    deps = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return deps

    for section in ("require", "require-dev"):
        for name, ver in data.get(section, {}).items():
            if name == "php" or name.startswith("ext-"):
                continue
            clean = re.sub(r"^[\^~>=<! |]+", "", ver.split("||")[0])
            deps.append(Dependency(
                name=name, version=clean,
                ecosystem=Ecosystem.PHP, source_file=source,
                is_dev=(section == "require-dev")))
    return deps


MANIFEST_PARSERS: dict[str, Any] = {
    "requirements.txt": parse_requirements_txt,
    "requirements-dev.txt": parse_requirements_txt,
    "requirements_dev.txt": parse_requirements_txt,
    "Pipfile": None,
    "package.json": parse_package_json,
    "Gemfile": parse_gemfile,
    "go.mod": parse_go_mod,
    "Cargo.toml": parse_cargo_toml,
    "pom.xml": parse_pom_xml,
    "composer.json": parse_composer_json,
}

CSPROJ_PATTERN = re.compile(r"\.csproj$")


# =========================================================================== #
#  ADVISORY DATABASE                                                           #
# =========================================================================== #

ADVISORY_DB: list[Advisory] = [
    Advisory("CVE-2021-44228", "log4j-core", Ecosystem.JAVA,
             "< 2.17.0", "2.17.0", RiskLevel.CRITICAL, 10.0,
             "Log4Shell RCE via JNDI lookup", cwe=502),
    Advisory("CVE-2021-45046", "log4j-core", Ecosystem.JAVA,
             "< 2.17.0", "2.17.0", RiskLevel.CRITICAL, 9.0,
             "Log4j2 incomplete fix for CVE-2021-44228", cwe=502),
    Advisory("CVE-2022-22965", "spring-beans", Ecosystem.JAVA,
             "< 5.3.18", "5.3.18", RiskLevel.CRITICAL, 9.8,
             "Spring4Shell RCE", cwe=94),
    Advisory("CVE-2017-5638", "struts2-core", Ecosystem.JAVA,
             "< 2.5.13", "2.5.13", RiskLevel.CRITICAL, 10.0,
             "Apache Struts2 RCE via Content-Type", cwe=78),
    Advisory("CVE-2023-44487", "h2", Ecosystem.JAVA,
             "< 2.0.24", "2.0.24", RiskLevel.HIGH, 7.5,
             "HTTP/2 Rapid Reset DoS", cwe=400),
    Advisory("CVE-2021-3749", "axios", Ecosystem.JAVASCRIPT,
             "< 0.21.2", "0.21.2", RiskLevel.HIGH, 7.5,
             "Axios ReDoS via trim()", cwe=400),
    Advisory("CVE-2022-0155", "follow-redirects", Ecosystem.JAVASCRIPT,
             "< 1.14.7", "1.14.7", RiskLevel.MEDIUM, 6.5,
             "Sensitive cookie exposure on redirect", cwe=601),
    Advisory("CVE-2021-23337", "lodash", Ecosystem.JAVASCRIPT,
             "< 4.17.21", "4.17.21", RiskLevel.HIGH, 7.2,
             "Prototype pollution in zipObjectDeep", cwe=1321),
    Advisory("CVE-2020-28469", "glob-parent", Ecosystem.JAVASCRIPT,
             "< 5.1.2", "5.1.2", RiskLevel.HIGH, 7.5,
             "Regular expression denial of service", cwe=400),
    Advisory("CVE-2022-24999", "qs", Ecosystem.JAVASCRIPT,
             "< 6.10.3", "6.10.3", RiskLevel.HIGH, 7.5,
             "Prototype poisoning via __proto__", cwe=1321),
    Advisory("CVE-2019-10744", "lodash", Ecosystem.JAVASCRIPT,
             "< 4.17.12", "4.17.12", RiskLevel.CRITICAL, 9.1,
             "Prototype pollution in defaultsDeep", cwe=1321),
    Advisory("CVE-2023-32681", "requests", Ecosystem.PYTHON,
             "< 2.31.0", "2.31.0", RiskLevel.MEDIUM, 6.1,
             "Leaking Proxy-Authorization header on redirect", cwe=200),
    Advisory("CVE-2022-42969", "py", Ecosystem.PYTHON,
             "< 1.11.0", "1.11.0", RiskLevel.HIGH, 7.5,
             "ReDoS in py.path.svnwc", cwe=400),
    Advisory("CVE-2021-32052", "django", Ecosystem.PYTHON,
             "< 3.2.4", "3.2.4", RiskLevel.MEDIUM, 6.1,
             "Header injection via URLValidator", cwe=113),
    Advisory("CVE-2023-37920", "certifi", Ecosystem.PYTHON,
             "< 2023.7.22", "2023.7.22", RiskLevel.HIGH, 7.5,
             "Removal of e-Tugra root certificate", cwe=295),
    Advisory("CVE-2019-8341", "jinja2", Ecosystem.PYTHON,
             "< 2.10.1", "2.10.1", RiskLevel.CRITICAL, 9.8,
             "Sandbox escape via str.format_map()", cwe=94),
    Advisory("CVE-2024-3651", "idna", Ecosystem.PYTHON,
             "< 3.7", "3.7", RiskLevel.MEDIUM, 6.5,
             "Denial of service via resource consumption", cwe=400),
    Advisory("CVE-2023-36053", "django", Ecosystem.PYTHON,
             "< 4.2.2", "4.2.2", RiskLevel.HIGH, 7.5,
             "ReDoS in EmailValidator and URLValidator", cwe=400),
    Advisory("CVE-2022-40674", "expat", Ecosystem.PYTHON,
             "< 2.4.9", "2.4.9", RiskLevel.CRITICAL, 9.8,
             "Use-after-free in XML parsing", cwe=416),
    Advisory("CVE-2023-25136", "openssh", Ecosystem.GO,
             "< 9.2", "9.2", RiskLevel.MEDIUM, 6.5,
             "Double free in pre-auth", cwe=415),
    Advisory("CVE-2022-41721", "golang.org/x/net", Ecosystem.GO,
             "< 0.4.0", "0.4.0", RiskLevel.HIGH, 7.5,
             "HTTP/2 request smuggling", cwe=444),
    Advisory("CVE-2021-25740", "k8s.io/api", Ecosystem.GO,
             "< 0.22.0", "0.22.0", RiskLevel.MEDIUM, 5.8,
             "Endpoint slicing TOCTOU", cwe=367),
    Advisory("CVE-2022-27191", "golang.org/x/crypto", Ecosystem.GO,
             "< 0.0.0-20220315160706", "0.0.0-20220315160706",
             RiskLevel.HIGH, 7.5,
             "Denial of service in SSH server", cwe=400),
    Advisory("CVE-2021-38561", "golang.org/x/text", Ecosystem.GO,
             "< 0.3.7", "0.3.7", RiskLevel.HIGH, 7.5,
             "Panic in language.Parse", cwe=400),
    Advisory("CVE-2022-32149", "golang.org/x/text", Ecosystem.GO,
             "< 0.3.8", "0.3.8", RiskLevel.HIGH, 7.5,
             "Denial of service in ParseAcceptLanguage", cwe=400),
    Advisory("CVE-2021-42574", "unicode-bidi", Ecosystem.RUST,
             "< 0.3.7", "0.3.7", RiskLevel.HIGH, 8.6,
             "Trojan Source: bidirectional override", cwe=451),
    Advisory("CVE-2022-21658", "remove_dir_all", Ecosystem.RUST,
             "< 0.8.0", "0.8.0", RiskLevel.MEDIUM, 6.3,
             "Race condition in directory removal", cwe=367),
    Advisory("CVE-2021-28831", "busybox", Ecosystem.RUST,
             "< 1.33.1", "1.33.1", RiskLevel.HIGH, 7.5,
             "Invalid free in decompress_gunzip", cwe=763),
    Advisory("CVE-2022-24439", "gitpython", Ecosystem.PYTHON,
             "< 3.1.30", "3.1.30", RiskLevel.CRITICAL, 9.8,
             "Remote code execution via clone", cwe=78),
    Advisory("CVE-2023-25577", "werkzeug", Ecosystem.PYTHON,
             "< 2.2.3", "2.2.3", RiskLevel.HIGH, 7.5,
             "Denial of service via multipart parser", cwe=400),
    Advisory("CVE-2022-42004", "jackson-databind", Ecosystem.JAVA,
             "< 2.13.4", "2.13.4", RiskLevel.HIGH, 7.5,
             "Deep nesting DoS in BeanDeserializer", cwe=400),
    Advisory("CVE-2021-0341", "okhttp", Ecosystem.JAVA,
             "< 4.9.1", "4.9.1", RiskLevel.MEDIUM, 5.9,
             "Certificate pinning bypass", cwe=295),
    Advisory("CVE-2021-36090", "commons-compress", Ecosystem.JAVA,
             "< 1.21", "1.21", RiskLevel.HIGH, 7.5,
             "Denial of service via zip bomb", cwe=400),
    Advisory("CVE-2021-37714", "jsoup", Ecosystem.JAVA,
             "< 1.14.2", "1.14.2", RiskLevel.HIGH, 7.5,
             "Denial of service in HTML parser", cwe=400),
    Advisory("CVE-2023-2976", "guava", Ecosystem.JAVA,
             "< 32.0.0", "32.0.0", RiskLevel.MEDIUM, 5.5,
             "Temp file creation with insecure permissions", cwe=276),
    Advisory("CVE-2022-31197", "postgresql", Ecosystem.JAVA,
             "< 42.4.1", "42.4.1", RiskLevel.HIGH, 7.1,
             "SQL injection in ResultSet.refreshRow()", cwe=89),
    Advisory("CVE-2023-46604", "activemq-client", Ecosystem.JAVA,
             "< 5.18.3", "5.18.3", RiskLevel.CRITICAL, 10.0,
             "Apache ActiveMQ RCE via ClassInfo", cwe=502),
    Advisory("CVE-2023-34035", "spring-security-config", Ecosystem.JAVA,
             "< 6.1.2", "6.1.2", RiskLevel.HIGH, 7.3,
             "Authorization bypass with requestMatchers", cwe=862),
    Advisory("CVE-2022-23307", "log4j", Ecosystem.JAVA,
             "< 2.17.1", "2.17.1", RiskLevel.CRITICAL, 8.8,
             "Deserialization of untrusted data in Chainsaw", cwe=502),
    Advisory("CVE-2023-2650", "pyopenssl", Ecosystem.PYTHON,
             "< 23.1.1", "23.1.1", RiskLevel.MEDIUM, 6.5,
             "Denial of service processing ASN.1 object IDs", cwe=400),
    Advisory("CVE-2023-43804", "urllib3", Ecosystem.PYTHON,
             "< 2.0.6", "2.0.6", RiskLevel.HIGH, 8.1,
             "Cookie leaking on cross-origin redirect", cwe=200),
    Advisory("CVE-2024-35195", "requests", Ecosystem.PYTHON,
             "< 2.32.0", "2.32.0", RiskLevel.MEDIUM, 5.6,
             "Cert verification disabled after redirect", cwe=295),
    Advisory("CVE-2023-44270", "postcss", Ecosystem.JAVASCRIPT,
             "< 8.4.31", "8.4.31", RiskLevel.MEDIUM, 5.3,
             "Line return parsing issue in external context", cwe=74),
    Advisory("CVE-2023-45133", "babel-traverse", Ecosystem.JAVASCRIPT,
             "< 7.23.2", "7.23.2", RiskLevel.CRITICAL, 9.8,
             "Arbitrary code execution via crafted AST", cwe=94),
    Advisory("CVE-2022-25883", "semver", Ecosystem.JAVASCRIPT,
             "< 7.5.2", "7.5.2", RiskLevel.HIGH, 7.5,
             "Regular expression denial of service", cwe=400),
    Advisory("CVE-2020-7788", "ini", Ecosystem.JAVASCRIPT,
             "< 1.3.6", "1.3.6", RiskLevel.HIGH, 7.3,
             "Prototype pollution via ini.parse()", cwe=1321),
    Advisory("CVE-2022-29078", "ejs", Ecosystem.JAVASCRIPT,
             "< 3.1.7", "3.1.7", RiskLevel.CRITICAL, 9.8,
             "Server-side template injection RCE", cwe=94),
    Advisory("CVE-2023-26159", "follow-redirects", Ecosystem.JAVASCRIPT,
             "< 1.15.4", "1.15.4", RiskLevel.MEDIUM, 6.1,
             "Improper input validation on URL", cwe=601),
]

_ADVISORY_INDEX: dict[str, list[Advisory]] = {}
for _adv in ADVISORY_DB:
    _ADVISORY_INDEX.setdefault(_adv.key, []).append(_adv)


# =========================================================================== #
#  SCANNER                                                                     #
# =========================================================================== #

class DepScanner:
    """Scans project dependencies for known CVEs."""

    def __init__(self):
        self._deps: list[Dependency] = []
        self._vulns: list[VulnMatch] = []
        self._files_scanned: list[str] = []

    def scan_file(self, path: str) -> list[Dependency]:
        basename = os.path.basename(path)
        parser = MANIFEST_PARSERS.get(basename)

        if parser is None and CSPROJ_PATTERN.search(basename):
            parser = parse_csproj

        if parser is None:
            return []

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except (OSError, IOError):
            return []

        deps = parser(content, path)
        self._deps.extend(deps)
        self._files_scanned.append(path)
        return deps

    def scan_content(self, content: str, filename: str) -> list[Dependency]:
        parser = MANIFEST_PARSERS.get(filename)
        if parser is None and CSPROJ_PATTERN.search(filename):
            parser = parse_csproj
        if parser is None:
            return []
        deps = parser(content, filename)
        self._deps.extend(deps)
        self._files_scanned.append(filename)
        return deps

    def scan_project(self, root: str) -> list[VulnMatch]:
        for dirpath, _dirnames, filenames in os.walk(root):
            if "node_modules" in dirpath or ".git" in dirpath:
                continue
            for fname in filenames:
                if fname in MANIFEST_PARSERS or CSPROJ_PATTERN.search(fname):
                    self.scan_file(os.path.join(dirpath, fname))

        self._check_advisories()
        return self._vulns

    def _check_advisories(self) -> None:
        self._vulns = []
        for dep in self._deps:
            keys = [dep.key]
            if ":" in dep.name:
                artifact = dep.name.rsplit(":", 1)[-1]
                keys.append("%s:%s" % (dep.ecosystem.value, artifact.lower()))
            seen_cves: set[str] = set()
            for key in keys:
                for adv in _ADVISORY_INDEX.get(key, []):
                    if adv.cve_id in seen_cves:
                        continue
                    if dep.version == "*" or version_in_range(dep.version, adv.affected_versions):
                        seen_cves.add(adv.cve_id)
                        self._vulns.append(VulnMatch(
                            dependency=dep, advisory=adv,
                            is_fixable=bool(adv.fixed_version)))

    def check(self) -> list[VulnMatch]:
        self._check_advisories()
        return self._vulns

    @property
    def dependencies(self) -> list[Dependency]:
        return list(self._deps)

    @property
    def vulnerabilities(self) -> list[VulnMatch]:
        return list(self._vulns)

    @property
    def files_scanned(self) -> list[str]:
        return list(self._files_scanned)

    def report(self) -> str:
        lines = [
            "=== Dependency CVE Scan ===",
            "Files scanned: %d" % len(self._files_scanned),
            "Dependencies found: %d" % len(self._deps),
            "Vulnerabilities found: %d" % len(self._vulns),
        ]

        if self._vulns:
            by_sev: dict[str, int] = {}
            for v in self._vulns:
                name = v.advisory.severity.name
                by_sev[name] = by_sev.get(name, 0) + 1
            lines.append("")
            lines.append("By severity:")
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if sev in by_sev:
                    lines.append("  %s: %d" % (sev, by_sev[sev]))

            lines.append("")
            lines.append("Details:")
            self._vulns.sort(key=lambda v: (-v.advisory.cvss, v.advisory.cve_id))
            for v in self._vulns:
                lines.append("  [%s] %s (CVSS %.1f)" % (
                    v.advisory.severity.name, v.advisory.cve_id, v.advisory.cvss))
                lines.append("    Package: %s@%s (%s)" % (
                    v.dependency.name, v.dependency.version,
                    v.dependency.ecosystem.value))
                lines.append("    Title: %s" % v.advisory.title)
                lines.append("    Fix: %s" % v.upgrade_action)
                lines.append("")

        return "\n".join(lines)

    def as_findings(self) -> list[dict[str, Any]]:
        results = []
        for v in self._vulns:
            results.append({
                "cve": v.advisory.cve_id,
                "cwe": v.advisory.cwe,
                "package": v.dependency.name,
                "version": v.dependency.version,
                "ecosystem": v.dependency.ecosystem.value,
                "severity": v.advisory.severity.name,
                "cvss": v.advisory.cvss,
                "title": v.advisory.title,
                "fixed_version": v.advisory.fixed_version,
                "source_file": v.dependency.source_file,
                "fixable": v.is_fixable,
            })
        return results


def scan(root: str) -> list[VulnMatch]:
    s = DepScanner()
    return s.scan_project(root)
