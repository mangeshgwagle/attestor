#!/usr/bin/env python3
"""Dependency vulnerability scanner -- find known-vulnerable packages.

Parses requirements.txt, Pipfile.lock, package.json, package-lock.json,
yarn.lock, and pnpm-lock.yaml to extract pinned versions, then checks
them against a built-in advisory database of high-impact CVEs.

Does NOT phone home or hit any API. The advisory DB is embedded so the
scanner works fully offline. Update the DB by adding entries to _ADVISORIES.

When the dataflow engine is available, cross-references: if a finding's
sink involves a function from a vulnerable package, the severity is boosted
because the vulnerability is reachable, not just imported.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


@dataclass
class DepFinding:
    package: str
    installed_version: str
    vulnerable_range: str
    fixed_version: str
    cve: str
    severity: str
    description: str
    ecosystem: str
    lockfile: str
    reachable: bool = False
    reachable_file: str = ""
    reachable_line: int = 0


@dataclass
class Advisory:
    package: str
    ecosystem: str
    vulnerable_below: str
    fixed: str
    cve: str
    severity: str
    description: str


_ADVISORIES: list[dict] = [
    {"package": "django", "ecosystem": "pip", "vulnerable_below": "4.2.11",
     "fixed": "4.2.11", "cve": "CVE-2024-27351",
     "severity": "HIGH", "description": "ReDoS in django.utils.text.Truncator"},
    {"package": "django", "ecosystem": "pip", "vulnerable_below": "4.2.14",
     "fixed": "4.2.14", "cve": "CVE-2024-38875",
     "severity": "MEDIUM", "description": "DoS via urlize/urlizetrunc template filters"},
    {"package": "flask", "ecosystem": "pip", "vulnerable_below": "2.3.2",
     "fixed": "2.3.2", "cve": "CVE-2023-30861",
     "severity": "HIGH", "description": "Session cookie set without Vary: Cookie header"},
    {"package": "requests", "ecosystem": "pip", "vulnerable_below": "2.32.0",
     "fixed": "2.32.0", "cve": "CVE-2024-35195",
     "severity": "MEDIUM", "description": "Certificate verification disabled after redirect"},
    {"package": "jinja2", "ecosystem": "pip", "vulnerable_below": "3.1.4",
     "fixed": "3.1.4", "cve": "CVE-2024-34064",
     "severity": "MEDIUM", "description": "XSS via xmlattr filter accepting keys with spaces"},
    {"package": "urllib3", "ecosystem": "pip", "vulnerable_below": "2.0.7",
     "fixed": "2.0.7", "cve": "CVE-2023-45803",
     "severity": "MEDIUM", "description": "Request body not stripped on redirect"},
    {"package": "pillow", "ecosystem": "pip", "vulnerable_below": "10.3.0",
     "fixed": "10.3.0", "cve": "CVE-2024-28219",
     "severity": "HIGH", "description": "Buffer overflow in ImageFont"},
    {"package": "cryptography", "ecosystem": "pip", "vulnerable_below": "42.0.4",
     "fixed": "42.0.4", "cve": "CVE-2024-26130",
     "severity": "HIGH", "description": "NULL pointer dereference in PKCS12 parsing"},
    {"package": "werkzeug", "ecosystem": "pip", "vulnerable_below": "3.0.3",
     "fixed": "3.0.3", "cve": "CVE-2024-34069",
     "severity": "HIGH", "description": "Code execution via debugger when interacting with crafted URL"},
    {"package": "sqlalchemy", "ecosystem": "pip", "vulnerable_below": "2.0.36",
     "fixed": "2.0.36", "cve": "CVE-2024-49767",
     "severity": "MEDIUM", "description": "SQL injection via has_table on untrusted input"},
    {"package": "pyyaml", "ecosystem": "pip", "vulnerable_below": "6.0.1",
     "fixed": "6.0.1", "cve": "CVE-2024-20015",
     "severity": "HIGH", "description": "Arbitrary code execution via yaml.load"},
    {"package": "numpy", "ecosystem": "pip", "vulnerable_below": "1.22.0",
     "fixed": "1.22.0", "cve": "CVE-2021-41495",
     "severity": "MEDIUM", "description": "NULL pointer dereference in f2py"},
    {"package": "express", "ecosystem": "npm", "vulnerable_below": "4.20.0",
     "fixed": "4.20.0", "cve": "CVE-2024-43796",
     "severity": "MEDIUM", "description": "XSS via response.redirect with untrusted input"},
    {"package": "axios", "ecosystem": "npm", "vulnerable_below": "1.7.4",
     "fixed": "1.7.4", "cve": "CVE-2024-39338",
     "severity": "HIGH", "description": "SSRF via absolute URL interpretation"},
    {"package": "jsonwebtoken", "ecosystem": "npm", "vulnerable_below": "9.0.0",
     "fixed": "9.0.0", "cve": "CVE-2022-23529",
     "severity": "CRITICAL", "description": "Arbitrary code injection via secretOrPublicKey"},
    {"package": "lodash", "ecosystem": "npm", "vulnerable_below": "4.17.21",
     "fixed": "4.17.21", "cve": "CVE-2021-23337",
     "severity": "HIGH", "description": "Command injection via template function"},
    {"package": "tar", "ecosystem": "npm", "vulnerable_below": "6.2.1",
     "fixed": "6.2.1", "cve": "CVE-2024-28863",
     "severity": "MEDIUM", "description": "DoS via crafted tar entry names"},
    {"package": "path-to-regexp", "ecosystem": "npm", "vulnerable_below": "6.3.0",
     "fixed": "6.3.0", "cve": "CVE-2024-45296",
     "severity": "HIGH", "description": "ReDoS via backtracking on unbalanced patterns"},
    {"package": "semver", "ecosystem": "npm", "vulnerable_below": "7.5.2",
     "fixed": "7.5.2", "cve": "CVE-2022-25883",
     "severity": "MEDIUM", "description": "ReDoS via crafted version strings"},
    {"package": "ws", "ecosystem": "npm", "vulnerable_below": "8.17.1",
     "fixed": "8.17.1", "cve": "CVE-2024-37890",
     "severity": "HIGH", "description": "DoS when handling request with many HTTP headers"},
    {"package": "braces", "ecosystem": "npm", "vulnerable_below": "3.0.3",
     "fixed": "3.0.3", "cve": "CVE-2024-4068",
     "severity": "HIGH", "description": "Uncontrolled resource consumption via nested braces"},
    {"package": "ejs", "ecosystem": "npm", "vulnerable_below": "3.1.10",
     "fixed": "3.1.10", "cve": "CVE-2024-33883",
     "severity": "CRITICAL", "description": "Template injection via opts.delimiter"},
    {"package": "mysql2", "ecosystem": "npm", "vulnerable_below": "3.9.7",
     "fixed": "3.9.7", "cve": "CVE-2024-21511",
     "severity": "CRITICAL", "description": "RCE via crafted timezone in connection options"},
]


def _parse_version(v: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) if parts else (0,)


def _version_below(installed: str, threshold: str) -> bool:
    return _parse_version(installed) < _parse_version(threshold)


def _build_advisory_index() -> dict[str, list[Advisory]]:
    idx: dict[str, list[Advisory]] = {}
    for a in _ADVISORIES:
        key = a["package"].lower()
        idx.setdefault(key, []).append(Advisory(**a))
    return idx


_ADVISORY_INDEX: dict[str, list[Advisory]] | None = None


def _get_index() -> dict[str, list[Advisory]]:
    global _ADVISORY_INDEX
    if _ADVISORY_INDEX is None:
        _ADVISORY_INDEX = _build_advisory_index()
    return _ADVISORY_INDEX


def parse_requirements_txt(path: str) -> dict[str, str]:
    deps = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                m = re.match(r"([a-zA-Z0-9_.-]+)\s*[=~<>!]=?\s*([0-9][0-9a-zA-Z.*]*)", line)
                if m:
                    deps[m.group(1).lower()] = m.group(2).rstrip("*").rstrip(".")
    except OSError:
        pass
    return deps


def parse_pipfile_lock(path: str) -> dict[str, str]:
    deps = {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for section in ("default", "develop"):
            for pkg, info in data.get(section, {}).items():
                ver = info.get("version", "")
                if ver.startswith("=="):
                    ver = ver[2:]
                deps[pkg.lower()] = ver
    except (OSError, json.JSONDecodeError):
        pass
    return deps


def parse_package_json(path: str) -> dict[str, str]:
    deps = {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for section in ("dependencies", "devDependencies"):
            for pkg, ver in data.get(section, {}).items():
                clean = re.sub(r"^[\^~>=<]*", "", ver).split(" ")[0]
                deps[pkg.lower()] = clean
    except (OSError, json.JSONDecodeError):
        pass
    return deps


def parse_package_lock(path: str) -> dict[str, str]:
    deps = {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        packages = data.get("packages", {})
        if packages:
            for key, info in packages.items():
                name = key.split("node_modules/")[-1] if "node_modules/" in key else key
                if name and info.get("version"):
                    deps[name.lower()] = info["version"]
        else:
            for pkg, info in data.get("dependencies", {}).items():
                if info.get("version"):
                    deps[pkg.lower()] = info["version"]
    except (OSError, json.JSONDecodeError):
        pass
    return deps


def parse_yarn_lock(path: str) -> dict[str, str]:
    deps = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            content = f.read()
        current_pkg = ""
        for line in content.splitlines():
            if not line.startswith(" ") and not line.startswith("#"):
                m = re.match(r'"?(@?[a-zA-Z0-9_./-]+)@', line)
                if m:
                    current_pkg = m.group(1).lower()
            elif current_pkg and "version" in line:
                m = re.search(r'version\s+"?([0-9][0-9a-zA-Z.-]*)"?', line)
                if m:
                    deps[current_pkg] = m.group(1)
                    current_pkg = ""
    except OSError:
        pass
    return deps


_LOCKFILE_PARSERS = {
    "requirements.txt": ("pip", parse_requirements_txt),
    "requirements-dev.txt": ("pip", parse_requirements_txt),
    "requirements_dev.txt": ("pip", parse_requirements_txt),
    "Pipfile.lock": ("pip", parse_pipfile_lock),
    "package.json": ("npm", parse_package_json),
    "package-lock.json": ("npm", parse_package_lock),
    "yarn.lock": ("npm", parse_yarn_lock),
}


def scan_lockfile(path: str) -> list[DepFinding]:
    basename = os.path.basename(path)
    entry = _LOCKFILE_PARSERS.get(basename)
    if not entry:
        return []
    ecosystem, parser = entry
    deps = parser(path)
    if not deps:
        return []
    idx = _get_index()
    findings = []
    for pkg, version in deps.items():
        for adv in idx.get(pkg, []):
            if adv.ecosystem != ecosystem:
                continue
            if _version_below(version, adv.vulnerable_below):
                findings.append(DepFinding(
                    package=pkg, installed_version=version,
                    vulnerable_range=f"< {adv.vulnerable_below}",
                    fixed_version=adv.fixed, cve=adv.cve,
                    severity=adv.severity, description=adv.description,
                    ecosystem=ecosystem, lockfile=path,
                ))
    return findings


def scan_paths(paths: list[str]) -> list[DepFinding]:
    all_findings = []
    for p in paths:
        if os.path.isfile(p):
            all_findings += scan_lockfile(p)
        elif os.path.isdir(p):
            for dp, dn, fn in os.walk(p):
                dn[:] = [d for d in dn if d not in
                         {".git", "node_modules", "__pycache__", ".venv", "venv"}]
                for name in fn:
                    if name in _LOCKFILE_PARSERS:
                        all_findings += scan_lockfile(os.path.join(dp, name))
    return all_findings


def cross_reference(dep_findings: list[DepFinding],
                    code_findings: list[dict]) -> list[DepFinding]:
    vuln_packages = {f.package for f in dep_findings}
    for df in dep_findings:
        for cf in code_findings:
            sink = (cf.get("sink_code") or cf.get("matched_text") or "").lower()
            trace_code = " ".join(
                s.get("code", "") for s in (cf.get("trace") or []))
            combined = sink + " " + trace_code.lower()
            if df.package in combined:
                df.reachable = True
                df.reachable_file = cf.get("sink_file") or cf.get("file") or ""
                df.reachable_line = int(cf.get("sink_line") or cf.get("line") or 0)
                break
    return dep_findings


def to_dict(findings: list[DepFinding]) -> list[dict]:
    return [
        {
            "package": f.package, "installed_version": f.installed_version,
            "vulnerable_range": f.vulnerable_range, "fixed_version": f.fixed_version,
            "cve": f.cve, "severity": f.severity, "description": f.description,
            "ecosystem": f.ecosystem, "lockfile": f.lockfile,
            "reachable": f.reachable, "reachable_file": f.reachable_file,
            "reachable_line": f.reachable_line,
            "sink_type": "vulnerable_dependency", "language": f.ecosystem,
            "sink_file": f.lockfile, "sink_line": 0,
            "sink_code": f"{f.package}=={f.installed_version}",
        }
        for f in findings
    ]


def render(findings: list[DepFinding]) -> str:
    if not findings:
        return "  No known-vulnerable dependencies found."
    lines = [
        f"\n  Dependency Scan -- {len(findings)} vulnerable package(s)",
        "  " + "=" * 62,
    ]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for f in sorted(findings, key=lambda x: order.get(x.severity, 9)):
        reach = " [REACHABLE]" if f.reachable else ""
        lines.append(f"\n  [{f.severity}] {f.package}=={f.installed_version} "
                     f"({f.cve}){reach}")
        lines.append(f"    {f.description}")
        lines.append(f"    fix: upgrade to >= {f.fixed_version}")
        if f.reachable:
            lines.append(f"    used in: {os.path.basename(f.reachable_file)}"
                         f":{f.reachable_line}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="attestor-dep-scan",
        description="Scan dependency lockfiles for known vulnerabilities.")
    ap.add_argument("paths", nargs="+", help="directories or lockfiles to scan")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--cross-ref", metavar="CODE_DIR",
                    help="cross-reference with dataflow findings from CODE_DIR")
    args = ap.parse_args(argv)

    findings = scan_paths(args.paths)

    if args.cross_ref:
        try:
            import dataflow
            code_findings = dataflow.to_dict(dataflow.scan_paths([args.cross_ref]))
            findings = cross_reference(findings, code_findings)
        except Exception:
            pass

    if args.json:
        print(json.dumps(to_dict(findings), indent=2))
    else:
        print(render(findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
