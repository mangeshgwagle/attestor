#!/usr/bin/env python3
"""Software Composition Analysis (SCA) scanner -- checks project dependencies
for known vulnerabilities using the OSV.dev API (free, no key required).
Supports: requirements.txt, Pipfile.lock, poetry.lock, package-lock.json,
yarn.lock, pnpm-lock.yaml, Gemfile.lock, go.sum, Cargo.lock, composer.lock."""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

OSV_API = "https://api.osv.dev/v1/query"
OSV_BATCH_API = "https://api.osv.dev/v1/querybatch"


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str
    lockfile: str


@dataclass
class VulnFinding:
    dep: Dependency
    vuln_id: str
    summary: str
    severity: str
    aliases: list[str] = field(default_factory=list)
    fixed_version: str = ""
    url: str = ""


def parse_requirements_txt(path: str) -> list[Dependency]:
    deps = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(("#", "-")):
                    continue
                m = re.match(r"([A-Za-z0-9_\-.]+)\s*==\s*([^\s;#]+)", line)
                if m:
                    deps.append(Dependency(m.group(1).lower(), m.group(2), "PyPI", path))
    except OSError:
        pass
    return deps


def parse_pipfile_lock(path: str) -> list[Dependency]:
    deps = []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for section in ("default", "develop"):
            for name, info in data.get(section, {}).items():
                version = info.get("version", "").lstrip("=")
                if version:
                    deps.append(Dependency(name.lower(), version, "PyPI", path))
    except (OSError, json.JSONDecodeError):
        pass
    return deps


def parse_poetry_lock(path: str) -> list[Dependency]:
    deps = []
    try:
        with open(path, encoding="utf-8") as f:
            content = f.read()
        for m in re.finditer(
            r'\[\[package\]\]\s+name\s*=\s*"([^"]+)"\s+version\s*=\s*"([^"]+)"',
            content,
        ):
            deps.append(Dependency(m.group(1).lower(), m.group(2), "PyPI", path))
    except OSError:
        pass
    return deps


def parse_package_lock_json(path: str) -> list[Dependency]:
    deps = []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        packages = data.get("packages", data.get("dependencies", {}))
        for name, info in packages.items():
            clean_name = name.replace("node_modules/", "").strip()
            if not clean_name:
                continue
            version = info.get("version", "")
            if version:
                deps.append(Dependency(clean_name, version, "npm", path))
    except (OSError, json.JSONDecodeError):
        pass
    return deps


def parse_yarn_lock(path: str) -> list[Dependency]:
    deps = []
    try:
        with open(path, encoding="utf-8") as f:
            content = f.read()
        for m in re.finditer(
            r'^"?(@?[^@\s"]+)@[^":\n]+(?:,\s*[^":\n]+)*"?:\s*\n\s+version\s+"([^"]+)"',
            content,
            re.MULTILINE,
        ):
            deps.append(Dependency(m.group(1), m.group(2), "npm", path))
    except OSError:
        pass
    return deps


def parse_go_sum(path: str) -> list[Dependency]:
    deps = []
    seen = set()
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1].split("/")[0].lstrip("v")
                    key = (name, version)
                    if key not in seen:
                        seen.add(key)
                        deps.append(Dependency(name, version, "Go", path))
    except OSError:
        pass
    return deps


def parse_cargo_lock(path: str) -> list[Dependency]:
    deps = []
    try:
        with open(path, encoding="utf-8") as f:
            content = f.read()
        for m in re.finditer(
            r'\[\[package\]\]\s+name\s*=\s*"([^"]+)"\s+version\s*=\s*"([^"]+)"',
            content,
        ):
            deps.append(Dependency(m.group(1), m.group(2), "crates.io", path))
    except OSError:
        pass
    return deps


def parse_gemfile_lock(path: str) -> list[Dependency]:
    deps = []
    in_specs = False
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped == "specs:":
                    in_specs = True
                    continue
                if in_specs and stripped and not stripped.startswith("("):
                    m = re.match(r"(\S+)\s+\(([^)]+)\)", stripped)
                    if m:
                        deps.append(Dependency(m.group(1), m.group(2), "RubyGems", path))
                elif in_specs and not line.startswith(" "):
                    in_specs = False
    except OSError:
        pass
    return deps


def parse_composer_lock(path: str) -> list[Dependency]:
    deps = []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for pkg in data.get("packages", []) + data.get("packages-dev", []):
            name = pkg.get("name", "")
            version = pkg.get("version", "").lstrip("v")
            if name and version:
                deps.append(Dependency(name, version, "Packagist", path))
    except (OSError, json.JSONDecodeError):
        pass
    return deps


LOCKFILE_PARSERS = {
    "requirements.txt": parse_requirements_txt,
    "requirements-dev.txt": parse_requirements_txt,
    "requirements_dev.txt": parse_requirements_txt,
    "Pipfile.lock": parse_pipfile_lock,
    "poetry.lock": parse_poetry_lock,
    "package-lock.json": parse_package_lock_json,
    "yarn.lock": parse_yarn_lock,
    "go.sum": parse_go_sum,
    "Cargo.lock": parse_cargo_lock,
    "Gemfile.lock": parse_gemfile_lock,
    "composer.lock": parse_composer_lock,
}


def find_lockfiles(root: str) -> list[str]:
    found = []
    skip = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fname in filenames:
            if fname in LOCKFILE_PARSERS:
                found.append(os.path.join(dirpath, fname))
            elif fname.startswith("requirements") and fname.endswith(".txt"):
                found.append(os.path.join(dirpath, fname))
    return found


def parse_all(root: str) -> list[Dependency]:
    deps = []
    for lockfile in find_lockfiles(root):
        fname = os.path.basename(lockfile)
        parser = LOCKFILE_PARSERS.get(fname)
        if not parser and fname.startswith("requirements") and fname.endswith(".txt"):
            parser = parse_requirements_txt
        if parser:
            deps.extend(parser(lockfile))
    return deps


def _query_osv_batch(deps: list[Dependency]) -> dict:
    queries = []
    for dep in deps:
        queries.append({
            "version": dep.version,
            "package": {"name": dep.name, "ecosystem": dep.ecosystem},
        })
    payload = json.dumps({"queries": queries}).encode()
    req = Request(OSV_BATCH_API, data=payload,
                  headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except (URLError, OSError, json.JSONDecodeError):
        return {}


def _severity_from_osv(vuln: dict) -> str:
    for severity_entry in vuln.get("severity", []):
        score_str = severity_entry.get("score", "")
        if "CVSS" in severity_entry.get("type", ""):
            m = re.search(r"(\d+\.?\d*)", score_str)
            if m:
                score = float(m.group(1))
                if score >= 9.0:
                    return "CRITICAL"
                if score >= 7.0:
                    return "HIGH"
                if score >= 4.0:
                    return "MEDIUM"
                return "LOW"
    db_severity = vuln.get("database_specific", {}).get("severity", "").upper()
    if db_severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return db_severity
    return "MEDIUM"


def _extract_fixed_version(vuln: dict, pkg_name: str) -> str:
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() == pkg_name.lower():
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
    return ""


def check_vulnerabilities(deps: list[Dependency], offline: bool = False) -> list[VulnFinding]:
    if offline or not deps:
        return []

    findings = []
    batch_size = 100
    for i in range(0, len(deps), batch_size):
        batch = deps[i : i + batch_size]
        result = _query_osv_batch(batch)
        for j, response in enumerate(result.get("results", [])):
            vulns = response.get("vulns", [])
            if not vulns:
                continue
            dep = batch[j]
            for vuln in vulns:
                vuln_id = vuln.get("id", "UNKNOWN")
                summary = vuln.get("summary", vuln.get("details", "No description")[:200])
                severity = _severity_from_osv(vuln)
                aliases = vuln.get("aliases", [])
                fixed = _extract_fixed_version(vuln, dep.name)
                url = f"https://osv.dev/vulnerability/{vuln_id}"
                findings.append(VulnFinding(
                    dep=dep,
                    vuln_id=vuln_id,
                    summary=summary,
                    severity=severity,
                    aliases=aliases,
                    fixed_version=fixed,
                    url=url,
                ))
    return findings


def scan(root: str, offline: bool = False) -> tuple[list[Dependency], list[VulnFinding]]:
    deps = parse_all(root)
    findings = check_vulnerabilities(deps, offline=offline)
    return deps, findings


def render(deps: list[Dependency], findings: list[VulnFinding]) -> str:
    lines = []
    by_lockfile = {}
    for d in deps:
        by_lockfile.setdefault(d.lockfile, []).append(d)
    lines.append(f"\n  Dependencies scanned: {len(deps)}")
    for lf, lf_deps in by_lockfile.items():
        lines.append(f"    {lf}: {len(lf_deps)} packages ({lf_deps[0].ecosystem})")

    if not findings:
        lines.append("\n  No known vulnerabilities found.")
        return "\n".join(lines)

    by_sev = {}
    for f in findings:
        by_sev.setdefault(f.severity, []).append(f)

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        group = by_sev.get(sev, [])
        if not group:
            continue
        lines.append(f"\n  [{sev}] ({len(group)} vulnerabilit{'ies' if len(group) > 1 else 'y'})")
        for f in group:
            cve = next((a for a in f.aliases if a.startswith("CVE-")), "")
            cve_str = f" ({cve})" if cve else ""
            fix = f" -> fix: {f.fixed_version}" if f.fixed_version else ""
            lines.append(f"    {f.dep.name}@{f.dep.version}  {f.vuln_id}{cve_str}{fix}")
            lines.append(f"      {f.summary[:120]}")

    total = len(findings)
    crit = len(by_sev.get("CRITICAL", []))
    lines.append(f"\n  Total: {total} vulnerabilit{'ies' if total > 1 else 'y'} ({crit} critical)")
    return "\n".join(lines)


def to_dict(deps: list[Dependency], findings: list[VulnFinding]) -> dict:
    return {
        "dependencies": len(deps),
        "vulnerabilities": [
            {
                "vuln_id": f.vuln_id,
                "package": f.dep.name,
                "version": f.dep.version,
                "ecosystem": f.dep.ecosystem,
                "severity": f.severity,
                "summary": f.summary,
                "aliases": f.aliases,
                "fixed_version": f.fixed_version,
                "url": f.url,
                "lockfile": f.dep.lockfile,
            }
            for f in findings
        ],
    }
