#!/usr/bin/env python3
"""SBOM generator -- CycloneDX and SPDX output from dependency trees.

Parses dependency manifests (requirements.txt, Pipfile.lock, package.json,
package-lock.json, yarn.lock, go.sum, Cargo.toml) and generates:
  - CycloneDX 1.5 JSON
  - SPDX 2.3 JSON

No external dependencies required.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str
    source_file: str
    purl: str = ""
    license: str = ""

    def __post_init__(self):
        if not self.purl:
            eco = {"pip": "pypi", "npm": "npm", "go": "golang",
                   "cargo": "cargo"}.get(self.ecosystem, self.ecosystem)
            self.purl = f"pkg:{eco}/{self.name}@{self.version}"


def parse_requirements_txt(text: str, filepath: str) -> list[Dependency]:
    deps = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"([a-zA-Z0-9_.-]+)\s*([=<>!~]+)\s*([^\s,;#]+)", line)
        if m:
            deps.append(Dependency(
                name=m.group(1).lower(), version=m.group(3),
                ecosystem="pip", source_file=filepath,
            ))
        elif re.match(r"^[a-zA-Z0-9_.-]+$", line):
            deps.append(Dependency(
                name=line.lower(), version="*",
                ecosystem="pip", source_file=filepath,
            ))
    return deps


def parse_pipfile_lock(text: str, filepath: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    deps = []
    for section in ("default", "develop"):
        for name, info in data.get(section, {}).items():
            ver = info.get("version", "").lstrip("=")
            deps.append(Dependency(
                name=name.lower(), version=ver or "*",
                ecosystem="pip", source_file=filepath,
            ))
    return deps


def parse_package_json(text: str, filepath: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    deps = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, ver in data.get(section, {}).items():
            ver_clean = re.sub(r"^[\^~>=<]+", "", ver)
            deps.append(Dependency(
                name=name, version=ver_clean,
                ecosystem="npm", source_file=filepath,
            ))
    return deps


def parse_package_lock(text: str, filepath: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    deps = []
    packages = data.get("packages", data.get("dependencies", {}))
    for key, info in packages.items():
        name = key
        if key.startswith("node_modules/"):
            name = key[len("node_modules/"):]
        if not name:
            continue
        ver = info.get("version", "")
        if ver:
            deps.append(Dependency(
                name=name, version=ver,
                ecosystem="npm", source_file=filepath,
            ))
    return deps


def parse_go_sum(text: str, filepath: str) -> list[Dependency]:
    deps = []
    seen = set()
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            mod = parts[0]
            ver = parts[1].split("/")[0].lstrip("v")
            key = (mod, ver)
            if key not in seen:
                seen.add(key)
                deps.append(Dependency(
                    name=mod, version=ver,
                    ecosystem="go", source_file=filepath,
                ))
    return deps


def parse_cargo_toml(text: str, filepath: str) -> list[Dependency]:
    deps = []
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[dependencies]" or stripped == "[dev-dependencies]":
            in_deps = True
            continue
        if stripped.startswith("[") and in_deps:
            in_deps = False
            continue
        if in_deps and "=" in stripped:
            m = re.match(r'(\w[\w-]*)\s*=\s*"([^"]+)"', stripped)
            if m:
                deps.append(Dependency(
                    name=m.group(1), version=m.group(2),
                    ecosystem="cargo", source_file=filepath,
                ))
            else:
                m2 = re.match(r'(\w[\w-]*)\s*=\s*\{.*version\s*=\s*"([^"]+)"', stripped)
                if m2:
                    deps.append(Dependency(
                        name=m2.group(1), version=m2.group(2),
                        ecosystem="cargo", source_file=filepath,
                    ))
    return deps


_PARSERS = {
    "requirements.txt": parse_requirements_txt,
    "requirements-dev.txt": parse_requirements_txt,
    "requirements_dev.txt": parse_requirements_txt,
    "Pipfile.lock": parse_pipfile_lock,
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock,
    "go.sum": parse_go_sum,
    "Cargo.toml": parse_cargo_toml,
}


def collect_deps(paths: list[str]) -> list[Dependency]:
    all_deps = []
    for p in paths:
        if os.path.isfile(p):
            basename = os.path.basename(p)
            parser = _PARSERS.get(basename)
            if parser:
                try:
                    with open(p, encoding="utf-8", errors="replace") as f:
                        all_deps += parser(f.read(), p)
                except OSError:
                    pass
        elif os.path.isdir(p):
            for dp, dn, fn in os.walk(p):
                dn[:] = [d for d in dn if d not in
                         {".git", "__pycache__", ".venv", "node_modules",
                          "vendor", "dist", "build"}]
                for n in fn:
                    parser = _PARSERS.get(n)
                    if parser:
                        fp = os.path.join(dp, n)
                        try:
                            with open(fp, encoding="utf-8", errors="replace") as f:
                                all_deps += parser(f.read(), fp)
                        except OSError:
                            pass
    return all_deps


def to_cyclonedx(deps: list[Dependency], project_name: str = "attestor-project") -> dict:
    serial = str(uuid.uuid4())
    components = []
    for d in deps:
        comp = {
            "type": "library",
            "name": d.name,
            "version": d.version,
            "purl": d.purl,
            "bom-ref": d.purl,
        }
        if d.license:
            comp["licenses"] = [{"license": {"id": d.license}}]
        components.append(comp)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "attestor", "name": "sbom-gen", "version": "4.3"}],
            "component": {
                "type": "application",
                "name": project_name,
            }
        },
        "components": components,
        "dependencies": [
            {"ref": d.purl, "dependsOn": []}
            for d in deps
        ],
    }


def to_spdx(deps: list[Dependency], project_name: str = "attestor-project") -> dict:
    doc_ns = f"https://attestor.dev/spdx/{uuid.uuid4()}"
    packages = []
    for d in deps:
        pkg_id = f"SPDXRef-{re.sub(r'[^a-zA-Z0-9.-]', '-', d.name)}-{d.version}"
        packages.append({
            "SPDXID": pkg_id,
            "name": d.name,
            "versionInfo": d.version,
            "downloadLocation": "NOASSERTION",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": d.purl,
            }],
            "filesAnalyzed": False,
            "licenseConcluded": d.license or "NOASSERTION",
            "licenseDeclared": d.license or "NOASSERTION",
            "copyrightText": "NOASSERTION",
        })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": project_name,
        "documentNamespace": doc_ns,
        "creationInfo": {
            "created": datetime.now(timezone.utc).isoformat(),
            "creators": ["Tool: attestor-sbom-gen-4.3"],
            "licenseListVersion": "3.21",
        },
        "packages": packages,
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": p["SPDXID"],
                "relationshipType": "DESCRIBES",
            }
            for p in packages
        ],
    }


def render(deps: list[Dependency]) -> str:
    if not deps:
        return "  No dependencies found for SBOM generation."
    by_eco = {}
    for d in deps:
        by_eco.setdefault(d.ecosystem, []).append(d)
    lines = [
        f"\n  SBOM Summary -- {len(deps)} component(s) across "
        f"{len(by_eco)} ecosystem(s)",
        "  " + "=" * 62,
    ]
    for eco, eco_deps in sorted(by_eco.items()):
        lines.append(f"\n  {eco.upper()} ({len(eco_deps)} packages):")
        for d in sorted(eco_deps, key=lambda x: x.name)[:20]:
            lines.append(f"    {d.name}@{d.version}")
        if len(eco_deps) > 20:
            lines.append(f"    ... and {len(eco_deps) - 20} more")
    return "\n".join(lines)


def to_dict(deps: list[Dependency]) -> list[dict]:
    return [
        {
            "name": d.name, "version": d.version,
            "ecosystem": d.ecosystem, "purl": d.purl,
            "source_file": d.source_file, "license": d.license,
            "category": "dependency", "severity": "INFO",
            "sink_type": "sbom_component",
        }
        for d in deps
    ]
