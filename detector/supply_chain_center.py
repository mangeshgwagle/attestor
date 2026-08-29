"""Attestor 3.0 offline-first software supply-chain command center.

The module inventories local dependency declarations without resolving, installing,
importing, or executing them.  It can emit deterministic CycloneDX/SPDX SBOMs,
authenticated advisory-snapshot assessments, CycloneDX/OpenVEX documents, and
provenance evidence.  Network access is deliberately absent.

Truthfulness rules:

* an unprovided advisory feed is ``unavailable``, never "clean";
* an expired authenticated snapshot is ``stale``;
* no advisory match means only ``no_match_in_snapshot``;
* dependency versions and licenses are unknown unless local evidence declares them;
* the SLSA-shaped provenance output is evidence, not a SLSA certification.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as _datetime
import hashlib
import hmac
import json
import os
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import quote

try:
    import tomllib
except ImportError:  # pragma: no cover - Attestor's supported runtime includes 3.11+
    tomllib = None  # type: ignore[assignment]


SCHEMA = "attestor-supply-chain-report/1"
SNAPSHOT_SCHEMA = "attestor-advisory-snapshot/1"
VERSION = "3.0.0"
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024
MAX_MANIFESTS = 4_000
MAX_DEPENDENCIES = 200_000
MAX_ADVISORIES = 250_000
MAX_FINDINGS = 50_000
MAX_JSON_DEPTH = 64
MAX_TEXT_FIELD = 4_096
DEFAULT_CREATED = "1970-01-01T00:00:00Z"
CLEARTEXT_HTTP = "http" + "://"
CLEARTEXT_GIT = "git" + "://"

SKIP_DIRECTORIES = frozenset({
    ".git", ".hg", ".svn", ".idea", ".vscode", "__pycache__",
    "node_modules", "vendor", "target", "dist", "build", ".tox",
    ".venv", "venv", ".mypy_cache", ".pytest_cache", ".attestor-cache",
})

EXACT_MANIFESTS = frozenset({
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "pnpm-lock.yaml", "pyproject.toml", "pipfile", "pipfile.lock", "poetry.lock", "uv.lock", "pdm.lock",
    "cargo.toml", "cargo.lock", "go.mod", "go.sum", "pom.xml",
    "gradle.lockfile", "packages.lock.json", "composer.json", "composer.lock", "gemfile", "gemfile.lock",
    "package.swift", "package.resolved", ".gitmodules",
})

LOCK_EXPECTATIONS: dict[str, tuple[str, ...]] = {
    "package.json": ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"),
    "pyproject.toml": ("poetry.lock", "uv.lock", "pdm.lock"),
    "pipfile": ("pipfile.lock",),
    "cargo.toml": ("cargo.lock",),
    "go.mod": ("go.sum",),
    "composer.json": ("composer.lock",),
    "gemfile": ("gemfile.lock",),
    "package.swift": ("package.resolved",),
    "build.gradle": ("gradle.lockfile",),
    "build.gradle.kts": ("gradle.lockfile",),
}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_REACHABILITY_STATES = frozenset({"reachable", "unreachable", "unknown"})
REACHABILITY_PROOF_SCHEMA = "attestor.reachability-proof/4.1"
_SAFE_ECOSYSTEM = re.compile(r"^[a-z][a-z0-9.+-]{0,31}$")
_SAFE_NAME = re.compile(r"^[^\x00-\x1f\x7f]{1,512}$")
_HEX_COMMIT = re.compile(r"^[0-9a-fA-F]{40,64}$")
_SPDX_LICENSE_IDS = frozenset({
    "0BSD", "Apache-1.1", "Apache-2.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "BSD-2-Clause", "BSD-3-Clause", "BSL-1.0", "CC0-1.0", "EPL-1.0", "EPL-2.0",
    "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
    "ISC", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only",
    "LGPL-3.0-or-later", "MIT", "MPL-2.0", "Unlicense", "Zlib",
})


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    version: str
    version_spec: str
    scope: str
    manifests: tuple[str, ...]
    purl: str
    direct: bool = True
    integrity: tuple[str, ...] = ()
    licenses: tuple[str, ...] = ()
    source: str = ""

    @property
    def bom_ref(self) -> str:
        return self.purl


@dataclass(frozen=True)
class RiskFinding:
    rule_id: str
    severity: str
    path: str
    message: str
    evidence: str
    remediation: str
    cwe: str


@dataclass
class Inventory:
    root: str
    dependencies: list[Dependency] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    file_hashes: dict[str, str] = field(default_factory=dict)
    lock_coverage: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "status": "partial" if self.errors or self.skipped else "complete",
            "dependencies": [asdict(item) for item in self.dependencies],
            "manifests": list(self.manifests),
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "skipped": list(self.skipped),
            "file_hashes": dict(self.file_hashes),
            "lock_coverage": list(self.lock_coverage),
            "limits": {
                "max_manifest_bytes": MAX_MANIFEST_BYTES,
                "max_manifests": MAX_MANIFESTS,
                "max_dependencies": MAX_DEPENDENCIES,
            },
        }


@dataclass(frozen=True)
class SnapshotVerification:
    valid: bool
    authenticated: bool
    state: str
    key_id: str
    generated_at: str
    expires_at: str
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SupplyChainError(ValueError):
    """Expected, safe-to-display input or verification error."""


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _bounded(value: Any, limit: int = MAX_TEXT_FIELD) -> str:
    text = str(value or "").replace("\x00", "\\0").replace("\r", " ").replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _redact_evidence(value: Any, limit: int = MAX_TEXT_FIELD) -> str:
    """Bound likely-sensitive evidence before it can enter reports or exports."""
    text = _bounded(value, limit * 2)
    text = re.sub(r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@", r"\1[REDACTED]@", text)
    text = re.sub(
        r"(?i)(\b(?:token|password|passwd|secret|api[_-]?key|authorization|_authToken)\s*[=:]\s*)"
        r"(?:bearer\s+)?[^\s;&,'\"]+",
        r"\1[REDACTED]", text,
    )
    text = re.sub(r"(?i)([?&](?:token|key|secret|signature|password)=)[^&#\s]+", r"\1[REDACTED]", text)
    return _bounded(text, limit)


def _safe_json_depth(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise SupplyChainError("JSON nesting exceeds %d levels" % MAX_JSON_DEPTH)
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > MAX_TEXT_FIELD:
                raise SupplyChainError("JSON object contains an invalid or oversized key")
            _safe_json_depth(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _safe_json_depth(child, depth + 1)
    elif isinstance(value, str) and len(value) > MAX_SNAPSHOT_BYTES:
        raise SupplyChainError("JSON string is unreasonably large")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SupplyChainError("duplicate JSON key: %s" % _bounded(key, 128))
        result[key] = value
    return result


def _json_loads(text: str) -> Any:
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except SupplyChainError:
        raise
    except (json.JSONDecodeError, UnicodeError, TypeError, ValueError, RecursionError) as exc:
        raise SupplyChainError("malformed JSON: %s" % _bounded(exc, 256)) from exc
    _safe_json_depth(value)
    return value


def canonical_json(value: Any) -> bytes:
    """Return the byte representation used for IDs and HMAC authentication."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _read_bounded(path: Path, limit: int) -> bytes:
    try:
        stat = path.stat()
    except OSError as exc:
        raise SupplyChainError("cannot stat file: %s" % _bounded(exc, 256)) from exc
    if not path.is_file():
        raise SupplyChainError("not a regular file")
    if stat.st_size > limit:
        raise SupplyChainError("file exceeds %d bytes" % limit)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise SupplyChainError("cannot read file: %s" % _bounded(exc, 256)) from exc
    if len(data) > limit:
        raise SupplyChainError("file grew beyond %d bytes while reading" % limit)
    return data


def _decode_utf8(data: bytes) -> str:
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SupplyChainError("file is not valid UTF-8: %s" % exc) from exc


def _discover(root: Path) -> list[Path]:
    found: list[Path] = []
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(directory.iterdir(), key=lambda p: p.name.casefold(), reverse=True)
        except OSError:
            continue
        for path in entries:
            try:
                if path.is_symlink():
                    continue
                if path.is_dir():
                    if path.name.casefold() not in SKIP_DIRECTORIES:
                        stack.append(path)
                    continue
                if not path.is_file():
                    continue
            except OSError:
                continue
            lower = path.name.casefold()
            rel = _relative(root, path).casefold()
            supported = (
                lower in EXACT_MANIFESTS
                or (lower.startswith("requirements") and lower.endswith(".txt"))
                or lower.endswith(".csproj")
                or lower in {"build.gradle", "build.gradle.kts"}
                or rel.startswith(".github/workflows/") and lower.endswith((".yml", ".yaml"))
                or lower in {"dockerfile", "jenkinsfile", ".gitlab-ci.yml", "azure-pipelines.yml"}
            )
            if supported:
                found.append(path)
                if len(found) > MAX_MANIFESTS:
                    raise SupplyChainError("manifest limit of %d exceeded" % MAX_MANIFESTS)
    return sorted(found, key=lambda p: _relative(root, p).casefold())


def _normal_name(ecosystem: str, name: str) -> str:
    value = name.strip()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", value).lower()
    if ecosystem in {"npm", "cargo", "nuget", "gem", "composer"}:
        return value.lower()
    return value


def _exact_version(spec: str) -> str:
    value = spec.strip()
    if value.startswith("=="):
        value = value[2:].strip()
    if not value or value.lower() in {"latest", "release", "*", "x"}:
        return ""
    if re.search(r"[<>=~^*|,\s$(){}\[\]]", value):
        return ""
    if value.startswith(("git+", CLEARTEXT_GIT, CLEARTEXT_HTTP, "https://", "file:", "path:")):
        return ""
    return value


def make_purl(ecosystem: str, name: str, version: str = "") -> str:
    """Create a normalized package URL for a supported package ecosystem."""
    ecosystem = ecosystem.strip().lower()
    if not _SAFE_ECOSYSTEM.fullmatch(ecosystem):
        raise SupplyChainError("invalid ecosystem")
    name = _normal_name(ecosystem, name)
    if not _SAFE_NAME.fullmatch(name) or name.startswith(("/", ".")) or ".." in name.split("/"):
        raise SupplyChainError("invalid package name")
    namespace = ""
    package = name
    if ecosystem == "maven" and ":" in name:
        namespace, package = name.rsplit(":", 1)
    elif ecosystem in {"npm", "composer"} and "/" in name:
        namespace, package = name.rsplit("/", 1)
    elif ecosystem == "golang" and "/" in name:
        namespace, package = name.rsplit("/", 1)
    safe = ".-_~"
    encoded = quote(package, safe=safe)
    if namespace:
        encoded = "/".join(quote(part, safe=safe) for part in namespace.split("/")) + "/" + encoded
    exact = _exact_version(version)
    return "pkg:%s/%s%s" % (ecosystem, encoded, ("@" + quote(exact, safe=safe + "+")) if exact else "")


def _split_pep508(spec: str) -> tuple[str, str]:
    clean = spec.split(";", 1)[0].strip()
    match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(.*)$", clean)
    return (match.group(1), match.group(2).strip()) if match else ("", "")


def _add(rows: list[dict[str, Any]], ecosystem: str, name: Any, spec: Any, scope: str,
         manifest: str, *, direct: bool = True, resolved: Any = "", integrity: Iterable[Any] = (),
         licenses: Iterable[Any] = (), source: Any = "") -> None:
    clean_name = _bounded(name, 512).strip()
    clean_spec = _redact_evidence(spec, 1024).strip()
    clean_version = _bounded(resolved, 512).strip() or _exact_version(clean_spec)
    if not clean_name:
        return
    try:
        purl = make_purl(ecosystem, clean_name, clean_version)
    except SupplyChainError:
        return
    hashes = tuple(sorted({_bounded(item, 1024) for item in integrity if item}))
    declared_licenses = tuple(sorted({_bounded(item, 256) for item in licenses if item}))
    rows.append({
        "ecosystem": ecosystem, "name": _normal_name(ecosystem, clean_name),
        "version": clean_version, "version_spec": clean_spec, "scope": scope,
        "manifest": manifest, "purl": purl, "direct": bool(direct),
        "integrity": hashes, "licenses": declared_licenses,
        "source": _redact_evidence(source, 2048),
    })


def _parse_requirements(text: str, manifest: str, rows: list[dict[str, Any]]) -> None:
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r", "--requirement", "-c", "--constraint", "--index-url",
                            "--extra-index-url", "--find-links", "--trusted-host")):
            continue
        if line.startswith(("-e ", "--editable ")):
            line = line.split(None, 1)[1]
        line = line.split(" #", 1)[0].rstrip()
        hashes = re.findall(r"--hash[= ]([^\s]+)", line)
        line = re.sub(r"\s+--hash(?:=|\s+)[^\s]+", "", line)
        name, spec = _split_pep508(line)
        _add(rows, "pypi", name, spec, "runtime", manifest, integrity=hashes,
             source=line if "@" in line or "://" in line else "")


def _parse_pyproject(text: str, manifest: str, rows: list[dict[str, Any]]) -> None:
    if tomllib is None:
        raise SupplyChainError("TOML parser unavailable")
    try:
        data = tomllib.loads(text)
    except (ValueError, TypeError) as exc:
        raise SupplyChainError("malformed TOML: %s" % _bounded(exc, 256)) from exc
    project = data.get("project", {}) if isinstance(data, dict) else {}
    if isinstance(project, dict):
        for spec in project.get("dependencies", []) or []:
            name, version = _split_pep508(str(spec))
            _add(rows, "pypi", name, version, "runtime", manifest)
        groups = project.get("optional-dependencies", {}) or {}
        if isinstance(groups, dict):
            for group, specs in sorted(groups.items()):
                for spec in specs if isinstance(specs, list) else []:
                    name, version = _split_pep508(str(spec))
                    _add(rows, "pypi", name, version, "optional:" + str(group), manifest)
    tool = data.get("tool", {}) if isinstance(data, dict) else {}
    poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
    if isinstance(poetry, dict):
        for section, scope in (("dependencies", "runtime"), ("dev-dependencies", "development")):
            dependencies = poetry.get(section, {}) or {}
            if isinstance(dependencies, dict):
                for name, value in sorted(dependencies.items()):
                    if str(name).lower() == "python":
                        continue
                    spec = value.get("version", "") if isinstance(value, dict) else value
                    source = value.get("git", "") if isinstance(value, dict) else ""
                    _add(rows, "pypi", name, spec, scope, manifest, source=source)


def _parse_pipfile_lock(text: str, manifest: str, rows: list[dict[str, Any]]) -> None:
    data = _json_loads(text)
    if not isinstance(data, dict):
        raise SupplyChainError("Pipfile.lock root must be an object")
    for section, scope in (("default", "runtime"), ("develop", "development")):
        dependencies = data.get(section, {}) or {}
        if not isinstance(dependencies, dict):
            continue
        for name, info in sorted(dependencies.items()):
            spec = info.get("version", "") if isinstance(info, dict) else info
            hashes = info.get("hashes", []) if isinstance(info, dict) else []
            _add(rows, "pypi", name, spec, scope, manifest, integrity=hashes or ())


def _parse_pipfile(text: str, manifest: str, rows: list[dict[str, Any]]) -> None:
    if tomllib is None:
        raise SupplyChainError("TOML parser unavailable")
    try:
        data = tomllib.loads(text)
    except (ValueError, TypeError) as exc:
        raise SupplyChainError("malformed TOML: %s" % _bounded(exc, 256)) from exc
    for section, scope in (("packages", "runtime"), ("dev-packages", "development")):
        dependencies = data.get(section, {}) if isinstance(data, dict) else {}
        if not isinstance(dependencies, dict):
            continue
        for name, info in sorted(dependencies.items()):
            spec = info.get("version", "") if isinstance(info, dict) else info
            source = info.get("git", "") if isinstance(info, dict) else ""
            _add(rows, "pypi", name, spec, scope, manifest, source=source)


def _parse_python_lock_toml(text: str, manifest: str, rows: list[dict[str, Any]]) -> None:
    if tomllib is None:
        raise SupplyChainError("TOML parser unavailable")
    try:
        data = tomllib.loads(text)
    except (ValueError, TypeError) as exc:
        raise SupplyChainError("malformed TOML: %s" % _bounded(exc, 256)) from exc
    packages = data.get("package", []) if isinstance(data, dict) else []
    if isinstance(packages, dict):
        packages = list(packages.values())
    for package in packages if isinstance(packages, list) else []:
        if not isinstance(package, dict):
            continue
        hashes: list[str] = []
        files = package.get("files", [])
        for item in files if isinstance(files, list) else []:
            if isinstance(item, dict) and item.get("hash"):
                hashes.append(str(item["hash"]))
        _add(rows, "pypi", package.get("name"), package.get("version", ""), "runtime", manifest,
             direct=False, resolved=package.get("version", ""), integrity=hashes,
             source=(package.get("source") or {}).get("url", "") if isinstance(package.get("source"), dict) else "")


def _parse_package_json(text: str, manifest: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    data = _json_loads(text)
    if not isinstance(data, dict):
        raise SupplyChainError("package.json root must be an object")
    for section, scope in (("dependencies", "runtime"), ("devDependencies", "development"),
                           ("peerDependencies", "peer"), ("optionalDependencies", "optional")):
        dependencies = data.get(section, {}) or {}
        if not isinstance(dependencies, dict):
            continue
        for name, spec in sorted(dependencies.items()):
            if isinstance(spec, (str, int, float)):
                _add(rows, "npm", name, spec, scope, manifest,
                     source=spec if isinstance(spec, str) and (":" in spec or "/" in spec) else "")
    return data


def _parse_package_lock(text: str, manifest: str, rows: list[dict[str, Any]]) -> None:
    data = _json_loads(text)
    if not isinstance(data, dict):
        raise SupplyChainError("npm lockfile root must be an object")
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, info in sorted(packages.items()):
            if not key or not isinstance(info, dict):
                continue
            name = info.get("name") or str(key).rsplit("node_modules/", 1)[-1]
            scope = "development" if info.get("dev") else "optional" if info.get("optional") else "runtime"
            integrity = [info.get("integrity")] if info.get("integrity") else []
            licenses = info.get("license", [])
            if isinstance(licenses, str):
                licenses = [licenses]
            _add(rows, "npm", name, info.get("version", ""), scope, manifest,
                 direct=False, resolved=info.get("version", ""), integrity=integrity,
                 licenses=licenses if isinstance(licenses, list) else [], source=info.get("resolved", ""))
        return
    dependencies = data.get("dependencies", {}) or {}
    if isinstance(dependencies, dict):
        for name, info in sorted(dependencies.items()):
            if not isinstance(info, dict):
                continue
            _add(rows, "npm", name, info.get("version", ""), "runtime", manifest,
                 direct=False, resolved=info.get("version", ""),
                 integrity=[info.get("integrity")] if info.get("integrity") else [],
                 source=info.get("resolved", ""))


def _parse_yarn_lock(text: str, manifest: str, rows: list[dict[str, Any]]) -> None:
    current: list[str] = []
    version = ""
    integrity = ""
    def flush() -> None:
        for selector in current:
            name = selector.strip('"\'').rsplit("@", 1)[0]
            if selector.startswith("@"):
                at = selector.find("@", 1)
                name = selector[:at] if at > 0 else selector
            _add(rows, "npm", name, version, "runtime", manifest, direct=False,
                 resolved=version, integrity=[integrity] if integrity else [])
    for raw in text.splitlines() + [""]:
        if raw and not raw[0].isspace() and raw.rstrip().endswith(":"):
            flush()
            current = [item.strip() for item in raw.rstrip()[:-1].split(",")]
            version = integrity = ""
        elif current:
            match = re.match(r'^\s+version\s+["\']([^"\']+)', raw)
            if match:
                version = match.group(1)
            match = re.match(r'^\s+integrity\s+(.+)', raw)
            if match:
                integrity = match.group(1).strip()
    flush()


def _parse_pnpm_lock(text: str, manifest: str, rows: list[dict[str, Any]]) -> None:
    # A conservative line parser: it recognizes exact package keys but does not pretend
    # to implement the entire YAML specification or execute custom tags.
    for match in re.finditer(r"(?m)^\s{2,}(?:/|['\"]?)(@?[^\s:'\"]+(?:/[^\s:'\"]+)?)[@/]([^\s:'\"]+)['\"]?:\s*$", text):
        _add(rows, "npm", match.group(1), match.group(2), "runtime", manifest,
             direct=False, resolved=match.group(2))


def _parse_cargo(text: str, manifest: str, rows: list[dict[str, Any]], locked: bool) -> None:
    if tomllib is None:
        raise SupplyChainError("TOML parser unavailable")
    try:
        data = tomllib.loads(text)
    except (ValueError, TypeError) as exc:
        raise SupplyChainError("malformed TOML: %s" % _bounded(exc, 256)) from exc
    if locked:
        for package in data.get("package", []) if isinstance(data, dict) else []:
            if isinstance(package, dict):
                checksum = package.get("checksum")
                _add(rows, "cargo", package.get("name"), package.get("version", ""), "runtime", manifest,
                     direct=False, resolved=package.get("version", ""),
                     integrity=["sha256:" + str(checksum)] if checksum else [], source=package.get("source", ""))
        return
    for section, scope in (("dependencies", "runtime"), ("dev-dependencies", "development"),
                           ("build-dependencies", "build")):
        deps = data.get(section, {}) if isinstance(data, dict) else {}
        if not isinstance(deps, dict):
            continue
        for name, info in sorted(deps.items()):
            spec = info.get("version", "") if isinstance(info, dict) else info
            source = info.get("git", "") if isinstance(info, dict) else ""
            _add(rows, "cargo", name, spec, scope, manifest, source=source)


def _parse_go_mod(text: str, manifest: str, rows: list[dict[str, Any]]) -> None:
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line == "require (":
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        spec = line if in_block else line[8:].strip() if line.startswith("require ") else ""
        parts = spec.split()
        if len(parts) >= 2:
            _add(rows, "golang", parts[0], parts[1], "runtime", manifest, resolved=parts[1])


def _parse_go_sum(text: str, manifest: str, rows: list[dict[str, Any]]) -> None:
    for raw in text.splitlines():
        parts = raw.strip().split()
        if len(parts) != 3 or not parts[2].startswith("h1:"):
            continue
        version = parts[1]
        if version.endswith("/go.mod"):
            version = version[:-7]
        _add(rows, "golang", parts[0], version, "runtime", manifest, direct=False,
             resolved=version, integrity=[parts[2]])


def _parse_pom(text: str, manifest: str, rows: list[dict[str, Any]]) -> None:
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise SupplyChainError("XML DTD/entity declarations are not accepted")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise SupplyChainError("malformed XML: %s" % _bounded(exc, 256)) from exc
    def child(node: ET.Element, name: str) -> str:
        item = node.find("{*}" + name)
        return (item.text or "").strip() if item is not None else ""
    for dep in root.findall(".//{*}dependencies/{*}dependency"):
        artifact = child(dep, "artifactId")
        group = child(dep, "groupId")
        if artifact:
            _add(rows, "maven", (group + ":" if group else "") + artifact,
                 child(dep, "version"), child(dep, "scope") or "runtime", manifest)


def _parse_gradle(text: str, manifest: str, rows: list[dict[str, Any]]) -> None:
    pattern = r"(?m)^\s*(implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(?\s*['\"]([^'\"]+)['\"]"
    for match in re.finditer(pattern, text):
        parts = match.group(2).split(":")
        if len(parts) >= 2:
            scope = "development" if match.group(1).startswith("test") else "runtime"
            _add(rows, "maven", parts[0] + ":" + parts[1], parts[2] if len(parts) > 2 else "", scope, manifest)


def _parse_gradle_lock(text: str, manifest: str, rows: list[dict[str, Any]]) -> None:
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        coordinate = line.split("=", 1)[0]
        parts = coordinate.split(":")
        if len(parts) == 3 and all(parts):
            _add(rows, "maven", parts[0] + ":" + parts[1], parts[2], "runtime", manifest,
                 direct=False, resolved=parts[2])


def _parse_csproj(text: str, manifest: str, rows: list[dict[str, Any]]) -> None:
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise SupplyChainError("XML DTD/entity declarations are not accepted")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise SupplyChainError("malformed XML: %s" % _bounded(exc, 256)) from exc
    for item in root.findall(".//{*}PackageReference"):
        name = item.attrib.get("Include") or item.attrib.get("Update")
        version = item.attrib.get("Version", "")
        if not version:
            node = item.find("{*}Version")
            version = (node.text or "").strip() if node is not None else ""
        _add(rows, "nuget", name, version, "runtime", manifest)


def _parse_nuget_lock(text: str, manifest: str, rows: list[dict[str, Any]]) -> None:
    data = _json_loads(text)
    dependencies = data.get("dependencies", {}) if isinstance(data, dict) else {}
    if not isinstance(dependencies, dict):
        return
    for framework, packages in sorted(dependencies.items()):
        if not isinstance(packages, dict):
            continue
        for name, info in sorted(packages.items()):
            resolved = info.get("resolved", "") if isinstance(info, dict) else info
            digest = info.get("contentHash") if isinstance(info, dict) else ""
            _add(rows, "nuget", name, resolved, "development" if "test" in framework.lower() else "runtime",
                 manifest, direct=False, resolved=resolved,
                 integrity=["sha512-" + str(digest)] if digest else [])


def _parse_composer(text: str, manifest: str, rows: list[dict[str, Any]], locked: bool) -> None:
    data = _json_loads(text)
    if not isinstance(data, dict):
        raise SupplyChainError("Composer file root must be an object")
    if locked:
        for section, scope in (("packages", "runtime"), ("packages-dev", "development")):
            for package in data.get(section, []) if isinstance(data.get(section, []), list) else []:
                if not isinstance(package, dict):
                    continue
                dist = package.get("dist") or {}
                source = package.get("source") or {}
                digest = dist.get("shasum", "") if isinstance(dist, dict) else ""
                licenses = package.get("license", [])
                _add(rows, "composer", package.get("name"), package.get("version", ""), scope, manifest,
                     direct=False, resolved=package.get("version", ""),
                     integrity=["sha1:" + digest] if digest else [],
                     licenses=licenses if isinstance(licenses, list) else [],
                     source=source.get("url", "") if isinstance(source, dict) else "")
        return
    for section, scope in (("require", "runtime"), ("require-dev", "development")):
        deps = data.get(section, {})
        if isinstance(deps, dict):
            for name, spec in sorted(deps.items()):
                if name == "php" or name.startswith("ext-"):
                    continue
                _add(rows, "composer", name, spec, scope, manifest)


def _parse_gemfile_lock(text: str, manifest: str, rows: list[dict[str, Any]]) -> None:
    in_specs = False
    for raw in text.splitlines():
        if raw.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and raw and not raw.startswith("    "):
            in_specs = False
        if in_specs:
            match = re.match(r"^    ([A-Za-z0-9_.-]+) \(([^)]+)\)", raw)
            if match:
                _add(rows, "gem", match.group(1), match.group(2), "runtime", manifest,
                     direct=False, resolved=match.group(2))


def _parse_gemfile(text: str, manifest: str, rows: list[dict[str, Any]]) -> None:
    for raw in text.splitlines():
        match = re.match(r"^\s*gem\s+['\"]([A-Za-z0-9_.-]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", raw)
        if match:
            scope = "development" if re.search(r"\b(?:development|test)\b", raw) else "runtime"
            _add(rows, "gem", match.group(1), match.group(2) or "", scope, manifest)


def _parse_package_swift(text: str, manifest: str, rows: list[dict[str, Any]]) -> None:
    pattern = (r"\.package\s*\(\s*url\s*:\s*['\"]([^'\"]+)['\"]\s*,\s*"
               r"(?:from|exact|branch|revision)\s*:\s*['\"]([^'\"]+)['\"]")
    for match in re.finditer(pattern, text):
        source, spec = match.groups()
        name = source.rstrip("/").rsplit("/", 1)[-1]
        if name.lower().endswith(".git"):
            name = name[:-4]
        _add(rows, "swift", name, spec, "runtime", manifest, source=source)


def _parse_swift_resolved(text: str, manifest: str, rows: list[dict[str, Any]]) -> None:
    data = _json_loads(text)
    pins = data.get("pins") if isinstance(data, dict) else None
    if pins is None and isinstance(data, dict) and isinstance(data.get("object"), dict):
        pins = data["object"].get("pins")
    for pin in pins if isinstance(pins, list) else []:
        if not isinstance(pin, dict):
            continue
        state = pin.get("state", {}) if isinstance(pin.get("state"), dict) else {}
        name = pin.get("identity") or pin.get("package")
        version = state.get("version") or state.get("revision", "")
        _add(rows, "swift", name, version, "runtime", manifest, direct=False,
             resolved=version, source=pin.get("location") or pin.get("repositoryURL", ""))


def _merge_dependencies(rows: list[dict[str, Any]]) -> list[Dependency]:
    # Reconcile one unambiguous lockfile resolution with a direct declaration first.
    # This avoids duplicate CycloneDX bom-refs while preserving the declared range.
    locked: dict[tuple[str, str], set[str]] = {}
    for row in rows:
        if not row["direct"] and row["version"]:
            locked.setdefault((row["ecosystem"], row["name"]), set()).add(row["version"])
    normalized: list[dict[str, Any]] = []
    for row in rows:
        candidate = dict(row)
        if row["direct"]:
            versions = locked.get((row["ecosystem"], row["name"]), set())
            exact = _exact_version(row["version_spec"])
            resolved = exact if exact in versions else next(iter(versions)) if len(versions) == 1 else ""
            if resolved:
                candidate["version"] = resolved
                candidate["purl"] = make_purl(row["ecosystem"], row["name"], resolved)
        normalized.append(candidate)

    merged: dict[str, dict[str, Any]] = {}
    for row in normalized:
        key = row["purl"]
        item = merged.setdefault(key, {**row, "manifests": set(), "integrity_set": set(),
                                       "license_set": set(), "sources": set(), "specs": set(),
                                       "scopes": set(), "any_direct": False})
        item["manifests"].add(row["manifest"])
        item["integrity_set"].update(row["integrity"])
        item["license_set"].update(row["licenses"])
        if row["version_spec"]:
            item["specs"].add(row["version_spec"])
        item["scopes"].add(row["scope"])
        item["any_direct"] = item["any_direct"] or row["direct"]
        if row["source"]:
            item["sources"].add(row["source"])
    result: list[Dependency] = []
    scope_priority = {"runtime": 0, "build": 1, "optional": 2, "peer": 3, "development": 4}
    for key in sorted(merged, key=str.casefold):
        item = merged[key]
        scopes = sorted(item["scopes"], key=lambda value: (scope_priority.get(value, 5), value))
        result.append(Dependency(
            ecosystem=item["ecosystem"], name=item["name"], version=item["version"],
            version_spec=" | ".join(sorted(item["specs"])), scope=scopes[0],
            manifests=tuple(sorted(item["manifests"])), purl=item["purl"], direct=item["any_direct"],
            integrity=tuple(sorted(item["integrity_set"])),
            licenses=tuple(sorted(item["license_set"])), source="; ".join(sorted(item["sources"])),
        ))
    return result


def _lock_coverage(root: Path, paths: Sequence[Path]) -> list[dict[str, Any]]:
    by_directory: dict[Path, set[str]] = {}
    for path in paths:
        by_directory.setdefault(path.parent, set()).add(path.name.casefold())
    rows: list[dict[str, Any]] = []
    for directory, names in sorted(by_directory.items(), key=lambda item: str(item[0]).casefold()):
        for manifest, locks in LOCK_EXPECTATIONS.items():
            if manifest not in names:
                continue
            present = sorted(name for name in locks if name in names)
            rows.append({
                "manifest": _relative(root, directory / manifest),
                "status": "present" if present else "missing",
                "lockfiles": [_relative(root, directory / name) for name in present],
                "expected_any_of": list(locks),
            })
    return rows


def inventory_workspace(root: str | Path) -> Inventory:
    """Inventory supported local manifests.  No command execution or network access."""
    base = Path(root).expanduser().resolve()
    inventory = Inventory(root=str(base))
    if not base.is_dir():
        inventory.errors.append("workspace is not a directory: %s" % base)
        return inventory
    try:
        paths = _discover(base)
    except SupplyChainError as exc:
        inventory.errors.append(str(exc))
        return inventory
    rows: list[dict[str, Any]] = []
    for path in paths:
        manifest = _relative(base, path)
        inventory.manifests.append(manifest)
        try:
            data = _read_bounded(path, MAX_MANIFEST_BYTES)
            inventory.file_hashes[manifest] = "sha256:" + hashlib.sha256(data).hexdigest()
            text = _decode_utf8(data)
            lower = path.name.casefold()
            if lower.startswith("requirements") and lower.endswith(".txt"):
                _parse_requirements(text, manifest, rows)
            elif lower == "pyproject.toml":
                _parse_pyproject(text, manifest, rows)
            elif lower == "pipfile.lock":
                _parse_pipfile_lock(text, manifest, rows)
            elif lower == "pipfile":
                _parse_pipfile(text, manifest, rows)
            elif lower in {"poetry.lock", "uv.lock", "pdm.lock"}:
                _parse_python_lock_toml(text, manifest, rows)
            elif lower == "package.json":
                _parse_package_json(text, manifest, rows)
            elif lower in {"package-lock.json", "npm-shrinkwrap.json"}:
                _parse_package_lock(text, manifest, rows)
            elif lower == "yarn.lock":
                _parse_yarn_lock(text, manifest, rows)
            elif lower == "pnpm-lock.yaml":
                _parse_pnpm_lock(text, manifest, rows)
            elif lower in {"cargo.toml", "cargo.lock"}:
                _parse_cargo(text, manifest, rows, lower == "cargo.lock")
            elif lower == "go.mod":
                _parse_go_mod(text, manifest, rows)
            elif lower == "go.sum":
                _parse_go_sum(text, manifest, rows)
            elif lower == "pom.xml":
                _parse_pom(text, manifest, rows)
            elif lower in {"build.gradle", "build.gradle.kts"}:
                _parse_gradle(text, manifest, rows)
            elif lower == "gradle.lockfile":
                _parse_gradle_lock(text, manifest, rows)
            elif lower.endswith(".csproj"):
                _parse_csproj(text, manifest, rows)
            elif lower == "packages.lock.json":
                _parse_nuget_lock(text, manifest, rows)
            elif lower in {"composer.json", "composer.lock"}:
                _parse_composer(text, manifest, rows, lower == "composer.lock")
            elif lower == "gemfile":
                _parse_gemfile(text, manifest, rows)
            elif lower == "gemfile.lock":
                _parse_gemfile_lock(text, manifest, rows)
            elif lower == "package.swift":
                _parse_package_swift(text, manifest, rows)
            elif lower == "package.resolved":
                _parse_swift_resolved(text, manifest, rows)
            # CI and source-control inputs are hashed and risk-scanned, not dependencies.
        except (OSError, SupplyChainError, ValueError, TypeError) as exc:
            inventory.errors.append("%s: %s" % (manifest, _bounded(exc, 512)))
        if len(rows) > MAX_DEPENDENCIES:
            inventory.errors.append("dependency limit of %d exceeded" % MAX_DEPENDENCIES)
            rows = rows[:MAX_DEPENDENCIES]
            break
    inventory.dependencies = _merge_dependencies(rows)
    inventory.manifests.sort()
    inventory.errors.sort()
    inventory.file_hashes = dict(sorted(inventory.file_hashes.items()))
    inventory.lock_coverage = _lock_coverage(base, paths)
    for item in inventory.lock_coverage:
        if item["status"] == "missing":
            inventory.warnings.append("%s has no recognized lockfile" % item["manifest"])
    inventory.warnings.sort()
    return inventory


def _risk(rule_id: str, severity: str, path: str, message: str, evidence: str,
          remediation: str, cwe: str = "CWE-494") -> RiskFinding:
    return RiskFinding(rule_id, severity, path, message, _redact_evidence(evidence, 512), remediation, cwe)


def _source_risks(path: str, name: str, text: str) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    lower_name = name.casefold()
    remote_pipe = re.compile(r"(?i)\b(?:curl|wget)\b[^\n|]{0,1000}\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b")
    for match in remote_pipe.finditer(text):
        findings.append(_risk("scc-remote-script-pipe", "critical", path,
            "remote content is piped directly into a shell", match.group(0),
            "Remove the pipe-to-shell flow; pin, authenticate, verify, and execute a reviewed local artifact."))
    if lower_name == "package.json":
        try:
            data = _json_loads(text)
        except SupplyChainError:
            data = {}
        scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
        if isinstance(scripts, dict):
            for hook in ("preinstall", "install", "postinstall", "prepare"):
                command = scripts.get(hook)
                if isinstance(command, str):
                    severity = "high" if re.search(r"(?i)\b(?:curl|wget|powershell|Invoke-WebRequest)\b", command) else "medium"
                    findings.append(_risk("scc-install-lifecycle-script", severity, path,
                        "npm lifecycle hook '%s' executes during dependency installation" % hook,
                        "%s: %s" % (hook, command),
                        "Remove unnecessary install hooks; otherwise review, sandbox, and constrain their inputs."))
        sections = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
        for section in sections:
            deps = data.get(section, {}) if isinstance(data, dict) else {}
            if not isinstance(deps, dict):
                continue
            for package, spec in deps.items():
                if not isinstance(spec, str):
                    continue
                clean = spec.strip()
                if clean.lower().startswith(CLEARTEXT_HTTP):
                    findings.append(_risk("scc-cleartext-dependency", "high", path,
                        "dependency uses unauthenticated HTTP", "%s=%s" % (package, clean),
                        "Use a trusted HTTPS registry plus lockfile integrity metadata."))
                if clean.startswith(("git+", CLEARTEXT_GIT, "github:", "gitlab:", CLEARTEXT_HTTP, "https://")):
                    revision = clean.rsplit("#", 1)[1] if "#" in clean else ""
                    if not _HEX_COMMIT.fullmatch(revision):
                        findings.append(_risk("scc-mutable-vcs-dependency", "high", path,
                            "VCS dependency is not pinned to an immutable full commit", "%s=%s" % (package, clean),
                            "Pin the reviewed source to a full commit ID and retain lockfile integrity.", "CWE-829"))
                elif clean.lower() in {"*", "latest", "next"}:
                    findings.append(_risk("scc-floating-dependency", "medium", path,
                        "dependency uses a floating version", "%s=%s" % (package, clean),
                        "Declare an intentional range and commit an integrity-bearing lockfile.", "CWE-829"))
    if lower_name in {"package-lock.json", "npm-shrinkwrap.json"}:
        try:
            data = _json_loads(text)
        except SupplyChainError:
            data = {}
        packages = data.get("packages", {}) if isinstance(data, dict) else {}
        if isinstance(packages, dict):
            for key, info in packages.items():
                if not isinstance(info, dict):
                    continue
                resolved = str(info.get("resolved", ""))
                if resolved.lower().startswith(CLEARTEXT_HTTP):
                    findings.append(_risk("scc-lock-cleartext-artifact", "high", path,
                        "lockfile resolves an artifact over HTTP", "%s: %s" % (key, resolved),
                        "Regenerate from a trusted HTTPS registry and verify integrity."))
                if resolved and not info.get("integrity") and not resolved.startswith(("git+", "file:")):
                    findings.append(_risk("scc-lock-missing-integrity", "medium", path,
                        "resolved npm artifact lacks integrity metadata", key,
                        "Regenerate the lockfile with a current package manager and trusted registry."))
    if lower_name.startswith("requirements") and lower_name.endswith(".txt"):
        if re.search(r"(?mi)^\s*--extra-index-url\b", text):
            findings.append(_risk("scc-extra-package-index", "medium", path,
                "an additional Python package index changes dependency trust boundaries", "--extra-index-url",
                "Use one controlled index or prevent dependency confusion with namespace and hash controls.", "CWE-427"))
        for raw in text.splitlines():
            line = raw.strip()
            if line.startswith(("git+", CLEARTEXT_HTTP, "https://")) or " @ git+" in line:
                revision = line.rsplit("@", 1)[-1].split("#", 1)[0]
                if "git+" in line and not _HEX_COMMIT.fullmatch(revision):
                    findings.append(_risk("scc-python-mutable-vcs", "high", path,
                        "Python VCS dependency is not pinned to a full commit", line,
                        "Pin the source to a reviewed full commit and require artifact hashes.", "CWE-829"))
                if line.lower().startswith(CLEARTEXT_HTTP):
                    findings.append(_risk("scc-cleartext-dependency", "high", path,
                        "Python dependency uses HTTP", line,
                        "Use an authenticated HTTPS index and require hashes."))
    if lower_name == "cargo.toml":
        for match in re.finditer(r"(?mi)^\s*[^#\n=]+\s*=\s*\{[^}\n]*\bgit\s*=\s*['\"][^'\"]+['\"][^}\n]*\}", text):
            if not re.search(r"\brev\s*=\s*['\"][0-9a-fA-F]{40,64}['\"]", match.group(0)):
                findings.append(_risk("scc-cargo-mutable-git", "high", path,
                    "Cargo Git dependency lacks an immutable revision", match.group(0),
                    "Set rev to a reviewed full commit and commit Cargo.lock.", "CWE-829"))
    if lower_name in {"build.gradle", "build.gradle.kts", "pom.xml"}:
        for match in re.finditer(r"(?i)(?:latest(?:\.release|\.integration)?|\[[^\]]*,[^\]]*\]|\d+\.\+)", text):
            findings.append(_risk("scc-dynamic-build-dependency", "medium", path,
                "build dependency uses a mutable/dynamic selector", match.group(0),
                "Use a reviewed fixed version and dependency verification/locking.", "CWE-829"))
        cleartext_repository = re.compile(
            r"(?i)\burl\s*[=>( ]+['\"]?" + re.escape(CLEARTEXT_HTTP) + r"[^\s<'\"]+")
        for match in cleartext_repository.finditer(text):
            findings.append(_risk("scc-cleartext-repository", "high", path,
                "build repository uses HTTP", match.group(0),
                "Use a trusted HTTPS repository and artifact verification."))
    if lower_name == "package.swift":
        for match in re.finditer(
                r"\.package\s*\([^)]*\b(?:branch)\s*:\s*['\"][^'\"]+['\"][^)]*\)", text):
            findings.append(_risk("scc-swift-mutable-branch", "high", path,
                "Swift package dependency follows a mutable branch", match.group(0),
                "Pin the reviewed dependency to an exact version or immutable revision.", "CWE-829"))
    if lower_name == ".gitmodules":
        insecure_submodule = re.compile(
            r"(?mi)^\s*url\s*=\s*(?:" + re.escape(CLEARTEXT_HTTP) + "|" +
            re.escape(CLEARTEXT_GIT) + r")[^\s]+")
        for match in insecure_submodule.finditer(text):
            findings.append(_risk("scc-insecure-submodule", "high", path,
                "Git submodule uses an unauthenticated transport", match.group(0),
                "Use HTTPS or SSH and review the committed submodule revision."))
    if "/.github/workflows/" in ("/" + path.casefold()) or lower_name.endswith((".yml", ".yaml")):
        for match in re.finditer(r"(?mi)^\s*-?\s*uses:\s*([^\s#]+)@([^\s#]+)", text):
            action, revision = match.groups()
            if not _HEX_COMMIT.fullmatch(revision):
                findings.append(_risk("scc-mutable-ci-action", "high", path,
                    "CI action is not pinned to an immutable full commit", "%s@%s" % (action, revision),
                    "Pin the reviewed action to a full commit SHA and track updates deliberately.", "CWE-829"))
    if lower_name == "dockerfile":
        for match in re.finditer(r"(?mi)^\s*ADD\s+https?://[^\s]+", text):
            findings.append(_risk("scc-docker-remote-add", "high", path,
                "Docker build downloads a remote artifact without an explicit digest check", match.group(0),
                "Fetch in a controlled step, verify a pinned digest/signature, then copy the local artifact."))
    return findings


def scan_supply_chain_risks(root: str | Path) -> list[RiskFinding]:
    base = Path(root).expanduser().resolve()
    if not base.is_dir():
        return [_risk("scc-invalid-workspace", "high", str(base), "workspace is not a directory", "",
                      "Provide a readable local workspace.", "CWE-20")]
    try:
        paths = _discover(base)
    except SupplyChainError as exc:
        return [_risk("scc-scan-limit", "high", str(base), str(exc), "",
                      "Reduce scan scope or review configured limits.", "CWE-400")]
    findings: list[RiskFinding] = []
    for path in paths:
        try:
            text = _decode_utf8(_read_bounded(path, MAX_MANIFEST_BYTES))
            local = _source_risks(_relative(base, path), path.name, text)
            remaining = MAX_FINDINGS - len(findings)
            if len(local) > remaining:
                findings.extend(local[:max(0, remaining)])
                findings.append(_risk(
                    "scc-finding-limit", "info", _relative(base, path),
                    "supply-chain finding limit reached", "limit=%d" % MAX_FINDINGS,
                    "Narrow the workspace or increase the reviewed limit before rescanning.", "CWE-400"))
                break
            findings.extend(local)
        except SupplyChainError:
            continue
    unique = {(f.rule_id, f.path, f.message, f.evidence): f for f in findings}
    return sorted(unique.values(), key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), f.path, f.rule_id, f.evidence))


def _created(source_date_epoch: int | None = None) -> str:
    if source_date_epoch is None:
        raw = os.environ.get("SOURCE_DATE_EPOCH", "")
        try:
            source_date_epoch = int(raw) if raw else 0
        except ValueError:
            source_date_epoch = 0
    try:
        return _datetime.datetime.fromtimestamp(max(0, source_date_epoch), _datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return DEFAULT_CREATED


def _inventory_digest(inventory: Inventory) -> str:
    material = [{"purl": dep.purl, "scope": dep.scope, "manifests": dep.manifests,
                 "integrity": dep.integrity} for dep in inventory.dependencies]
    return hashlib.sha256(canonical_json(material)).hexdigest()


def _decoded_integrity(values: Iterable[str]) -> list[tuple[str, str]]:
    """Normalize hexadecimal and SRI base64 hashes without weakening semantics."""
    expected = {"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}
    result: set[tuple[str, str]] = set()
    for value in values:
        for token in value.split():
            algorithm = payload = ""
            if ":" in token:
                algorithm, payload = token.split(":", 1)
            elif "-" in token:
                algorithm, payload = token.split("-", 1)
            algorithm = algorithm.lower().replace("-", "")
            size = expected.get(algorithm)
            if not size or not payload:
                continue
            if len(payload) == size * 2 and re.fullmatch(r"[0-9a-fA-F]+", payload):
                result.add((algorithm, payload.lower()))
                continue
            try:
                padding = "=" * (-len(payload) % 4)
                decoded = base64.b64decode(payload + padding, validate=True)
            except (binascii.Error, ValueError):
                continue
            if len(decoded) == size:
                result.add((algorithm, decoded.hex()))
    return sorted(result)


def _license_kind(value: str) -> tuple[str, str]:
    """Classify local license text conservatively without claiming full SPDX validation."""
    clean = value.strip()
    if clean in _SPDX_LICENSE_IDS:
        return "id", clean
    expression = re.fullmatch(r"[A-Za-z0-9.+() -]+", clean)
    tokens = re.findall(r"[A-Za-z0-9][A-Za-z0-9.+-]*", clean)
    license_tokens = [token for token in tokens if token not in {"AND", "OR", "WITH"}]
    if (expression and any(token in {"AND", "OR", "WITH"} for token in tokens)
            and license_tokens and all(token in _SPDX_LICENSE_IDS for token in license_tokens)):
        return "expression", clean
    return "name", _bounded(clean, 256)


def build_cyclonedx(inventory: Inventory, *, source_date_epoch: int | None = None) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    for dep in inventory.dependencies:
        component: dict[str, Any] = {
            "type": "library", "bom-ref": dep.bom_ref, "name": dep.name, "purl": dep.purl,
            "scope": "excluded" if dep.scope == "development" else "required",
            "properties": [
                {"name": "attestor:ecosystem", "value": dep.ecosystem},
                {"name": "attestor:declared-scope", "value": dep.scope},
                {"name": "attestor:version-state", "value": "resolved" if dep.version else "unknown"},
                {"name": "attestor:manifests", "value": ",".join(dep.manifests)},
            ],
        }
        if dep.version:
            component["version"] = dep.version
        if dep.integrity:
            hashes = []
            for algorithm, digest in _decoded_integrity(dep.integrity):
                hashes.append({"alg": algorithm.upper().replace("SHA", "SHA-"),
                               "content": digest})
            if hashes:
                component["hashes"] = hashes
        if dep.licenses:
            licenses = []
            for value in dep.licenses:
                kind, clean = _license_kind(value)
                if kind == "expression" and len(dep.licenses) == 1:
                    licenses.append({"expression": clean})
                else:
                    licenses.append({"license": {"id": clean} if kind == "id" else {"name": clean}})
            component["licenses"] = licenses
        components.append(component)
    digest = _inventory_digest(inventory)
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX", "specVersion": "1.7",
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "attestor:inventory:" + digest)),
        "version": 1,
        "metadata": {
            "timestamp": _created(source_date_epoch),
            "tools": {"components": [{"type": "application", "name": "Attestor Supply-Chain Center", "version": VERSION}]},
            "component": {"type": "application", "name": Path(inventory.root).name},
            "properties": [{"name": "attestor:inventory-status", "value": "partial" if inventory.errors else "complete"}],
        },
        "components": components,
    }


def _spdx_id(value: str, used: set[str]) -> str:
    base = "SPDXRef-" + re.sub(r"[^A-Za-z0-9.-]+", "-", value).strip("-")[:100]
    base = base if base != "SPDXRef-" else "SPDXRef-Package"
    candidate = base
    count = 2
    while candidate in used:
        candidate = "%s-%d" % (base, count)
        count += 1
    used.add(candidate)
    return candidate


def build_spdx_2_3(inventory: Inventory, *, source_date_epoch: int | None = None) -> dict[str, Any]:
    """Build the explicitly legacy SPDX 2.3 JSON serialization."""
    digest = _inventory_digest(inventory)
    namespace = "https://attestor.local/spdx/%s" % digest
    used = {"SPDXRef-DOCUMENT", "SPDXRef-Root"}
    packages: list[dict[str, Any]] = [{
        "SPDXID": "SPDXRef-Root", "name": Path(inventory.root).name,
        "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }]
    relationships: list[dict[str, str]] = [{
        "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
        "relatedSpdxElement": "SPDXRef-Root",
    }]
    for dep in inventory.dependencies:
        identifier = _spdx_id(dep.ecosystem + "-" + dep.name + "-" + (dep.version or "unknown"), used)
        license_values = [_license_kind(value) for value in dep.licenses]
        valid_expression = (license_values[0][1] if len(license_values) == 1
                            and license_values[0][0] in {"id", "expression"} else "")
        raw_license_note = "; declared licenses: " + ", ".join(dep.licenses) if dep.licenses else ""
        package: dict[str, Any] = {
            "SPDXID": identifier, "name": dep.name, "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False, "licenseConcluded": "NOASSERTION",
            "licenseDeclared": valid_expression or "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": dep.purl}],
            "comment": "Declared scope: %s; local manifests: %s%s" %
                       (dep.scope, ", ".join(dep.manifests), raw_license_note),
        }
        if dep.version:
            package["versionInfo"] = dep.version
        packages.append(package)
        relationships.append({"spdxElementId": "SPDXRef-Root", "relationshipType": "DEPENDS_ON",
                              "relatedSpdxElement": identifier})
    return {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Attestor-SBOM-%s" % Path(inventory.root).name,
        "documentNamespace": namespace,
        "creationInfo": {"created": _created(source_date_epoch),
                         "creators": ["Tool: Attestor-Supply-Chain-Center-%s" % VERSION]},
        "packages": packages, "relationships": relationships,
        "documentDescribes": ["SPDXRef-Root"],
    }


def _spdx3_identifier(namespace: str, kind: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]
    return "%s/%s/%s" % (namespace, kind, digest)


def _spdx3_hashes(dep: Dependency) -> list[dict[str, str]]:
    return [{"type": "Hash", "algorithm": algorithm, "hashValue": digest}
            for algorithm, digest in _decoded_integrity(dep.integrity)]


def validate_spdx_3_shape(document: Mapping[str, Any]) -> list[str]:
    """Validate Attestor's emitted SPDX 3.0.1 subset before claiming that serialization.

    This enforces the mandatory context, typed graph, creation information, unique
    identifiers, and referential integrity used by Attestor's Core, Software, and Simple
    Licensing profile subset.  Full third-party semantic/SHACL validation remains a
    consumer or CI responsibility and is not misrepresented here.
    """
    errors: list[str] = []
    if document.get("@context") != "https://spdx.org/rdf/3.0.1/spdx-context.jsonld":
        errors.append("invalid SPDX 3.0.1 JSON-LD context")
    graph = document.get("@graph")
    if not isinstance(graph, list) or not graph:
        return errors + ["@graph must be a non-empty array"]
    allowed_types = {
        "CreationInfo", "Agent", "Tool", "software_Package", "Relationship",
        "simplelicensing_LicenseExpression", "software_Sbom", "SpdxDocument",
    }
    allowed_keys = {
        "CreationInfo": {"type", "@id", "comment", "created", "createdBy", "createdUsing", "specVersion"},
        "Agent": {"type", "spdxId", "creationInfo", "name", "comment", "summary", "description"},
        "Tool": {"type", "spdxId", "creationInfo", "name", "comment", "summary", "description"},
        "software_Package": {"type", "spdxId", "creationInfo", "name", "comment", "summary",
                             "description", "software_packageUrl", "software_packageVersion",
                             "software_downloadLocation", "verifiedUsing"},
        "Relationship": {"type", "spdxId", "creationInfo", "name", "comment", "summary",
                         "description", "from", "relationshipType", "to", "completeness"},
        "simplelicensing_LicenseExpression": {"type", "spdxId", "creationInfo", "name", "comment",
                                              "summary", "description",
                                              "simplelicensing_licenseExpression",
                                              "simplelicensing_licenseListVersion"},
        "software_Sbom": {"type", "spdxId", "creationInfo", "name", "comment", "summary",
                          "description", "profileConformance", "software_sbomType", "element", "rootElement"},
        "SpdxDocument": {"type", "spdxId", "creationInfo", "name", "comment", "summary",
                         "description", "dataLicense", "profileConformance", "element", "rootElement",
                         "namespaceMap", "import"},
    }
    by_id: dict[str, Mapping[str, Any]] = {}
    documents = 0
    sboms = 0
    for index, item in enumerate(graph):
        if not isinstance(item, dict):
            errors.append("graph item %d is not an object" % index)
            continue
        item_type = item.get("type")
        if not isinstance(item_type, str) or item_type not in allowed_types:
            errors.append("graph item %d has an unsupported type" % index)
            continue
        unexpected = sorted(str(key) for key in set(item) - allowed_keys[item_type])
        if unexpected:
            errors.append("%s contains unsupported fields: %s" %
                          (item_type, ",".join(unexpected)))
        if item_type == "SpdxDocument":
            documents += 1
        if item_type == "software_Sbom":
            sboms += 1
        identifier = item.get("spdxId", item.get("@id"))
        if not isinstance(identifier, str) or not identifier:
            errors.append("graph item %d has no identifier" % index)
        elif identifier in by_id:
            errors.append("duplicate SPDX identifier: %s" % identifier)
        else:
            by_id[identifier] = item
    if documents != 1:
        errors.append("serialization must contain exactly one SpdxDocument")
    if sboms != 1:
        errors.append("serialization must contain exactly one software_Sbom")
    creation_ids = {identifier for identifier, item in by_id.items()
                    if item.get("type") == "CreationInfo"}
    for identifier, item in by_id.items():
        item_type = item.get("type")
        if item_type == "CreationInfo":
            if item.get("specVersion") != "3.0.1":
                errors.append("CreationInfo must declare specVersion 3.0.1")
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", str(item.get("created", ""))):
                errors.append("CreationInfo has an invalid canonical timestamp")
            for key in ("createdBy", "createdUsing"):
                refs = item.get(key, [])
                if key == "createdBy" and (not isinstance(refs, list) or not refs):
                    errors.append("CreationInfo.createdBy is required")
                elif isinstance(refs, list):
                    for ref in refs:
                        if not isinstance(ref, str) or ref not in by_id:
                            errors.append("unresolved %s reference: %s" % (key, ref))
            continue
        if item.get("creationInfo") not in creation_ids:
            errors.append("%s has no resolvable CreationInfo" % identifier)
        for key in ("element", "rootElement", "to"):
            refs = item.get(key, [])
            if refs is not None and not isinstance(refs, list):
                errors.append("%s.%s must be an array" % (identifier, key))
                continue
            for ref in refs or []:
                if not isinstance(ref, str) or ref not in by_id:
                    errors.append("unresolved %s reference: %s" % (key, ref))
        if item_type == "Relationship":
            source = item.get("from")
            if not isinstance(source, str) or source not in by_id:
                errors.append("unresolved relationship source: %s" % item.get("from"))
            if not item.get("to"):
                errors.append("relationship has no target")
            if item.get("relationshipType") not in {"dependsOn", "hasOptionalDependency",
                                                     "hasDeclaredLicense"}:
                errors.append("relationship uses an unsupported type")
        if item_type == "software_Package":
            purl = item.get("software_packageUrl")
            if purl is not None and (not isinstance(purl, str) or not purl.startswith("pkg:")):
                errors.append("package has an invalid package URL")
            hashes = item.get("verifiedUsing", [])
            if hashes is not None and not isinstance(hashes, list):
                errors.append("package verifiedUsing must be an array")
            for value in hashes if isinstance(hashes, list) else []:
                if (not isinstance(value, dict) or set(value) != {"type", "algorithm", "hashValue"}
                        or value.get("type") != "Hash"
                        or value.get("algorithm") not in {"sha1", "sha256", "sha384", "sha512"}
                        or not re.fullmatch(r"[0-9a-f]+", str(value.get("hashValue", "")))):
                    errors.append("package has invalid hash evidence")
        if item_type == "simplelicensing_LicenseExpression" and not item.get("simplelicensing_licenseExpression"):
            errors.append("license expression node has no expression")
    return sorted(set(errors))


def build_spdx_3_0_1(inventory: Inventory, *, source_date_epoch: int | None = None) -> dict[str, Any]:
    """Build a deterministic SPDX 3.0.1 JSON-LD Software SBOM subset."""
    digest = _inventory_digest(inventory)
    namespace = "https://attestor.local/spdx/3.0.1/%s" % digest
    creation_id = "_:attestor-creation-" + digest[:16]
    agent_id = namespace + "/agent/attestor"
    tool_id = namespace + "/tool/supply-chain-center"
    document_id = namespace + "/document"
    sbom_id = namespace + "/sbom"
    root_id = namespace + "/package/root"
    created = _created(source_date_epoch)

    graph: list[dict[str, Any]] = [{
        "type": "CreationInfo", "@id": creation_id, "created": created,
        "createdBy": [agent_id], "createdUsing": [tool_id], "specVersion": "3.0.1",
        "comment": "Deterministic offline manifest inventory; SOURCE_DATE_EPOCH controls the timestamp.",
    }, {
        "type": "Agent", "spdxId": agent_id, "creationInfo": creation_id,
        "name": "Attestor",
    }, {
        "type": "Tool", "spdxId": tool_id, "creationInfo": creation_id,
        "name": "Attestor Supply-Chain Center %s" % VERSION,
    }]
    root_package: dict[str, Any] = {
        "type": "software_Package", "spdxId": root_id, "creationInfo": creation_id,
        "name": Path(inventory.root).name,
        "comment": "Local source workspace; inventory status: %s."
                   % ("partial" if inventory.errors else "complete"),
    }
    graph.append(root_package)
    package_ids: list[str] = []
    relationship_ids: list[str] = []
    license_ids: dict[str, str] = {}

    for dep in inventory.dependencies:
        package_id = _spdx3_identifier(namespace, "package", dep.purl)
        package_ids.append(package_id)
        unknown_licenses = [value for value in dep.licenses if _license_kind(value)[0] == "name"]
        comment = "scope=%s; direct=%s; manifests=%s; version-state=%s" % (
            dep.scope, str(dep.direct).lower(), ",".join(dep.manifests),
            "resolved" if dep.version else "unknown",
        )
        if unknown_licenses:
            comment += "; unmodeled declared-license text=" + ",".join(unknown_licenses)
        package: dict[str, Any] = {
            "type": "software_Package", "spdxId": package_id,
            "creationInfo": creation_id, "name": dep.name,
            "software_packageUrl": dep.purl, "comment": _bounded(comment, 2048),
        }
        if dep.version:
            package["software_packageVersion"] = dep.version
        hashes = _spdx3_hashes(dep)
        if hashes:
            package["verifiedUsing"] = hashes
        graph.append(package)

        relation_id = _spdx3_identifier(namespace, "relationship", "dependency:" + dep.purl)
        relationship_ids.append(relation_id)
        graph.append({
            "type": "Relationship", "spdxId": relation_id, "creationInfo": creation_id,
            "from": root_id,
            "relationshipType": "hasOptionalDependency" if dep.scope in {"optional", "peer"} else "dependsOn",
            "to": [package_id], "comment": "Dependency scope declared as %s." % dep.scope,
        })

        for license_text in dep.licenses:
            kind, expression = _license_kind(license_text)
            if kind == "name":
                continue
            license_id = license_ids.get(expression)
            if license_id is None:
                license_id = _spdx3_identifier(namespace, "license", expression)
                license_ids[expression] = license_id
                graph.append({
                    "type": "simplelicensing_LicenseExpression", "spdxId": license_id,
                    "creationInfo": creation_id, "name": expression,
                    "simplelicensing_licenseExpression": expression,
                })
            license_relation = _spdx3_identifier(
                namespace, "relationship", "license:%s:%s" % (dep.purl, expression))
            relationship_ids.append(license_relation)
            graph.append({
                "type": "Relationship", "spdxId": license_relation,
                "creationInfo": creation_id, "from": package_id,
                "relationshipType": "hasDeclaredLicense", "to": [license_id],
            })

    license_element_ids = sorted(license_ids.values())
    sbom_elements = [root_id] + package_ids + license_element_ids + relationship_ids
    graph.append({
        "type": "software_Sbom", "spdxId": sbom_id, "creationInfo": creation_id,
        "name": "Attestor-SBOM-%s" % Path(inventory.root).name,
        "profileConformance": ["core", "simpleLicensing", "software"],
        "software_sbomType": ["source"], "element": sbom_elements,
        "rootElement": [root_id],
        "comment": "Generated statically without installing or executing target dependencies.",
    })
    document_elements = [agent_id, tool_id, sbom_id] + sbom_elements
    graph.append({
        "type": "SpdxDocument", "spdxId": document_id, "creationInfo": creation_id,
        "name": "Attestor-SPDX-3.0.1-%s" % Path(inventory.root).name,
        "dataLicense": "https://spdx.org/licenses/CC0-1.0",
        "profileConformance": ["core", "simpleLicensing", "software"],
        "element": document_elements, "rootElement": [sbom_id],
    })
    document = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": graph,
    }
    errors = validate_spdx_3_shape(document)
    if errors:
        raise SupplyChainError("internal SPDX 3.0.1 shape error: " + "; ".join(errors[:10]))
    return document


def build_spdx(inventory: Inventory, *, source_date_epoch: int | None = None) -> dict[str, Any]:
    """Build Attestor's primary SPDX export (SPDX 3.0.1 JSON-LD)."""
    return build_spdx_3_0_1(inventory, source_date_epoch=source_date_epoch)


def _without_signature(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in snapshot.items() if key != "signature"}


def sign_advisory_snapshot(snapshot: Mapping[str, Any], key: bytes, key_id: str) -> dict[str, Any]:
    """Authenticate a deterministic snapshot using a caller-managed HMAC key."""
    if not isinstance(key, bytes) or len(key) < 32:
        raise SupplyChainError("HMAC key must contain at least 32 bytes")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", key_id or ""):
        raise SupplyChainError("invalid key ID")
    unsigned = _without_signature(dict(snapshot))
    if unsigned.get("schema") != SNAPSHOT_SCHEMA:
        raise SupplyChainError("unsupported advisory snapshot schema")
    _validate_snapshot_structure(unsigned)
    digest = hmac.new(key, canonical_json(unsigned), hashlib.sha256).hexdigest()
    return {**unsigned, "signature": {"algorithm": "hmac-sha256", "key_id": key_id, "digest": digest}}


def _parse_time(value: Any, field_name: str) -> _datetime.datetime:
    if not isinstance(value, str) or not value:
        raise SupplyChainError("%s must be an ISO-8601 UTC timestamp" % field_name)
    clean = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = _datetime.datetime.fromisoformat(clean)
    except ValueError as exc:
        raise SupplyChainError("%s is not a valid ISO-8601 timestamp" % field_name) from exc
    if parsed.tzinfo is None:
        raise SupplyChainError("%s must include a timezone" % field_name)
    return parsed.astimezone(_datetime.timezone.utc)


def _validate_snapshot_structure(snapshot: Mapping[str, Any]) -> None:
    _safe_json_depth(snapshot)
    if snapshot.get("schema") != SNAPSHOT_SCHEMA:
        raise SupplyChainError("unsupported advisory snapshot schema")
    generated = _parse_time(snapshot.get("generated_at"), "generated_at")
    if snapshot.get("expires_at"):
        expires = _parse_time(snapshot.get("expires_at"), "expires_at")
        if expires <= generated:
            raise SupplyChainError("expires_at must be later than generated_at")
    source = snapshot.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("name"), str) or not source.get("name"):
        raise SupplyChainError("snapshot source.name is required")
    for key, value in source.items():
        if not isinstance(key, str) or not isinstance(value, (str, int, float, bool, type(None))):
            raise SupplyChainError("snapshot source fields must be scalar values")
        if len(str(value)) > MAX_TEXT_FIELD:
            raise SupplyChainError("snapshot source field is oversized")
    advisories = snapshot.get("advisories")
    if not isinstance(advisories, list):
        raise SupplyChainError("snapshot advisories must be a list")
    if len(advisories) > MAX_ADVISORIES:
        raise SupplyChainError("advisory limit of %d exceeded" % MAX_ADVISORIES)
    seen: set[str] = set()
    for index, advisory in enumerate(advisories):
        if not isinstance(advisory, dict):
            raise SupplyChainError("advisory %d must be an object" % index)
        advisory_id = advisory.get("id")
        if not isinstance(advisory_id, str) or not advisory_id or len(advisory_id) > 256:
            raise SupplyChainError("advisory %d has an invalid ID" % index)
        if advisory_id in seen:
            raise SupplyChainError("duplicate advisory ID: %s" % _bounded(advisory_id, 128))
        seen.add(advisory_id)
        package = advisory.get("package")
        if not isinstance(package, dict):
            raise SupplyChainError("advisory %s has no package object" % advisory_id)
        ecosystem = package.get("ecosystem")
        name = package.get("name")
        if not isinstance(ecosystem, str) or not isinstance(name, str):
            raise SupplyChainError("advisory %s package is invalid" % advisory_id)
        make_purl(ecosystem, name)
        summary = advisory.get("summary", "")
        severity = advisory.get("severity", "unknown")
        aliases = advisory.get("aliases", [])
        fixed_versions = advisory.get("fixed_versions", [])
        if not isinstance(summary, str) or len(summary) > MAX_TEXT_FIELD:
            raise SupplyChainError("advisory %s summary is invalid" % advisory_id)
        if not isinstance(severity, str) or severity.lower() not in {"critical", "high", "medium", "low", "info", "unknown"}:
            raise SupplyChainError("advisory %s severity is invalid" % advisory_id)
        for field_name, values in (("aliases", aliases), ("fixed_versions", fixed_versions)):
            if (not isinstance(values, list) or len(values) > 256 or
                    not all(isinstance(item, str) and len(item) <= 512 for item in values)):
                raise SupplyChainError("advisory %s %s are invalid" % (advisory_id, field_name))
        versions = advisory.get("versions", [])
        ranges = advisory.get("ranges", [])
        if (not isinstance(versions, list) or len(versions) > 10_000 or
                not all(isinstance(item, str) and len(item) <= 512 for item in versions)):
            raise SupplyChainError("advisory %s versions are invalid" % advisory_id)
        if not isinstance(ranges, list) or len(ranges) > 128:
            raise SupplyChainError("advisory %s ranges are invalid" % advisory_id)
        for item in ranges:
            if not isinstance(item, dict) or not set(item) <= {"introduced", "fixed", "last_affected"}:
                raise SupplyChainError("advisory %s has an invalid range" % advisory_id)
            if not all(isinstance(value, str) and len(value) <= 512 for value in item.values()):
                raise SupplyChainError("advisory %s has invalid range values" % advisory_id)
        if not isinstance(advisory.get("all_versions", False), bool):
            raise SupplyChainError("advisory %s all_versions must be boolean" % advisory_id)
        if not versions and not ranges and not advisory.get("all_versions", False):
            raise SupplyChainError("advisory %s declares no affected versions" % advisory_id)


def load_advisory_snapshot(path: str | Path) -> dict[str, Any]:
    data = _read_bounded(Path(path), MAX_SNAPSHOT_BYTES)
    value = _json_loads(_decode_utf8(data))
    if not isinstance(value, dict):
        raise SupplyChainError("advisory snapshot root must be an object")
    return value


def verify_advisory_snapshot(snapshot: Mapping[str, Any], trusted_keys: Mapping[str, bytes],
                             *, now: _datetime.datetime | None = None) -> SnapshotVerification:
    errors: list[str] = []
    key_id = generated_at = expires_at = ""
    try:
        _validate_snapshot_structure(snapshot)
        generated_at = str(snapshot.get("generated_at", ""))
        expires_at = str(snapshot.get("expires_at", ""))
        signature = snapshot.get("signature")
        if not isinstance(signature, dict):
            raise SupplyChainError("snapshot has no authentication signature")
        if signature.get("algorithm") != "hmac-sha256":
            raise SupplyChainError("unsupported snapshot signature algorithm")
        key_id = str(signature.get("key_id", ""))
        key = trusted_keys.get(key_id)
        if not isinstance(key, bytes) or len(key) < 32:
            raise SupplyChainError("snapshot key is not trusted")
        digest = signature.get("digest")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise SupplyChainError("snapshot signature digest is invalid")
        expected = hmac.new(key, canonical_json(_without_signature(snapshot)), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, digest):
            raise SupplyChainError("snapshot authentication failed")
        current = now or _datetime.datetime.now(_datetime.timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=_datetime.timezone.utc)
        current = current.astimezone(_datetime.timezone.utc)
        generated = _parse_time(generated_at, "generated_at")
        if generated > current + _datetime.timedelta(minutes=5):
            return SnapshotVerification(True, True, "future-dated", key_id, generated_at, expires_at,
                                        ("snapshot generation time is in the future",))
        if expires_at and _parse_time(expires_at, "expires_at") <= current:
            return SnapshotVerification(True, True, "stale", key_id, generated_at, expires_at,
                                        ("snapshot has expired",))
        if not expires_at:
            return SnapshotVerification(True, True, "expiry-unknown", key_id, generated_at, expires_at,
                                        ("snapshot has no expiry time",))
        return SnapshotVerification(True, True, "fresh", key_id, generated_at, expires_at)
    except (SupplyChainError, TypeError, ValueError) as exc:
        errors.append(_bounded(exc, 512))
        return SnapshotVerification(False, False, "invalid", key_id, generated_at, expires_at, tuple(errors))


def _version_key(value: str) -> tuple[tuple[int, Any], ...]:
    result: list[tuple[int, Any]] = []
    for token in re.findall(r"\d+|[A-Za-z]+", value.lstrip("v")):
        result.append((0, int(token)) if token.isdigit() else (1, token.casefold()))
    return tuple(result)


def _range_match(version: str, ranges: Sequence[Mapping[str, Any]]) -> bool | None:
    comparable = re.compile(r"^[vV]?\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?$")
    if not version or not comparable.fullmatch(version):
        return None
    current = _version_key(version)
    if not current:
        return None
    for item in ranges:
        introduced = str(item.get("introduced", "0"))
        fixed = str(item.get("fixed", ""))
        last = str(item.get("last_affected", ""))
        if ((introduced not in {"", "0"} and not comparable.fullmatch(introduced))
                or (fixed and not comparable.fullmatch(fixed))
                or (last and not comparable.fullmatch(last))):
            return None
        lower_ok = introduced in {"", "0"} or current >= _version_key(introduced)
        upper_ok = (not fixed or current < _version_key(fixed)) and (not last or current <= _version_key(last))
        if lower_ok and upper_ok:
            return True
    return False


def assess_advisories(inventory: Inventory, snapshot: Mapping[str, Any] | None = None,
                      trusted_keys: Mapping[str, bytes] | None = None,
                      *, now: _datetime.datetime | None = None,
                      reachability: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Match authenticated local advisory data; never fetches or claims live status."""
    reach = normalize_reachability(inventory, reachability or {})
    if snapshot is None:
        return {
            "state": "unavailable", "live_status": False,
            "message": "No advisory snapshot was provided; vulnerability status is unknown.",
            "verification": {"valid": False, "authenticated": False, "state": "not-provided"},
            "dependencies": [{"purl": dep.purl, "status": "unknown", "advisories": [],
                              "reachability": reach[dep.purl]} for dep in inventory.dependencies],
        }
    verification = verify_advisory_snapshot(snapshot, trusted_keys or {}, now=now)
    if not verification.valid:
        return {
            "state": "invalid", "live_status": False,
            "message": "Advisory snapshot could not be authenticated; results are unknown.",
            "verification": verification.to_dict(),
            "dependencies": [{"purl": dep.purl, "status": "unknown", "advisories": [],
                              "reachability": reach[dep.purl]} for dep in inventory.dependencies],
        }
    advisories = snapshot.get("advisories", [])
    results: list[dict[str, Any]] = []
    for dep in inventory.dependencies:
        matches: list[dict[str, Any]] = []
        indeterminate_range = False
        base_purl = make_purl(dep.ecosystem, dep.name)
        for advisory in advisories:
            package = advisory["package"]
            if make_purl(str(package["ecosystem"]), str(package["name"])) != base_purl:
                continue
            exact_versions = advisory.get("versions", [])
            range_result = _range_match(dep.version, advisory.get("ranges", []))
            if advisory.get("ranges") and range_result is None:
                indeterminate_range = True
            affected = bool(advisory.get("all_versions", False)) or bool(dep.version and dep.version in exact_versions) or range_result is True
            if affected:
                matches.append({
                    "id": advisory["id"], "summary": _bounded(advisory.get("summary", ""), 512),
                    "severity": str(advisory.get("severity", "unknown")).lower(),
                    "aliases": sorted(str(item) for item in advisory.get("aliases", []) if isinstance(item, str)),
                    "fixed_versions": sorted(str(item) for item in advisory.get("fixed_versions", []) if isinstance(item, str)),
                })
        matches.sort(key=lambda item: item["id"])
        results.append({
            "purl": dep.purl,
            "status": ("affected" if matches else "range_evaluation_unknown" if indeterminate_range
                       else "unknown_version" if not dep.version else "no_match_in_snapshot"),
            "advisories": matches,
            "reachability": reach[dep.purl],
            "caveat": "No match is not proof of safety; this is an authenticated offline snapshot, not a live feed." if not matches else "",
        })
    return {
        "state": verification.state, "live_status": False,
        "message": "Authenticated offline snapshot assessed; this is not live registry/advisory status.",
        "source": {str(key): _redact_evidence(value, 1024)
                   for key, value in sorted(snapshot.get("source", {}).items())},
        "verification": verification.to_dict(), "dependencies": results,
        "affected": sum(item["status"] == "affected" for item in results),
    }


def verify_exhaustive_reachability_proof(proof: Any,
                                         component_id: str | None = None) -> bool:
    """Verify the exact 4.1 proof contract used for a not-affected decision.

    This validates content addresses and exhaustive scope.  It intentionally
    does not treat a boolean, a state string, or an unsigned tool assertion as
    evidence that vulnerable code cannot execute.
    """
    try:
        if type(proof) is not dict or proof.get("schema") != REACHABILITY_PROOF_SCHEMA:
            return False
        if type(proof.get("reachable")) is not bool:
            return False
        proof_component = proof.get("component_id")
        if (not isinstance(proof_component, str) or not proof_component or
                len(proof_component) > 500):
            return False
        if component_id is not None and proof_component != str(component_id)[:500]:
            return False
        digest = proof.get("proof_sha256")
        body = {key: value for key, value in proof.items() if key != "proof_sha256"}
        if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or
                not hmac.compare_digest(
                    digest, hashlib.sha256(canonical_json(body)).hexdigest())):
            return False
        for name in ("analysis_sha256", "inventory_sha256", "entrypoints_sha256",
                     "scope_sha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", str(proof.get(name, ""))):
                return False
        if (proof["analysis_sha256"] == "0" * 64 or
                proof["inventory_sha256"] == "0" * 64):
            return False
        entries = proof.get("entrypoints")
        chains = proof.get("call_chains")
        if (type(entries) is not list or not entries or len(entries) > 2_000 or
                any(not isinstance(item, str) or not item or len(item) > 300
                    for item in entries) or
                entries != sorted(set(entries)) or type(chains) is not list or
                len(chains) > 2_000 or
                any(type(chain) is not list or not 2 <= len(chain) <= 64 or
                    any(not isinstance(item, str) or not item or len(item) > 300
                        for item in chain)
                    for chain in chains) or
                proof.get("method") != "attestor-call-graph/4.1" or
                type(proof.get("exhaustive")) is not bool):
            return False
        entry_digest = hashlib.sha256(canonical_json(entries)).hexdigest()
        if not hmac.compare_digest(str(proof["entrypoints_sha256"]), entry_digest):
            return False
        scope = {"component_id": proof_component,
                 "analysis_sha256": proof["analysis_sha256"],
                 "inventory_sha256": proof["inventory_sha256"],
                 "entrypoints_sha256": proof["entrypoints_sha256"]}
        scope_digest = hashlib.sha256(canonical_json(scope)).hexdigest()
        if not hmac.compare_digest(str(proof["scope_sha256"]), scope_digest):
            return False
        if proof["reachable"]:
            return (proof["exhaustive"] is False and
                    any(chain[0] in entries for chain in chains))
        concrete = [item for item in entries if item != "<all-observed-entrypoints>"]
        return (proof["exhaustive"] is True and not chains and bool(concrete) and
                "<all-observed-entrypoints>" in entries)
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def _verified_unreachable(row: Any, component_id: str | None = None) -> bool:
    if type(row) is not dict or row.get("status") != "unreachable":
        return False
    proof = row.get("proof")
    return bool(verify_exhaustive_reachability_proof(proof, component_id) and
                proof.get("reachable") is False)


def normalize_reachability(inventory: Inventory, evidence: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Normalize caller/static-tool reachability evidence without importing target code."""
    result: dict[str, dict[str, Any]] = {}
    for dep in inventory.dependencies:
        raw = evidence.get(dep.purl, evidence.get(make_purl(dep.ecosystem, dep.name), evidence.get(dep.name)))
        status = "unknown"
        reason = "no reachability evidence was provided"
        source = "none"
        proof: dict[str, Any] | None = None
        if isinstance(raw, bool):
            status = "reachable" if raw else "unknown"
            reason = ("caller supplied a conservative reachable result" if raw else
                      "caller boolean cannot prove exhaustive unreachability")
            source = "caller"
        elif isinstance(raw, str) and raw.lower() in _REACHABILITY_STATES:
            status = raw.lower() if raw.lower() != "unreachable" else "unknown"
            reason = ("caller supplied a reachability state" if status != "unknown" else
                      "caller state cannot prove exhaustive unreachability")
            source = "caller"
        elif isinstance(raw, dict):
            proposed = str(raw.get("status", "unknown")).lower()
            candidate = raw.get("proof")
            if candidate is None and raw.get("schema") == REACHABILITY_PROOF_SCHEMA:
                candidate = raw
            if (verify_exhaustive_reachability_proof(candidate, dep.purl) and
                    candidate.get("reachable") is False):
                status = "unreachable"
                proof = dict(candidate)
                reason = "content-addressed exhaustive reachability proof verified"
                source = _bounded(raw.get("source") or "attestor-call-graph/4.1", 128)
            elif proposed == "reachable":
                status = proposed
                reason = _bounded(raw.get("reason") or "external static-analysis evidence", 512)
                source = _bounded(raw.get("source") or "external-hook", 128)
            elif proposed == "unreachable" or candidate is not None:
                reason = "unreachable claim lacks a valid content-addressed exhaustive proof"
                source = _bounded(raw.get("source") or "unverified-external-hook", 128)
            else:
                # Preserve an explicit unknown/tool-error disposition without
                # accidentally upgrading it to evidence of non-reachability.
                reason = _bounded(raw.get("reason") or "external analysis returned unknown", 512)
                source = _bounded(raw.get("source") or "external-hook", 128)
        result[dep.purl] = {"status": status, "reason": reason, "source": source,
                            "evidence_state": "verified" if proof else "unverified",
                            "proof_sha256": proof.get("proof_sha256", "") if proof else "",
                            "proof": proof}
    return result


def run_reachability_hook(inventory: Inventory, hook: Callable[[Dependency], Any]) -> dict[str, dict[str, Any]]:
    """Run an explicitly supplied analysis hook.  Attestor never supplies target imports here."""
    evidence: dict[str, Any] = {}
    for dep in inventory.dependencies:
        try:
            evidence[dep.purl] = hook(dep)
        except Exception as exc:  # Hooks are untrusted extension points; preserve unknown state.
            evidence[dep.purl] = {"status": "unknown", "source": "hook-error",
                                  "reason": "%s: %s" % (type(exc).__name__, _bounded(exc, 256))}
    return normalize_reachability(inventory, evidence)


def build_cyclonedx_vex(inventory: Inventory, assessment: Mapping[str, Any],
                        *, source_date_epoch: int | None = None) -> dict[str, Any]:
    vulnerabilities: list[dict[str, Any]] = []
    for item in assessment.get("dependencies", []):
        for advisory in item.get("advisories", []):
            reachability = item.get("reachability", {})
            unreachable = _verified_unreachable(reachability, item.get("purl"))
            reach = "unreachable" if unreachable else reachability.get("status", "unknown")
            state = "not_affected" if unreachable else "in_triage"
            detail = ("Static reachability evidence reports the component unreachable."
                      if reach == "unreachable" else "Reachability/exploitability requires review.")
            vulnerabilities.append({
                "bom-ref": "urn:attestor:vulnerability:" + quote(str(advisory["id"]), safe=".-_"),
                "id": advisory["id"],
                "source": {"name": str(assessment.get("source", {}).get("name", "offline-snapshot"))},
                "ratings": [{"severity": advisory.get("severity", "unknown")}],
                "affects": [{"ref": item["purl"]}],
                "analysis": {"state": state, "justification": "code_not_reachable" if unreachable else "requires_environment",
                             "detail": detail},
            })
    vulnerabilities.sort(key=lambda item: (item["id"], item["affects"][0]["ref"]))
    affected_refs = {item["affects"][0]["ref"] for item in vulnerabilities}
    components: list[dict[str, Any]] = []
    for dep in inventory.dependencies:
        if dep.purl not in affected_refs:
            continue
        component: dict[str, Any] = {
            "type": "library", "bom-ref": dep.purl, "name": dep.name, "purl": dep.purl,
        }
        if dep.version:
            component["version"] = dep.version
        components.append(component)
    digest = hashlib.sha256(canonical_json({"components": components,
                                            "vulnerabilities": vulnerabilities})).hexdigest()
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX", "specVersion": "1.7",
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "attestor:vex:" + digest)),
        "version": 1,
        "metadata": {"timestamp": _created(source_date_epoch),
                     "tools": {"components": [{"type": "application", "name": "Attestor Supply-Chain Center", "version": VERSION}]},
                     "properties": [{"name": "attestor:advisory-state", "value": str(assessment.get("state", "unknown"))},
                                    {"name": "attestor:live-status", "value": "false"}]},
        "components": components, "vulnerabilities": vulnerabilities,
    }


def build_openvex(inventory: Inventory, assessment: Mapping[str, Any],
                  *, source_date_epoch: int | None = None) -> dict[str, Any]:
    statements: list[dict[str, Any]] = []
    for item in assessment.get("dependencies", []):
        for advisory in item.get("advisories", []):
            reachability = item.get("reachability", {})
            unreachable = _verified_unreachable(reachability, item.get("purl"))
            statement: dict[str, Any] = {
                "vulnerability": {"name": advisory["id"]},
                "products": [{"@id": item["purl"]}],
                "status": "not_affected" if unreachable else "under_investigation",
            }
            if unreachable:
                statement["justification"] = "vulnerable_code_not_in_execute_path"
                statement["impact_statement"] = "A content-addressed exhaustive reachability proof reports this dependency unreachable."
            statements.append(statement)
    statements.sort(key=lambda item: (item["vulnerability"]["name"], item["products"][0]["@id"]))
    if not statements:
        return {
            "schema": "attestor-openvex-result/1", "state": "not-generated",
            "reason": "OpenVEX 0.2.0 requires at least one vulnerability statement; Attestor will not fabricate one.",
            "document": None,
        }
    digest = hashlib.sha256(canonical_json(statements)).hexdigest()
    return {
        "@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://attestor.local/vex/%s" % digest,
        "author": "Attestor Supply-Chain Center", "timestamp": _created(source_date_epoch),
        "version": 1, "tooling": "Attestor Supply-Chain Center %s" % VERSION,
        "statements": statements,
    }


def build_provenance_evidence(inventory: Inventory, risks: Sequence[RiskFinding],
                              *, source_date_epoch: int | None = None) -> dict[str, Any]:
    materials = [{"uri": "file:" + path, "digest": {"sha256": digest.split(":", 1)[1]}}
                 for path, digest in inventory.file_hashes.items()]
    known_licenses = sum(bool(dep.licenses) for dep in inventory.dependencies)
    known_integrity = sum(bool(dep.integrity) for dep in inventory.dependencies)
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": Path(inventory.root).name,
                     "digest": {"sha256": _inventory_digest(inventory)}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://attestor.local/buildtypes/offline-inventory/v1",
                "externalParameters": {"network": "disabled-by-design", "dependency_execution": False},
                "internalParameters": {}, "resolvedDependencies": materials,
            },
            "runDetails": {
                "builder": {"id": "https://attestor.local/supply-chain-center/%s" % VERSION},
                "metadata": {"invocationId": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, _inventory_digest(inventory))),
                             "startedOn": _created(source_date_epoch), "finishedOn": _created(source_date_epoch)},
                "byproducts": [],
            },
        },
        "attestorEvidence": {
            "claim": "SLSA-shaped local evidence; not a SLSA certification or signed build provenance",
            "inventory_status": "partial" if inventory.errors else "complete",
            "license_evidence": {"declared": known_licenses,
                                 "unknown": len(inventory.dependencies) - known_licenses,
                                 "state": "partial" if known_licenses < len(inventory.dependencies) else "declared"},
            "integrity_evidence": {"present": known_integrity,
                                   "unknown": len(inventory.dependencies) - known_integrity,
                                   "state": "partial" if known_integrity < len(inventory.dependencies) else "present"},
            "risk_findings": len(risks),
            "lock_coverage": list(inventory.lock_coverage),
        },
    }


def analyze_workspace(root: str | Path, *, snapshot: Mapping[str, Any] | None = None,
                      trusted_keys: Mapping[str, bytes] | None = None,
                      reachability: Mapping[str, Any] | None = None,
                      now: _datetime.datetime | None = None,
                      source_date_epoch: int | None = None) -> dict[str, Any]:
    inventory = inventory_workspace(root)
    risks = scan_supply_chain_risks(root)
    assessment = assess_advisories(inventory, snapshot, trusted_keys, now=now, reachability=reachability)
    return {
        "schema": SCHEMA, "version": VERSION,
        "execution": {"network_access": False, "dependencies_installed": False,
                      "target_code_executed": False, "mode": "offline-static"},
        "inventory": inventory.to_dict(),
        "risk_findings": [asdict(item) for item in risks],
        "advisory_assessment": assessment,
        "sbom": {
            "cyclonedx": build_cyclonedx(inventory, source_date_epoch=source_date_epoch),
            "spdx": build_spdx(inventory, source_date_epoch=source_date_epoch),
            "spdx_2_3_legacy": build_spdx_2_3(inventory, source_date_epoch=source_date_epoch),
        },
        "vex": {"cyclonedx": build_cyclonedx_vex(inventory, assessment, source_date_epoch=source_date_epoch),
                "openvex": build_openvex(inventory, assessment, source_date_epoch=source_date_epoch)},
        "provenance": build_provenance_evidence(inventory, risks, source_date_epoch=source_date_epoch),
    }


def render_json(value: Any, *, pretty: bool = True) -> str:
    return json.dumps(value, sort_keys=True, indent=2 if pretty else None,
                      separators=None if pretty else (",", ":"), ensure_ascii=False, allow_nan=False) + "\n"


def _write_output(path: str | None, value: Any) -> None:
    rendered = render_json(value)
    if not path or path == "-":
        sys.stdout.write(rendered)
        return
    destination = Path(path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(rendered, encoding="utf-8", newline="\n")
    os.replace(temporary, destination)


def _load_mapping(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    value = _json_loads(_decode_utf8(_read_bounded(Path(path), MAX_MANIFEST_BYTES)))
    if not isinstance(value, dict):
        raise SupplyChainError("reachability evidence must be a JSON object")
    return value


def _key(path: str | None) -> bytes:
    if not path:
        raise SupplyChainError("--hmac-key-file is required for authenticated snapshots")
    data = _read_bounded(Path(path), 64 * 1024)
    if len(data) < 32:
        raise SupplyChainError("HMAC key file must contain at least 32 bytes")
    return data


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Attestor 3.0 offline supply-chain command center")
    parser.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    sub = parser.add_subparsers(dest="command", required=True)
    inventory = sub.add_parser("inventory", help="inventory local dependency manifests")
    inventory.add_argument("root")
    inventory.add_argument("--output", "-o", default="-")
    sbom = sub.add_parser("sbom", help="emit a deterministic SBOM")
    sbom.add_argument("root")
    sbom.add_argument("--format", choices=("cyclonedx", "spdx", "spdx-3.0.1", "spdx-2.3"),
                      default="cyclonedx",
                      help="spdx and spdx-3.0.1 emit JSON-LD; spdx-2.3 is legacy JSON")
    sbom.add_argument("--output", "-o", default="-")
    analyze = sub.add_parser("analyze", help="produce inventory, risks, SBOM, VEX, and evidence")
    analyze.add_argument("root")
    analyze.add_argument("--snapshot")
    analyze.add_argument("--hmac-key-file")
    analyze.add_argument("--key-id", default="default")
    analyze.add_argument("--reachability", help="local JSON map keyed by purl/package")
    analyze.add_argument("--output", "-o", default="-")
    sign = sub.add_parser("sign-snapshot", help="authenticate a local advisory snapshot using HMAC-SHA256")
    sign.add_argument("input")
    sign.add_argument("output")
    sign.add_argument("--hmac-key-file", required=True)
    sign.add_argument("--key-id", required=True)
    verify = sub.add_parser("verify-snapshot", help="verify a local authenticated advisory snapshot")
    verify.add_argument("snapshot")
    verify.add_argument("--hmac-key-file", required=True)
    verify.add_argument("--key-id", required=True)
    verify.add_argument("--output", "-o", default="-")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "inventory":
            report = inventory_workspace(args.root)
            _write_output(args.output, report.to_dict())
            return 1 if report.errors else 0
        if args.command == "sbom":
            inventory = inventory_workspace(args.root)
            if args.format == "cyclonedx":
                value = build_cyclonedx(inventory)
            elif args.format == "spdx-2.3":
                value = build_spdx_2_3(inventory)
            else:
                value = build_spdx(inventory)
            _write_output(args.output, value)
            return 1 if inventory.errors else 0
        if args.command == "sign-snapshot":
            snapshot = load_advisory_snapshot(args.input)
            _write_output(args.output, sign_advisory_snapshot(snapshot, _key(args.hmac_key_file), args.key_id))
            return 0
        if args.command == "verify-snapshot":
            snapshot = load_advisory_snapshot(args.snapshot)
            verification = verify_advisory_snapshot(snapshot, {args.key_id: _key(args.hmac_key_file)})
            _write_output(args.output, verification.to_dict())
            return 0 if verification.valid else 2
        if args.command == "analyze":
            snapshot = load_advisory_snapshot(args.snapshot) if args.snapshot else None
            keys = {args.key_id: _key(args.hmac_key_file)} if snapshot is not None else {}
            value = analyze_workspace(args.root, snapshot=snapshot, trusted_keys=keys,
                                      reachability=_load_mapping(args.reachability))
            _write_output(args.output, value)
            return 1 if value["inventory"]["errors"] else 0
    except (OSError, SupplyChainError, ValueError, TypeError) as exc:
        sys.stderr.write("Attestor supply-chain error: %s\n" % _bounded(exc, 512))
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
