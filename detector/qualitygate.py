#!/usr/bin/env python3
"""Deterministic repository quality gate and local dependency inventory for Attestor.

The default evaluation is deliberately dry: it reads local files, runs Attestor's
in-process scanners and static graders, and builds an SBOM without resolving or
installing packages.  External syntax tools are opt-in with ``--tools``.  Tests
are even more explicit: both ``--run-tests`` and a JSON argv list are required,
and the command is launched without a shell under time/output bounds.

Examples::

    python qualitygate.py .. --min-grade B --max-high 0
    python qualitygate.py .. --format markdown
    python qualitygate.py .. --run-tests \
        --test-command-json '["python", "-m", "unittest", "discover"]'
    python qualitygate.py .. --format sbom
"""
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import grade
import nativegrade
import repo_intel
import scanengine

try:  # Python 3.11+, with a conservative text fallback below for older Python.
    import tomllib
except ImportError:  # pragma: no cover - exercised on supported older runtimes.
    tomllib = None


SCHEMA_VERSION = "attestor-quality-gate/1"
GRADE_RANK = {"F": 0, "D": 1, "C": 2, "B": 3, "A": 4}
NATIVE_LANGUAGES = {"c", "cpp", "asm"}
MAX_COMMAND_ARGS = 64
MAX_COMMAND_CHARS = 16 * 1024
MAX_ARG_CHARS = 4096
MAX_TEST_TIMEOUT = 300
DEFAULT_OUTPUT_BYTES = 64 * 1024
MAX_MANIFEST_BYTES = 5 * 1024 * 1024
MANIFEST_NAMES = {
    "pyproject.toml", "pipfile.lock", "package.json", "package-lock.json",
    "npm-shrinkwrap.json", "cargo.toml", "cargo.lock", "go.mod", "pom.xml",
    "packages.lock.json",
}


@dataclass(frozen=True)
class GateReason:
    code: str
    message: str


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    version: str
    scope: str
    manifests: tuple[str, ...]
    purl: str = ""


@dataclass
class DependencyInventory:
    manifests: list[str] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class QualityGateReport:
    schema: str
    root: str
    status: str
    passed: bool
    policy: dict[str, Any]
    reasons: list[GateReason]
    scan: dict[str, Any]
    grades: dict[str, Any]
    repository: dict[str, Any]
    tests: dict[str, Any]
    inventory: DependencyInventory
    sbom: dict[str, Any]


def _relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return path.as_posix()


def _safe_env() -> dict[str, str]:
    allowed = {
        "PATH", "PATHEXT", "SystemRoot", "WINDIR", "COMSPEC", "TEMP", "TMP",
        "HOME", "USERPROFILE", "LANG", "LC_ALL", "TERM", "NUMBER_OF_PROCESSORS",
    }
    return {key: value for key, value in os.environ.items() if key in allowed}


def _validate_command(command: list[str] | tuple[str, ...] | None) -> list[str]:
    if not isinstance(command, (list, tuple)) or not command:
        raise ValueError("test command must be a non-empty argv list")
    if len(command) > MAX_COMMAND_ARGS:
        raise ValueError("test command exceeds %d arguments" % MAX_COMMAND_ARGS)
    if any(not isinstance(arg, str) or not arg or "\x00" in arg for arg in command):
        raise ValueError("every test command argument must be a non-empty string without NUL")
    if command[0].startswith("-"):
        raise ValueError("test command executable cannot begin with '-'")
    if any(len(arg) > MAX_ARG_CHARS for arg in command):
        raise ValueError("a test command argument exceeds %d characters" % MAX_ARG_CHARS)
    if sum(len(arg) for arg in command) > MAX_COMMAND_CHARS:
        raise ValueError("test command exceeds %d total characters" % MAX_COMMAND_CHARS)
    return list(command)


class _BoundedCapture:
    def __init__(self, limit: int):
        self.limit = max(1024, min(int(limit), 1024 * 1024))
        self.data = bytearray()
        self.total = 0

    def drain(self, stream) -> None:
        try:
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    break
                self.total += len(chunk)
                room = self.limit - len(self.data)
                if room > 0:
                    self.data.extend(chunk[:room])
        finally:
            try:
                stream.close()
            except OSError:
                pass

    def text(self) -> tuple[str, bool]:
        text = bytes(self.data).decode("utf-8", "replace")
        truncated = self.total > len(self.data)
        if truncated:
            text += "\n[output truncated at %d bytes]" % self.limit
        return text, truncated


def _terminate_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=5, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            proc.kill()
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            proc.kill()


def run_test_command(root: str | Path, command: list[str] | tuple[str, ...],
                     timeout: int = 120,
                     output_bytes: int = DEFAULT_OUTPUT_BYTES) -> dict[str, Any]:
    """Run an explicitly supplied argv list without a shell and return bounded output."""
    argv = _validate_command(command)
    timeout = max(1, min(int(timeout), MAX_TEST_TIMEOUT))
    base = Path(root).expanduser().resolve()
    capture = _BoundedCapture(output_bytes)
    popen_args: dict[str, Any] = {
        "cwd": str(base), "env": _safe_env(), "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE, "stderr": subprocess.STDOUT, "shell": False,
    }
    if os.name == "nt":
        popen_args["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        popen_args["start_new_session"] = True
    try:
        proc = subprocess.Popen(argv, **popen_args)
    except OSError as exc:
        return {"status": "error", "command": argv, "exit_code": None,
                "timeout_seconds": timeout, "output": "", "truncated": False,
                "detail": "%s: %s" % (type(exc).__name__, exc)}
    reader = threading.Thread(target=capture.drain, args=(proc.stdout,), daemon=True)
    reader.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_tree(proc)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    reader.join(timeout=5)
    output, truncated = capture.text()
    if timed_out:
        status, detail = "timeout", "test command exceeded %d seconds" % timeout
    elif proc.returncode == 0:
        status, detail = "passed", ""
    else:
        status, detail = "failed", "test command exited with code %d" % proc.returncode
    return {"status": status, "command": argv, "exit_code": proc.returncode,
            "timeout_seconds": timeout, "output": output, "truncated": truncated,
            "detail": detail}


def _manifest_paths(root: Path) -> list[Path]:
    paths = []
    for path in root.rglob("*"):
        if not path.is_file() or any(part in scanengine.SKIP_DIRS for part in path.parts):
            continue
        lower = path.name.lower()
        if (lower in MANIFEST_NAMES or
                (lower.startswith("requirements") and lower.endswith(".txt")) or
                lower.endswith(".csproj")):
            paths.append(path)
    return sorted(paths, key=lambda item: _relative(root, item).lower())


def _read_manifest(path: Path) -> str:
    size = path.stat().st_size
    if size > MAX_MANIFEST_BYTES:
        raise ValueError("manifest exceeds %d bytes" % MAX_MANIFEST_BYTES)
    return path.read_text(encoding="utf-8", errors="strict")


def _split_requirement(spec: str) -> tuple[str, str]:
    clean = spec.strip()
    clean = clean.split(";", 1)[0].strip()
    match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(.*)$", clean)
    if not match:
        return "", ""
    return match.group(1), match.group(2).strip()


def _add(rows: list[tuple[str, str, str, str, str]], ecosystem: str, name: Any,
         version: Any, scope: str, manifest: str) -> None:
    name = str(name or "").strip()
    if not name:
        return
    version = str(version or "").strip()
    rows.append((ecosystem, name, version, scope, manifest))


def _parse_requirements(text: str, manifest: str, rows: list) -> None:
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(("-r", "--requirement", "--index-url", "--extra-index-url", "--find-links")):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].rstrip()
        if line.startswith(("-e ", "--editable ")):
            line = line.split(None, 1)[1]
        name, version = _split_requirement(line)
        _add(rows, "pypi", name, version, "runtime", manifest)


def _parse_pyproject(text: str, manifest: str, rows: list) -> None:
    data = None
    if tomllib is not None:
        data = tomllib.loads(text)
    if isinstance(data, dict):
        project = data.get("project", {})
        for spec in project.get("dependencies", []) or []:
            name, version = _split_requirement(str(spec))
            _add(rows, "pypi", name, version, "runtime", manifest)
        for group, specs in sorted((project.get("optional-dependencies", {}) or {}).items()):
            for spec in specs or []:
                name, version = _split_requirement(str(spec))
                _add(rows, "pypi", name, version, "optional:" + str(group), manifest)
        poetry = ((data.get("tool", {}) or {}).get("poetry", {}) or {})
        for section, scope in (("dependencies", "runtime"), ("dev-dependencies", "development")):
            for name, value in sorted((poetry.get(section, {}) or {}).items()):
                if name.lower() == "python":
                    continue
                version = value.get("version", "") if isinstance(value, dict) else value
                _add(rows, "pypi", name, version, scope, manifest)
        return
    # Minimal fallback for Python versions without tomllib: quoted PEP 508 rows.
    project = re.search(r"(?ms)^\[project\].*?^dependencies\s*=\s*\[(.*?)\]", text)
    if project:
        for _quote, spec in re.findall(r"(['\"])(.*?)\1", project.group(1)):
            name, version = _split_requirement(spec)
            _add(rows, "pypi", name, version, "runtime", manifest)


def _parse_pipfile_lock(text: str, manifest: str, rows: list) -> None:
    data = json.loads(text)
    for section, scope in (("default", "runtime"), ("develop", "development")):
        for name, info in sorted((data.get(section, {}) or {}).items()):
            version = info.get("version", "") if isinstance(info, dict) else info
            _add(rows, "pypi", name, version, scope, manifest)


def _parse_package_json(text: str, manifest: str, rows: list) -> None:
    data = json.loads(text)
    sections = (("dependencies", "runtime"), ("devDependencies", "development"),
                ("peerDependencies", "peer"), ("optionalDependencies", "optional"))
    for section, scope in sections:
        for name, version in sorted((data.get(section, {}) or {}).items()):
            _add(rows, "npm", name, version, scope, manifest)


def _parse_package_lock(text: str, manifest: str, rows: list) -> None:
    data = json.loads(text)
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, info in sorted(packages.items()):
            if not key or not isinstance(info, dict):
                continue
            name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
            scope = "development" if info.get("dev") else ("optional" if info.get("optional") else "runtime")
            _add(rows, "npm", name, info.get("version", ""), scope, manifest)
    else:
        for name, info in sorted((data.get("dependencies", {}) or {}).items()):
            version = info.get("version", "") if isinstance(info, dict) else info
            _add(rows, "npm", name, version, "runtime", manifest)


def _parse_cargo(text: str, manifest: str, rows: list, locked: bool) -> None:
    data = tomllib.loads(text) if tomllib is not None else None
    if locked:
        if isinstance(data, dict):
            for package in data.get("package", []) or []:
                _add(rows, "cargo", package.get("name"), package.get("version"), "runtime", manifest)
            return
        for block in re.split(r"(?m)^\[\[package\]\]\s*$", text)[1:]:
            name = re.search(r'(?m)^name\s*=\s*["\']([^"\']+)', block)
            version = re.search(r'(?m)^version\s*=\s*["\']([^"\']+)', block)
            if name:
                _add(rows, "cargo", name.group(1), version.group(1) if version else "", "runtime", manifest)
        return
    if isinstance(data, dict):
        for section, scope in (("dependencies", "runtime"), ("dev-dependencies", "development"),
                               ("build-dependencies", "build")):
            for name, value in sorted((data.get(section, {}) or {}).items()):
                version = value.get("version", "") if isinstance(value, dict) else value
                _add(rows, "cargo", name, version, scope, manifest)


def _parse_go_mod(text: str, manifest: str, rows: list) -> None:
    in_require = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line == "require (":
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        spec = line if in_require else (line[len("require "):].strip() if line.startswith("require ") else "")
        parts = spec.split()
        if len(parts) >= 2:
            _add(rows, "golang", parts[0], parts[1], "runtime", manifest)


def _child_text(node, name: str) -> str:
    child = node.find("{*}" + name)
    return (child.text or "").strip() if child is not None else ""


def _parse_pom(text: str, manifest: str, rows: list) -> None:
    root = ET.fromstring(text)
    for dep in root.findall(".//{*}dependencies/{*}dependency"):
        group = _child_text(dep, "groupId")
        artifact = _child_text(dep, "artifactId")
        name = (group + ":" if group else "") + artifact
        scope = _child_text(dep, "scope") or "runtime"
        _add(rows, "maven", name, _child_text(dep, "version"), scope, manifest)


def _parse_csproj(text: str, manifest: str, rows: list) -> None:
    root = ET.fromstring(text)
    for dep in root.findall(".//{*}PackageReference"):
        name = dep.attrib.get("Include") or dep.attrib.get("Update")
        version = dep.attrib.get("Version") or _child_text(dep, "Version")
        _add(rows, "nuget", name, version, "runtime", manifest)


def _parse_packages_lock(text: str, manifest: str, rows: list) -> None:
    data = json.loads(text)
    for framework, dependencies in sorted((data.get("dependencies", {}) or {}).items()):
        for name, info in sorted((dependencies or {}).items()):
            version = info.get("resolved") or info.get("requested", "") if isinstance(info, dict) else info
            scope = "development" if isinstance(info, dict) and info.get("type") == "Direct" and "test" in framework.lower() else "runtime"
            _add(rows, "nuget", name, version, scope, manifest)


def _purl(ecosystem: str, name: str, version: str) -> str:
    exact = version.strip()
    exact = exact[2:] if exact.startswith("==") else exact
    if not exact or any(token in exact for token in (">", "<", "~", "^", "*", " ", "@", "$", "{")):
        exact = ""
    encoded = quote(name, safe="@/:" if ecosystem in {"npm", "maven"} else "/")
    return "pkg:%s/%s%s" % (ecosystem, encoded, ("@" + quote(exact, safe=".-_+")) if exact else "")


def inventory_dependencies(root: str | Path) -> DependencyInventory:
    """Read supported local manifests.  This never contacts a registry or installs."""
    base = Path(root).expanduser().resolve()
    inventory = DependencyInventory()
    if not base.is_dir():
        inventory.errors.append("workspace is not a directory: %s" % base)
        return inventory
    rows: list[tuple[str, str, str, str, str]] = []
    for path in _manifest_paths(base):
        manifest = _relative(base, path)
        inventory.manifests.append(manifest)
        try:
            text = _read_manifest(path)
            lower = path.name.lower()
            if lower.startswith("requirements") and lower.endswith(".txt"):
                _parse_requirements(text, manifest, rows)
            elif lower == "pyproject.toml":
                _parse_pyproject(text, manifest, rows)
            elif lower == "pipfile.lock":
                _parse_pipfile_lock(text, manifest, rows)
            elif lower == "package.json":
                _parse_package_json(text, manifest, rows)
            elif lower in {"package-lock.json", "npm-shrinkwrap.json"}:
                _parse_package_lock(text, manifest, rows)
            elif lower in {"cargo.toml", "cargo.lock"}:
                _parse_cargo(text, manifest, rows, lower == "cargo.lock")
            elif lower == "go.mod":
                _parse_go_mod(text, manifest, rows)
            elif lower == "pom.xml":
                _parse_pom(text, manifest, rows)
            elif lower.endswith(".csproj"):
                _parse_csproj(text, manifest, rows)
            elif lower == "packages.lock.json":
                _parse_packages_lock(text, manifest, rows)
        except (OSError, UnicodeError, ValueError, TypeError, ET.ParseError) as exc:
            inventory.errors.append("%s: %s: %s" % (manifest, type(exc).__name__, exc))
    merged: dict[tuple[str, str, str, str], set[str]] = {}
    display_names: dict[tuple[str, str, str, str], str] = {}
    for ecosystem, name, version, scope, manifest in rows:
        key = (ecosystem, name.lower(), version, scope)
        merged.setdefault(key, set()).add(manifest)
        display_names.setdefault(key, name)
    inventory.dependencies = [
        Dependency(ecosystem, display_names[key], version, scope,
                   tuple(sorted(manifests)), _purl(ecosystem, display_names[key], version))
        for key, manifests in sorted(merged.items())
        for ecosystem, _normalized, version, scope in [key]
    ]
    inventory.manifests.sort()
    inventory.errors.sort()
    return inventory


def build_sbom(root: str | Path, inventory: DependencyInventory) -> dict[str, Any]:
    base = Path(root).expanduser().resolve()
    components = []
    for dep in inventory.dependencies:
        component: dict[str, Any] = {
            "type": "library", "name": dep.name, "purl": dep.purl,
            "scope": "excluded" if dep.scope == "development" else "required",
            "properties": [
                {"name": "attestor:ecosystem", "value": dep.ecosystem},
                {"name": "attestor:declared-scope", "value": dep.scope},
                {"name": "attestor:manifests", "value": ",".join(dep.manifests)},
            ],
        }
        if dep.version:
            component["version"] = dep.version
        components.append(component)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"type": "application", "name": base.name}},
        "components": components,
    }


def _python_grades(paths: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    rows, errors = [], []
    for path in sorted(paths, key=str.lower):
        local_errors: list[str] = []
        try:
            graded = grade.collect([path], errors=local_errors)
        except (OSError, UnicodeError, ValueError, SyntaxError) as exc:
            local_errors.append("%s: %s: %s" % (path, type(exc).__name__, exc))
            graded = []
        for fg, tips in graded:
            rows.append({**asdict(fg), "engine": "grade", "verification": "static",
                         "fix_first": list(tips)})
        if not graded and not local_errors:
            local_errors.append("%s: Python grader returned no result" % path)
        errors.extend(local_errors)
    return rows, sorted(errors)


def _native_grades(paths: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    """Use nativegrade's scanners/metrics without invoking its compiler adapter."""
    rows, errors = [], []
    for path in sorted(paths, key=str.lower):
        try:
            findings = nativegrade._findings(path)
            funcs = nativegrade.nativemetrics.analyze_file(path)
            score = nativegrade._score(findings, funcs, nativegrade.nativemetrics.DEFAULT_LIMITS)
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for _line, _rule, severity, _message in findings:
                counts[severity] = counts.get(severity, 0) + 1
            over = [metric for metric in funcs if metric.exceeded(nativegrade.nativemetrics.DEFAULT_LIMITS)]
            rows.append({
                "path": path, "score": score, "grade": nativegrade.letter(score),
                "critical": counts["CRITICAL"], "high": counts["HIGH"],
                "medium": counts["MEDIUM"], "low_info": counts["LOW"] + counts["INFO"],
                "worst_cognitive": max((metric.cognitive for metric in funcs), default=0),
                "worst_cyclomatic": max((metric.cyclomatic for metric in funcs), default=0),
                "functions": len(funcs), "over_threshold": len(over),
                "engine": "nativegrade", "verification": "static-only",
                "fix_first": nativegrade.improvements(findings, funcs),
            })
        except (OSError, UnicodeError, ValueError, SyntaxError) as exc:
            errors.append("%s: %s: %s" % (path, type(exc).__name__, exc))
    return rows, sorted(errors)


def _scan_summary(result: scanengine.WorkspaceResult) -> dict[str, Any]:
    severities = {name: 0 for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    for issue in result.issues:
        severities[issue.severity] = severities.get(issue.severity, 0) + 1
    issues = [asdict(issue) for issue in result.issues]
    verifications: dict[str, int] = {}
    for file_result in result.files:
        verifications[file_result.verification] = verifications.get(file_result.verification, 0) + 1
    return {
        "status": result.status, "files_discovered": result.files_discovered,
        "files_scanned": result.files_scanned, "findings": len(result.issues),
        "severities": severities, "verifications": dict(sorted(verifications.items())),
        "issues": issues, "errors": sorted(result.errors), "skipped": sorted(result.skipped),
    }


def _repository_summary(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "modules": len(report.get("modules", {})),
        "definitions": len(report.get("definitions", {})),
        "resolved_call_edges": sum(bool(row.get("target")) for row in report.get("resolved_calls", [])),
        "call_edges": len(report.get("resolved_calls", [])),
        "entrypoints": list(report.get("entrypoints", [])),
        "reachable": len(report.get("reachable", [])),
        "import_cycles": list(report.get("import_cycles", [])),
        "unsafe_flows": list(report.get("unsafe_flows", [])),
        "unreferenced": list(report.get("unreferenced", [])),
        "config_undeclared": list(report.get("config_undeclared", [])),
        "parse_errors": list(report.get("parse_errors", [])),
    }


def evaluate(root: str | Path, *, min_grade: str = "B", max_high: int = 0,
             run_tests: bool = False, test_command: list[str] | tuple[str, ...] | None = None,
             test_timeout: int = 120, jobs: int = 1, deep: bool = False,
             external_tools: bool = False, use_cache: bool = False,
             cache_path: str = "") -> QualityGateReport:
    """Evaluate a repository and return a deterministic, JSON-compatible report."""
    min_grade = min_grade.upper()
    if min_grade not in GRADE_RANK:
        raise ValueError("min_grade must be one of A, B, C, D, F")
    if int(max_high) < 0:
        raise ValueError("max_high cannot be negative")
    max_high = int(max_high)
    jobs = max(1, min(int(jobs), 32))
    base = Path(root).expanduser().resolve()
    reasons: list[GateReason] = []

    if not base.is_dir():
        reasons.append(GateReason("invalid-workspace", "workspace is not a readable directory: %s" % base))
    scan = scanengine.scan([str(base)], jobs=jobs, deep=deep, tools=external_tools,
                           use_cache=use_cache, cache_path=cache_path)
    scan_summary = _scan_summary(scan)
    if scan.status in {"failed", "unsupported"}:
        reasons.append(GateReason("scan-" + scan.status,
                                  "workspace scan status is %s; see scan errors/skips" % scan.status))

    high_count = sum(1 for issue in scan.issues if issue.severity in {"CRITICAL", "HIGH"})
    if high_count > max_high:
        reasons.append(GateReason(
            "high-threshold", "%d CRITICAL/HIGH finding(s) exceed the allowed maximum of %d" %
            (high_count, max_high)))

    python_paths = [row.path for row in scan.files if row.language == "python"]
    native_paths = [row.path for row in scan.files if row.language in NATIVE_LANGUAGES]
    python_rows, python_errors = _python_grades(python_paths)
    native_rows, native_errors = _native_grades(native_paths)
    grade_rows = sorted(python_rows + native_rows, key=lambda row: (row["score"], row["path"].lower()))
    grade_errors = sorted(python_errors + native_errors)
    below = [row for row in grade_rows if GRADE_RANK.get(row["grade"], -1) < GRADE_RANK[min_grade]]
    if grade_errors:
        reasons.append(GateReason("grade-error", "%d source file(s) could not be graded" % len(grade_errors)))
    if below:
        reasons.append(GateReason(
            "minimum-grade", "%d source file(s) are below the required grade %s" %
            (len(below), min_grade)))
    grades = {
        "minimum": min_grade, "status": "not-applicable" if not grade_rows else ("failed" if below or grade_errors else "passed"),
        "files": grade_rows, "files_graded": len(grade_rows), "below_minimum": [row["path"] for row in below],
        "worst": min((row["grade"] for row in grade_rows), key=lambda item: GRADE_RANK[item]) if grade_rows else None,
        "average_score": round(sum(row["score"] for row in grade_rows) / len(grade_rows), 2) if grade_rows else None,
        "errors": grade_errors,
        "note": "native grades are static-only; --tools controls separate scanengine syntax adapters",
    }

    try:
        intelligence = repo_intel.analyze(str(base))
    except (OSError, UnicodeError, ValueError, SyntaxError) as exc:
        intelligence = {"parse_errors": [{"path": str(base), "line": 1,
                                             "message": "%s: %s" % (type(exc).__name__, exc)}]}
    repository = _repository_summary(intelligence)
    if repository["parse_errors"]:
        reasons.append(GateReason("repository-parse-error", "%d Python file(s) failed repository parsing" %
                                  len(repository["parse_errors"])))

    inventory = inventory_dependencies(base)
    if inventory.errors:
        reasons.append(GateReason("inventory-error", "%d dependency manifest(s) could not be read or parsed" %
                                  len(inventory.errors)))
    sbom = build_sbom(base, inventory)

    if run_tests:
        try:
            tests = run_test_command(base, _validate_command(test_command), timeout=test_timeout)
        except ValueError as exc:
            tests = {"status": "error", "command": list(test_command or []), "exit_code": None,
                     "timeout_seconds": max(1, min(int(test_timeout), MAX_TEST_TIMEOUT)),
                     "output": "", "truncated": False, "detail": str(exc)}
        if tests["status"] != "passed":
            reasons.append(GateReason("tests-" + tests["status"], tests["detail"] or "requested tests did not pass"))
    else:
        tests = {"status": "not-run", "command": list(test_command or []), "exit_code": None,
                 "timeout_seconds": max(1, min(int(test_timeout), MAX_TEST_TIMEOUT)),
                 "output": "", "truncated": False,
                 "detail": "tests are dry by default; set run_tests=True/--run-tests to execute"}

    unique = {(reason.code, reason.message): reason for reason in reasons}
    reasons = [unique[key] for key in sorted(unique)]
    passed = not reasons
    return QualityGateReport(
        schema=SCHEMA_VERSION, root=str(base), status="passed" if passed else "failed", passed=passed,
        policy={"minimum_grade": min_grade, "max_critical_high": max_high,
                "deep_scan": bool(deep), "external_tools": bool(external_tools),
                "tests_requested": bool(run_tests), "cache_enabled": bool(use_cache)},
        reasons=reasons, scan=scan_summary, grades=grades, repository=repository,
        tests=tests, inventory=inventory, sbom=sbom,
    )


def to_dict(report: QualityGateReport) -> dict[str, Any]:
    return asdict(report)


def render_json(report: QualityGateReport) -> str:
    return json.dumps(to_dict(report), indent=2, sort_keys=True)


def render_markdown(report: QualityGateReport) -> str:
    lines = ["# Attestor 3.0 quality gate", "", "- Status: **%s**" % report.status,
             "- Minimum grade: **%s**" % report.policy["minimum_grade"],
             "- Maximum CRITICAL/HIGH findings: **%d**" % report.policy["max_critical_high"],
             "- Scanned files: **%d**" % report.scan["files_scanned"],
             "- Graded files: **%d**" % report.grades["files_graded"],
             "- Dependencies inventoried: **%d**" % len(report.inventory.dependencies),
             "- Tests: **%s**" % report.tests["status"]]
    if report.reasons:
        lines += ["", "## Failure reasons", ""]
        lines += ["- `%s`: %s" % (reason.code, reason.message) for reason in report.reasons]
    lines += ["", "## Scan", "", "| Severity | Count |", "|---|---:|"]
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append("| %s | %d |" % (severity, report.scan["severities"].get(severity, 0)))
    if report.grades["files"]:
        lines += ["", "## Grades", "", "| Grade | Score | Engine | File |", "|---|---:|---|---|"]
        for row in report.grades["files"]:
            lines.append("| %s | %d | %s | `%s` |" %
                         (row["grade"], row["score"], row["engine"], row["path"].replace("|", "\\|")))
    if report.inventory.dependencies:
        lines += ["", "## Dependency inventory", "", "| Ecosystem | Package | Version/spec | Scope | Manifest |",
                  "|---|---|---|---|---|"]
        for dep in report.inventory.dependencies:
            lines.append("| %s | %s | %s | %s | %s |" % (
                dep.ecosystem, dep.name.replace("|", "\\|"), dep.version.replace("|", "\\|"),
                dep.scope, ", ".join(dep.manifests)))
    lines += ["", "## Repository intelligence", "",
              "- Import cycles: %d" % len(report.repository["import_cycles"]),
              "- Confirmed unsafe flows: %d" % len(report.repository["unsafe_flows"]),
              "- Unreferenced candidates: %d" % len(report.repository["unreferenced"]),
              "- Undeclared configuration keys: %d" % len(report.repository["config_undeclared"])]
    return "\n".join(lines) + "\n"


def _command_from_json(value: str, parser: argparse.ArgumentParser) -> list[str] | None:
    if not value:
        return None
    try:
        command = json.loads(value)
        return _validate_command(command)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        parser.error("--test-command-json must be a bounded JSON array of strings: %s" % exc)
    return None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("root", help="repository root directory")
    parser.add_argument("--min-grade", choices=("A", "B", "C", "D", "F"), default="B")
    parser.add_argument("--max-high", type=int, default=0,
                        help="maximum combined CRITICAL/HIGH findings (default 0)")
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--tools", action="store_true",
                        help="opt in to scanengine's non-running external syntax adapters")
    parser.add_argument("--cache", default="", help="enable scan cache at this explicit path")
    parser.add_argument("--run-tests", action="store_true",
                        help="execute the explicitly supplied test argv list")
    parser.add_argument("--test-command-json", default="",
                        help='test argv as JSON, for example ["python","-m","unittest"]')
    parser.add_argument("--test-timeout", type=int, default=120)
    parser.add_argument("--format", choices=("json", "markdown", "sbom"), default="json")
    args = parser.parse_args(argv)
    if args.max_high < 0:
        parser.error("--max-high cannot be negative")
    command = _command_from_json(args.test_command_json, parser)
    if args.run_tests and command is None:
        parser.error("--run-tests requires --test-command-json")
    report = evaluate(
        args.root, min_grade=args.min_grade, max_high=args.max_high,
        run_tests=args.run_tests, test_command=command, test_timeout=args.test_timeout,
        jobs=args.jobs, deep=args.deep, external_tools=args.tools,
        use_cache=bool(args.cache), cache_path=args.cache,
    )
    if args.format == "markdown":
        sys.stdout.write(render_markdown(report))
    elif args.format == "sbom":
        print(json.dumps(report.sbom, indent=2, sort_keys=True))
    else:
        print(render_json(report))
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
