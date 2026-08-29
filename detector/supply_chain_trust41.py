#!/usr/bin/env python3
"""Attestor 4.1.3 deterministic supply-chain graph and offline trust contracts.

No function in this module resolves dependencies, invokes a package manager,
imports target code, or performs network I/O.  An edge is emitted only when a
bounded local lock/manifest representation identifies both endpoints.
"""
from __future__ import annotations

import datetime as _datetime
import hashlib
import hmac
import json
import os
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping


VERSION = "4.1.3"
GRAPH_SCHEMA = "attestor.supply-chain-trust/4.1"
OSV_SCHEMA = "attestor.osv-offline-snapshot/4.1"
MAX_FILES = 1_000
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_NODES = 200_000
MAX_EDGES = 400_000
MAX_OSV_RECORDS = 250_000
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTITY = re.compile(r"[^\x00-\x1f\x7f]{1,512}\Z")
_BIDI_CONTROLS = frozenset({
    0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D,
    0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x206A, 0x206B,
    0x206C, 0x206D, 0x206E, 0x206F,
})
_LOCK_NAMES = frozenset({
    "package-lock.json", "cargo.lock", "pnpm-lock.yaml", "yarn.lock", "uv.lock", "pdm.lock", "go.mod",
    "pom.xml", "gradle.lockfile", "packages.lock.json", "composer.lock",
})
_SKIP_DIRECTORIES = frozenset({".git", ".hg", ".svn", "node_modules", "vendor",
                               ".venv", "venv", "target", "dist", "build",
                               "__pycache__", ".attestor-cache"})


class SupplyChainTrustError(ValueError):
    pass


@dataclass(frozen=True)
class GraphNode:
    id: str
    ecosystem: str
    name: str
    version: str
    evidence: str
    kind: str = "package"


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    relationship: str
    evidence: str


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _terminal_text(value: Any, maximum: int = 4_096) -> str:
    """Preserve ordinary Unicode while visibly escaping display controls."""
    result: list[str] = []
    rendered_size = 0
    for character in str(value if value is not None else ""):
        codepoint = ord(character)
        if character in "\t\r\n":
            rendered = " "
        elif codepoint < 32 or 0x7F <= codepoint <= 0x9F:
            rendered = "\\x%02x" % codepoint
        elif codepoint in _BIDI_CONTROLS:
            rendered = "\\u%04x" % codepoint
        else:
            rendered = character
        if rendered_size + len(rendered) > maximum:
            break
        result.append(rendered)
        rendered_size += len(rendered)
    return "".join(result)


def _terminal_json(value: Any, depth: int = 0) -> Any:
    """Return JSON-shaped advisory data with terminal-safe keys and strings."""
    if depth > 128:
        raise SupplyChainTrustError("advisory nesting exceeds boundary")
    if isinstance(value, str):
        return _terminal_text(value, max(1, len(value) * 6))
    if isinstance(value, (list, tuple)):
        return [_terminal_json(item, depth + 1) for item in value]
    if type(value) is dict:
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise SupplyChainTrustError("advisory object key is not text")
            safe_key = _terminal_text(key, max(1, len(key) * 6))
            if safe_key in result:
                raise SupplyChainTrustError("advisory keys collide after control escaping")
            result[safe_key] = _terminal_json(item, depth + 1)
        return result
    return value


def _osv_hmac_input(key_id: str, payload_sha256: str) -> bytes:
    return _canonical({
        "schema": OSV_SCHEMA,
        "purpose": "offline-osv-snapshot-authentication",
        "algorithm": "hmac-sha256",
        "key_id": key_id,
        "payload_sha256": payload_sha256,
    })


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SupplyChainTrustError("JSON contains duplicate object keys")
        result[key] = value
    return result


def _json(text: str, label: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise SupplyChainTrustError(label + " cannot be parsed") from exc


def _timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise SupplyChainTrustError("snapshot generated_at is invalid")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = _datetime.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise SupplyChainTrustError("snapshot generated_at is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SupplyChainTrustError("snapshot generated_at must include a timezone")
    return value


def _validated_osv_rows(records: Any) -> list[dict[str, Any]]:
    if type(records) is not list or len(records) > MAX_OSV_RECORDS:
        raise SupplyChainTrustError("snapshot record boundary is invalid")
    rows: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for row in records:
        if type(row) is not dict:
            raise SupplyChainTrustError("record is not OSV-compatible")
        safe_row = _terminal_json(row)
        identifier = safe_row.get("id")
        affected = safe_row.get("affected", [])
        if (not isinstance(identifier, str) or not _IDENTITY.fullmatch(identifier) or
                type(affected) is not list or
                any(type(item) is not dict for item in affected)):
            raise SupplyChainTrustError("record is not OSV-compatible")
        if identifier in identifiers:
            raise SupplyChainTrustError("snapshot contains duplicate OSV identifiers")
        identifiers.add(identifier)
        rows.append(safe_row)
    try:
        _canonical(rows)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise SupplyChainTrustError("OSV records are not canonically serializable") from exc
    return sorted(rows, key=lambda row: row["id"])


def _node(ecosystem: str, name: str, version: str, evidence: str,
          kind: str = "package") -> GraphNode:
    clean_name, clean_version = str(name).strip(), str(version).strip()
    if not _IDENTITY.fullmatch(clean_name) or len(clean_version) > 256:
        raise SupplyChainTrustError("invalid dependency identity")
    identifier = "dep41-" + _sha([ecosystem, clean_name, clean_version, evidence])[:24]
    return GraphNode(identifier, ecosystem, clean_name, clean_version, evidence, kind)


def _root(ecosystem: str, relative: str, name: str = "workspace-root") -> GraphNode:
    return _node(ecosystem, name, "", relative + "#root", "workspace")


def _read(path: Path) -> tuple[str, bytes]:
    if path.is_symlink() or not path.is_file():
        raise SupplyChainTrustError("linked/non-regular manifest is not accepted")
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise SupplyChainTrustError("manifest exceeds byte boundary")
        return raw.decode("utf-8"), raw
    except (OSError, UnicodeError) as exc:
        raise SupplyChainTrustError("manifest is not valid UTF-8") from exc


def _resolve_edges(rows: list[tuple[Mapping[str, Any], GraphNode]],
                   dependency_names: Callable[[Mapping[str, Any]], Iterable[str]],
                   evidence: str) -> tuple[list[GraphEdge], list[str]]:
    by_name: dict[str, list[GraphNode]] = {}
    for _row, node in rows:
        by_name.setdefault(node.name.casefold(), []).append(node)
    edges: list[GraphEdge] = []
    gaps: list[str] = []
    for row, owner in rows:
        for name in sorted(set(map(str, dependency_names(row)))):
            candidates = by_name.get(name.casefold(), [])
            if len(candidates) == 1:
                edges.append(GraphEdge(owner.id, candidates[0].id, "depends-on", evidence))
            else:
                gaps.append("dependency endpoint is not exact: " + name[:200])
    return edges, gaps


def _parse_package_lock(text: str, relative: str):
    value = _json(text, "package-lock.json")
    if type(value) is not dict:
        raise SupplyChainTrustError("package-lock root is not an object")
    packages = value.get("packages")
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    gaps: list[str] = []
    if type(packages) is dict:
        by_path: dict[str, GraphNode] = {}
        rows: dict[str, Mapping[str, Any]] = {}
        for raw_path, row in sorted(packages.items()):
            if type(row) is not dict:
                gaps.append("npm package row is not an object: " + str(raw_path)[:200])
                continue
            path_key = str(raw_path)
            if path_key:
                name = str(row.get("name") or path_key.rsplit("node_modules/", 1)[-1])
                kind = "package"
            else:
                name = "workspace-root"; kind = "workspace"
            node = _node("npm", name, str(row.get("version", value.get("version", ""))),
                         relative + "#/packages/" + (path_key or "<root>"), kind)
            by_path[path_key] = node; rows[path_key] = row; nodes.append(node)
        if "" not in by_path:
            root = _root("npm", relative)
            by_path[""] = root
            rows[""] = {"dependencies": value.get("dependencies", {})}
            nodes.append(root)
            gaps.append("package-lock omitted its workspace package row; an explicit synthetic root was added")
        for owner_path, row in sorted(rows.items()):
            owner = by_path[owner_path]
            dependencies = row.get("dependencies")
            if type(dependencies) is not dict:
                continue
            for dep_name in sorted(map(str, dependencies)):
                current = owner_path
                target: GraphNode | None = None
                while True:
                    candidate = (current + "/node_modules/" + dep_name).strip("/")
                    if candidate in by_path:
                        target = by_path[candidate]; break
                    if "/node_modules/" not in current:
                        break
                    current = current.rsplit("/node_modules/", 1)[0]
                if target is None:
                    target = by_path.get("node_modules/" + dep_name)
                if target is None:
                    gaps.append("npm dependency endpoint is absent: " + dep_name[:200])
                else:
                    edges.append(GraphEdge(owner.id, target.id, "depends-on",
                                           relative + " packages map"))
        return nodes, edges, gaps

    # package-lock v1 stores an exact nested tree instead of a packages map.
    root = _root("npm", relative); nodes.append(root)

    def visit(dependencies: Any, owner: GraphNode, pointer: str) -> None:
        if type(dependencies) is not dict:
            return
        for name, row in sorted(dependencies.items()):
            if type(row) is not dict or not row.get("version"):
                gaps.append("npm v1 dependency lacks an exact version: " + str(name)[:200])
                continue
            node = _node("npm", str(name), str(row["version"]),
                         relative + pointer + "/" + str(name))
            nodes.append(node)
            edges.append(GraphEdge(owner.id, node.id, "depends-on",
                                   relative + " nested dependency tree"))
            visit(row.get("dependencies"), node, pointer + "/" + str(name) + "/dependencies")

    visit(value.get("dependencies"), root, "#/dependencies")
    if len(nodes) == 1:
        gaps.append("package-lock has neither an exact packages map nor a nested dependency tree")
    return nodes, edges, gaps


def _parse_cargo_lock(text: str, relative: str):
    try:
        value = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise SupplyChainTrustError("Cargo.lock cannot be parsed") from exc
    packages = value.get("package") if type(value) is dict else None
    if type(packages) is not list:
        raise SupplyChainTrustError("Cargo.lock has no package array")
    rows: list[tuple[Mapping[str, Any], GraphNode]] = []
    by_name: dict[str, list[GraphNode]] = {}
    by_identity: dict[tuple[str, str], list[GraphNode]] = {}
    for index, row in enumerate(packages):
        if type(row) is not dict or not row.get("name") or not row.get("version"):
            continue
        node = _node("cargo", str(row["name"]), str(row["version"]),
                     f"{relative}#/package/{index}")
        rows.append((row, node))
        by_name.setdefault(node.name, []).append(node)
        by_identity.setdefault((node.name, node.version), []).append(node)
    edges: list[GraphEdge] = []; gaps: list[str] = []
    for row, owner in rows:
        dependencies = row.get("dependencies", [])
        if type(dependencies) is not list:
            gaps.append("Cargo dependency table is not an array for " + owner.name[:200]); continue
        for raw in dependencies:
            if not isinstance(raw, str) or not raw.strip():
                gaps.append("Cargo dependency identity is malformed"); continue
            parts = raw.split()
            candidates = (by_identity.get((parts[0], parts[1]), [])
                          if len(parts) >= 2 else by_name.get(parts[0], []))
            if len(candidates) == 1:
                edges.append(GraphEdge(owner.id, candidates[0].id, "depends-on",
                                       relative + " package dependency array"))
            else:
                gaps.append("Cargo dependency endpoint is not exact: " + raw[:200])
    return [node for _row, node in rows], edges, gaps


def _parse_python_lock(text: str, relative: str, ecosystem: str):
    try:
        value = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise SupplyChainTrustError("TOML lockfile cannot be parsed") from exc
    packages = value.get("package") if type(value) is dict else None
    if type(packages) is not list:
        raise SupplyChainTrustError("lockfile has no package array")
    rows: list[tuple[Mapping[str, Any], GraphNode]] = []
    for index, row in enumerate(packages):
        if type(row) is not dict or not row.get("name"):
            continue
        rows.append((row, _node(ecosystem, row["name"], row.get("version", ""),
                                f"{relative}#/package/{index}")))

    def names(row: Mapping[str, Any]) -> Iterable[str]:
        deps = row.get("dependencies", row.get("dependency", []))
        if type(deps) is list:
            for item in deps:
                if type(item) is dict and item.get("name"):
                    yield str(item["name"])
                elif isinstance(item, str):
                    yield item.split()[0]
        elif type(deps) is dict:
            yield from map(str, deps)

    edges, gaps = _resolve_edges(rows, names, relative + " package dependency table")
    return [node for _row, node in rows], edges, gaps


def _parse_go_mod(text: str, relative: str):
    root_name = "workspace-root"
    module = re.search(r"(?m)^\s*module\s+([^\s]+)\s*$", text)
    if module:
        root_name = module.group(1)
    root = _root("go", relative, root_name)
    dependencies: dict[str, str] = {}
    in_require = False
    gaps: list[str] = []
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line == "require (":
            in_require = True; continue
        if in_require and line == ")":
            in_require = False; continue
        if line.startswith("replace ") or line.startswith("exclude "):
            gaps.append("go replace/exclude directives require separate semantic resolution")
            continue
        body = line[len("require "):].strip() if line.startswith("require ") else line if in_require else ""
        parts = body.split()
        if len(parts) >= 2:
            dependencies[parts[0]] = parts[1]
    nodes = [root]
    edges: list[GraphEdge] = []
    for name, version in sorted(dependencies.items()):
        node = _node("go", name, version, relative + "#require/" + name)
        nodes.append(node); edges.append(GraphEdge(root.id, node.id, "depends-on", relative + " require"))
    return nodes, edges, gaps


def _parse_maven(text: str, relative: str):
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise SupplyChainTrustError("XML entity declarations are forbidden")
    try:
        root_xml = ET.fromstring(text)
    except ET.ParseError as exc:
        raise SupplyChainTrustError("pom.xml cannot be parsed") from exc
    strip = lambda tag: tag.rsplit("}", 1)[-1]
    props: dict[str, str] = {}
    for child in root_xml:
        if strip(child.tag) == "properties":
            for item in child:
                props[strip(item.tag)] = (item.text or "").strip()
    project: dict[str, str] = {}
    for child in root_xml:
        tag = strip(child.tag)
        if tag in {"groupId", "artifactId", "version"} and tag not in project:
            project[tag] = (child.text or "").strip()
    root = _root("maven", relative,
                 ":".join(filter(None, [project.get("groupId", ""), project.get("artifactId", "")])) or "workspace-root")
    nodes = [root]; edges: list[GraphEdge] = []; gaps: list[str] = []
    direct_tables = [child for child in root_xml if strip(child.tag) == "dependencies"]
    all_tables = [item for item in root_xml.iter() if strip(item.tag) == "dependencies"]
    if len(all_tables) > len(direct_tables):
        gaps.append("Maven profile, plugin, or dependency-management tables are outside the exact direct-dependency scope")
    for parent in direct_tables:
        for dep in parent:
            if strip(dep.tag) != "dependency":
                continue
            fields = {strip(item.tag): (item.text or "").strip() for item in dep}
            group, artifact, version = fields.get("groupId", ""), fields.get("artifactId", ""), fields.get("version", "")
            if version.startswith("${") and version.endswith("}"):
                version = props.get(version[2:-1], "")
            if not group or not artifact or not version:
                gaps.append("Maven dependency needs unresolved inheritance/property data")
                continue
            node = _node("maven", group + ":" + artifact, version,
                         relative + "#dependency/" + group + ":" + artifact)
            nodes.append(node); edges.append(GraphEdge(root.id, node.id, "depends-on", relative + " dependencies"))
    return nodes, edges, gaps


def _parse_gradle(text: str, relative: str):
    root = _root("gradle", relative); nodes = [root]; edges = []; gaps = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(('#', 'empty=', 'strict=')):
            continue
        coordinate = line.split("=", 1)[0]
        parts = coordinate.split(":")
        if len(parts) != 3 or not all(parts):
            gaps.append(f"Gradle lock line {number} is unsupported")
            continue
        node = _node("gradle", parts[0] + ":" + parts[1], parts[2], f"{relative}#line/{number}")
        nodes.append(node); edges.append(GraphEdge(root.id, node.id, "depends-on", f"{relative} line {number}"))
    return nodes, edges, gaps


def _parse_nuget(text: str, relative: str):
    value = _json(text, "NuGet lock")
    frameworks = value.get("dependencies") if type(value) is dict else None
    if type(frameworks) is not dict:
        raise SupplyChainTrustError("NuGet lock has no dependencies map")
    nodes: list[GraphNode] = []; edges: list[GraphEdge] = []; gaps: list[str] = []
    for framework, packages in sorted(frameworks.items()):
        if type(packages) is not dict:
            continue
        root = _root("nuget", relative + "#" + str(framework), "workspace:" + str(framework)); nodes.append(root)
        by_name: dict[str, GraphNode] = {}
        rows: list[tuple[Mapping[str, Any], GraphNode]] = []
        for name, row in sorted(packages.items()):
            if type(row) is not dict or not row.get("resolved"):
                gaps.append("NuGet package lacks an exact resolved version: " + str(name)[:200]); continue
            node = _node("nuget", name, row["resolved"], f"{relative}#/dependencies/{framework}/{name}")
            nodes.append(node); by_name[str(name).casefold()] = node; rows.append((row, node))
            if str(row.get("type", "")).lower() in {"direct", "project"}:
                edges.append(GraphEdge(root.id, node.id, "depends-on", relative + " direct dependency"))
        for row, owner in rows:
            for name in sorted(row.get("dependencies", {})) if type(row.get("dependencies")) is dict else ():
                target = by_name.get(str(name).casefold())
                if target: edges.append(GraphEdge(owner.id, target.id, "depends-on", relative + " transitive dependency"))
                else: gaps.append("NuGet dependency endpoint is absent: " + str(name)[:200])
    return nodes, edges, gaps


def _parse_composer(text: str, relative: str):
    value = _json(text, "composer.lock")
    packages = []
    if type(value) is dict:
        packages = [item for key in ("packages", "packages-dev")
                    for item in (value.get(key) if type(value.get(key)) is list else [])]
    rows = []
    for index, row in enumerate(packages):
        if type(row) is dict and row.get("name") and row.get("version"):
            rows.append((row, _node("composer", row["name"], row["version"], f"{relative}#/packages/{index}")))
    edges, gaps = _resolve_edges(rows, lambda row: (row.get("require") or {}).keys()
                                 if type(row.get("require")) is dict else (), relative + " require map")
    return [node for _row, node in rows], edges, gaps


def _parse_yarn(text: str, relative: str):
    records: list[tuple[str, str, list[str], int]] = []
    current_name = ""; current_version = ""; deps: list[str] = []; start = 0; in_deps = False
    def finish():
        if current_name and current_version:
            records.append((current_name, current_version, list(deps), start))
    for number, raw in enumerate(text.splitlines(), 1):
        if raw and not raw[0].isspace() and raw.rstrip().endswith(":"):
            finish(); descriptor = raw.rstrip()[:-1].split(",", 1)[0].strip().strip('"')
            current_name = descriptor.rsplit("@", 1)[0] if "@" in descriptor.lstrip("@") else descriptor
            if descriptor.startswith("@"):
                current_name = "@" + descriptor[1:].rsplit("@", 1)[0]
            current_version = ""; deps = []; start = number; in_deps = False
        elif raw.startswith("  version "):
            current_version = raw.strip().split(None, 1)[1].strip('"')
        elif raw.strip() in {"dependencies:", "optionalDependencies:"}:
            in_deps = True
        elif in_deps and raw.startswith("    ") and raw.strip():
            deps.append(raw.strip().split()[0].strip('"'))
        elif raw.startswith("  ") and not raw.startswith("    "):
            in_deps = False
    finish()
    rows = [({"deps": deps}, _node("yarn", name, version, f"{relative}#line/{line}"))
            for name, version, deps, line in records]
    edges, gaps = _resolve_edges(rows, lambda row: row["deps"], relative + " dependency block")
    if not rows: gaps.append("Yarn lock grammar was not recognized")
    return [node for _row, node in rows], edges, gaps


def _parse_pnpm(text: str, relative: str):
    # This intentionally supports only package/snapshot keys with an explicit
    # name@version identity. Importer/peer encodings that cannot be resolved
    # exactly are reported as gaps.
    records: list[tuple[str, str, list[str], int]] = []
    current: tuple[str, str, int] | None = None; deps: list[str] = []; in_deps = False
    key_re = re.compile(r"^\s{2,4}['\"]?/?((?:@[^/]+/)?[^:@'\"\s]+)@([^:'\"\s(]+)(?:\([^)]*\))?['\"]?:\s*$")
    dep_re = re.compile(r"^\s{6,10}['\"]?([^:'\"\s]+)['\"]?:\s+.+$")
    def finish():
        if current: records.append((current[0], current[1], list(deps), current[2]))
    for number, raw in enumerate(text.splitlines(), 1):
        match = key_re.match(raw)
        if match:
            finish(); current = (match.group(1).replace("/", "/", 1), match.group(2), number); deps = []; in_deps = False; continue
        if current and raw.strip() in {"dependencies:", "optionalDependencies:"}:
            in_deps = True; continue
        if current and in_deps:
            dep = dep_re.match(raw)
            if dep: deps.append(dep.group(1)); continue
            if raw.strip() and len(raw) - len(raw.lstrip()) <= 4: in_deps = False
    finish()
    rows = [({"deps": deps}, _node("pnpm", name, version, f"{relative}#line/{line}"))
            for name, version, deps, line in records]
    edges, gaps = _resolve_edges(rows, lambda row: row["deps"], relative + " package/snapshot block")
    if not rows: gaps.append("pnpm package/snapshot grammar was not recognized exactly")
    gaps.append("pnpm importer-to-package edges are unavailable in the bounded lexical adapter")
    return [node for _row, node in rows], edges, gaps


_PARSERS: dict[str, tuple[str, Callable[[str, str], Any], str]] = {
    "package-lock.json": ("npm", _parse_package_lock, "exact-json-lock-tree"),
    "cargo.lock": ("cargo", _parse_cargo_lock, "exact-toml"),
    "pnpm-lock.yaml": ("pnpm", _parse_pnpm, "bounded-exact-subset"),
    "yarn.lock": ("yarn", _parse_yarn, "bounded-exact-subset"),
    "uv.lock": ("uv", lambda t, r: _parse_python_lock(t, r, "uv"), "exact-toml"),
    "pdm.lock": ("pdm", lambda t, r: _parse_python_lock(t, r, "pdm"), "exact-toml"),
    "go.mod": ("go", _parse_go_mod, "exact-declared-requires"),
    "pom.xml": ("maven", _parse_maven, "exact-local-model-subset"),
    "gradle.lockfile": ("gradle", _parse_gradle, "exact-lock-lines"),
    "packages.lock.json": ("nuget", _parse_nuget, "exact-json"),
    "composer.lock": ("composer", _parse_composer, "exact-json"),
}


def analyze_dependency_graph(root: str | os.PathLike[str]) -> dict[str, Any]:
    supplied = Path(root).expanduser()
    if supplied.is_symlink():
        raise SupplyChainTrustError("graph root must be a real directory")
    base = supplied.resolve(strict=True)
    if not base.is_dir():
        raise SupplyChainTrustError("graph root must be a directory")
    candidates: list[Path] = []
    for current, directories, names in os.walk(base, topdown=True, followlinks=False):
        here = Path(current)
        directories[:] = sorted(
            (name for name in directories
             if name not in _SKIP_DIRECTORIES and not (here / name).is_symlink()),
            key=str.casefold)
        candidates.extend(here / name for name in sorted(names, key=str.casefold)
                          if name.lower() in _LOCK_NAMES)
    candidates.sort(key=lambda path: path.as_posix().casefold())
    if len(candidates) > MAX_FILES:
        raise SupplyChainTrustError("manifest count exceeds boundary")
    nodes: dict[str, GraphNode] = {}; edges: dict[tuple[str, str, str], GraphEdge] = {}
    gaps: list[str] = []; manifests: list[dict[str, str]] = []; total = 0
    for path in candidates:
        try:
            relative = path.resolve().relative_to(base).as_posix()
            text, raw = _read(path); total += len(raw)
            if total > MAX_TOTAL_BYTES: raise SupplyChainTrustError("total manifest bytes exceed boundary")
            ecosystem, parser, exactness = _PARSERS[path.name.lower()]
            found_nodes, found_edges, found_gaps = parser(text, relative)
            manifests.append({"path": _terminal_text(relative), "ecosystem": ecosystem,
                              "exactness": exactness,
                              "sha256": hashlib.sha256(raw).hexdigest()})
            gaps.extend(relative + ": " + gap for gap in found_gaps)
            for node in found_nodes: nodes[node.id] = node
            for edge in found_edges: edges[(edge.source, edge.target, edge.relationship)] = edge
        except (OSError, SupplyChainTrustError, TypeError, ValueError, OverflowError) as exc:
            gaps.append(path.name + ": " + str(exc))
        if len(nodes) > MAX_NODES or len(edges) > MAX_EDGES:
            raise SupplyChainTrustError("graph exceeds node/edge boundary")
    node_rows = []
    for node in sorted(nodes.values(), key=lambda item: item.id):
        row = asdict(node)
        for field in ("name", "version", "evidence"):
            row[field] = _terminal_text(row[field])
        node_rows.append(row)
    node_ids = {item["id"] for item in node_rows}
    edge_rows = []
    for edge in sorted(edges.values(), key=lambda item: (item.source, item.target)):
        if edge.source in node_ids and edge.target in node_ids:
            row = asdict(edge)
            row["evidence"] = _terminal_text(row["evidence"])
            edge_rows.append(row)
    status = "unavailable" if not candidates else "partial" if gaps else "complete"
    body = {"schema": GRAPH_SCHEMA, "version": VERSION, "status": status,
            "root": _terminal_text(str(base), 32_768), "manifests": manifests,
            "nodes": node_rows, "edges": edge_rows,
            "gaps": sorted(set(_terminal_text(gap) for gap in gaps))[:2_000],
            "unavailable_adapters": ["Bazel resolved graph", "Maven effective model",
                                     "Gradle variant-aware graph", "registry resolution"],
            "execution": {"network": False, "package_managers": False,
                          "target_code": False, "dependency_install": False}}
    body["graph_sha256"] = _sha({key: value for key, value in body.items()
                                  if key != "graph_sha256"})
    return body


def verify_graph_report(report: Any) -> bool:
    """Verify graph integrity and that every edge names two emitted nodes."""
    try:
        if (type(report) is not dict or report.get("schema") != GRAPH_SCHEMA or
                report.get("version") != VERSION or
                report.get("status") not in {"complete", "partial", "unavailable"} or
                type(report.get("nodes")) is not list or type(report.get("edges")) is not list):
            return False
        identifiers = [node.get("id") for node in report["nodes"] if type(node) is dict]
        if len(identifiers) != len(report["nodes"]) or len(set(identifiers)) != len(identifiers):
            return False
        identifier_set = set(identifiers)
        if any(type(edge) is not dict or edge.get("source") not in identifier_set or
               edge.get("target") not in identifier_set for edge in report["edges"]):
            return False
        digest = report.get("graph_sha256")
        body = {key: value for key, value in report.items()
                if key != "graph_sha256"}
        return bool(isinstance(digest, str) and _HEX64.fullmatch(digest) and
                    hmac.compare_digest(digest, _sha(body)))
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return False


def create_osv_snapshot(records: Iterable[Mapping[str, Any]], *, key: bytes,
                        key_id: str, sequence: int, generated_at: str) -> dict[str, Any]:
    if not isinstance(key, bytes) or len(key) < 32:
        raise SupplyChainTrustError("snapshot authentication key must contain 32 bytes")
    try:
        supplied_rows: list[dict[str, Any]] = []
        for index, item in enumerate(records):
            if index >= MAX_OSV_RECORDS:
                raise SupplyChainTrustError("snapshot record boundary is invalid")
            supplied_rows.append(dict(item))
        rows = _validated_osv_rows(supplied_rows)
    except (TypeError, ValueError) as exc:
        raise SupplyChainTrustError("record is not OSV-compatible") from exc
    if (type(sequence) is not int or sequence < 0 or
            not isinstance(key_id, str) or not _IDENTITY.fullmatch(key_id) or
            key_id != _terminal_text(key_id, 512)):
        raise SupplyChainTrustError("snapshot metadata exceeds contract")
    generated = _timestamp(generated_at)
    body = {"schema": OSV_SCHEMA, "sequence": int(sequence),
            "generated_at": generated, "records": rows,
            "transport": "caller-supplied-offline-bytes", "network": False}
    try:
        digest = _sha(body)
    except (TypeError, ValueError, OverflowError, RecursionError):
        digest = ""
        errors.append("snapshot body is not canonically serializable")
    key_id = _terminal_text(key_id, 512)
    body["authentication"] = {"algorithm": "hmac-sha256", "key_id": key_id,
                              "payload_sha256": digest,
                              "tag": hmac.new(
                                  key, _osv_hmac_input(key_id, digest),
                                  hashlib.sha256).hexdigest()}
    return body


def import_osv_snapshot(payload: bytes | str | Mapping[str, Any],
                        trusted_keys: Mapping[str, bytes],
                        previous_checkpoint: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Authenticate caller-supplied offline bytes and return, but never persist, a checkpoint."""
    try:
        if isinstance(payload, bytes):
            if len(payload) > MAX_TOTAL_BYTES: raise SupplyChainTrustError("snapshot exceeds byte boundary")
            value = _json(payload.decode("utf-8"), "snapshot")
        elif isinstance(payload, str):
            if len(payload.encode("utf-8", "replace")) > MAX_TOTAL_BYTES:
                raise SupplyChainTrustError("snapshot exceeds byte boundary")
            value = _json(payload, "snapshot")
        else:
            value = dict(payload)
            if len(_canonical(value)) > MAX_TOTAL_BYTES:
                raise SupplyChainTrustError("snapshot exceeds byte boundary")
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError,
            OverflowError, RecursionError) as exc:
        raise SupplyChainTrustError("snapshot cannot be decoded") from exc
    if type(value) is not dict:
        raise SupplyChainTrustError("snapshot root must be an object")
    auth = value.get("authentication") if type(value) is dict else None
    auth_valid = bool(
        type(auth) is dict and
        set(auth) == {"algorithm", "key_id", "payload_sha256", "tag"} and
        auth.get("algorithm") == "hmac-sha256" and
        isinstance(auth.get("key_id"), str) and
        _IDENTITY.fullmatch(auth["key_id"]) and
        auth["key_id"] == _terminal_text(auth["key_id"], 512) and
        isinstance(auth.get("payload_sha256"), str) and
        _HEX64.fullmatch(auth["payload_sha256"]) and
        isinstance(auth.get("tag"), str) and _HEX64.fullmatch(auth["tag"])
    )
    body = {key: item for key, item in value.items() if key != "authentication"}
    errors: list[str] = []
    if value.get("schema") != OSV_SCHEMA or not auth_valid:
        errors.append("snapshot schema/authentication is invalid")
    records = value.get("records")
    try:
        validated_records = _validated_osv_rows(records)
        if validated_records != records:
            errors.append("snapshot records are not in canonical identifier order")
    except SupplyChainTrustError as exc:
        validated_records = []
        errors.append(str(exc))
    if (value.get("transport") != "caller-supplied-offline-bytes" or
            value.get("network") is not False):
        errors.append("snapshot offline transport contract is invalid")
    try:
        _timestamp(value.get("generated_at"))
    except SupplyChainTrustError as exc:
        errors.append(str(exc))
    digest = _sha(body)
    key_id = auth.get("key_id") if auth_valid else None
    key = (trusted_keys.get(key_id)
           if (isinstance(trusted_keys, Mapping) and isinstance(key_id, str)) else None)
    authenticated = False
    if (auth_valid and isinstance(key_id, str) and
            isinstance(key, bytes) and len(key) >= 32):
        expected = hmac.new(
            key, _osv_hmac_input(key_id, digest), hashlib.sha256).hexdigest()
        authenticated = (hmac.compare_digest(auth["payload_sha256"], digest) and
                         hmac.compare_digest(auth["tag"], expected))
    if not authenticated: errors.append("snapshot authentication failed")
    sequence = value.get("sequence")
    if type(sequence) is not int or sequence < 0: errors.append("snapshot sequence is invalid")
    if previous_checkpoint and not isinstance(previous_checkpoint, Mapping):
        errors.append("previous checkpoint is invalid")
    elif previous_checkpoint:
        prior_sequence = previous_checkpoint.get("sequence")
        prior_digest = previous_checkpoint.get("payload_sha256")
        if (type(prior_sequence) is not int or prior_sequence < 0 or
                not isinstance(prior_digest, str) or not _HEX64.fullmatch(prior_digest)):
            errors.append("previous checkpoint is invalid")
        elif type(sequence) is int:
            if sequence < prior_sequence: errors.append("snapshot rollback detected")
            if sequence == prior_sequence and prior_digest != digest:
                errors.append("snapshot equivocation detected")
    accepted = authenticated and not errors
    return {"accepted": accepted, "authenticated": authenticated, "errors": errors,
            "records": validated_records if accepted else [], "network": False,
            "checkpoint": {"sequence": sequence, "payload_sha256": digest,
                           "generated_at": value.get("generated_at", "")}
            if accepted else None}


__all__ = ["SupplyChainTrustError", "analyze_dependency_graph", "create_osv_snapshot",
           "import_osv_snapshot", "verify_graph_report", "GRAPH_SCHEMA", "OSV_SCHEMA"]
