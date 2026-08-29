#!/usr/bin/env python3
"""Exact-evidence supply-chain additions for Attestor 3.5.

The module extracts dependency edges only when a lockfile encodes them, applies
ecosystem-aware bounded version comparison, prevents ungrounded ``not_affected``
VEX decisions, and rejects advisory snapshot rollback/equivocation.  It performs
no dependency installation, imports, build execution, or network access.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

import supply_chain_center


VERSION = "3.5.0"
SCHEMA = "attestor.supply-chain-graph/3.5"
REACHABILITY_PROOF_SCHEMA = "attestor.reachability-proof/4.1"
MAX_MANIFESTS = 512
MAX_BYTES = 16 * 1024 * 1024
MAX_NODES = 100_000
MAX_EDGES = 250_000
_NAME = re.compile(r"^[A-Za-z0-9@._/+~-]{1,300}$")


class SupplyChain35Error(ValueError):
    pass


@dataclass(frozen=True)
class DependencyNode:
    id: str
    ecosystem: str
    name: str
    version: str
    source: str
    integrity: str = ""


@dataclass(frozen=True)
class DependencyEdge:
    source: str
    target: str
    relationship: str
    evidence: str
    state: str = "exact"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _safe_relative(root: Path, path: Path) -> str:
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise SupplyChain35Error("manifest escapes workspace") from exc
    if path.is_symlink() or not path.is_file():
        raise SupplyChain35Error("linked/non-regular manifests are not accepted")
    return relative


def _node_id(ecosystem: str, name: str, version: str, source: str) -> str:
    return "dep35-" + _sha([ecosystem, name, version, source])[:24]


def _node(ecosystem: str, name: str, version: str, source: str,
          integrity: str = "") -> DependencyNode:
    clean_name = str(name).strip()
    clean_version = str(version).strip()
    if not _NAME.fullmatch(clean_name) or len(clean_version) > 200:
        raise SupplyChain35Error("dependency identity is invalid")
    safe_integrity = integrity if re.fullmatch(r"(?:sha(?:256|384|512)-)?[A-Za-z0-9+/=_-]{16,512}", integrity or "") else ""
    return DependencyNode(_node_id(ecosystem, clean_name, clean_version, source),
                          ecosystem, clean_name, clean_version, source, safe_integrity)


def _npm_name(path_key: str, row: Mapping[str, Any]) -> str:
    if isinstance(row.get("name"), str) and row["name"]:
        return row["name"]
    marker = "node_modules/"
    return path_key.rsplit(marker, 1)[-1] if marker in path_key else "workspace-root"


def _parse_package_lock(path: Path, relative: str) -> tuple[list[DependencyNode], list[DependencyEdge], list[str]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SupplyChain35Error("package-lock cannot be parsed") from exc
    if type(value) is not dict:
        raise SupplyChain35Error("package-lock root is not an object")
    nodes: list[DependencyNode] = []
    edges: list[DependencyEdge] = []
    gaps: list[str] = []
    packages = value.get("packages")
    if type(packages) is dict:
        by_path: dict[str, DependencyNode] = {}
        for path_key, row in sorted(packages.items()):
            if type(row) is not dict:
                continue
            # package-lock v2/v3 encodes the workspace root under the empty key.
            # It must be a real graph node: a synthetic id that is absent from
            # ``nodes`` makes every root dependency edge structurally invalid.
            name = (_npm_name(str(path_key), row) if path_key else "workspace-root")
            node = _node("npm", name, str(row.get("version", value.get("version", ""))),
                         relative + "#/packages/" + (str(path_key) or "<root>"),
                         str(row.get("integrity", "")))
            by_path[str(path_key)] = node; nodes.append(node)
        for owner_path, row in sorted(packages.items()):
            if type(row) is not dict:
                continue
            owner = by_path.get(str(owner_path))
            if owner is None:
                gaps.append("npm edge owner is absent from the exact graph: " +
                            (str(owner_path)[:200] or "<root>"))
                continue
            source_id = owner.id
            for dep_name in sorted((row.get("dependencies") or {}).keys()) \
                    if type(row.get("dependencies")) is dict else ():
                candidates = []
                current = str(owner_path)
                while True:
                    candidate = (current + "/node_modules/" + dep_name).strip("/")
                    if candidate in by_path:
                        candidates.append(by_path[candidate]); break
                    if "/node_modules/" not in current:
                        break
                    current = current.rsplit("/node_modules/", 1)[0]
                root_candidate = "node_modules/" + dep_name
                if not candidates and root_candidate in by_path:
                    candidates.append(by_path[root_candidate])
                if len(candidates) == 1:
                    edges.append(DependencyEdge(source_id, candidates[0].id, "depends-on",
                                                relative + " package-lock packages map"))
                else:
                    gaps.append("npm edge could not be resolved exactly: " + str(dep_name)[:200])
    else:
        gaps.append("package-lock lacks the v2/v3 packages map; graph is partial")
    return nodes, edges, gaps


def _parse_toml_lock(path: Path, relative: str, ecosystem: str) -> tuple[list[DependencyNode], list[DependencyEdge], list[str]]:
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise SupplyChain35Error("%s lockfile cannot be parsed" % ecosystem) from exc
    packages = value.get("package") if type(value) is dict else None
    if type(packages) is not list:
        raise SupplyChain35Error("%s lockfile has no package table" % ecosystem)
    nodes: list[DependencyNode] = []
    edges: list[DependencyEdge] = []
    gaps: list[str] = []
    by_name: dict[str, list[DependencyNode]] = {}
    rows: list[tuple[Mapping[str, Any], DependencyNode]] = []
    for index, row in enumerate(packages):
        if type(row) is not dict:
            continue
        node = _node(ecosystem, str(row.get("name", "")), str(row.get("version", "")),
                     "%s#/package/%d" % (relative, index), str(row.get("checksum", "")))
        nodes.append(node); rows.append((row, node)); by_name.setdefault(node.name, []).append(node)
    for row, owner in rows:
        dependencies = row.get("dependencies")
        if type(dependencies) is dict:
            names = sorted(str(name) for name in dependencies)
        elif type(dependencies) is list:
            names = sorted(str(item).split()[0] for item in dependencies if str(item).strip())
        else:
            names = []
        for name in names:
            candidates = by_name.get(name, [])
            if len(candidates) == 1:
                edges.append(DependencyEdge(owner.id, candidates[0].id, "depends-on",
                                            relative + " package dependency table"))
            else:
                gaps.append("%s dependency is version-ambiguous: %s" % (ecosystem, name[:200]))
    return nodes, edges, gaps


def analyze_dependency_graph(root: str | os.PathLike[str]) -> dict[str, Any]:
    base = Path(root).expanduser().resolve()
    if not base.is_dir():
        raise SupplyChain35Error("dependency graph root must be a directory")
    candidates = []
    for name in ("package-lock.json", "Cargo.lock", "poetry.lock"):
        candidates.extend(base.rglob(name))
    candidates = sorted(set(candidates), key=lambda item: item.as_posix().casefold())
    if len(candidates) > MAX_MANIFESTS:
        raise SupplyChain35Error("manifest count exceeds graph boundary")
    nodes: dict[str, DependencyNode] = {}
    edges: dict[tuple[str, str, str], DependencyEdge] = {}
    gaps: list[str] = []
    manifests: list[str] = []
    total = 0
    for path in candidates:
        relative = _safe_relative(base, path)
        size = path.stat().st_size; total += size
        if size > MAX_BYTES or total > MAX_BYTES:
            gaps.append(relative + ": graph input exceeded byte boundary"); continue
        try:
            if path.name == "package-lock.json":
                found_nodes, found_edges, found_gaps = _parse_package_lock(path, relative)
            elif path.name == "Cargo.lock":
                found_nodes, found_edges, found_gaps = _parse_toml_lock(path, relative, "cargo")
            else:
                found_nodes, found_edges, found_gaps = _parse_toml_lock(path, relative, "pypi")
        except SupplyChain35Error as exc:
            gaps.append(relative + ": " + str(exc)); continue
        manifests.append(relative); gaps.extend(found_gaps)
        for item in found_nodes:
            nodes[item.id] = item
        for item in found_edges:
            edges[(item.source, item.target, item.relationship)] = item
        if len(nodes) > MAX_NODES or len(edges) > MAX_EDGES:
            raise SupplyChain35Error("dependency graph exceeds node/edge boundary")
    node_rows = [asdict(item) for item in sorted(nodes.values(), key=lambda row: row.id)]
    edge_rows = [asdict(item) for item in sorted(edges.values(), key=lambda row: (row.source, row.target))]
    status = "complete" if manifests and not gaps else "partial" if manifests else "unavailable"
    body = {"schema": SCHEMA, "version": VERSION, "status": status,
            "root": str(base), "manifests": manifests, "nodes": node_rows,
            "edges": edge_rows, "gaps": sorted(set(gaps))[:1_000],
            "execution": {"dependencies_installed": False, "network": False,
                          "build_scripts": False, "target_code": False}}
    body["graph_sha256"] = _sha({key: value for key, value in body.items()
                                 if key not in {"root", "graph_sha256"}})
    return body


def _semver(value: str) -> tuple[tuple[int, int, int], tuple[Any, ...]] | None:
    match = re.fullmatch(r"v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
                         r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?", value.strip())
    if not match:
        return None
    prerelease: tuple[Any, ...] = ()
    if match.group(4):
        prerelease = tuple(int(part) if part.isdigit() else part.lower()
                           for part in match.group(4).split("."))
    return (tuple(int(match.group(i)) for i in range(1, 4)), prerelease)


def _pep440(value: str) -> tuple[int, ...] | None:
    match = re.fullmatch(r"(?i)v?(\d+(?:\.\d+)*)(?:(a|b|rc)(\d+))?(?:\.post(\d+))?", value.strip())
    if not match:
        return None
    release = tuple(int(part) for part in match.group(1).split("."))
    tag_rank = {None: 3, "a": 0, "b": 1, "rc": 2}[match.group(2).lower() if match.group(2) else None]
    return release + (tag_rank, int(match.group(3) or 0), int(match.group(4) or -1))


def compare_versions(ecosystem: str, left: str, right: str) -> int | None:
    """Return -1/0/1, or None when comparison cannot be proven."""
    family = str(ecosystem).lower()
    if family in {"npm", "cargo", "nuget", "go", "golang", "composer"}:
        parsed_left, parsed_right = _semver(left), _semver(right)
        if parsed_left is None or parsed_right is None:
            return None
        if parsed_left[0] != parsed_right[0]:
            return -1 if parsed_left[0] < parsed_right[0] else 1
        # A release is newer than its prerelease.  Mixed numeric/text identifiers
        # are deliberately left unknown instead of approximated incorrectly.
        if not parsed_left[1] and parsed_right[1]: return 1
        if parsed_left[1] and not parsed_right[1]: return -1
        if parsed_left[1] == parsed_right[1]: return 0
        if all(type(a) is type(b) for a, b in zip(parsed_left[1], parsed_right[1])):
            return -1 if parsed_left[1] < parsed_right[1] else 1
        return None
    if family in {"pypi", "python"}:
        parsed_left, parsed_right = _pep440(left), _pep440(right)
        if parsed_left is None or parsed_right is None:
            return None
        width = max(len(parsed_left), len(parsed_right))
        a = parsed_left + (0,) * (width - len(parsed_left))
        b = parsed_right + (0,) * (width - len(parsed_right))
        return 0 if a == b else -1 if a < b else 1
    return None


def make_reachability_proof(component_id: str, *, reachable: bool,
                            entrypoints: Iterable[str], call_chains: Iterable[Iterable[str]],
                            analysis_sha256: str,
                            inventory_sha256: str = "") -> dict[str, Any]:
    entries = sorted(set(str(item)[:300] for item in entrypoints if item))
    chains = [list(map(lambda item: str(item)[:300], chain))[:64]
              for chain in call_chains]
    analysis_digest = str(analysis_sha256)
    # Backward-compatible callers may only have one content-addressed analysis
    # snapshot.  New callers should bind the proof to the separate inventory
    # digest as well.
    inventory_digest = str(inventory_sha256 or analysis_digest)
    bounded_entries = entries[:2_000]
    entrypoints_digest = _sha(bounded_entries)
    scope_digest = _sha({"component_id": str(component_id)[:500],
                         "analysis_sha256": analysis_digest,
                         "inventory_sha256": inventory_digest,
                         "entrypoints_sha256": entrypoints_digest})
    body = {"schema": REACHABILITY_PROOF_SCHEMA,
            "component_id": str(component_id)[:500], "reachable": bool(reachable),
            "entrypoints": bounded_entries, "call_chains": chains[:2_000],
            "analysis_sha256": analysis_digest,
            "inventory_sha256": inventory_digest,
            "entrypoints_sha256": entrypoints_digest,
            "scope_sha256": scope_digest,
            "exhaustive": bool(not reachable and "<all-observed-entrypoints>" in entries),
            "method": "attestor-call-graph/4.1"}
    body["proof_sha256"] = _sha(body)
    return body


def verify_reachability_proof(proof: Any, component_id: str | None = None) -> bool:
    """Fail closed unless the complete content-addressed proof contract holds."""
    try:
        if type(proof) is not dict or type(proof.get("reachable")) is not bool:
            return False
        if proof.get("schema") != REACHABILITY_PROOF_SCHEMA:
            return False
        proof_component = proof.get("component_id")
        if (not isinstance(proof_component, str) or not proof_component or
                len(proof_component) > 500):
            return False
        if component_id is not None and proof_component != str(component_id)[:500]:
            return False
        digest = proof.get("proof_sha256")
        body = {key: value for key, value in proof.items() if key != "proof_sha256"}
        digest_fields = ("analysis_sha256", "inventory_sha256", "entrypoints_sha256",
                         "scope_sha256")
        if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or
                not hmac.compare_digest(digest, _sha(body)) or
                any(not re.fullmatch(r"[0-9a-f]{64}", str(proof.get(name, "")))
                    for name in digest_fields) or
                proof["analysis_sha256"] == "0" * 64 or
                proof["inventory_sha256"] == "0" * 64):
            return False
        chains = proof.get("call_chains")
        entries = proof.get("entrypoints")
        if (type(chains) is not list or len(chains) > 2_000 or
                type(entries) is not list or not entries or len(entries) > 2_000 or
                any(not isinstance(item, str) or not item or len(item) > 300
                    for item in entries) or
                entries != sorted(set(entries)) or
                any(type(chain) is not list or not 2 <= len(chain) <= 64 or
                    any(not isinstance(item, str) or not item or len(item) > 300
                        for item in chain)
                    for chain in chains) or
                proof.get("method") != "attestor-call-graph/4.1" or
                type(proof.get("exhaustive")) is not bool):
            return False
        if not hmac.compare_digest(proof["entrypoints_sha256"], _sha(entries)):
            return False
        expected_scope = _sha({"component_id": proof_component,
                               "analysis_sha256": proof["analysis_sha256"],
                               "inventory_sha256": proof["inventory_sha256"],
                               "entrypoints_sha256": proof["entrypoints_sha256"]})
        if not hmac.compare_digest(proof["scope_sha256"], expected_scope):
            return False
        if proof["reachable"]:
            return (proof["exhaustive"] is False and
                    any(chain[0] in entries for chain in chains))
        # An unreachable disposition needs an exhaustive entrypoint set marker,
        # at least one concrete entrypoint, and no alleged positive call chain.
        concrete_entries = [item for item in entries
                            if item != "<all-observed-entrypoints>"]
        return (not chains and proof["exhaustive"] is True and
                "<all-observed-entrypoints>" in entries and bool(concrete_entries))
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def vex_disposition(advisory_id: str, component_id: str, reachability: Any) -> dict[str, Any]:
    verified = verify_reachability_proof(reachability, str(component_id))
    unreachable = verified and reachability.get("reachable") is False
    return {"advisory_id": str(advisory_id)[:256], "component_id": str(component_id)[:500],
            "status": "not_affected" if unreachable else "under_investigation",
            "justification": "code_not_reachable" if unreachable else "insufficient_evidence",
            "reachability_proof_sha256": reachability.get("proof_sha256", "") if verified else "",
            "evidence_state": "verified" if verified else "unknown"}


def verify_snapshot_progress(snapshot: Mapping[str, Any], trusted_keys: Mapping[str, bytes],
                             previous: Mapping[str, Any] | None = None, *, now=None) -> dict[str, Any]:
    verification = supply_chain_center.verify_advisory_snapshot(
        snapshot, trusted_keys, now=now)
    errors = list(verification.errors)
    current_digest = _sha(snapshot)
    generated = str(snapshot.get("generated_at", ""))
    if previous:
        previous_time = str(previous.get("generated_at", ""))
        previous_digest = str(previous.get("snapshot_sha256", ""))
        if generated < previous_time:
            errors.append("advisory snapshot rollback detected")
        if generated == previous_time and previous_digest and previous_digest != current_digest:
            errors.append("advisory snapshot equivocation detected")
    # The legacy verifier deliberately distinguishes cryptographic validity
    # from freshness.  Attestor 3.5 only advances a trusted checkpoint when both
    # properties hold; stale, future-dated, and expiry-unknown snapshots remain
    # inspectable but cannot replace the last known-good snapshot.
    accepted = bool(verification.valid and verification.authenticated
                    and verification.state == "fresh" and not errors)
    return {"accepted": accepted, "authenticated": bool(verification.authenticated),
            "freshness": verification.state, "generated_at": generated,
            "snapshot_sha256": current_digest, "errors": errors,
            "checkpoint": {"generated_at": generated, "snapshot_sha256": current_digest}
            if accepted else None}
