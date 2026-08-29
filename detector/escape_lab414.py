#!/usr/bin/env python3
"""Private, data-only sandbox escape simulation for Attestor 4.1.4.

This module never attempts to escape an operating-system, VM, container, or
language sandbox.  It gives Cockroach Janta Party a compiled in-memory policy
graph containing synthetic boundary mistakes, asks it to find a path to a
*simulated* outside node, and explains the policy defect used by that path.

There are deliberately no caller-supplied commands, source files, paths, URLs,
payloads, plugins, processes, network adapters, or filesystem operations here.
The lab is a defensive policy-reasoning exercise, not an exploit runner.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import unicodedata
from typing import Any

import variant414


VERSION = "4.1.4"
SCHEMA = "attestor-private-escape-report/4.1.4"
SCENARIO_SCHEMA = "attestor-private-escape-scenario/4.1.4"
PROFILE_SLUG = "cockroach-janta-party"
ALL_SCENARIOS = "all"
MAX_GRAPH_NODES = 64
MAX_GRAPH_EDGES = 128
MAX_PATH_STEPS = 63
MAX_REPORT_BYTES = 256 * 1024
_SLUG = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")


class EscapeLabError(ValueError):
    """A bounded simulation contract was invalid."""


@dataclass(frozen=True)
class Edge:
    edge_id: str
    source: str
    target: str
    intended: str
    effective: str
    hole_type: str = "none"


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    title: str
    nodes: tuple[tuple[str, str], ...]
    edges: tuple[Edge, ...]
    start: str = "attestor-inside"
    goal: str = "simulated-outside"


_REASONS = {
    "stale-capability": (
        "the simulated use-time gate accepts an expired one-use capability "
        "without atomically re-checking expiry and consumption state",
        "Revalidate expiry, exact scope, issuer registry state, and one-use "
        "consumption atomically at the simulated boundary.",
    ),
    "path-alias": (
        "the simulated boundary validates an alias before resolving its final "
        "identity, then trusts the changed identity",
        "Resolve once to an owned identity, reject aliases/links, and recheck "
        "that identity immediately before simulated use.",
    ),
    "permission-inheritance": (
        "a simulated helper inherits a capability that its caller was never "
        "authorized to delegate",
        "Strip inherited capabilities and issue a new least-privilege grant "
        "bound to the helper's exact simulated operation.",
    ),
    "confused-deputy": (
        "a simulated trusted broker checks who it is rather than what the "
        "untrusted requester is allowed to ask it to do",
        "Authorize the original requester, purpose, target identity, and action "
        "at the broker boundary.",
    ),
    "boundary-misclassification": (
        "the simulated egress broker labels every loopback request internal "
        "even when its destination represents the outside zone",
        "Classify and allowlist the final simulated destination after proxy "
        "resolution, with external destinations denied by default.",
    ),
}


def _scenario(
        scenario_id: str,
        title: str,
        middle: str,
        hole_type: str,
        *,
        planted: bool = True,
) -> Scenario:
    return Scenario(
        scenario_id=scenario_id,
        title=title,
        nodes=tuple(sorted((
            ("boundary-gate", "boundary"),
            (middle, "sandbox"),
            ("attestor-inside", "sandbox"),
            ("simulated-outside", "synthetic-outside"),
        ), key=lambda row: row[0])),
        edges=(
            Edge("edge-enter", "attestor-inside", middle, "allow", "allow"),
            Edge("edge-gate", middle, "boundary-gate", "allow", "allow"),
            Edge(
                "edge-planted" if planted else "edge-sealed",
                "boundary-gate", "simulated-outside", "deny",
                "allow" if planted else "deny",
                hole_type if planted else "none"),
        ),
    )


SCENARIOS = (
    _scenario(
        "stale-capability-recheck",
        "Expired one-use capability is not rechecked",
        "capability-console", "stale-capability"),
    _scenario(
        "path-alias-rebinding",
        "Validated identity can be rebound through an alias",
        "alias-resolver", "path-alias"),
    _scenario(
        "helper-permission-inheritance",
        "Helper receives a non-delegable capability",
        "approved-helper", "permission-inheritance"),
    _scenario(
        "broker-confused-deputy",
        "Trusted broker authorizes itself instead of the requester",
        "trusted-broker", "confused-deputy"),
    _scenario(
        "proxy-boundary-misclassification",
        "Loopback proxy misclassifies a synthetic outside destination",
        "loopback-proxy", "boundary-misclassification"),
    _scenario(
        "contained-reference",
        "Reference policy remains contained",
        "sealed-gate", "none", planted=False),
)
SCENARIO_IDS = tuple(item.scenario_id for item in SCENARIOS)
_SCENARIO_BY_ID = {item.scenario_id: item for item in SCENARIOS}


_CONTROLS = {
    "scope": (
        "escape-simulation-core-only; a caller may separately launch Attestor "
        "or request report serialization"),
    "simulation_only": True,
    "pure_in_memory": True,
    "offline": True,
    "host_files_read": False,
    "host_files_written": False,
    "files_deleted": False,
    "processes_started": False,
    "shell_invoked": False,
    "network_accessed": False,
    "target_code_executed": False,
    "real_escape_attempted": False,
    "kernel_or_container_boundary_touched": False,
    "permission_persisted": False,
}

# The presentation-layer deletion joke was removed.  Its only factual content
# was that the lab deletes nothing, and _CONTROLS states that directly through
# files_deleted and host_files_written, so no safety claim was lost with it.


def _canonical(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise EscapeLabError(
            "escape-lab value is not bounded deterministic JSON") from exc
    if len(encoded) > MAX_REPORT_BYTES:
        raise EscapeLabError("escape-lab value exceeds the public byte boundary")
    return encoded


def _sha(value: Any) -> str:
    return hashlib.sha256(
        value if type(value) is bytes else _canonical(value)).hexdigest()


def _profile_metadata() -> tuple[str, dict[str, Any]]:
    profile = variant414.require_compiled_profile(
        variant414.COCKROACH_JANTA_PARTY)
    return (
        variant414.profile_identity(profile),
        variant414.response_language_metadata(profile),
    )


def _scenario_body(scenario: Scenario) -> dict[str, Any]:
    return {
        "schema": SCENARIO_SCHEMA,
        "version": VERSION,
        "scenario_id": scenario.scenario_id,
        "title": scenario.title,
        "environment": "private-in-memory-policy-graph",
        "objective": (
            "Find a path from inside to the simulated outside state and "
            "explain the defective policy transition."),
        "start_node": scenario.start,
        "escape_node": scenario.goal,
        "nodes": [
            {"id": node_id, "zone": zone}
            for node_id, zone in scenario.nodes
        ],
        "edges": [
            {
                "id": edge.edge_id,
                "source": edge.source,
                "target": edge.target,
                "intended": edge.intended,
                "effective": edge.effective,
                "planted_hole": edge.hole_type != "none",
                "hole_type": edge.hole_type,
            }
            for edge in scenario.edges
        ],
    }


def _validate_compiled_scenario(scenario: Scenario) -> None:
    body = _scenario_body(scenario)
    nodes = body["nodes"]
    edges = body["edges"]
    if (not _SLUG.fullmatch(scenario.scenario_id)
            or len(nodes) > MAX_GRAPH_NODES
            or len(edges) > MAX_GRAPH_EDGES):
        raise EscapeLabError("compiled scenario exceeds its graph boundary")
    node_ids = [row["id"] for row in nodes]
    if (node_ids != sorted(node_ids) or len(node_ids) != len(set(node_ids))
            or any(_SLUG.fullmatch(value) is None for value in node_ids)):
        raise EscapeLabError("compiled scenario node identities are invalid")
    zones = {row["id"]: row["zone"] for row in nodes}
    if (zones.get(scenario.start) != "sandbox"
            or zones.get(scenario.goal) != "synthetic-outside"):
        raise EscapeLabError("compiled scenario zones are invalid")
    edge_ids: set[str] = set()
    pairs: set[tuple[str, str]] = set()
    for edge in scenario.edges:
        if (not _SLUG.fullmatch(edge.edge_id)
                or edge.edge_id in edge_ids
                or (edge.source, edge.target) in pairs
                or edge.source not in zones or edge.target not in zones
                or edge.intended not in {"allow", "deny"}
                or edge.effective not in {"allow", "deny"}):
            raise EscapeLabError("compiled scenario edge is invalid")
        edge_ids.add(edge.edge_id)
        pairs.add((edge.source, edge.target))
        if edge.hole_type == "none":
            if edge.intended != edge.effective:
                raise EscapeLabError("non-hole edge changes policy")
        elif (edge.hole_type not in _REASONS
              or edge.intended != "deny" or edge.effective != "allow"):
            raise EscapeLabError("planted policy hole is inconsistent")
    if _find_path(scenario, "intended")[0]:
        raise EscapeLabError("compiled scenario is not contained by intent")


def _find_path(
        scenario: Scenario,
        decision: str,
) -> tuple[bool, list[Edge], int, int]:
    adjacency: dict[str, list[Edge]] = {}
    for edge in scenario.edges:
        if getattr(edge, decision) == "allow":
            adjacency.setdefault(edge.source, []).append(edge)
    for rows in adjacency.values():
        rows.sort(key=lambda edge: (edge.edge_id, edge.target))
    queue = deque([(scenario.start, tuple())])
    seen = {scenario.start}
    evaluated = 0
    while queue:
        node, path = queue.popleft()
        if node == scenario.goal:
            return True, list(path), len(seen), evaluated
        for edge in adjacency.get(node, ()):
            evaluated += 1
            if evaluated > MAX_GRAPH_EDGES:
                raise EscapeLabError("escape search exceeded its edge boundary")
            if edge.target in seen:
                continue
            candidate = path + (edge,)
            if len(candidate) > MAX_PATH_STEPS:
                raise EscapeLabError("escape search exceeded its path boundary")
            seen.add(edge.target)
            queue.append((edge.target, candidate))
    return False, [], len(seen), evaluated


def _solve(scenario: Scenario) -> dict[str, Any]:
    _validate_compiled_scenario(scenario)
    escaped, path, visited, evaluated = _find_path(scenario, "effective")
    holes = [edge for edge in path if edge.hole_type != "none"]
    if escaped and not holes:
        raise EscapeLabError(
            "effective escape path lacks a compiled planted policy hole")
    rows = [
        {
            "step": index,
            "edge_id": edge.edge_id,
            "source": edge.source,
            "target": edge.target,
            "planted_hole": edge.hole_type != "none",
            "hole_type": edge.hole_type,
        }
        for index, edge in enumerate(path, 1)
    ]
    if escaped:
        hole = holes[0]
        reason, mitigation = _REASONS[hole.hole_type]
        explanation = (
            "Synthetic escape succeeded because " + reason + ".")
        reason_code = hole.hole_type
    else:
        explanation = (
            "No effective allow-path reaches the simulated outside node.")
        mitigation = (
            "Keep the final boundary default-deny and continue replay tests.")
        reason_code = "contained"
    body = {
        "scenario_id": scenario.scenario_id,
        "scenario_sha256": _sha(_scenario_body(scenario)),
        "title": scenario.title,
        "status": "simulated-escaped" if escaped else "simulated-contained",
        "escaped_simulation": escaped,
        "path": rows,
        "escape_reason_code": reason_code,
        "escape_explanation": explanation,
        "mitigation": mitigation,
        "planted_holes_used": [edge.edge_id for edge in holes],
        "metrics": {
            "nodes": len(scenario.nodes),
            "edges": len(scenario.edges),
            "states_visited": visited,
            "edges_evaluated": evaluated,
            "path_steps": len(rows),
        },
    }
    return {**body, "evidence_sha256": _sha(body)}


def _selected(selection: str) -> tuple[Scenario, ...]:
    if type(selection) is not str:
        raise EscapeLabError("escape-lab scenario selection must be exact text")
    if selection == ALL_SCENARIOS:
        return SCENARIOS
    scenario = _SCENARIO_BY_ID.get(selection)
    if scenario is None:
        raise EscapeLabError("unknown compiled escape-lab scenario")
    return (scenario,)


def run(
        selection: str = ALL_SCENARIOS,
        *,
        simulation_confirmed: bool = False,
) -> dict[str, Any]:
    """Run only the compiled abstract policy simulation."""
    if type(simulation_confirmed) is not bool:
        raise EscapeLabError("simulation confirmation must be a literal boolean")
    if type(selection) is not str:
        raise EscapeLabError("escape-lab scenario selection must be exact text")
    profile_sha256, language = _profile_metadata()
    base = {
        "schema": SCHEMA,
        "version": VERSION,
        "profile": PROFILE_SLUG,
        "profile_sha256": profile_sha256,
        "response_language": language,
        "selection": selection,
        "mode": "private-in-memory-policy-graph",
        "objective": (
            "Find paths to a synthetic outside state and explain the planted "
            "policy defects without attempting a real escape."),
        "controls": dict(_CONTROLS),
        "limits": {
            "max_graph_nodes": MAX_GRAPH_NODES,
            "max_graph_edges": MAX_GRAPH_EDGES,
            "max_path_steps": MAX_PATH_STEPS,
            "max_report_bytes": MAX_REPORT_BYTES,
        },
    }
    if not simulation_confirmed:
        body = {
            **base,
            "status": "simulation-confirmation-required",
            "simulation_confirmed": False,
            "scenario_results": [],
            "summary": {
                "scenarios": 0,
                "simulated_escapes": 0,
                "contained": 0,
            },
        }
        return {**body, "report_sha256": _sha(body)}
    results = [_solve(item) for item in _selected(selection)]
    escapes = sum(row["escaped_simulation"] is True for row in results)
    body = {
        **base,
        "status": "simulated-escape-demonstrated" if escapes else "contained",
        "simulation_confirmed": True,
        "scenario_results": results,
        "summary": {
            "scenarios": len(results),
            "simulated_escapes": escapes,
            "contained": len(results) - escapes,
        },
    }
    return {**body, "report_sha256": _sha(body)}


def verify_report(report: Any) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if type(report) is not dict:
        return False, ["escape-lab report must be an exact object"]
    try:
        encoded = _canonical(report)
    except EscapeLabError as exc:
        return False, [str(exc)]
    if len(encoded) > MAX_REPORT_BYTES:
        errors.append("escape-lab report exceeds its byte boundary")
    selection = report.get("selection")
    if type(selection) is not str:
        return False, errors + ["escape-lab selection is invalid"]
    confirmed = report.get("simulation_confirmed")
    if type(confirmed) is not bool:
        return False, errors + ["escape-lab confirmation state is invalid"]
    try:
        expected = run(selection, simulation_confirmed=confirmed)
    except (EscapeLabError, variant414.VariantError):
        return False, errors + ["escape-lab report cannot be replayed"]
    if report != expected:
        errors.append("escape-lab replay mismatch")
    claimed = report.get("report_sha256")
    body = {key: value for key, value in report.items()
            if key != "report_sha256"}
    if (type(claimed) is not str or not re.fullmatch(r"[0-9a-f]{64}", claimed)
            or not hmac.compare_digest(claimed, _sha(body))):
        errors.append("escape-lab report digest mismatch")
    return not errors, errors


def _terminal_safe(value: str) -> str:
    output: list[str] = []
    for character in str(value):
        category = unicodedata.category(character)
        bidirectional = unicodedata.bidirectional(character)
        if (ord(character) < 32 or ord(character) == 127
                or category in {"Cf", "Cs"}
                or bidirectional in {"RLO", "LRO", "RLE", "LRE", "PDF",
                                     "RLI", "LRI", "FSI", "PDI"}):
            output.append("\\u%04x" % ord(character))
        else:
            output.append(character)
    return "".join(output)


def render_text(report: Any) -> str:
    valid, errors = verify_report(report)
    if not valid:
        detail = "; ".join(_terminal_safe(item) for item in errors[:3])
        return "Attestor private escape-lab report is invalid: " + detail + "\n"
    lines = [
        "Attestor 4.1.4 Private Sandbox Escape Lab",
        "SIMULATION ONLY - no host escape was attempted.",
        "Profile: Cockroach Janta Party | C3 (Attestor-specific)",
        "Status: " + _terminal_safe(report["status"]),
        "Environment: private in-memory policy graph",
        "Real deletion authority: 0%",
    ]
    if not report["simulation_confirmed"]:
        lines.append("Select the escape-lab mode to confirm this data-only simulation.")
        return "\n".join(lines) + "\n"
    for row in report["scenario_results"]:
        lines.extend([
            "",
            _terminal_safe(row["title"]),
            "  Result: " + _terminal_safe(row["status"]),
            "  Path: " + (
                " -> ".join(_terminal_safe(step["source"])
                             for step in row["path"])
                + (" -> " + _terminal_safe(row["path"][-1]["target"])
                   if row["path"] else "none")),
            "  Why: " + _terminal_safe(row["escape_explanation"]),
            "  Mitigation: " + _terminal_safe(row["mitigation"]),
        ])
    lines.extend([
        "",
        "Host files read: no; written: no; deleted: no",
    ])
    return "\n".join(lines).rstrip() + "\n"


__all__ = [
    "ALL_SCENARIOS",
    "EscapeLabError",
    "MAX_GRAPH_EDGES",
    "MAX_GRAPH_NODES",
    "MAX_PATH_STEPS",
    "MAX_REPORT_BYTES",
    "PROFILE_SLUG",
    "SCENARIOS",
    "SCENARIO_IDS",
    "SCHEMA",
    "VERSION",
    "render_text",
    "run",
    "verify_report",
]
