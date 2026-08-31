#!/usr/bin/env python3
"""Exploit chaining engine -- build multi-step attack paths from findings.

Takes findings from any scanner (dataflow, js_scanner, secret_scanner, etc.)
and chains them across vulnerability boundaries into attack graphs. Each edge
represents a capability gained from exploiting one finding that enables the
next. The engagement planner can consume these graphs to produce ordered
operation plans.

Example chain: SSRF → internal API access → SQLi → credential dump → lateral movement

Chaining rules (what each vuln class enables):
- command_injection / code_injection → full host compromise → pivot to any finding on same host
- sql_injection → database access → credential dump → if creds found, enable auth bypass
- ssrf → internal network access → enable findings on internal services
- path_traversal → file read → config/credential disclosure
- xss → session hijack → enable actions as victim user
- deserialization → code execution (same as RCE)
- file_upload → webshell → code execution
- secret (live) → direct access to the service the key belongs to
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from collections import defaultdict

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


@dataclass
class Node:
    id: str
    finding: dict
    vuln_type: str
    cwe: str
    file: str
    line: int
    severity: str
    host: str = "localhost"
    capability: str = ""


@dataclass
class Edge:
    src: str
    dst: str
    label: str
    capability_gained: str
    capability_required: str = ""


@dataclass
class AttackPath:
    nodes: list[Node]
    edges: list[Edge]
    impact: str
    score: float


@dataclass
class AttackGraph:
    nodes: list[Node]
    edges: list[Edge]
    paths: list[AttackPath]
    entry_points: list[str]

    def to_dict(self) -> dict:
        return {
            "nodes": [
                {"id": n.id, "vuln_type": n.vuln_type, "cwe": n.cwe,
                 "file": n.file, "line": n.line, "severity": n.severity,
                 "host": n.host, "capability": n.capability}
                for n in self.nodes
            ],
            "edges": [
                {"src": e.src, "dst": e.dst, "label": e.label,
                 "capability_gained": e.capability_gained,
                 "capability_required": e.capability_required}
                for e in self.edges
            ],
            "paths": [
                {"nodes": [n.id for n in p.nodes],
                 "edges": [{"src": e.src, "dst": e.dst, "label": e.label}
                           for e in p.edges],
                 "impact": p.impact, "score": p.score}
                for p in self.paths
            ],
            "entry_points": self.entry_points,
            "stats": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "total_paths": len(self.paths),
                "max_depth": max((len(p.nodes) for p in self.paths), default=0),
            },
        }


_RCE_TYPES = {"command_injection", "code_injection", "deserialization", "file_upload"}
_DATA_ACCESS_TYPES = {"sql_injection", "path_traversal", "xxe"}
_NETWORK_TYPES = {"ssrf"}
_CLIENT_TYPES = {"xss", "open_redirect"}

_CAPABILITY_MAP = {
    "command_injection": "code_execution",
    "code_injection": "code_execution",
    "deserialization": "code_execution",
    "file_upload": "code_execution",
    "sql_injection": "database_access",
    "path_traversal": "file_read",
    "ssrf": "internal_network",
    "xss": "session_hijack",
    "open_redirect": "phishing",
    "xxe": "file_read",
    "information_disclosure": "info_leak",
    "idor": "data_access",
    "template_injection": "code_execution",
    "log_injection": "log_tampering",
    "email_injection": "spam",
}

_IMPACT_MAP = {
    "code_execution": 10.0,
    "database_access": 8.0,
    "internal_network": 7.0,
    "file_read": 6.0,
    "session_hijack": 5.0,
    "credential_access": 9.0,
    "data_access": 7.0,
    "info_leak": 4.0,
    "phishing": 3.0,
    "log_tampering": 2.0,
    "spam": 1.0,
}

_SEV_SCORE = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _normalize_finding(f: dict) -> dict:
    vt = (f.get("sink_type") or f.get("category") or f.get("vulnerability") or "")
    if not vt and f.get("rule_id"):
        parts = f["rule_id"].split("-")
        vt = parts[1] if len(parts) > 1 else "unknown"
    vt = (vt or "unknown").lower().replace("-", "_")
    return {
        "vuln_type": vt,
        "cwe": f.get("cwe") or f.get("sink_cwe") or "",
        "file": f.get("sink_file") or f.get("file") or f.get("path") or "",
        "line": int(f.get("sink_line") or f.get("line") or 0),
        "severity": f.get("severity") or "MEDIUM",
        "host": f.get("host") or _infer_host(f),
        "source_type": f.get("source_type") or "",
        "trace": f.get("trace") or [],
        "reachable": f.get("reachable", True),
        "raw": f,
    }


def _infer_host(f: dict) -> str:
    path = f.get("sink_file") or f.get("file") or ""
    for marker in ("api/", "services/", "backend/", "server/"):
        if marker in path.replace("\\", "/"):
            return "server"
    return "localhost"


def _can_chain(src_cap: str, dst_vuln: str, dst_host: str, src_host: str) -> tuple[bool, str]:
    if src_cap == "code_execution":
        if src_host == dst_host:
            return True, "host compromised → exploit co-located vulnerability"
        return True, "pivot from compromised host"

    if src_cap == "database_access":
        if dst_vuln in ("command_injection", "code_injection"):
            return True, "credentials from DB → authenticate and exploit"
        if dst_vuln == "path_traversal":
            return True, "DB data reveals file paths"
        return False, ""

    if src_cap == "internal_network":
        if dst_host != src_host:
            return True, "SSRF → reach internal service"
        return False, ""

    if src_cap == "file_read":
        if dst_vuln in _RCE_TYPES:
            return True, "config/credentials from file read → exploit service"
        if dst_vuln == "sql_injection":
            return True, "DB credentials from config file → direct DB access"
        return False, ""

    if src_cap == "session_hijack":
        if dst_vuln in ("idor", "information_disclosure"):
            return True, "hijacked session → access restricted endpoints"
        return False, ""

    if src_cap == "credential_access":
        return True, "stolen credentials → authenticate to service"

    return False, ""


def build_graph(findings: list[dict]) -> AttackGraph:
    normalized = [_normalize_finding(f) for f in findings]
    normalized = [f for f in normalized if f["reachable"]]

    nodes = []
    node_map = {}
    for i, f in enumerate(normalized):
        nid = f"v{i}"
        cap = _CAPABILITY_MAP.get(f["vuln_type"], "")
        n = Node(id=nid, finding=f["raw"], vuln_type=f["vuln_type"],
                 cwe=f["cwe"], file=f["file"], line=f["line"],
                 severity=f["severity"], host=f["host"], capability=cap)
        nodes.append(n)
        node_map[nid] = n

    edges = []
    for src in nodes:
        if not src.capability:
            continue
        for dst in nodes:
            if src.id == dst.id:
                continue
            can, label = _can_chain(src.capability, dst.vuln_type,
                                    dst.host, src.host)
            if can:
                edges.append(Edge(
                    src=src.id, dst=dst.id, label=label,
                    capability_gained=_CAPABILITY_MAP.get(dst.vuln_type, ""),
                    capability_required=src.capability,
                ))

    adj = defaultdict(list)
    for e in edges:
        adj[e.src].append(e)

    entry_points = [n.id for n in nodes
                    if n.vuln_type in _RCE_TYPES | _NETWORK_TYPES | _DATA_ACCESS_TYPES
                    and n.severity in ("CRITICAL", "HIGH")]
    if not entry_points:
        entry_points = [n.id for n in nodes if n.capability]

    paths = []
    for start in entry_points:
        for p in _find_paths(start, adj, node_map, max_depth=6):
            paths.append(p)

    paths.sort(key=lambda p: p.score, reverse=True)

    return AttackGraph(nodes=nodes, edges=edges, paths=paths,
                       entry_points=entry_points)


def _find_paths(start: str, adj: dict[str, list[Edge]],
                node_map: dict[str, Node], max_depth: int) -> list[AttackPath]:
    results = []
    stack = [(start, [start], [], set([start]))]
    while stack:
        current, path_nodes, path_edges, visited = stack.pop()
        if len(path_nodes) >= 2:
            nodes = [node_map[nid] for nid in path_nodes]
            impact = _compute_impact(nodes)
            score = _compute_score(nodes, path_edges)
            results.append(AttackPath(nodes=nodes, edges=path_edges,
                                      impact=impact, score=score))
        if len(path_nodes) >= max_depth:
            continue
        for edge in adj.get(current, []):
            if edge.dst not in visited:
                stack.append((
                    edge.dst,
                    path_nodes + [edge.dst],
                    path_edges + [edge],
                    visited | {edge.dst},
                ))
    return results


def _compute_impact(nodes: list[Node]) -> str:
    caps = {n.capability for n in nodes if n.capability}
    if "code_execution" in caps:
        if "database_access" in caps:
            return "full compromise: RCE + data exfiltration"
        return "remote code execution"
    if "database_access" in caps:
        if "file_read" in caps:
            return "data breach: DB + file access"
        return "database compromise"
    if "internal_network" in caps:
        return "internal network access"
    if "session_hijack" in caps:
        return "account takeover"
    return "multi-stage attack"


def _compute_score(nodes: list[Node], edges: list[Edge]) -> float:
    sev_total = sum(_SEV_SCORE.get(n.severity, 1) for n in nodes)
    cap_total = sum(_IMPACT_MAP.get(n.capability, 1) for n in nodes if n.capability)
    depth_bonus = len(nodes) * 0.5
    return sev_total + cap_total + depth_bonus


def render(graph: AttackGraph) -> str:
    if not graph.paths:
        return "  No exploit chains found."
    lines = [
        f"\n  Attack Graph -- {len(graph.nodes)} nodes, {len(graph.edges)} edges, "
        f"{len(graph.paths)} chain(s)",
        "  " + "=" * 62,
    ]
    for i, path in enumerate(graph.paths[:10]):
        lines.append(f"\n  Chain {i+1} (score {path.score:.1f}): {path.impact}")
        for j, node in enumerate(path.nodes):
            arrow = "  " if j == 0 else "→ "
            base = os.path.basename(node.file) if node.file else "?"
            lines.append(f"    {arrow}[{node.severity}] {node.vuln_type} ({node.cwe}) "
                        f"at {base}:{node.line}")
            if node.capability:
                lines.append(f"       gains: {node.capability}")
        for edge in path.edges:
            lines.append(f"    ⟶ {edge.label}")

    lines.append(f"\n  {len(graph.entry_points)} entry point(s), "
                 f"{len(graph.paths)} total chain(s)")
    return "\n".join(lines)


def to_engagement_findings(graph: AttackGraph) -> list[dict]:
    """Convert best attack paths into findings the engagement planner consumes."""
    results = []
    for path in graph.paths[:5]:
        for node in path.nodes:
            entry = {
                "sink_type": node.vuln_type,
                "cwe": node.cwe,
                "file": node.file,
                "sink_file": node.file,
                "line": node.line,
                "sink_line": node.line,
                "severity": node.severity,
                "reachable": True,
                "entry_point": "",
                "chain_impact": path.impact,
                "chain_score": path.score,
            }
            results.append(entry)
    seen, deduped = set(), []
    for r in results:
        k = (r["sink_file"], r["sink_line"], r["sink_type"])
        if k not in seen:
            seen.add(k)
            deduped.append(r)
    return deduped
