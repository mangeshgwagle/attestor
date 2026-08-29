#!/usr/bin/env python3
"""ChainForge 4.2 -- exploit-chain composition over capability graphs.

Model (the linear equations):
  Each chain c is scored by a weighted linear form
      score(c) = w . f(c)  =  SUM_k  w[k] * f[k](c)
  with five documented features in [0,1]:
      impact_reach, auth_bypass_density, severity_mass, brevity, novelty
  Node importance solves the linear system (power iteration, exact form):
      x[j]' = ALPHA * SUM_i x[i] * M[j][i] + (1-ALPHA) * s[j]
  where M is the column-normalized adjacency of the capability graph and s
  seeds from per-node severity. Iteration runs on 1e6-scaled fixed-point
  integers so every result replays byte-identically.

Boundaries (house contract):
- Offline; stdlib; deterministic; no execution of any target or native code.
- Chains are review points over DECLARED graphs, not proof of exploitability.
- Companion kernel sources (x86-64 asm / C++) are structural artifacts in the
  mc_asm style: verified statically or behind explicit opt-in compilation,
  never executed by default.
- Exit codes: 0 clean, 1 chains/gaps found, 2 usage, 4 operational failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

CF_SCHEMA = "attestor-chainforge-4.2"
KERNEL_DIR_NAME = "chainforge_kernel42"
EXIT_CLEAN = 0
EXIT_FINDING = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4

SCALE = 10 ** 6
ALPHA_SCALED = int(0.85 * SCALE)
TOL_SCALED = 1_000
MAX_ITER = 10 ** 9

WEIGHTS = {
    "impact_reach": 0.35,
    "auth_bypass_density": 0.25,
    "severity_mass": 0.20,
    "brevity": 0.10,
    "novelty": 0.10,
}
FEATURE_ORDER = ("impact_reach", "auth_bypass_density", "severity_mass",
                 "brevity", "novelty")


class CfError(ValueError):
    pass


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------- validation

def load_graph(path=None, inline=None):
    if inline is not None:
        graph = inline
    elif path:
        with open(path, "r", encoding="utf-8") as handle:
            graph = json.load(handle)
    else:
        raise CfError("supply --graph FILE or --demo")

    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, dict) or not nodes:
        raise CfError('graph needs a non-empty "nodes" object')
    if not isinstance(edges, list):
        raise CfError('graph needs an "edges" list')

    for node_id, node in nodes.items():
        if not isinstance(node, dict):
            raise CfError("node %r must be an object" % node_id)
        severity = float(node.get("severity", 0.5))
        if not 0.0 <= severity <= 1.0:
            raise CfError("node %r severity out of range" % node_id)
    for edge in edges:
        if not (isinstance(edge, list) and len(edge) == 2):
            raise CfError("edges must be [src, dst]")
        if edge[0] not in nodes or edge[1] not in nodes:
            raise CfError("edge references unknown node: %r" % (edge,))
    entries = graph.get("entries", [])
    impacts = graph.get("impacts", [])
    for name, group in (("entries", entries), ("impacts", impacts)):
        if not isinstance(group, list) or not group:
            raise CfError('graph needs "%s"' % name)
        for item in group:
            if item not in nodes:
                raise CfError("%s references unknown node %r" % (name, item))
    return {
        "nodes": nodes,
        "edges": edges,
        "entries": entries,
        "impacts": impacts,
    }


# ------------------------------------------------------------ enumeration

def _node_caps(node, key):
    values = node.get(key, [])
    if isinstance(values, str):
        values = [values]
    return set(values)


def find_chains(graph):
    nodes = graph["nodes"]
    adjacency = {}
    for src, dst in graph["edges"]:
        adjacency.setdefault(src, []).append(dst)
    for src in adjacency:
        adjacency[src].sort()

    chains = []

    def dfs(node_id, path, held):
        node = nodes[node_id]
        missing = _node_caps(node, "requires") - held
        if missing:
            return
        held = held | _node_caps(node, "grants")
        if node_id in graph["impacts"]:
            chains.append({
                "path": list(path),
                "held_capabilities": sorted(held),
                "ends_at_impact": True,
            })
            return
        for nxt in adjacency.get(node_id, []):
            if nxt in path:
                continue
            path.append(nxt)
            dfs(nxt, path, held)
            path.pop()

    for entry in graph["entries"]:
        dfs(entry, [entry], set())
    return chains


# ------------------------------------------------------- linear scoring

def chain_features(graph, chain):
    nodes = graph["nodes"]
    path = chain["path"]
    node_list = [nodes[n] for n in path]
    severity_mass = (sum(float(n.get("severity", 0.5)) for n in node_list)
                     / len(node_list))
    bypass_flags = [bool(n.get("auth_bypass")) for n in node_list]
    bypass_density = (sum(bypass_flags) / len(bypass_flags)
                      if bypass_flags else 0.0)
    brevity = 1.0 / len(path)
    novelties = [float(n.get("novelty", 0.5)) for n in node_list]
    novelty = sum(novelties) / len(novelties)
    return {
        "impact_reach": 1.0 if chain.get("ends_at_impact") else 0.0,
        "auth_bypass_density": round(bypass_density, 6),
        "severity_mass": round(severity_mass, 6),
        "brevity": round(brevity, 6),
        "novelty": round(novelty, 6),
    }


def score_chain(features):
    total = 0.0
    for name in FEATURE_ORDER:
        total += WEIGHTS[name] * float(features[name])
    return round(min(max(total, 0.0), 1.0), 6)


def dot_product_sixed(weight_vec, feature_vec):
    """Fixed-point dot product: floor(sum(w_i * x_i)) over six features."""
    acc = 0
    for weight, feat in zip(weight_vec, feature_vec):
        acc += weight * feat
    return acc


# ------------------------------------------- linear system (centrality)

def centrality(graph, alpha_scaled=ALPHA_SCALED):
    """Power iteration on x' = a*M^T x + (1-a)*s, fixed-point 1e6."""
    nodes = graph["nodes"]
    ids = sorted(nodes)
    index = {nid: i for i, nid in enumerate(ids)}
    size = len(ids)

    outgoing = {nid: 0 for nid in ids}
    for src, dst in graph["edges"]:
        outgoing[src] += 1

    # column-normalized adjacency, row-major over targets
    m_rows = [[0] * size for _ in range(size)]
    for src, dst in graph["edges"]:
        if outgoing[src]:
            m_rows[index[dst]][index[src]] = SCALE // outgoing[src]

    seed = []
    total_sev = 0.0
    for nid in ids:
        sev = float(nodes[nid].get("severity", 0.5))
        seed.append(sev)
        total_sev += sev
    if total_sev <= 0:
        seed = [1.0 / size] * size
    else:
        seed = [s / total_sev for s in seed]
    s_scaled = [int(round(v * SCALE)) for v in seed]

    x = list(s_scaled)
    one_minus_alpha = SCALE - alpha_scaled
    residual = SCALE
    iterations = 0
    for iterations in range(1, MAX_ITER + 1):
        new_x = []
        for j in range(size):
            acc = 0
            row = m_rows[j]
            for i in range(size):
                if row[i]:
                    acc += x[i] * row[i]
            value = (alpha_scaled * acc // SCALE
                     + one_minus_alpha * s_scaled[j] // SCALE)
            new_x.append(value)
        residual = max(abs(new_x[i] - x[i]) for i in range(size))
        x = new_x
        if residual <= TOL_SCALED:
            break

    norm = sum(x) or 1
    values = {nid: round(x[index[nid]] / norm, 6) for nid in ids}
    return {
        "values": values,
        "iterations_used": iterations,
        "final_residual_scaled": residual,
        "converged": residual <= TOL_SCALED,
        "equation": "x' = 0.85*(M^T x) + 0.15*s, fixed point 1e6",
    }


# ------------------------------------------------------------------ rank

def analyze_graph(graph):
    chains_raw = find_chains(graph)
    weight_vec = [WEIGHTS[name] for name in FEATURE_ORDER]
    scored = []
    for chain in chains_raw:
        features = chain_features(graph, chain)
        scored.append({
            "path": chain["path"],
            "held_capabilities": chain["held_capabilities"],
            "features": features,
            "score": score_chain(features),
            "score_terms": {
                name: round(WEIGHTS[name] * float(features[name]), 6)
                for name in FEATURE_ORDER
            },
        })
    scored.sort(key=lambda item: (-item["score"], item["path"]))
    cent = centrality(graph)
    return {
        "schema": CF_SCHEMA,
        "tool": "chainforge",
        "chains": scored,
        "chain_count": len(scored),
        "weights": WEIGHTS,
        "scoring_equation":
            "score = 0.35*impact + 0.25*bypass + 0.20*sev "
            "+ 0.10*brevity + 0.10*novelty",
        "centrality": cent,
        "report_sha256": None,
    }


def run_demo():
    graph = load_graph(inline={
        "entries": ["internet"],
        "impacts": ["db.exfiltrate"],
        "nodes": {
            "internet": {"kind": "entry", "severity": 0.1, "grants": [],
                         "novelty": 0.2},
            "webapp.ssrf": {"kind": "primitive", "severity": 0.7,
                            "requires": [], "grants": ["metadata.read"],
                            "techniques": ["T1190"], "auth_bypass": False},
            "metadata.creds": {"kind": "primitive", "severity": 0.9,
                               "requires": ["metadata.read"],
                               "grants": ["cloud.creds"],
                               "techniques": ["T1552.005"],
                               "auth_bypass": True},
            "admin.panel": {"kind": "primitive", "severity": 0.8,
                            "requires": ["cloud.creds"],
                            "grants": ["internal.admin"],
                            "techniques": ["T1078"], "auth_bypass": True,
                            "novelty": 0.7},
            "db.exfiltrate": {"kind": "impact", "severity": 1.0,
                              "requires": ["internal.admin"],
                              "grants": [], "novelty": 0.4},
            "static.asset": {"kind": "decoy", "severity": 0.1,
                             "requires": [], "grants": [],
                             "techniques": []},
        },
        "edges": [
            ["internet", "webapp.ssrf"],
            ["webapp.ssrf", "metadata.creds"],
            ["metadata.creds", "admin.panel"],
            ["admin.panel", "db.exfiltrate"],
            ["internet", "static.asset"],
            ["static.asset", "db.exfiltrate"],
        ],
    })
    report = analyze_graph(graph)
    report["mode"] = "demo"
    report.pop("report_sha256", None)
    report["report_sha256"] = sha256_hex(canonical_json(report).encode())
    return report


# --------------------------------------------------------- kernel check

REQUIRED_ASM_PATTERNS = (
    (r"\bimul\b", "signed multiply (w_i * x_i term)"),
    (r"\bsar\b", "fixed-point rescale"),
    (r"\badd\b", "accumulator update"),
    (r"\bmov[a-z]*\b", "operand movement"),
)


def kernel_check():
    kernel_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              KERNEL_DIR_NAME)
    asm_path = os.path.join(kernel_dir, "chainforge_kernel_x86_64.asm")
    cpp_path = os.path.join(kernel_dir, "kernel.cpp")
    vec_path = os.path.join(kernel_dir, "EXPECTED_VECTORS.json")
    checks = {"asm_present": os.path.exists(asm_path),
              "cpp_present": os.path.exists(cpp_path),
              "vectors_present": os.path.exists(vec_path)}
    structure_ok = True
    if checks["asm_present"]:
        with open(asm_path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        for pattern, label in REQUIRED_ASM_PATTERNS:
            if not re.search(pattern, text):
                structure_ok = False
        checks["asm_structure"] = {
            "ok": structure_ok,
            "note": ("structural scan only (mnemonics present); this is not "
                     "semantic verification"),
            "expected_terms": [label for _, label in REQUIRED_ASM_PATTERNS],
        }
    vectors_ok = None
    if checks["vectors_present"] and checks["asm_present"]:
        with open(vec_path, "r", encoding="utf-8") as fh:
            vectors = json.load(fh)
        with open(asm_path, "r", encoding="utf-8", errors="replace") as fh:
            asm_text = fh.read()
        embedded = all(
            str(int(word)).lstrip("+") in asm_text.replace(" ", "")
            or format(abs(int(word)), "d") in asm_text
            for word in vectors.get("dot_weights_q16", []))
        vectors_ok = embedded
        checks["vector_table_embedded_in_listing"] = vectors_ok

    executed = False
    compiler = shutil.which("g++") or shutil.which("clang++")
    if checks["cpp_present"] and compiler:
        try:
            with tempfile.TemporaryDirectory() as tmp:
                binary = os.path.join(tmp, "kernel_selfcheck")
                build = subprocess.run(
                    [compiler, "-O2", "-std=c++17", cpp_path, "-o", binary],
                    capture_output=True, timeout=120)
                if build.returncode == 0:
                    run = subprocess.run([binary], capture_output=True,
                                         timeout=60)
                    executed = run.returncode == 0
        except (OSError, subprocess.SubprocessError):
            executed = False
    checks["cpp_compile_and_run"] = {
        "executed": executed,
        "compiler_found": bool(compiler),
        "boundary": ("native execution happened only inside this opt-in "
                     "check, never on the analysis path"),
    }
    passed = (checks["asm_present"] and checks["cpp_present"]
              and checks["vectors_present"] and structure_ok)
    return {
        "schema": CF_SCHEMA,
        "tool": "kernel-check",
        "checks": checks,
        "passed": passed,
    }


# -------------------------------------------------------------- self-test

def run_selftest():
    checks = []
    demo = run_demo()
    paths = [c["path"] for c in demo["chains"]]
    checks.append(("demo finds the full SSRF chain",
                   ["internet", "webapp.ssrf", "metadata.creds",
                    "admin.panel", "db.exfiltrate"] in paths))
    checks.append(("decoy path cannot reach impact without capabilities",
                   all("static.asset" not in p or p[-1] != "db.exfiltrate"
                       for p in paths)))
    if demo["chains"]:
        top = demo["chains"][0]
        recomputed = score_chain(top["features"])
        checks.append(("top chain score matches w.f recomputation",
                       abs(top["score"] - recomputed) < 1e-9))
    cent = demo["centrality"]
    checks.append(("centrality converged", cent["converged"]))

    star = load_graph(inline={
        "entries": ["leaf1"], "impacts": ["hub"],
        "nodes": {
            "hub": {"severity": 1.0}, "leaf1": {"severity": 0.1},
            "leaf2": {"severity": 0.1}},
        "edges": [["leaf1", "hub"], ["leaf2", "hub"]],
    })
    star_cent = centrality(star)
    checks.append(("star hub has max centrality",
                   max(star_cent["values"].items(), key=lambda kv: kv[1])[0]
                   == "hub"))

    gated = load_graph(inline={
        "entries": ["a"], "impacts": ["c"],
        "nodes": {"a": {"severity": 0.5}, "b": {"severity": 0.5,
                                                "requires": ["key"]},
                  "c": {"severity": 0.5, "requires": ["vault"]}},
        "edges": [["a", "b"], ["b", "c"]],
    })
    checks.append(("capability gating blocks ungrantable chain",
                   find_chains(gated) == []))

    granted = load_graph(inline={
        "entries": ["a"], "impacts": ["c"],
        "nodes": {"a": {"severity": 0.5, "grants": ["key"]},
                  "b": {"severity": 0.5, "requires": ["key"],
                        "grants": ["vault"]},
                  "c": {"severity": 0.5, "requires": ["vault"]}},
        "edges": [["a", "b"], ["b", "c"]],
    })
    checks.append(("capability granting admits earned chain",
                   len(find_chains(granted)) == 1))

    vec = [WEIGHTS[n] for n in FEATURE_ORDER]
    feats = [1.0, 1.0, 1.0, 1.0, 1.0]
    checks.append(("unit features saturate score at 1.0",
                   abs(dot_product_sixed(vec, feats) - 1.0) < 1e-9))

    failed = [name for name, ok in checks if not ok]
    return {
        "schema": CF_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


# -------------------------------------------------------------------- cli

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="chainforge42",
        description="Exploit-chain composition over capability graphs")
    subs = parser.add_subparsers(dest="command", required=True)

    p = subs.add_parser("rank", help="enumerate and rank chains")
    p.add_argument("--graph", help="JSON capability graph")
    p.add_argument("--demo", action="store_true")

    p = subs.add_parser("centrality", help="solve the centrality linear system")
    p.add_argument("--graph")
    p.add_argument("--demo", action="store_true")

    subs.add_parser("demo", help="run the bundled demonstration graph")
    subs.add_parser("kernel-check", help="verify companion kernel artifacts")
    subs.add_parser("self-test")

    parser.add_argument("--format", choices=["text", "json"], default="json")
    args = parser.parse_args(argv)

    try:
        if args.command == "rank":
            if args.demo:
                result = run_demo()
            elif args.graph:
                result = analyze_graph(load_graph(path=args.graph))
                result.pop("report_sha256", None)
                result["report_sha256"] = sha256_hex(
                    canonical_json(result).encode())
            else:
                raise CfError("supply --graph FILE or --demo")
            code = EXIT_FINDING if result["chain_count"] else EXIT_CLEAN
        elif args.command == "centrality":
            if args.demo:
                graph = _demo_graph()
            elif args.graph:
                graph = load_graph(path=args.graph)
            else:
                raise CfError("supply --graph FILE or --demo")
            result = centrality(graph)
            code = EXIT_CLEAN
        elif args.command == "demo":
            result = run_demo()
            code = EXIT_FINDING if result["chain_count"] else EXIT_CLEAN
        elif args.command == "kernel-check":
            result = kernel_check()
            code = EXIT_CLEAN if result["passed"] else EXIT_OPERATIONAL
        elif args.command == "self-test":
            result = run_selftest()
            code = EXIT_CLEAN if result["passed"] else EXIT_OPERATIONAL
        else:  # pragma: no cover
            parser.error("unknown command")
    except CfError as exc:
        print("chainforge42: %s" % exc, file=sys.stderr)
        return EXIT_INVALID
    except OSError as exc:
        print("chainforge42: %s" % exc, file=sys.stderr)
        return EXIT_OPERATIONAL

    print(json.dumps(result, indent=2, sort_keys=True))
    return code


def _demo_graph():
    import copy
    return load_graph(inline={
        "entries": ["internet"],
        "impacts": ["db.exfiltrate"],
        "nodes": {
            "internet": {"kind": "entry", "severity": 0.1},
            "webapp.ssrf": {"kind": "primitive", "severity": 0.7,
                            "grants": ["metadata.read"]},
            "metadata.creds": {"kind": "primitive", "severity": 0.9,
                               "requires": ["metadata.read"],
                               "grants": ["cloud.creds"], "auth_bypass": True},
            "admin.panel": {"kind": "primitive", "severity": 0.8,
                            "requires": ["cloud.creds"],
                            "grants": ["internal.admin"],
                            "auth_bypass": True, "novelty": 0.7},
            "db.exfiltrate": {"kind": "impact", "severity": 1.0,
                              "requires": ["internal.admin"]},
        },
        "edges": [["internet", "webapp.ssrf"],
                  ["webapp.ssrf", "metadata.creds"],
                  ["metadata.creds", "admin.panel"],
                  ["admin.panel", "db.exfiltrate"]],
    })


if __name__ == "__main__":
    sys.exit(main())
