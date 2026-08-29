#!/usr/bin/env python3
"""directed_fuzz42 -- sink-directed fuzzing (the reader drives the fuzzer).

AFLGo-style directed fuzzing, mini edition: the static callgraph computes
each function's DISTANCE to the nearest dangerous sink; at fuzz time a
tracer scores every input by the closest-to-sink function it entered.
Inputs that get closer to the sink join the corpus and dominate parent
selection, so evolution marches toward the danger zone.

    distance(fn) = 0   if fn calls a sink directly
                 = 1 + min over callees
                 = INF if no path

Crashes reached inside distance-0 code are flagged sink-adjacent.
"""

from __future__ import annotations

import ast
import hashlib
import random
import sys
import time

DF_SCHEMA = "attestor-directed-fuzzer-4.2"
INF = 10 ** 9


def sha256_hex(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------- static distance model

def extract_callgraph(source, sink_names):
    tree = ast.parse(source)
    functions = {}
    edges = {}

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node):  # noqa: N802
            calls = set()
            is_sink = False
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    if isinstance(sub.func, ast.Name):
                        name = sub.func.id
                    elif isinstance(sub.func, ast.Attribute):
                        name = sub.func.attr
                    else:
                        continue
                    calls.add(name)
                    if name in sink_names:
                        is_sink = True
            functions[node.name] = {
                "calls": calls,
                "is_sink": is_sink or node.name in sink_names,
            }
            self.generic_visit(node)

    Visitor().visit(tree)
    for name, info in functions.items():
        for callee in info["calls"]:
            if callee in functions:
                edges.setdefault(name, set()).add(callee)
    return functions, edges


def compute_distances(functions, edges):
    sink_roots = {n for n, i in functions.items() if i["is_sink"]}
    distances = {n: (0 if n in sink_roots else INF) for n in functions}
    callers = {}
    for caller, callees in edges.items():
        for callee in callees:
            callers.setdefault(callee, set()).add(caller)
    frontier = list(sink_roots)
    while frontier:
        current = frontier.pop()
        for caller in callers.get(current, ()):
            if distances[caller] > distances[current] + 1:
                distances[caller] = distances[current] + 1
                frontier.append(caller)
    return distances


# ------------------------------------------------------- runtime scoring

def run_scored(fn, data, distances, allowed):
    """Single tracer pass: collect entered function names, line coverage,
    and crash info in one execution."""
    entered = set()
    covered = set()

    def tracer(frame, event, arg):
        if event == "call":
            entered.add(frame.f_code.co_name)
            return tracer
        if event == "line":
            covered.add((id(frame.f_code), frame.f_lineno))
            return tracer
        return None

    import sys
    previous = sys.gettrace()
    sys.settrace(tracer)
    crash = None
    try:
        fn(bytes(data))
    except allowed:
        pass
    except Exception as exc:  # noqa: BLE001
        crash = {"exception": "%s: %s" % (type(exc).__name__, exc)}
    finally:
        sys.settrace(previous)

    best = INF
    for name in entered:
        best = min(best, distances.get(name, INF))
    return best, covered, crash


def mutate_bytes(rng, parent, tokens=()):
    buf = bytearray(parent or b"A")
    if not buf:
        buf.extend(b"A")
    for _ in range(rng.randint(1, 3)):
        if tokens and rng.random() < 0.4:
            token = rng.choice(list(tokens))
            i = rng.randrange(len(buf) + 1)
            buf[i:i] = token
            continue
        i = rng.randrange(len(buf))
        op = rng.randrange(4)
        if op == 0:
            buf[i] = rng.randrange(256)
        elif op == 1:
            buf[i:i] = bytes([rng.randrange(256)])
        elif op == 2 and len(buf) > 1:
            del buf[i]
        else:
            buf.extend(bytes([rng.randrange(256)]))
    return bytes(buf)


def _raises(fn, data, allowed):
    try:
        fn(bytes(data))
        return False
    except allowed:
        return False
    except Exception:
        return True


def directed_fuzz(fn, source=None, sink_names=(), seeds=None,
                  iterations=4000, seconds=30.0, seed_rng=0,
                  tokens=(), allowed=(KeyboardInterrupt, SystemExit)):
    if source:
        functions, edges = extract_callgraph(source, set(sink_names))
        distances = compute_distances(functions, edges)
    else:
        distances = {}

    deadline = time.monotonic() + seconds if seconds else None
    rng = random.Random(seed_rng)

    corpus = []
    best_distance = INF
    global_covered = set()
    crashes = []
    seen_hex = set()
    tried = 0
    step = 0
    stop_reason = "iterations"

    for seed in (seeds or [b"A"]):
        tried += 1
        data = bytes(seed)
        dist, covered, crash = run_scored(fn, data, distances, allowed)
        corpus.append((data, dist, covered))
        best_distance = min(best_distance, dist)
        global_covered |= covered
        if crash:
            hexed = data.hex()
            seen_hex.add(hexed)
            crashes.append({"input_hex": hexed, "distance": dist, **crash})

    while iterations == 0 or step < iterations:
        if deadline and time.monotonic() >= deadline:
            stop_reason = "time-budget"
            break
        step += 1
        near = [(d, c) for (c, d, _cov) in corpus if d < INF]
        if near and rng.random() < 0.75:
            near.sort()
            pick = rng.choice(near[:max(1, len(near) // 3)])[1]
        elif corpus:
            pick = rng.choice(corpus)[0]
        else:
            pick = b"A"
        data = mutate_bytes(rng, pick, tokens=tokens)
        tried += 1
        dist, covered, crash = run_scored(fn, data, distances, allowed)

        improved = dist < best_distance
        if improved:
            best_distance = dist
        fresh = covered - global_covered
        if improved or dist == 0 or (dist < INF and fresh):
            corpus.append((data, dist, covered))
            global_covered |= fresh
        if crash:
            hexed = data.hex()
            if hexed not in seen_hex:
                seen_hex.add(hexed)
                crashes.append({
                    "input_hex": hexed,
                    "distance": dist,
                    "sink_adjacent": dist == 0,
                    "generation": step,
                    **crash,
                })

    histogram = {}
    for _d, dist, _c in corpus:
        key = str(dist if dist < INF else "inf")
        histogram[key] = histogram.get(key, 0) + 1

    return {
        "schema": DF_SCHEMA,
        "tool": "directed-fuzzer",
        "sink_names": sorted(sink_names),
        "distances": {k: (v if v < INF else None)
                      for k, v in sorted(distances.items())},
        "iterations_run": step,
        "inputs_tried": tried,
        "stop_reason": stop_reason,
        "best_distance_reached": (best_distance if best_distance < INF
                                  else None),
        "corpus_distance_histogram": histogram,
        "crashes_found": len(crashes),
        "crashes": crashes,
        "seed_rng": seed_rng,
        "boundary": ("directed evolution over operator-supplied targets; "
                     "distance model is static callgraph, approximate"),
    }


LAYERED_TARGET = """
def sink(data):
    if data[3:6] == b"PWN":
        raise RuntimeError("sink-detonated")
    return 0

def decode(data):
    if len(data) < 6:
        return -1
    return sink(bytes(data))

def validate(data):
    if data[0:2] != b"OP":
        return -2
    return decode(data)

def run(data):
    if len(data) < 4:
        return -3
    return validate(data)
"""


def run_selftest():
    checks = []
    namespace = {}
    exec(compile(LAYERED_TARGET, "target.py", "exec"), namespace)
    fn = namespace["run"]

    functions, edges = extract_callgraph(LAYERED_TARGET, {"sink"})
    distances = compute_distances(functions, edges)
    checks.append(("static distances layered correctly",
                   distances.get("sink") == 0
                   and distances.get("decode") == 0
                   and distances.get("validate") == 1
                   and distances.get("run") == 2))

    report = directed_fuzz(fn, source=LAYERED_TARGET,
                           sink_names=("sink",), seeds=[b"OP"],
                           iterations=4000, seconds=25.0, seed_rng=5,
                           tokens=(b"PWN",))
    checks.append(("directed fuzzer detonated the sink",
                   report["crashes_found"] >= 1))
    checks.append(("evolution reached distance zero",
                   report["best_distance_reached"] == 0))
    if report["crashes"]:
        top = report["crashes"][0]
        checks.append(("crash flagged sink-adjacent",
                       top["sink_adjacent"] is True))
        checks.append(("minimized crash detonates",
                       bytes.fromhex(top["input_hex"])[3:6] == b"PWN"))

    failed = [name for name, ok in checks if not ok]
    return {
        "schema": DF_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    import argparse
    import importlib.util
    parser = argparse.ArgumentParser(
        prog="directed_fuzz42",
        description="Sink-directed fuzzing (reader drives the fuzzer)")
    parser.add_argument("--target-module", required=True)
    parser.add_argument("--target-entry", required=True)
    parser.add_argument("--sinks", nargs="*", default=[])
    parser.add_argument("--iterations", type=int, default=4000)
    parser.add_argument("--seconds", type=float, default=30.0)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)

    spec = importlib.util.spec_from_file_location(
        "attestor_directed_target", args.target_module)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fn = getattr(module, args.target_entry)

    source = open(args.target_module, encoding="utf-8").read()
    report = directed_fuzz(fn, source=source,
                           sink_names=tuple(args.sinks),
                           iterations=args.iterations,
                           seconds=args.seconds, seed_rng=args.seed)
    import json
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if report["crashes_found"] else 0


if __name__ == "__main__":
    sys.exit(main())
