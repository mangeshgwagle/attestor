#!/usr/bin/env python3
"""Coverage-Guided Fuzzer 4.2 -- AFL-style feedback for Python targets.

Algorithm (the one that found most of the world's real bugs):
  execute input under a line tracer -> keep inputs that reach NEW lines ->
  mutate the interesting ones -> repeat until budget exhausted.

Deterministic: fixed seed => identical corpus evolution and identical crash
set. Reuses the mutation and minimization kernels from offensive_fuzz42.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import time

sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else ".")

from offensive_fuzz42 import minimize  # noqa: E402

CG_SCHEMA = "attestor-coverage-fuzzer-4.2"
EXIT_CLEAN = 0
EXIT_CRASHES = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _Budget(Exception):
    pass


def execute_with_coverage(fn, data, allowed=(KeyboardInterrupt, SystemExit)):
    """Run fn(data) under a line tracer. Returns (covered_set, crash|None)."""
    covered = set()

    def tracer(frame, event, arg):
        if event == "line":
            covered.add((id(frame.f_code), frame.f_lineno))
        return tracer

    previous = sys.gettrace()
    sys.settrace(tracer)
    try:
        fn(bytes(data))
        crash = None
    except allowed:
        crash = None
    except Exception as exc:  # noqa: BLE001 - any fault is signal here
        import traceback
        tail = traceback.format_exc(limit=3)[-600:]
        crash = {
            "exception": "%s: %s" % (type(exc).__name__, exc),
            "traceback_tail": tail,
        }
    finally:
        sys.settrace(previous)
    return covered, crash


def mutate(rng, data):
    """Local mutation ops tuned for coverage hill-climbing."""
    buf = bytearray(data)
    if not buf:
        buf.extend(b"A")
    for _ in range(rng.randint(1, 3)):
        if not buf:
            buf.extend(b"A")
        i = rng.randrange(len(buf))
        op = rng.randrange(4)
        if op == 0:
            buf[i] = rng.randrange(256)
        elif op == 1:
            buf.insert(i, rng.choice(b"ATTACKPWN"))
        elif op == 2:
            del buf[i:i + rng.randint(1, 4)]
        else:
            chunk = bytes(buf[i:i + 2]) or b"\x00"
            buf[i:i] = chunk * 2
    if len(buf) > 256:
        del buf[256:]
    return bytes(buf)


def fuzz(fn, seeds=None, iterations=5000, seconds=30.0, seed_rng=0,
         allowed=(KeyboardInterrupt, SystemExit)):
    deadline = time.monotonic() + seconds
    rng = random.Random(seed_rng)
    corpus = []
    global_covered = set()
    crashes = []

    def consider(data, covered):
        fresh = covered - global_covered
        if fresh:
            corpus.append(bytes(data))
            global_covered.update(fresh)
            return len(fresh)
        return 0

    for seed in (seeds or [b"A"]):
        data = bytes(seed)
        covered, crash = execute_with_coverage(fn, data, allowed)
        consider(data, covered)
        if crash:
            crashes.append({"input_hex": data.hex(), **crash})

    discoveries = 0
    stop_reason = "iterations"
    for step in range(iterations):
        if time.monotonic() >= deadline:
            stop_reason = "time-budget"
            break
        parent = rng.choice(corpus) if corpus else b"A"
        candidate = mutate(rng, parent)
        covered, crash = execute_with_coverage(fn, candidate, allowed)
        gained = consider(candidate, covered)
        discoveries += gained
        if crash:
            small = minimize(candidate,
                             lambda d: _raises(fn, d, allowed), allowed)
            entry = {"input_hex": small.hex(),
                     "corpus_generation": step, **crash}
            if entry not in crashes:
                crashes.append(entry)
    return {
        "schema": CG_SCHEMA,
        "tool": "coverage-fuzzer",
        "iterations_run": step,
        "stop_reason": stop_reason,
        "corpus_size": len(corpus),
        "lines_discovered_total": len(global_covered),
        "new_coverage_events": discoveries,
        "crashes_found": len(crashes),
        "crashes": crashes,
        "seed_rng": seed_rng,
    }


def _raises(fn, data, allowed):
    try:
        fn(bytes(data))
        return False
    except allowed:
        return False
    except Exception:
        return True


def run_selftest():
    checks = []

    def stepped_target(data):
        if len(data) < 4:
            return 0
        if data[0:1] != b"A":
            return 1
        if data[1:2] != b"T":
            return 2
        if data[2:3] != b"T":
            return 3
        if data[3:4] != b"A":
            return 4
        raise RuntimeError("planted-deep-bug")

    report = fuzz(stepped_target, seeds=[b"B"], iterations=4000,
                  seconds=20.0, seed_rng=7)
    checks.append(("guided fuzz reaches the deep bug",
                   report["crashes_found"] >= 1))
    checks.append(("coverage grew during run",
                   report["lines_discovered_total"] >= 6))

    if report["crashes"]:
        small = bytes.fromhex(report["crashes"][0]["input_hex"])
        checks.append(("minimized crash still crashes",
                       small.startswith(b"ATTA")))

    failed = [name for name, ok in checks if not ok]
    return {
        "schema": CG_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="coverage_fuzz42",
        description="Coverage-guided fuzzer for a named callable")
    parser.add_argument("--target-module", required=True)
    parser.add_argument("--target-entry", required=True)
    parser.add_argument("--iterations", type=int, default=5000)
    parser.add_argument("--seconds", type=float, default=30.0)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)


    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "attestor_cov_target", args.target_module)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fn = getattr(module, args.target_entry)

    report = fuzz(fn, iterations=args.iterations, seconds=args.seconds,
                  seed_rng=args.seed)
    print(json.dumps(report, indent=2, sort_keys=True))
    return EXIT_CRASHES if report["crashes_found"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
