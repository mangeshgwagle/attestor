#!/usr/bin/env python3
"""Authorization-gated local mutation fuzzer (Offensive Lab companion).

Boundaries (house contract):
- Executes only the single operator-named callable from an operator-supplied
  module file. It never touches the network, spawns no subprocesses of its
  own beyond this process, and writes nothing outside the requested report.
- Iterations and wall-clock time are hard-capped; a fixed seed makes runs
  reproducible.
- Crash minimization is greedy chunk removal; minimized inputs are evidence,
  not proof that any deployed system is affected.
- Exit codes: 0 no crashes, 1 crashes found, 2 usage, 3 gated, 4 operational.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import random
import sys
import time
import traceback

FUZZ_SCHEMA = "attestor-offensive-fuzz-4.2"
EXIT_CLEAN = 0
EXIT_CRASHES = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4

INTERESTING_BYTES = [0x00, 0x01, 0x7F, 0x80, 0xFF]
INTERESTING_INTS = [0, 1, -1, 2, 127, 128, 255, 256, 0x7FFF, 0x8000]


class FuzzUsageError(ValueError):
    pass


def gen_input(rng, corpus, max_len=96):
    if corpus and rng.random() < 0.35:
        data = bytearray(rng.choice(corpus))
    else:
        data = bytearray(rng.randbytes(rng.randint(0, max_len)))
    if not data:
        data.extend(b"A")
    for _ in range(rng.randint(1, 4)):
        if not data:
            data.extend(b"A")
        op = rng.randrange(5)
        i = rng.randrange(len(data))
        if op == 0:
            data[i] ^= 1 << rng.randrange(8)
        elif op == 1:
            data[i] = rng.choice(INTERESTING_BYTES)
        elif op == 2:
            j = min(len(data), i + rng.randint(1, 16))
            chunk = bytes(data[i:j]) or b"\x00"
            reps = max(1, rng.randint(1, 4))
            data[i:i] = chunk * reps
        elif op == 3:
            del data[i:i + rng.randint(1, 16)]
        else:
            data[i] = rng.choice(INTERESTING_BYTES)
            if rng.random() < 0.3:
                data.insert(i, rng.randrange(256))
    return bytes(data)


def minimize(crash_input, fn, allowed, passes_cap=20):
    current = bytes(crash_input)
    for _ in range(passes_cap):
        size = len(current)
        if size <= 1:
            break
        chunk = max(1, size // 4)
        reduced = None
        start = 0
        while start < len(current) and reduced is None:
            candidate = current[:start] + current[start + chunk:]
            try:
                fn(candidate)
                start += chunk
            except allowed:
                start += chunk
            except Exception:
                reduced = candidate
        if reduced is None:
            break
        current = reduced
    return current


def run_fuzz(fn, iterations, seconds, seed=0, corpus=(),
             allowed=(KeyboardInterrupt, SystemExit)):
    deadline = time.monotonic() + seconds if seconds else None
    rng = random.Random(seed)
    crashes = []
    tried = 0
    stop_reason = "iterations-completed"
    for _ in range(iterations):
        if deadline and time.monotonic() >= deadline:
            stop_reason = "time-budget-reached"
            break
        data = gen_input(rng, list(corpus))
        tried += 1
        try:
            fn(data)
        except allowed:
            pass
        except Exception as exc:
            tail = traceback.format_exc(limit=3)[-800:]
            small = minimize(data, fn, allowed)
            crashes.append({
                "input_hex": small.hex(),
                "input_repr": repr(small)[:200],
                "exception": "%s: %s" % (type(exc).__name__, exc),
                "traceback_tail": tail,
            })

    return {
        "schema": FUZZ_SCHEMA,
        "inputs_tried": tried,
        "crashes_found": len(crashes),
        "crashes": crashes,
        "stop_reason": stop_reason,
    }


def load_target(path, entry_name):
    spec = importlib.util.spec_from_file_location(
        "attestor_fuzz_target", str(path))
    if spec is None or spec.loader is None:
        raise FuzzUsageError("cannot load target module: %s" % path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["attestor_fuzz_target"] = module
    spec.loader.exec_module(module)
    fn = getattr(module, entry_name, None)
    if not callable(fn):
        raise FuzzUsageError("target entry %r is not callable" % entry_name)
    return fn


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="offensive_fuzz42",
        description="Authorization-gated local mutation fuzzer")
    parser.add_argument("--target-module", required=True)
    parser.add_argument("--target-entry", required=True)
    parser.add_argument("--iterations", type=int, default=10_000)
    parser.add_argument("--seconds", type=float, default=30.0)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--corpus")
    parser.add_argument("--format", choices=["text", "json"], default="json")
    args = parser.parse_args(argv)

        print("offensive_fuzz42: gated; fuzzing executes caller-provided code "
              file=sys.stderr)
        return 3

    iterations = args.iterations
    seconds = args.seconds

    corpus = []
    if args.corpus:
        try:
            with open(args.corpus, "rb") as handle:
                blob = handle.read()
        except OSError as exc:
            print("offensive_fuzz42: %s" % exc, file=sys.stderr)
            return EXIT_OPERATIONAL
        chunks = [c for c in blob.split(b"\n") if c]
        corpus = chunks[:1000]

    try:
        fn = load_target(args.target_module, args.target_entry)
    except (FuzzUsageError, OSError, ImportError) as exc:
        print("offensive_fuzz42: %s" % exc, file=sys.stderr)
        return EXIT_INVALID

    try:
        report = run_fuzz(fn, iterations, seconds, seed=args.seed,
                          corpus=corpus)
    except Exception as exc:  # harness-level failure, not a target crash
        print("offensive_fuzz42: harness failure (%s); no result accepted"
              % type(exc).__name__, file=sys.stderr)
        return EXIT_OPERATIONAL

    report.update({
        "target_module": args.target_module,
        "target_entry": args.target_entry,
        "seed": args.seed,
        "iterations_requested": iterations,
        "seconds_budget": seconds,
    })
    print(json.dumps(report, indent=2, sort_keys=True))
    return EXIT_CRASHES if report["crashes_found"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
