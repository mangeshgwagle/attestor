#!/usr/bin/env python3
"""Private bounded-output worker for Attestor 3.5 symbolic analysis."""
from __future__ import annotations

import argparse
import json

import symbolic_engine35


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("root")
    parser.add_argument("--max-files", type=int, required=True)
    parser.add_argument(
        "--max-total-bytes", type=int,
        default=symbolic_engine35.DEFAULT_MAX_TOTAL_BYTES)
    parser.add_argument("--max-states", type=int, required=True)
    parser.add_argument("--max-steps", type=int, required=True)
    parser.add_argument("--max-contexts", type=int, required=True)
    args = parser.parse_args(argv)
    report = symbolic_engine35.analyze_repository(
        args.root, max_files=args.max_files,
        max_total_bytes=args.max_total_bytes, max_states=args.max_states,
        max_steps=args.max_steps, max_call_contexts=args.max_contexts)
    print(json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
