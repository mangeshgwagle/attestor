#!/usr/bin/env python3
"""
nativepool.py -- run a per-file scan across all your cores.

Every native engine here processes one file independently, so scanning a tree is
embarrassingly parallel. This is the shared helper: pmap(func, items, jobs) fans
the work out over a process pool (stdlib multiprocessing, zero dependencies) and
falls back to a plain serial map for jobs<=1 or a single item. Nothing else about
the engines changes -- they just finish sooner on a big codebase.
"""
from __future__ import annotations

import multiprocessing
import os


def default_jobs() -> int:
    return os.cpu_count() or 1


def resolve(jobs) -> int:
    """Turn a --jobs value into a worker count: 0 (or None) means 'all cores'."""
    if not jobs:
        return default_jobs()
    return max(1, int(jobs))


def pmap(func, items, jobs) -> list:
    """Map func over items, in parallel when it pays off. func must be a top-level
    (picklable) function. Order of results matches order of items."""
    items = list(items)
    workers = resolve(jobs)
    if workers <= 1 or len(items) <= 1:
        return [func(item) for item in items]
    with multiprocessing.Pool(processes=workers) as pool:
        return pool.map(func, items)
