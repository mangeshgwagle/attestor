#!/usr/bin/env python3
"""Loader harness for the triage_kernel42.dll (pure x86-64 assembly).

This file contains NO security logic. It exists only to locate the DLL,
bind its two exported routines via ctypes, and expose them with clean
Python signatures for callers and tests. Every computation performed by
`score()` and `grade()` executes inside the assembled kernel.
"""

from __future__ import annotations

import ctypes
import os

KERNEL_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DLL = os.path.join(KERNEL_DIR, "triage_kernel.dll")

GRADE_NAMES = {
    0: "invalid-input",
    1: "theoretical-only",
    2: "chained-only",
    3: "exploitable-with-preconditions",
    4: "readily-exploitable",
}


def _to_q16(value):
    if not 0.0 <= value <= 1.0:
        raise ValueError("feature %r outside [0,1]" % (value,))
    return int(round(value * 65536))


def load(path=None):
    dll_path = path or DEFAULT_DLL
    if not os.path.exists(dll_path):
        raise FileNotFoundError(
            "%s missing; build it with nasm + link "
            "(see detector/triage_kernel42/)" % dll_path)
    dll = ctypes.CDLL(dll_path)
    dll.triage_score_q16.restype = ctypes.c_int64
    dll.triage_score_q16.argtypes = [
        ctypes.POINTER(ctypes.c_int64),
        ctypes.POINTER(ctypes.c_int64),
        ctypes.c_int64,
    ]
    dll.triage_grade.restype = ctypes.c_int64
    dll.triage_grade.argtypes = [ctypes.c_int64, ctypes.c_int64]
    return dll


def score(dll, weights_floats, features_floats):
    """Run the asm dot-product kernel on float inputs in [0,1]."""
    if len(weights_floats) != len(features_floats):
        raise ValueError("weight/feature length mismatch")
    w = (ctypes.c_int64 * len(weights_floats))(
        *[_to_q16(v) for v in weights_floats])
    f = (ctypes.c_int64 * len(features_floats))(
        *[_to_q16(v) for v in features_floats])
    raw = dll.triage_score_q16(w, f, len(w))
    return {
        "raw_q16": raw,
        "score": round(max(min(raw, 65535), 0) / 65536.0, 6),
        "engine": "x86-64 assembly (triage_kernel.dll)",
    }


def grade(dll, score_value, kev=False):
    q16 = int(round(score_value * 65536))
    result = int(dll.triage_grade(q16, 1 if kev else 0))
    return {
        "grade": result,
        "label": GRADE_NAMES.get(result, "unknown"),
        "kev_escalated": bool(kev) and result >= 3,
        "engine": "x86-64 assembly (triage_kernel.dll)",
    }
