#!/usr/bin/env python3
"""coder.py -- coding contracts, prompts, and scorecards for Attestor Forge.

The model can be creative. Attestor should be stubborn. This module turns a plain
coding request into a small engineering contract: public API shape, edge cases,
runtime expectations, safety limits, and a score that Forge can report after
each round.
"""
from __future__ import annotations

import re


BASE_RULES = [
    "Implement the exact requested behavior before adding extras.",
    "Expose clear public functions or classes with names that match the request.",
    "Handle empty inputs, one-item inputs, duplicates, and boundary values.",
    "Prefer deterministic, simple algorithms with explicit error handling.",
    "Use the Python standard library unless the request explicitly asks otherwise.",
    "Avoid network, file-system, shell, subprocess, and environment access.",
    "Keep import-time side effects out of the module.",
    "Return one complete, self-contained Python module and no markdown.",
]

MAXIMUM_CODING_RULES = [
    "Derive the public API from the nouns and verbs in the request.",
    "Prefer O(n) or O(n log n) solutions when the problem allows it.",
    "Keep functions pure unless state is essential to the requested abstraction.",
    "Make invalid inputs fail predictably instead of silently corrupting state.",
    "Structure code so a small unit test can exercise every branch.",
    "Avoid hidden global state, import-time work, and time-dependent behavior.",
]

DATA_STRUCTURE_RULES = [
    "Preserve the data-structure invariants after every public operation.",
    "Include predictable behavior for missing keys, empty containers, and capacity limits.",
]

ALGORITHM_RULES = [
    "Use a general algorithm, not a solution hard-coded to the visible examples.",
    "Stateful helpers must not leak data between calls.",
]

SERVICE_RULES = [
    "Separate parsing, validation, business rules, and persistence boundaries.",
    "Never interpolate untrusted input into SQL, paths, commands, or code.",
]

_DATA_WORDS = ("cache", "trie", "tree", "graph", "stack", "queue", "heap", "set")
_SERVICE_WORDS = ("api", "service", "crud", "database", "http", "server", "sql")
_GRAPH_WORDS = ("graph", "dijkstra", "topological", "shortest", "path")
_STRING_WORDS = ("string", "slug", "anagram", "palindrome", "parentheses")


def _words(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9_]+", text.lower()))


def contract(request: str) -> dict:
    """Build a deterministic coding contract for a request."""
    words = _words(request)
    rules = list(BASE_RULES) + list(MAXIMUM_CODING_RULES)
    if words.intersection(_DATA_WORDS):
        rules.extend(DATA_STRUCTURE_RULES)
    if words.intersection(_SERVICE_WORDS):
        rules.extend(SERVICE_RULES)
    else:
        rules.extend(ALGORITHM_RULES)
    return {
        "request": request,
        "rules": rules,
        "acceptance": [
            "imports without crashing",
            "passes Attestor static checks",
            "passes the request-aware smoke test when one exists",
            "keeps the public API small and obvious",
            "handles the edge cases listed in Attestor's power plan",
        ],
    }


def power_plan(request: str) -> dict:
    """Return a compact build plan used to push models toward better code."""
    words = _words(request)
    edge_cases = ["empty input", "single item", "duplicates", "invalid type"]
    if words.intersection(_GRAPH_WORDS):
        edge_cases.extend(["disconnected graph", "cycle where invalid", "missing start node"])
    if words.intersection(_STRING_WORDS):
        edge_cases.extend(["empty string", "mixed case", "punctuation"])
    if words.intersection(_DATA_WORDS):
        edge_cases.extend(["empty container", "missing key", "capacity boundary"])
    return {
        "phases": [
            "name the public API",
            "choose the simplest correct algorithm",
            "handle edge cases before optimization",
            "keep implementation deterministic",
            "make the code easy for Attestor's crucible to import and test",
        ],
        "edge_cases": edge_cases,
    }


def render_power_plan(request: str) -> str:
    plan = power_plan(request)
    lines = ["Attestor Power Plan:"]
    for phase in plan["phases"]:
        lines.append("- " + phase)
    lines.append("Edge cases to handle:")
    for case in plan["edge_cases"]:
        lines.append("- " + case)
    return "\n".join(lines)


def render_contract(request: str) -> str:
    spec = contract(request)
    lines = ["Attestor Coding Contract:"]
    for rule in spec["rules"]:
        lines.append("- " + rule)
    lines.append("Acceptance gates:")
    for gate in spec["acceptance"]:
        lines.append("- " + gate)
    return "\n".join(lines)


def generation_prompt(request: str) -> str:
    return (
        "Write a single, self-contained Python module for this request.\n\n"
        "Request: " + request + "\n\n" + render_power_plan(request) + "\n\n"
        + render_contract(request) + "\n\n"
        "Return ONLY Python code. Do not wrap it in markdown fences."
    )


def static_repair_prompt(request: str, code: str, issues: str) -> str:
    return (
        "You wrote this Python module for Attestor:\n\n"
        + code
        + "\n\n"
        + render_power_plan(request)
        + "\n\n"
        + render_contract(request)
        + "\n\nAttestor's static analyzers found these issues:\n"
        + issues
        + "\n\nRewrite the whole module to fix every issue while preserving the "
          "requested behavior. Return ONLY Python code."
    )


def runtime_repair_prompt(request: str, code: str, detail: str,
                          behavior_label: str = "", smoke: str = "") -> str:
    extra = ""
    if behavior_label:
        extra = (
            "\n\nRequest-specific behavior that failed: "
            + behavior_label
            + "\nSmoke test:\n"
            + smoke
        )
    return (
        "You wrote this Python module for Attestor:\n\n"
        + code
        + "\n\n"
        + render_power_plan(request)
        + "\n\n"
        + render_contract(request)
        + "\n\nThe code is statically clean, but it failed the runtime or "
          "behavior gate:\n"
        + detail
        + extra
        + "\n\nFix the implementation so it imports, runs, and satisfies the "
          "request. Return ONLY Python code."
    )


def _public_defs(code: str) -> int:
    count = 0
    for line in code.splitlines():
        if re.match(r"^(def|class)\s+[A-Za-z]\w*", line):
            count += 1
    return count


def score_candidate(code: str, findings=(), ran=None, behavior: bool = False,
                    auto_fixed=None) -> dict:
    """Return a compact scorecard for a candidate module."""
    static_count = len(list(findings or ()))
    auto_count = len(list(auto_fixed or ()))
    lines = code.count("\n") + (0 if code.endswith("\n") else 1) if code else 0
    defs = _public_defs(code)
    # An empty provider response is abstention, not a 90/100 program with one
    # missing style point.  Keep the score useful as a ranking signal without
    # allowing absence of code to masquerade as excellence.
    score = 0 if not code.strip() else 100
    score -= min(50, static_count * 15)
    if ran is False:
        score -= 35
    if code.strip() and defs == 0:
        score -= 10
    if lines > 400:
        score -= 5
    score += min(5, auto_count)
    score = max(0, min(100, score))
    if score >= 90:
        grade = "excellent"
    elif score >= 75:
        grade = "strong"
    elif score >= 55:
        grade = "needs repair"
    else:
        grade = "reject"
    return {
        "score": score,
        "grade": grade,
        "lines": lines,
        "public_defs": defs,
        "static_findings": static_count,
        "ran": ran,
        "behavior_checked": behavior,
        "auto_fixed": auto_count,
    }


def render_score(scorecard: dict) -> str:
    return (
        "coder score {score}/100 ({grade}, public defs {public_defs}, "
        "static findings {static_findings})"
    ).format(**scorecard)
