#!/usr/bin/env python3
"""Conservative, evidence-backed source remediation for Attestor 3.0.

The engine turns supported findings into a complete improved source file and a
unified diff.  It does not guess at ambiguous fixes: each transformation needs
an exact Python AST shape and every refusal explains the missing proof.  A
candidate is verified in disposable copies by PatchGuard, rescanned against its
baseline, exercised with deterministic property/mutation/fuzz probes, and may
run only explicitly selected tests through :mod:`runtime_lab`.

Dry-run is the invariant.  Applying an accepted candidate requires a separate
authorization and delegates to PatchGuard's atomic backup, stale-source check,
post-apply verification, and integrity-checked rollback.
"""
from __future__ import annotations

import argparse
import ast
import collections
import dataclasses
import difflib
import hashlib
import json
import os
import random
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import patchguard
import runtime_lab
import scanengine


ENGINE_VERSION = "3.0.0"
DEFAULT_FUZZ_CASES = 24
DEFAULT_SEED = 30_003
SUPPORTED_RULES = frozenset({
    "dangerous-eval", "py-yaml-load", "tls-verify-disabled",
    "adv-py-httpx-no-tls", "debug-enabled", "py-subprocess-shell",
    "py-sql-injection", "hardcoded-secret", "py-eq-none",
    "py-is-literal",
})
SECRET_NAME = re.compile(
    r"(?:password|passwd|pwd|secret|token|api_?key|private_?key|client_?secret)", re.I)


@dataclass(frozen=True)
class FindingRef:
    rule: str
    line: int
    path: str = ""
    severity: str = ""
    message: str = ""


@dataclass(frozen=True)
class FixEdit:
    rule: str
    line: int
    kind: str
    before: str
    after: str
    rationale: str
    confidence: float = 0.99
    mutation_before: str = ""


@dataclass(frozen=True)
class Refusal:
    rule: str
    line: int
    reason: str


@dataclass(frozen=True)
class FixProposal:
    version: str
    target: str
    language: str
    original_sha256: str
    candidate_sha256: str
    improved_source: str
    unified_diff: str
    edits: tuple[FixEdit, ...]
    refusals: tuple[Refusal, ...]
    deterministic: bool = True

    @property
    def changed(self) -> bool:
        return self.original_sha256 != self.candidate_sha256

    @property
    def complete(self) -> bool:
        return bool(self.edits) and not self.refusals


@dataclass(frozen=True)
class ProbeEvidence:
    name: str
    status: str
    seed: int
    cases: int
    detail: str

    @property
    def passed(self) -> bool:
        return self.status in {"passed", "skipped"}


@dataclass
class RemediationReport:
    version: str
    target: str
    accepted: bool
    complete: bool
    reasons: tuple[str, ...]
    proposal: FixProposal
    validation: patchguard.CandidateReport | None
    probes: tuple[ProbeEvidence, ...]
    selected_tests: runtime_lab.RuntimeResult


@dataclass(frozen=True)
class _Replacement:
    start: int
    end: int
    replacement: str
    rule: str
    line: int
    kind: str
    before: str
    rationale: str
    required_import: str = ""
    redact_before: bool = False


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _finding(value: FindingRef | Mapping[str, Any] | Any) -> FindingRef:
    if isinstance(value, FindingRef):
        return value
    getter = value.get if isinstance(value, Mapping) else lambda key, default=None: getattr(value, key, default)
    rule = getter("rule", "") or getter("rule_id", "") or getter("ruleId", "")
    try:
        line = int(getter("line", 1) or 1)
    except (TypeError, ValueError):
        line = 1
    return FindingRef(
        str(rule), max(1, line), str(getter("path", "") or ""),
        str(getter("severity", "") or ""), str(getter("message", "") or ""),
    )


def _normalize_findings(findings: Iterable[FindingRef | Mapping[str, Any] | Any]) -> tuple[FindingRef, ...]:
    unique = {}
    for value in findings:
        item = _finding(value)
        unique[(item.line, item.rule, item.path)] = item
    return tuple(unique[key] for key in sorted(unique))


def _line_offsets(source: str) -> tuple[list[str], list[int]]:
    lines = source.splitlines(keepends=True)
    if not lines and source == "":
        lines = []
    offsets = []
    cursor = 0
    for line in lines:
        offsets.append(cursor)
        cursor += len(line)
    return lines, offsets


def _char_column(line: str, byte_column: int) -> int:
    encoded = line.encode("utf-8")
    if not 0 <= byte_column <= len(encoded):
        raise ValueError("AST byte column is outside its source line")
    return len(encoded[:byte_column].decode("utf-8"))


def _span(source: str, node: ast.AST) -> tuple[int, int]:
    lines, offsets = _line_offsets(source)
    if not (getattr(node, "lineno", None) and getattr(node, "end_lineno", None)):
        raise ValueError("AST node has no source span")
    start_line = node.lineno - 1
    end_line = node.end_lineno - 1
    start = offsets[start_line] + _char_column(lines[start_line], node.col_offset)
    end = offsets[end_line] + _char_column(lines[end_line], node.end_col_offset)
    return start, end


def _module_state(tree: ast.Module, name: str) -> tuple[bool, bool]:
    """Return (already imported under its name, safe to add under its name)."""
    imported = False
    unsafe = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                if alias.name == name and bound == name:
                    imported = True
                elif bound == name:
                    unsafe = True
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if (alias.asname or alias.name) == name:
                    unsafe = True
        elif isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Store):
            unsafe = True
        elif isinstance(node, ast.arg) and node.arg == name:
            unsafe = True
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name:
            unsafe = True
    return imported, not unsafe


def _nodes(tree: ast.Module, kind, line: int, predicate) -> list[Any]:
    return [node for node in ast.walk(tree)
            if isinstance(node, kind) and getattr(node, "lineno", 0) == line and predicate(node)]


def _constant_false(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _eval_replacement(source: str, tree: ast.Module, finding: FindingRef) -> _Replacement | str:
    calls = _nodes(tree, ast.Call, finding.line, lambda node: (
        isinstance(node.func, ast.Name) and node.func.id == "eval"))
    calls = [node for node in calls if len(node.args) == 1 and not node.keywords]
    if len(calls) != 1:
        return "requires exactly one eval(value) call with no globals/locals on the finding line"
    imported, safe = _module_state(tree, "ast")
    if not safe:
        return "the name 'ast' is rebound, so adding ast.literal_eval could call the wrong object"
    start, end = _span(source, calls[0].func)
    return _Replacement(
        start, end, "ast.literal_eval", finding.rule, finding.line,
        "replace-runtime-evaluation", source[start:end],
        "Parse Python literals without executing expressions or statements.",
        "" if imported else "ast")


def _yaml_replacement(source: str, tree: ast.Module, finding: FindingRef) -> _Replacement | str:
    calls = _nodes(tree, ast.Call, finding.line, lambda node: (
        isinstance(node.func, ast.Attribute) and node.func.attr == "load"
        and isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml"))
    calls = [node for node in calls if len(node.args) == 1 and not node.keywords]
    if len(calls) != 1:
        return "requires exactly one yaml.load(value) call without a custom loader on the finding line"
    start, end = _span(source, calls[0].func)
    if source[start:end] != "yaml.load":
        return "the YAML call is syntactically unusual and cannot be replaced without guessing"
    return _Replacement(
        start, end, "yaml.safe_load", finding.rule, finding.line,
        "safe-deserialization", source[start:end],
        "Use PyYAML's safe data-only loader.")


def _keyword_bool_replacement(source: str, tree: ast.Module, finding: FindingRef,
                               keyword_name: str, expected: bool, replacement: str,
                               kind: str, rationale: str,
                               allowed_calls=None) -> _Replacement | str:
    matches = []
    for call in _nodes(tree, ast.Call, finding.line, lambda node: True):
        if allowed_calls is not None and not allowed_calls(call):
            continue
        for keyword in call.keywords:
            if (keyword.arg == keyword_name and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is expected):
                matches.append(keyword.value)
    if len(matches) != 1:
        return "requires exactly one %s=%s keyword on the finding line" % (
            keyword_name, expected)
    start, end = _span(source, matches[0])
    return _Replacement(start, end, replacement, finding.rule, finding.line,
                        kind, source[start:end], rationale)


def _tls_replacement(source: str, tree: ast.Module, finding: FindingRef) -> _Replacement | str:
    return _keyword_bool_replacement(
        source, tree, finding, "verify", False, "True", "restore-tls-verification",
        "Restore certificate validation; trust-store problems must be fixed explicitly.")


def _debug_replacement(source: str, tree: ast.Module, finding: FindingRef) -> _Replacement | str:
    matches: list[ast.Constant] = []
    for node in ast.walk(tree):
        if getattr(node, "lineno", 0) != finding.line:
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if not isinstance(value, ast.Constant) or value.value is not True:
                continue
            if any(isinstance(target, ast.Name) and target.id in {"debug", "DEBUG"}
                   for target in targets):
                matches.append(value)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "run" \
                and isinstance(node.func.value, ast.Name) \
                and node.func.value.id in {"app", "application"}:
            # Flask's documented development entry point.  Keep this narrow:
            # changing an arbitrary function's ``debug`` argument could alter
            # application semantics unrelated to production debug exposure.
            for keyword in node.keywords:
                if keyword.arg == "debug" and isinstance(keyword.value, ast.Constant) \
                        and keyword.value.value is True:
                    matches.append(keyword.value)
    if len(matches) != 1:
        return ("requires exactly one direct debug/DEBUG = True assignment or "
                "app.run(debug=True) keyword on the finding line")
    start, end = _span(source, matches[0])
    return _Replacement(start, end, "False", finding.rule, finding.line,
                        "disable-production-debug", source[start:end],
                        "Default debug mode off; deployments may opt in through reviewed configuration.")


def _subprocess_call(call: ast.Call) -> bool:
    return (isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "subprocess"
            and call.func.attr in {"run", "call", "check_call", "check_output", "Popen"}
            and bool(call.args) and isinstance(call.args[0], (ast.List, ast.Tuple)))


def _subprocess_replacement(source: str, tree: ast.Module,
                            finding: FindingRef) -> _Replacement | str:
    shell_calls = []
    for call in _nodes(tree, ast.Call, finding.line, lambda node: (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess")):
        if any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant)
               and keyword.value.value is True for keyword in call.keywords):
            shell_calls.append(call)
    if len(shell_calls) == 1 and not _subprocess_call(shell_calls[0]):
        return "shell removal requires an existing explicit argument vector; command strings need a reviewed rewrite"
    return _keyword_bool_replacement(
        source, tree, finding, "shell", True, "False", "disable-command-shell",
        "Keep the existing explicit argument vector and bypass command-shell parsing.",
        allowed_calls=_subprocess_call)


def _none_identity_replacement(source: str, tree: ast.Module,
                                finding: FindingRef) -> _Replacement | str:
    """``x == None`` -> ``x is None``.

    The only fix in this module with no policy in it.  Every other supported
    rule trades something -- a timeout value is a guess about the workload, a
    hash change breaks stored digests -- but ``is`` against ``None`` is what
    the ``==`` was already trying to express, and the singleton makes the two
    agree for every object that does not define a hostile ``__eq__``.  For one
    that does, ``is`` is the answer the author wanted anyway.

    Only the operator moves.  Both operands are left byte-identical, so this
    cannot disturb a side effect in either.
    """
    matches: list[tuple[ast.Compare, bool]] = []
    for node in _nodes(tree, ast.Compare, finding.line, lambda n: True):
        # A chained comparison (`a == None == b`) needs a rewrite, not a
        # token swap, and is not what this rule reports.
        if len(node.ops) != 1 or len(node.comparators) != 1:
            continue
        operator = node.ops[0]
        if not isinstance(operator, (ast.Eq, ast.NotEq)):
            continue
        against_none = (
            (isinstance(node.left, ast.Constant) and node.left.value is None)
            or (isinstance(node.comparators[0], ast.Constant)
                and node.comparators[0].value is None))
        if against_none:
            matches.append((node, isinstance(operator, ast.NotEq)))

    if len(matches) != 1:
        return ("requires exactly one `== None` or `!= None` comparison on "
                "the finding line")

    node, negated = matches[0]
    # The operator carries no position of its own, so it is located as the
    # text between the two operands rather than guessed at from the line.
    _, left_end = _span(source, node.left)
    right_start, _ = _span(source, node.comparators[0])
    between = source[left_end:right_start]
    token = "!=" if negated else "=="
    if between.count(token) != 1:
        return ("the comparison operator is not a single plain %r between the "
                "operands" % token)

    start = left_end + between.index(token)
    end = start + len(token)
    return _Replacement(
        start, end, "is not" if negated else "is", finding.rule, finding.line,
        "none-identity-comparison", source[start:end],
        "None is a singleton, so identity is the comparison that was meant; "
        "`==` lets a custom __eq__ answer the question instead.")


def _literal_identity_replacement(source: str, tree: ast.Module,
                                   finding: FindingRef) -> _Replacement | str:
    """``x is 1`` -> ``x == 1``. The mirror of the None case, inverted.

    ``is`` against ``None`` is correct because there is exactly one ``None``.
    ``is`` against a number or a string is a different situation entirely:
    whether ``x is 1`` holds depends on whether the interpreter happened to
    intern that value, which is implementation-defined and varies with build,
    version and how the value was produced. ``==`` is what the author meant in
    every case, and it is what the code will already appear to do in testing
    right up until it does not.

    ``None``, ``True`` and ``False`` are excluded: those are singletons, and
    rewriting them would be undoing `_none_identity_replacement`.
    """
    singletons = (None, True, False)
    matches: list[tuple[ast.Compare, bool]] = []
    for node in _nodes(tree, ast.Compare, finding.line, lambda n: True):
        if len(node.ops) != 1 or len(node.comparators) != 1:
            continue
        operator = node.ops[0]
        if not isinstance(operator, (ast.Is, ast.IsNot)):
            continue
        against_literal = any(
            isinstance(side, ast.Constant) and not any(
                side.value is item for item in singletons)
            for side in (node.left, node.comparators[0]))
        if against_literal:
            matches.append((node, isinstance(operator, ast.IsNot)))

    if len(matches) != 1:
        return ("requires exactly one `is` comparison against a non-singleton "
                "literal on the finding line")

    node, negated = matches[0]
    _, left_end = _span(source, node.left)
    right_start, _ = _span(source, node.comparators[0])
    between = source[left_end:right_start]
    token = "is not" if negated else "is"
    # `is not` may be spelled across whitespace; locate it as a word rather
    # than assuming a single space.
    found = re.search(r"\bis\s+not\b" if negated else r"\bis\b", between)
    if not found:
        return "the operator is not a plain %r between the operands" % token

    start = left_end + found.start()
    end = left_end + found.end()
    return _Replacement(
        start, end, "!=" if negated else "==", finding.rule, finding.line,
        "literal-value-comparison", source[start:end],
        "Identity against a non-singleton literal depends on interning, which "
        "is not a language guarantee; `==` compares the value that was meant.")


def _sql_replacement(source: str, tree: ast.Module, finding: FindingRef) -> _Replacement | str:
    sqlite_imported = any(
        isinstance(node, ast.Import) and any(alias.name == "sqlite3" for alias in node.names)
        for node in tree.body)
    if not sqlite_imported:
        return "automatic SQL placeholders are driver-specific; only an explicit sqlite3 module is supported"
    calls = _nodes(tree, ast.Call, finding.line, lambda node: (
        isinstance(node.func, ast.Attribute) and node.func.attr == "execute"
        and len(node.args) == 1 and not node.keywords
        and isinstance(node.args[0], ast.JoinedStr)))
    if len(calls) != 1:
        return "requires exactly one sqlite execute(f-string) call with no existing parameters"
    joined = calls[0].args[0]
    sql_parts: list[str] = []
    parameters: list[str] = []
    quote: str | None = None
    for index, value in enumerate(joined.values):
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            text = value.value
            for char in text:
                if char in {"'", '"'}:
                    quote = None if quote == char else (char if quote is None else quote)
            sql_parts.append(text)
        elif (isinstance(value, ast.FormattedValue) and isinstance(value.value, ast.Name)
              and value.conversion == -1 and value.format_spec is None and quote is None):
            prefix = "".join(sql_parts).rstrip()
            next_text = (joined.values[index + 1].value
                         if index + 1 < len(joined.values)
                         and isinstance(joined.values[index + 1], ast.Constant)
                         and isinstance(joined.values[index + 1].value, str) else "")
            value_prefix = bool(re.search(
                r"(?:=|<>|!=|<=|>=|<|>|\bLIKE|\bGLOB|\bLIMIT|\bOFFSET)\s*$",
                prefix, re.I))
            values_prefix = bool(re.search(
                r"\bVALUES\s*\([^)]*(?:,\s*)?$", prefix, re.I))
            safe_suffix = bool(re.match(
                r"^\s*(?:$|[,);]|\bAND\b|\bOR\b|\bGROUP\b|\bORDER\b|\bLIMIT\b|\bOFFSET\b)",
                next_text, re.I))
            if not (value_prefix or values_prefix) or not safe_suffix:
                return ("could not prove a SQLite value position; identifiers, SQL fragments, "
                        "and list expansion require a reviewed query rewrite")
            sql_parts.append("?")
            parameters.append(value.value.id)
        else:
            return ("could not prove a SQLite value position; interpolation must contain only "
                    "unformatted names outside SQL string literals")
    if not parameters or quote is not None:
        return "could not prove that every interpolation is a SQLite value position"
    parameter_tuple = "(" + ", ".join(parameters) + ("," if len(parameters) == 1 else "") + ")"
    replacement = repr("".join(sql_parts)) + ", " + parameter_tuple
    start, end = _span(source, joined)
    return _Replacement(
        start, end, replacement, finding.rule, finding.line,
        "parameterize-sqlite-query", source[start:end],
        "Move interpolated values into SQLite parameter bindings.")


def _hardcoded_secret_replacement(source: str, tree: ast.Module,
                                  finding: FindingRef) -> _Replacement | str:
    imported, safe = _module_state(tree, "os")
    if not safe:
        return "the name 'os' is rebound, so an environment lookup could call the wrong object"
    matches = []
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.lineno != finding.line:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = node.value
        names = [target.id for target in targets if isinstance(target, ast.Name)]
        if (len(names) == 1 and SECRET_NAME.search(names[0])
                and isinstance(value, ast.Constant) and isinstance(value.value, str)
                and value.value):
            matches.append((names[0], value))
    if len(matches) != 1:
        return "requires one module-level secret-named variable assigned a non-empty string"
    name, value = matches[0]
    env_name = re.sub(r"[^A-Za-z0-9_]", "_", name).upper()
    start, end = _span(source, value)
    return _Replacement(
        start, end, 'os.environ[%r]' % env_name, finding.rule, finding.line,
        "externalize-secret", source[start:end],
        "Require the credential at runtime instead of retaining it in source.",
        "" if imported else "os", True)


def _replacement_for(source: str, tree: ast.Module,
                     finding: FindingRef) -> _Replacement | str:
    rule = finding.rule.lower()
    if rule == "dangerous-eval" or (rule.startswith("p23-") and rule.endswith("-code-builtin-eval")):
        return _eval_replacement(source, tree, finding)
    if rule == "py-yaml-load":
        return _yaml_replacement(source, tree, finding)
    if rule in {"tls-verify-disabled", "adv-py-httpx-no-tls"}:
        return _tls_replacement(source, tree, finding)
    if rule == "debug-enabled":
        return _debug_replacement(source, tree, finding)
    if rule == "py-subprocess-shell":
        return _subprocess_replacement(source, tree, finding)
    if rule == "py-sql-injection":
        return _sql_replacement(source, tree, finding)
    if rule == "hardcoded-secret":
        return _hardcoded_secret_replacement(source, tree, finding)
    if rule == "py-eq-none":
        return _none_identity_replacement(source, tree, finding)
    if rule == "py-is-literal":
        return _literal_identity_replacement(source, tree, finding)
    if rule in {"weak-hash", "py-insecure-deserialize", "py-subprocess-no-timeout",
                "py-random-security"}:
        return "the correct replacement depends on protocol, data format, timeout policy, or token contract"
    return "this rule class has no semantics-preserving deterministic fixer"


def _import_insertion_line(source: str, tree: ast.Module) -> int:
    lines = source.splitlines(keepends=True)
    after = 0
    if lines and lines[0].startswith("#!"):
        after = 1
    if len(lines) > after and "coding" in lines[after][:100]:
        after += 1
    body = list(tree.body)
    index = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        after = max(after, int(body[0].end_lineno or body[0].lineno))
        index = 1
    while index < len(body) and isinstance(body[index], ast.ImportFrom) \
            and body[index].module == "__future__":
        after = max(after, int(body[index].end_lineno or body[index].lineno))
        index += 1
    return after


def _redacted_diff(original: str, candidate: str, target: str,
                   replacements: Sequence[_Replacement]) -> str:
    display_original = original
    for item in sorted((row for row in replacements if row.redact_before),
                       key=lambda row: row.start, reverse=True):
        display_original = display_original[:item.start] + "<redacted-secret>" + display_original[item.end:]
    name = Path(target).as_posix()
    return "".join(difflib.unified_diff(
        display_original.splitlines(keepends=True), candidate.splitlines(keepends=True),
        fromfile="a/" + name, tofile="b/" + name))


def propose_fixes(source: str, target: str,
                  findings: Iterable[FindingRef | Mapping[str, Any] | Any]) -> FixProposal:
    """Return a deterministic full-file candidate; never executes or writes it."""
    if not isinstance(source, str):
        raise TypeError("source must be text")
    normalized = _normalize_findings(findings)
    language = "python" if Path(target).suffix.lower() in {".py", ".pyw"} else "unsupported"
    refusals: list[Refusal] = []
    replacements: list[_Replacement] = []
    if language != "python":
        refusals.extend(Refusal(item.rule, item.line,
                                "compiler-backed automatic fixes currently require Python")
                        for item in normalized)
        return FixProposal(ENGINE_VERSION, target, language, _sha(source), _sha(source),
                           source, "", (), tuple(refusals))
    try:
        tree = ast.parse(source, filename=target)
    except SyntaxError as exc:
        refusals.append(Refusal("syntax-error", int(exc.lineno or 1),
                                "source does not parse, so AST-confirmed edits are unsafe"))
        return FixProposal(ENGINE_VERSION, target, language, _sha(source), _sha(source),
                           source, "", (), tuple(refusals))

    occupied: list[tuple[int, int]] = []
    for finding in normalized:
        if finding.line > max(1, len(source.splitlines())):
            refusals.append(Refusal(finding.rule, finding.line,
                                    "finding line is outside the supplied source"))
            continue
        result = _replacement_for(source, tree, finding)
        if isinstance(result, str):
            refusals.append(Refusal(finding.rule, finding.line, result))
            continue
        if any(result.start < end and start < result.end for start, end in occupied):
            refusals.append(Refusal(finding.rule, finding.line,
                                    "the proposed edit overlaps another finding's edit"))
            continue
        occupied.append((result.start, result.end))
        replacements.append(result)

    improved = source
    for item in sorted(replacements, key=lambda row: row.start, reverse=True):
        improved = improved[:item.start] + item.replacement + improved[item.end:]
    required_imports = sorted({item.required_import for item in replacements if item.required_import})
    edits: list[FixEdit] = []
    for item in sorted(replacements, key=lambda row: (row.line, row.rule, row.start)):
        before = "<redacted-secret>" if item.redact_before else item.before
        mutation_before = "" if item.redact_before else item.before
        edits.append(FixEdit(item.rule, item.line, item.kind, before, item.replacement,
                             item.rationale, mutation_before=mutation_before))
    if required_imports:
        updated_tree = ast.parse(improved, filename=target)
        insertion_line = _import_insertion_line(improved, updated_tree)
        lines = improved.splitlines(keepends=True)
        newline = "\r\n" if "\r\n" in improved else "\n"
        block = "".join("import %s%s" % (name, newline) for name in required_imports)
        if insertion_line >= len(lines):
            if improved and not improved.endswith(("\n", "\r")):
                improved += newline
            improved += block
        else:
            offset = sum(len(line) for line in lines[:insertion_line])
            improved = improved[:offset] + block + improved[offset:]
        for name in required_imports:
            edits.append(FixEdit("import", insertion_line + 1, "add-required-import", "",
                                 "import " + name,
                                 "Provide the standard-library module used by a verified fix."))

    # A candidate that cannot be parsed is never returned as an apparent fix.
    try:
        compile(improved, target, "exec")
    except SyntaxError:
        refusals.append(Refusal("candidate-syntax", 1,
                                "internal safety check rejected a syntactically invalid candidate"))
        improved = source
        edits = []
        replacements = []
    return FixProposal(
        ENGINE_VERSION, target, language, _sha(source), _sha(improved), improved,
        _redacted_diff(source, improved, target, replacements),
        tuple(edits), tuple(refusals))


def _target_path(root: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("target must be a normalized project-relative path")
    output = (root / path).resolve()
    try:
        output.relative_to(root)
    except ValueError as exc:
        raise ValueError("target escapes project root") from exc
    if not output.is_file():
        raise ValueError("target is not a file")
    return output


def _scan_source(source: str, target: str) -> tuple[str, ...]:
    suffix = Path(target).suffix or ".py"
    with tempfile.TemporaryDirectory(prefix="attestor-remediation-mutant-") as temporary:
        path = Path(temporary) / ("mutant" + suffix)
        path.write_text(source, encoding="utf-8", newline="")
        result = scanengine.scan([str(path)], jobs=1, tools=False, use_cache=False)
        return tuple(item.rule for item in result.issues)


def run_assurance_probes(proposal: FixProposal, original_source: str, *,
                         seed: int = DEFAULT_SEED,
                         fuzz_cases: int = DEFAULT_FUZZ_CASES) -> tuple[ProbeEvidence, ...]:
    if not 1 <= int(fuzz_cases) <= 256:
        raise ValueError("fuzz_cases must be between 1 and 256")
    evidence: list[ProbeEvidence] = []
    input_matches = _sha(original_source) == proposal.original_sha256
    evidence.append(ProbeEvidence(
        "property:input-integrity", "passed" if input_matches else "failed",
        seed, 1, "proposal is bound to the supplied source digest" if input_matches
        else "proposal original digest does not match the supplied source"))
    try:
        compile(proposal.improved_source, proposal.target, "exec")
        syntax_status, syntax_detail = "passed", "candidate parses under Python compile()"
    except SyntaxError as exc:
        syntax_status, syntax_detail = "failed", "candidate parse failed: %s" % exc.msg
    evidence.append(ProbeEvidence("property:parse", syntax_status, seed, 1, syntax_detail))

    # Re-scan the candidate findings and prove the transformation reaches a fixed point.
    baseline_counts = collections.Counter(_scan_source(original_source, proposal.target))
    candidate_counts = collections.Counter(_scan_source(proposal.improved_source, proposal.target))
    expected_reductions = collections.Counter(
        edit.rule for edit in proposal.edits if edit.rule != "import")
    recurrence = sorted(
        "%s (%d -> %d; expected reduction %d)" % (
            rule, baseline_counts[rule], candidate_counts[rule], reduction)
        for rule, reduction in expected_reductions.items()
        if candidate_counts[rule] > max(0, baseline_counts[rule] - reduction))
    evidence.append(ProbeEvidence(
        "property:targeted-rule-removal", "failed" if recurrence else "passed",
        seed, sum(expected_reductions.values()),
        "insufficient targeted reduction: %s" % ", ".join(recurrence) if recurrence
        else "each edited finding reduced its targeted scanner-rule count"))

    mutation_cases = 0
    mutation_failures: list[str] = []
    candidate_lines, candidate_offsets = _line_offsets(proposal.improved_source)
    import_lines = [edit.line for edit in proposal.edits if edit.rule == "import"]
    for edit in proposal.edits:
        if edit.rule == "import" or not edit.mutation_before:
            continue
        candidate_line = edit.line + sum(line <= edit.line for line in import_lines)
        line_text = candidate_lines[candidate_line - 1] if candidate_line <= len(candidate_lines) else ""
        positions = [candidate_offsets[candidate_line - 1] + match.start()
                     for match in re.finditer(re.escape(edit.after), line_text)] \
                    if line_text else []
        if len(positions) != 1:
            mutation_failures.append(edit.rule + " (safe fragment was not unique)")
            continue
        start = positions[0]
        mutant = (proposal.improved_source[:start] + edit.mutation_before
                  + proposal.improved_source[start + len(edit.after):])
        mutation_cases += 1
        rules = _scan_source(mutant, proposal.target)
        if edit.rule not in rules:
            mutation_failures.append(edit.rule + " (reverse mutation survived)")
    mutation_status = "failed" if mutation_failures else ("passed" if mutation_cases else "skipped")
    mutation_detail = ("; ".join(mutation_failures) if mutation_failures else
                       ("all %d reverse mutations were detected" % mutation_cases if mutation_cases
                        else "no non-secret reversible edits; secret material is never retained for mutation"))
    evidence.append(ProbeEvidence("mutation:reverse-fix", mutation_status, seed,
                                  mutation_cases, mutation_detail))

    generator = random.Random(seed)
    fuzz_failures = []
    eval_enabled = any(edit.kind == "replace-runtime-evaluation" for edit in proposal.edits)
    yaml_enabled = any(edit.kind == "safe-deserialization" for edit in proposal.edits)
    exercised = 0
    for index in range(fuzz_cases):
        spaces = " " * generator.randint(1, 4)
        if eval_enabled:
            sample = "def parse(value):\n" + spaces + "return" + spaces + "eval(value)\n"
            finding = FindingRef("dangerous-eval", 2)
        elif yaml_enabled:
            sample = ("import yaml\ndef parse(value):\n" + spaces
                      + "return" + spaces + "yaml.load(value)\n")
            finding = FindingRef("py-yaml-load", 3)
        else:
            sample = proposal.improved_source + ("\n" if not proposal.improved_source.endswith("\n") else "") \
                     + ("# deterministic-fuzz-%d-%d\n" % (seed, index))
            try:
                compile(sample, proposal.target, "exec")
            except SyntaxError as exc:
                fuzz_failures.append("case %d: %s" % (index, exc.msg))
            exercised += 1
            continue
        fuzzed = propose_fixes(sample, proposal.target, [finding])
        try:
            compile(fuzzed.improved_source, proposal.target, "exec")
        except SyntaxError as exc:
            fuzz_failures.append("case %d: %s" % (index, exc.msg))
        if not fuzzed.changed:
            fuzz_failures.append("case %d: supported pattern was not transformed" % index)
        exercised += 1
    evidence.append(ProbeEvidence(
        "fuzz:deterministic-transform", "failed" if fuzz_failures else "passed",
        seed, exercised,
        "; ".join(fuzz_failures[:5]) if fuzz_failures
        else "%d seeded parser/transform variants passed" % exercised))
    return tuple(evidence)


def verify_remediation(project_root: str | os.PathLike[str], target: str,
                       findings: Iterable[FindingRef | Mapping[str, Any] | Any], *,
                       test_command: Sequence[str] | None = None,
                       authorize_tests: bool = False,
                       runtime_policy: runtime_lab.RuntimePolicy | None = None,
                       jobs: int = 1, deep: bool = False,
                       require_verified: bool = True,
                       exact_file_scope: bool = False,
                       seed: int = DEFAULT_SEED,
                       fuzz_cases: int = DEFAULT_FUZZ_CASES) -> RemediationReport:
    """Propose and fully validate a replacement without changing the project."""
    root = Path(project_root).expanduser().resolve()
    source_path = _target_path(root, target)
    source = source_path.read_text(encoding="utf-8")
    proposal = propose_fixes(source, target, findings)
    not_run = runtime_lab.RuntimeResult(
        "selected-tests", "not-run", detail="no selected test command was requested")
    if test_command is not None and not authorize_tests:
        raise PermissionError("selected tests require authorize_tests=True/--run-tests")
    if not proposal.changed:
        return RemediationReport(
            ENGINE_VERSION, target, False, False,
            ("no supported deterministic source change was produced",), proposal,
            None, (), not_run)

    validation = patchguard.verify_candidate(
        root, target, proposal.improved_source, name="attestor-verified-remediation",
        jobs=jobs, deep=deep, require_verified=require_verified,
        exact_file_scope=exact_file_scope)
    probes = run_assurance_probes(proposal, source, seed=seed, fuzz_cases=fuzz_cases)
    selected_tests = not_run
    reasons = list(validation.reasons)
    target_rules = {edit.rule for edit in proposal.edits if edit.rule != "import"}
    resolved_rules = {item.rule for item in validation.resolved_issues}
    if not (target_rules & resolved_rules):
        reasons.append("the rescan did not confirm resolution of a targeted finding")
    failed_probes = [probe.name for probe in probes if not probe.passed]
    if failed_probes:
        reasons.append("assurance probes failed: " + ", ".join(failed_probes))

    if test_command is not None and not reasons:
        chosen_policy = runtime_policy or runtime_lab.RuntimePolicy.selected_tests(
            deterministic_seed=seed)
        with runtime_lab.staged_project(root) as stage:
            stage_root = Path(stage.root)
            staged_target = (stage_root / target).resolve()
            staged_target.write_text(proposal.improved_source, encoding="utf-8", newline="")
            expected_hash = hashlib.sha256(staged_target.read_bytes()).hexdigest()
            selected_tests = runtime_lab.run_selected_tests(
                test_command, stage_root, authorized=authorize_tests,
                policy=chosen_policy)
            if hashlib.sha256(staged_target.read_bytes()).hexdigest() != expected_hash:
                reasons.append("selected tests modified the candidate target")
        if not selected_tests.passed:
            reasons.append("selected tests did not pass: " + selected_tests.detail)

    accepted = validation.accepted and not reasons and all(probe.passed for probe in probes)
    return RemediationReport(
        ENGINE_VERSION, target, accepted, accepted and proposal.complete,
        tuple(dict.fromkeys(reasons)), proposal, validation, probes, selected_tests)


def apply_remediation(report: RemediationReport, *, authorized: bool = False,
                      backup_root: str | os.PathLike[str] | None = None,
                      require_verified: bool = True) -> patchguard.ApplyResult:
    """Apply only a previously accepted report, with backup and auto-rollback."""
    if not authorized:
        raise PermissionError("applying improved source requires authorized=True/--apply")
    if not report.accepted or report.validation is None:
        raise ValueError("a rejected or unverified remediation cannot be applied")
    return patchguard.apply_candidate(
        report.validation, report.proposal.improved_source, authorized=True,
        backup_root=backup_root, require_verified=require_verified)


def rollback_remediation(result: patchguard.ApplyResult, *,
                         authorized: bool = False) -> patchguard.ApplyResult:
    return patchguard.rollback_apply(result, authorized=authorized)


def improve_source(source: str, target: str, *,
                   findings: Iterable[FindingRef | Mapping[str, Any] | Any],
                   selection: Mapping[str, Any] | None = None,
                   verify: bool = True) -> dict[str, Any]:
    """Safe in-memory adapter for editors and the Attestor language server.

    ``selection`` may narrow the preview by exact ``rule`` and/or one-based
    ``line``.  The adapter never writes the real target and never runs it.  With
    verification enabled it creates a disposable one-file project, compiles,
    scans, compares, and probes the candidate.  With verification disabled it
    returns a preview but deliberately leaves ``accepted`` false.
    """
    if not isinstance(source, str) or not isinstance(target, str) or not target:
        raise TypeError("source and target must be non-empty text values")
    normalized = list(_normalize_findings(findings))
    chosen = dict(selection or {})
    selected_rule = str(chosen.get("rule", "") or "")
    selected_line = chosen.get("line")
    if selected_line not in {None, ""}:
        try:
            selected_line = max(1, int(selected_line))
        except (TypeError, ValueError) as exc:
            raise ValueError("selection.line must be a one-based integer") from exc
    selected = [item for item in normalized
                if (not selected_rule or item.rule == selected_rule)
                and (selected_line in {None, ""} or item.line == selected_line)]
    if not selected:
        return {
            "available": False, "accepted": False, "improved_source": source,
            "diff": "", "resolved_count": 0, "remaining_count": len(normalized),
            "reasons": ["the selection did not match an available finding"],
        }

    preview = propose_fixes(source, target, selected)
    refusal_reasons = ["%s:%d: %s" % (item.rule, item.line, item.reason)
                       for item in preview.refusals]
    if not preview.changed:
        return {
            "available": False, "accepted": False,
            "improved_source": preview.improved_source,
            "diff": preview.unified_diff, "resolved_count": 0,
            "remaining_count": len(selected),
            "reasons": refusal_reasons or ["no deterministic improvement is available"],
        }
    if not verify:
        return {
            "available": True, "accepted": False,
            "improved_source": preview.improved_source,
            "diff": preview.unified_diff, "resolved_count": 0,
            "remaining_count": len(selected),
            "reasons": refusal_reasons + [
                "verification was disabled; the preview is not accepted for application"],
        }

    suffix = Path(target).suffix.lower()
    filename = "attestor_editor_source" + (suffix if suffix in {".py", ".pyw"} else ".txt")
    with tempfile.TemporaryDirectory(prefix="attestor-editor-remediation-") as temporary:
        project = Path(temporary)
        (project / filename).write_text(source, encoding="utf-8", newline="")
        report = verify_remediation(
            project, filename, selected, jobs=1, deep=False,
            require_verified=True, seed=DEFAULT_SEED, fuzz_cases=8)

    requested_counts = collections.Counter(item.rule for item in selected)
    resolved_count = 0
    if report.validation is not None:
        for issue in report.validation.resolved_issues:
            if requested_counts[issue.rule] > 0:
                requested_counts[issue.rule] -= 1
                resolved_count += 1
    remaining_count = max(0, len(selected) - resolved_count)
    reasons = list(report.reasons) + refusal_reasons
    if remaining_count and report.accepted:
        reasons.append("%d selected finding(s) still require manual review" % remaining_count)
    return {
        "available": True, "accepted": report.accepted,
        "improved_source": report.proposal.improved_source,
        "diff": report.proposal.unified_diff,
        "resolved_count": resolved_count, "remaining_count": remaining_count,
        "reasons": list(dict.fromkeys(reasons)),
    }


def _issue_summary(issue: scanengine.Issue) -> dict[str, Any]:
    return {"path": issue.path, "line": issue.line, "rule": issue.rule,
            "severity": issue.severity, "message": issue.message}


def report_dict(report: RemediationReport) -> dict[str, Any]:
    validation = report.validation
    return {
        "version": report.version, "target": report.target,
        "accepted": report.accepted, "complete": report.complete,
        "reasons": list(report.reasons),
        "proposal": {
            "language": report.proposal.language,
            "original_sha256": report.proposal.original_sha256,
            "candidate_sha256": report.proposal.candidate_sha256,
            "improved_source": report.proposal.improved_source,
            "unified_diff": report.proposal.unified_diff,
            "edits": [dataclasses.asdict(item) | {"mutation_before": "<internal>" if item.mutation_before else ""}
                      for item in report.proposal.edits],
            "refusals": [dataclasses.asdict(item) for item in report.proposal.refusals],
            "deterministic": report.proposal.deterministic,
        },
        "validation": None if validation is None else {
            "accepted": validation.accepted,
            "compiler_or_parser": validation.candidate.verification,
            "findings_before": len(validation.baseline.issues),
            "findings_after": len(validation.candidate.issues),
            "new_findings": [_issue_summary(item) for item in validation.new_issues],
            "resolved_findings": [_issue_summary(item) for item in validation.resolved_issues],
            "new_failures": list(validation.new_failures),
        },
        "probes": [dataclasses.asdict(item) for item in report.probes],
        "selected_tests": dataclasses.asdict(report.selected_tests),
    }


def render(report: RemediationReport) -> str:
    validation = report.validation
    lines = [
        "Attestor Verified Remediation %s" % report.version,
        "RESULT: %s" % ("ACCEPTED" if report.accepted else "REFUSED"),
        "Target: %s" % report.target,
        "Coverage: %s" % ("complete" if report.complete else "partial/refused"),
        "Edits: %d; explicit refusals: %d" % (
            len(report.proposal.edits), len(report.proposal.refusals)),
    ]
    if validation:
        lines.append("Validation: %s; findings %d -> %d; resolved %d; new %d" % (
            validation.candidate.verification, len(validation.baseline.issues),
            len(validation.candidate.issues), len(validation.resolved_issues),
            len(validation.new_issues)))
    lines.append("Selected tests: %s (%s)" % (
        report.selected_tests.status, report.selected_tests.detail))
    if report.reasons:
        lines.append("Why Attestor refused:")
        lines.extend("  - " + item for item in report.reasons)
    if report.proposal.refusals:
        lines.append("Unsupported/ambiguous findings:")
        lines.extend("  - %s:%d: %s" % (item.rule, item.line, item.reason)
                     for item in report.proposal.refusals)
    if report.probes:
        lines.append("Evidence:")
        lines.extend("  - %s: %s (%d cases, seed %d) - %s" % (
            item.name, item.status, item.cases, item.seed, item.detail)
            for item in report.probes)
    lines.extend([
        "", "Unified diff (secrets redacted):",
        report.proposal.unified_diff or "(no change)",
        "", "Improved full source:", report.proposal.improved_source,
    ])
    return "\n".join(lines)


def _load_findings(path: str) -> list[Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("findings", data.get("issues", []))
    if not isinstance(data, list):
        raise ValueError("findings JSON must be a list or contain findings/issues")
    return data


def _scan_target(project: Path, target: str) -> list[scanengine.Issue]:
    result = scanengine.scan(
        [str(_target_path(project, target))], jobs=1, tools=False, use_cache=False)
    if result.status == "failed":
        raise RuntimeError("scan failed: " + "; ".join(result.errors))
    return list(result.issues)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project")
    parser.add_argument("target", help="project-relative source file")
    parser.add_argument("--findings", help="JSON findings; default rescans target")
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--fuzz-cases", type=int, default=DEFAULT_FUZZ_CASES)
    parser.add_argument("--run-tests", action="store_true",
                        help="explicitly authorize selected test execution")
    parser.add_argument("--apply", action="store_true",
                        help="explicitly apply an accepted candidate (default: dry-run)")
    parser.add_argument("--backup-root", default="")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--diff-out", default="")
    parser.add_argument("--source-out", default="")
    parser.add_argument("--test-command", nargs=argparse.REMAINDER,
                        help="argv to run in the isolated copy; this option must be last")
    args = parser.parse_args(argv)
    if args.test_command and not args.run_tests:
        parser.error("--test-command executes selected tests; pass --run-tests explicitly")
    root = Path(args.project).expanduser().resolve()
    try:
        findings = _load_findings(args.findings) if args.findings else _scan_target(root, args.target)
        report = verify_remediation(
            root, args.target, findings, test_command=args.test_command or None,
            authorize_tests=args.run_tests, jobs=args.jobs, deep=args.deep,
            seed=args.seed, fuzz_cases=args.fuzz_cases)
        if args.diff_out:
            Path(args.diff_out).write_text(report.proposal.unified_diff, encoding="utf-8")
        if args.source_out:
            Path(args.source_out).write_text(report.proposal.improved_source, encoding="utf-8")
        applied = None
        if args.apply:
            applied = apply_remediation(
                report, authorized=True, backup_root=args.backup_root or None)
        output = report_dict(report)
        if applied:
            output["apply"] = dataclasses.asdict(applied)
        print(json.dumps(output, indent=2, sort_keys=True) if args.json else render(report))
        if applied and not args.json:
            print("\nApply: %s; backup: %s" % (applied.detail, applied.backup))
        return 0 if report.accepted else 2
    except (OSError, ValueError, RuntimeError, PermissionError) as exc:
        print("verified remediation failed: %s" % exc, file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
