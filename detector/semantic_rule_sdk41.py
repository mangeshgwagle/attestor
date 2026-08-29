#!/usr/bin/env python3
"""Declarative semantic rule SDK for Attestor 4.1.3.

Rules select bounded AST or semantic-flow facts; they are data, never Python
plugins.  Every pack is content-addressed, may carry a detached HMAC-SHA256
authentication tag, and must pass positive and negative fixtures before use.
No regular-expression DSL, imports, target execution, network, or writes exist
in the evaluation path.
"""
from __future__ import annotations

import ast
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import analysis_snapshot41 as snapshot41
import semantic_graph41 as graph41


SCHEMA = "attestor.semantic-rule-pack/4.1"
REPORT_SCHEMA = "attestor.semantic-rule-results/4.1"
VERSION = "4.1.3"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"^attestor41-[a-z0-9][a-z0-9-]{2,95}$")
_PACK_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,95}$")
_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})
_KINDS = frozenset({"ast-call", "ast-node", "flow-to-sink"})
_BIDI_CONTROLS = frozenset({
    0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D,
    0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x206A, 0x206B,
    0x206C, 0x206D, 0x206E, 0x206F,
})
_NODE_TYPES = frozenset({
    "FunctionDef", "AsyncFunctionDef", "ClassDef", "Call", "With",
    "AsyncWith", "Try", "Raise", "Await", "Import", "ImportFrom",
    "Global", "Nonlocal", "Delete", "While", "For", "AsyncFor",
})
_STATIC_CONTRACT = {
    "target_code_executed": False,
    "target_modules_imported": False,
    "processes_started": False,
    "network_accessed": False,
    "filesystem_writes": False,
    "dynamic_plugins_loaded": False,
}


class RulePackError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise RulePackError("rule pack must contain bounded JSON data") from exc


def _sha(value: Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _terminal_text(value: Any, maximum: int = 2_000) -> str:
    """Preserve ordinary Unicode while visibly escaping display controls."""
    result: list[str] = []
    rendered_size = 0
    for character in str(value if value is not None else ""):
        codepoint = ord(character)
        if character in "\t\r\n":
            rendered = " "
        elif codepoint < 32 or 0x7F <= codepoint <= 0x9F:
            rendered = "\\x%02x" % codepoint
        elif codepoint in _BIDI_CONTROLS:
            rendered = "\\u%04x" % codepoint
        else:
            rendered = character
        if rendered_size + len(rendered) > maximum:
            break
        result.append(rendered)
        rendered_size += len(rendered)
    return "".join(result)


def _pack_hmac_input(key_id: str, payload_sha256: str) -> bytes:
    return _canonical({
        "schema": SCHEMA,
        "purpose": "semantic-rule-pack-authentication",
        "algorithm": "hmac-sha256",
        "key_id": key_id,
        "payload_sha256": payload_sha256,
    })


def _clean_pack(pack: Mapping[str, Any]) -> dict[str, Any]:
    if type(pack) is not dict:
        raise RulePackError("pack must be a JSON object")
    return {key: value for key, value in pack.items()
            if key not in {"pack_sha256", "signature"}}


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RulePackError("rule-pack JSON contains a duplicate object key")
        result[key] = value
    return result


def load_pack_json(payload: bytes | str, *, maximum_bytes: int = 8 * 1024 * 1024) -> dict[str, Any]:
    """Decode one bounded strict-JSON pack without duplicate-key collapse."""
    if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= 64 * 1024 * 1024:
        raise RulePackError("rule-pack JSON byte boundary is invalid")
    if isinstance(payload, bytes):
        raw = payload
        try:
            text = raw.decode("utf-8")
        except UnicodeError as exc:
            raise RulePackError("rule-pack JSON is not valid UTF-8") from exc
    elif isinstance(payload, str):
        text = payload
        raw = text.encode("utf-8")
    else:
        raise RulePackError("rule-pack JSON must be bytes or text")
    if len(raw) > maximum_bytes:
        raise RulePackError("rule-pack JSON exceeds the byte boundary")
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except RulePackError:
        raise
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise RulePackError("rule-pack JSON cannot be parsed") from exc
    if type(value) is not dict:
        raise RulePackError("rule-pack JSON root must be an object")
    _canonical(value)
    return value


@dataclass(frozen=True)
class RuleBudget:
    max_pack_bytes: int = 8 * 1024 * 1024
    max_rules: int = 5_000
    max_fixtures_per_rule: int = 64
    max_fixture_chars: int = 128_000
    max_ast_nodes_per_file: int = 250_000
    max_findings: int = 20_000
    max_gaps: int = 20_000

    def __post_init__(self) -> None:
        checks = {
            "max_pack_bytes": (self.max_pack_bytes, 1_024, 64 * 1024 * 1024),
            "max_rules": (self.max_rules, 1, 20_000),
            "max_fixtures_per_rule": (self.max_fixtures_per_rule, 2, 512),
            "max_fixture_chars": (self.max_fixture_chars, 16, 2 * 1024 * 1024),
            "max_ast_nodes_per_file": (self.max_ast_nodes_per_file, 100, 2_000_000),
            "max_findings": (self.max_findings, 1, 200_000),
            "max_gaps": (self.max_gaps, 1, 200_000),
        }
        for name, (value, low, high) in checks.items():
            if type(value) is not int or not low <= value <= high:
                raise RulePackError(f"{name} must be an integer between {low} and {high}")


def _tokens(value: Any, field: str, maximum: int = 64) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > maximum:
        raise RulePackError(f"{field} must be a non-empty bounded list")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or len(item) > 256 or any(ord(c) < 32 for c in item):
            raise RulePackError(f"{field} contains an invalid token")
        result.append(item)
    return tuple(sorted(set(result)))


def _dotted(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _dotted(node.value)
        return (left + "." if left else "") + node.attr
    return ""


def _parse_rule(value: Any, budget: RuleBudget) -> dict[str, Any]:
    if type(value) is not dict:
        raise RulePackError("each rule must be an object")
    identifier = value.get("id")
    if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
        raise RulePackError("rule id must match attestor41-[a-z0-9-]")
    display: dict[str, str] = {}
    for field in ("title", "description", "remediation"):
        text = value.get(field)
        if not isinstance(text, str) or not text.strip() or len(text) > 2_000:
            raise RulePackError(f"{identifier}.{field} is invalid")
        display[field] = _terminal_text(text, 2_000).strip()
    severity = value.get("severity")
    if severity not in _SEVERITIES:
        raise RulePackError(f"{identifier}.severity is invalid")
    language = value.get("language")
    if language not in {"python", "javascript", "typescript"}:
        raise RulePackError(f"{identifier}.language is unsupported")
    match = value.get("match")
    if type(match) is not dict or match.get("kind") not in _KINDS:
        raise RulePackError(f"{identifier}.match.kind is unsupported")
    kind = match["kind"]
    if language != "python":
        raise RulePackError(
            f"{identifier} requires Python AST evidence; JavaScript/TypeScript "
            "semantic rule facts need a future compiler-fact rule kind")
    normalized: dict[str, Any] = {"kind": kind}
    if kind == "ast-call":
        normalized["callee_in"] = list(_tokens(match.get("callee_in"), "callee_in"))
    elif kind == "ast-node":
        node_types = _tokens(match.get("node_type_in"), "node_type_in")
        if not set(node_types) <= _NODE_TYPES:
            raise RulePackError(f"{identifier} requests a disallowed AST node type")
        normalized["node_type_in"] = list(node_types)
        if "name_in" in match:
            normalized["name_in"] = list(_tokens(match["name_in"], "name_in"))
    else:
        if language != "python":
            raise RulePackError("flow-to-sink currently requires Python parser evidence")
        normalized["sink_in"] = list(_tokens(match.get("sink_in"), "sink_in"))
        if "cwe_in" in match:
            normalized["cwe_in"] = list(_tokens(match["cwe_in"], "cwe_in"))
    fixtures = value.get("fixtures")
    if type(fixtures) is not dict:
        raise RulePackError(f"{identifier}.fixtures must be an object")
    positive = fixtures.get("positive")
    negative = fixtures.get("negative")
    if not isinstance(positive, list) or not positive or not isinstance(negative, list) or not negative:
        raise RulePackError("every rule requires positive and negative fixtures")
    if len(positive) + len(negative) > budget.max_fixtures_per_rule:
        raise RulePackError("fixture budget exceeded")
    parsed_fixtures: dict[str, list[dict[str, Any]]] = {"positive": [], "negative": []}
    for polarity, fixtures_list in (("positive", positive), ("negative", negative)):
        for fixture in fixtures_list:
            if type(fixture) is not dict:
                raise RulePackError("fixtures must be objects")
            path = fixture.get("path", "fixture.py")
            source = fixture.get("source")
            if (not isinstance(path, str) or not path or len(path) > 512 or
                    not isinstance(source, str) or len(source) > budget.max_fixture_chars):
                raise RulePackError("fixture path/source is invalid")
            try:
                path = snapshot41.safe_relative(path)
            except snapshot41.SnapshotError as exc:
                raise RulePackError("fixture path is not a safe relative path") from exc
            if not path.casefold().endswith((".py", ".pyw")):
                raise RulePackError("Python fixtures must use a Python source path")
            expected_min = fixture.get("expected_min", 1 if polarity == "positive" else 0)
            if type(expected_min) is not int or expected_min < 0 or expected_min > 10_000:
                raise RulePackError("fixture expected_min is invalid")
            if polarity == "negative" and expected_min != 0:
                raise RulePackError("negative fixtures must expect zero")
            parsed_fixtures[polarity].append({"path": path, "source": source,
                                              "expected_min": expected_min})
    return {"id": identifier, "title": display["title"],
            "description": display["description"], "severity": severity,
            "language": language, "remediation": display["remediation"],
            "match": normalized, "fixtures": parsed_fixtures}


def _statement_sequence(body: list[ast.stmt]) -> list[ast.stmt]:
    result: list[ast.stmt] = []
    for statement in body:
        result.append(statement)
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for field in ("body", "orelse", "finalbody"):
            nested = getattr(statement, field, None)
            if isinstance(nested, list):
                result.extend(_statement_sequence(nested))
        if isinstance(statement, ast.Try):
            for handler in statement.handlers:
                result.extend(_statement_sequence(handler.body))
    return sorted(result, key=lambda row: getattr(row, "lineno", 1))


def _statement_expressions(statement: ast.stmt) -> list[ast.AST]:
    if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        value = getattr(statement, "value", None)
        return [value] if value is not None else []
    if isinstance(statement, ast.Expr):
        return [statement.value]
    if isinstance(statement, (ast.Return, ast.Raise, ast.Assert)):
        values = [getattr(statement, name, None) for name in ("value", "exc", "test", "msg")]
        return [value for value in values if isinstance(value, ast.AST)]
    if isinstance(statement, (ast.If, ast.While)):
        return [statement.test]
    if isinstance(statement, (ast.For, ast.AsyncFor)):
        return [statement.iter]
    if isinstance(statement, (ast.With, ast.AsyncWith)):
        return [item.context_expr for item in statement.items]
    return []


def _local_flow(tree: ast.AST) -> list[tuple[int, str, str]]:
    """Conservative same-scope source/assignment/sink witnesses for fixtures."""
    sources = graph41._SOURCE_CALLS
    sinks = graph41._SINKS
    result: list[tuple[int, str, str]] = []
    for scope in [tree, *[node for node in ast.walk(tree)
                           if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]]:
        env: set[str] = set()
        body = _statement_sequence(getattr(scope, "body", []))
        for statement in body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                tainted = any(isinstance(node, ast.Call) and _dotted(node.func) in sources
                              for node in ast.walk(value))
                names = {node.id for node in ast.walk(value) if isinstance(node, ast.Name)}
                tainted = tainted or bool(names & env)
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        if tainted:
                            env.add(target.id)
                        else:
                            env.discard(target.id)
            for expression in _statement_expressions(statement):
                for node in ast.walk(expression):
                    if not isinstance(node, ast.Call) or _dotted(node.func) not in sinks:
                        continue
                    argument = node.args[0] if node.args else next(
                        (keyword.value for keyword in node.keywords if keyword.arg is not None), None)
                    outer = _dotted(argument.func) if isinstance(argument, ast.Call) else ""
                    context = sinks[_dotted(node.func)][1]
                    if (outer in graph41._SANITIZERS or
                            outer in graph41._SINK_SANITIZERS.get(context, ())):
                        continue
                    direct = argument is not None and any(
                        isinstance(part, ast.Call) and _dotted(part.func) in sources
                        for part in ast.walk(argument))
                    names = ({part.id for part in ast.walk(argument) if isinstance(part, ast.Name)}
                             if argument is not None else set())
                    if direct or names & env:
                        result.append((node.lineno, _dotted(node.func),
                                       sinks[_dotted(node.func)][0]))
    return result


def _match_source(rule: Mapping[str, Any], source: str, *,
                  max_ast_nodes: int = 250_000) -> list[int]:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise RulePackError(f"fixture does not parse at line {exc.lineno or 1}") from exc
    if sum(1 for _ in ast.walk(tree)) > max_ast_nodes:
        raise RulePackError("AST node budget exceeded")
    kind = rule["match"]["kind"]
    lines: list[int] = []
    if kind == "ast-call":
        allowed = set(rule["match"]["callee_in"])
        lines = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and _dotted(node.func) in allowed]
    elif kind == "ast-node":
        allowed = set(rule["match"]["node_type_in"])
        names = set(rule["match"].get("name_in", []))
        lines = [getattr(node, "lineno", 1) for node in ast.walk(tree)
                 if type(node).__name__ in allowed and
                 (not names or getattr(node, "name", "") in names)]
    else:
        sinks = set(rule["match"]["sink_in"])
        cwes = set(rule["match"].get("cwe_in", []))
        lines = [line for line, sink, cwe in _local_flow(tree)
                 if sink in sinks and (not cwes or cwe in cwes)]
    return sorted(set(lines))


def seal_pack(pack: Mapping[str, Any], *, key: bytes | None = None,
              key_id: str = "") -> dict[str, Any]:
    """Return a content-addressed copy, optionally authenticated with HMAC."""
    body = _clean_pack(pack)
    body.setdefault("schema", SCHEMA)
    body.setdefault("version", VERSION)
    digest = _sha(body)
    sealed = json.loads(json.dumps(body))
    sealed["pack_sha256"] = digest
    if key is not None:
        if not isinstance(key, bytes) or len(key) < 16:
            raise RulePackError("signing key must contain at least 16 bytes")
        if (not isinstance(key_id, str) or not key_id or len(key_id) > 128 or
                key_id != _terminal_text(key_id, 128)):
            raise RulePackError("key_id is required for an authenticated pack")
        sealed["signature"] = {"algorithm": "hmac-sha256", "key_id": key_id,
                               "value": hmac.new(key, _pack_hmac_input(key_id, digest),
                                                 hashlib.sha256).hexdigest()}
    return sealed


def validate_pack(pack: Mapping[str, Any], *, key: bytes | None = None,
                  require_signature: bool = False,
                  expected_key_id: str = "",
                  budget: RuleBudget | None = None) -> dict[str, Any]:
    budget = budget or RuleBudget()
    if len(_canonical(pack)) > budget.max_pack_bytes:
        raise RulePackError("pack byte budget exceeded")
    body = _clean_pack(pack)
    if body.get("schema") != SCHEMA or body.get("version") != VERSION:
        raise RulePackError("unsupported rule pack schema or version")
    pack_id = body.get("pack_id")
    if not isinstance(pack_id, str) or not _PACK_ID.fullmatch(pack_id):
        raise RulePackError("pack_id is invalid")
    rules = body.get("rules")
    if not isinstance(rules, list) or not rules or len(rules) > budget.max_rules:
        raise RulePackError("rules must be a non-empty bounded list")
    normalized = [_parse_rule(rule, budget) for rule in rules]
    ids = [rule["id"] for rule in normalized]
    if len(ids) != len(set(ids)):
        raise RulePackError("duplicate rule id")
    expected_digest = _sha(body)
    if pack.get("pack_sha256") != expected_digest:
        raise RulePackError("pack digest mismatch; seal the pack before loading")
    signature = pack.get("signature")
    if require_signature and signature is None:
        raise RulePackError("authenticated pack signature is required")
    if signature is not None:
        if (type(signature) is not dict or
                set(signature) != {"algorithm", "key_id", "value"} or
                signature.get("algorithm") != "hmac-sha256" or
                not isinstance(signature.get("key_id"), str) or
                not 1 <= len(signature["key_id"]) <= 128 or
                signature["key_id"] != _terminal_text(signature["key_id"], 128) or
                not isinstance(signature.get("value"), str) or
                not _HEX64.fullmatch(signature["value"])):
            raise RulePackError("signature envelope is invalid")
        if key is None:
            raise RulePackError("verification key is required for signed pack")
        if not isinstance(key, bytes) or len(key) < 16:
            raise RulePackError("verification key must contain at least 16 bytes")
        if expected_key_id and signature["key_id"] != expected_key_id:
            raise RulePackError("signature key_id does not match the trusted key")
        expected = hmac.new(
            key, _pack_hmac_input(signature["key_id"], expected_digest),
            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature["value"], expected):
            raise RulePackError("pack signature mismatch")
    for rule in normalized:
        for fixture in rule["fixtures"]["positive"]:
            if len(_match_source(rule, fixture["source"],
                                 max_ast_nodes=budget.max_ast_nodes_per_file)) < fixture["expected_min"]:
                raise RulePackError(f"positive fixture failed for {rule['id']}")
        for fixture in rule["fixtures"]["negative"]:
            if _match_source(rule, fixture["source"],
                             max_ast_nodes=budget.max_ast_nodes_per_file):
                raise RulePackError(f"negative fixture failed for {rule['id']}")
    return {"pack_id": pack_id, "pack_sha256": expected_digest,
            "authenticated": signature is not None, "rules": normalized}


def evaluate(pack: Mapping[str, Any], snapshot: snapshot41.SourceSnapshot | str | Path,
             *, graph: Mapping[str, Any] | None = None, key: bytes | None = None,
             require_signature: bool = False, expected_key_id: str = "",
             budget: RuleBudget | None = None) -> dict[str, Any]:
    budget = budget or RuleBudget()
    validated = validate_pack(pack, key=key, require_signature=require_signature,
                              expected_key_id=expected_key_id, budget=budget)
    if not isinstance(snapshot, snapshot41.SourceSnapshot):
        snapshot = snapshot41.capture(snapshot)
    findings: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    gap_overflow = False

    def add_gap(row: dict[str, Any]) -> None:
        nonlocal gap_overflow
        normalized = {
            key: _terminal_text(value, 8_192 if key == "path" else 2_000)
            for key, value in row.items()
        }
        if len(gaps) < budget.max_gaps:
            gaps.append(normalized)
        else:
            gap_overflow = True

    for gap in snapshot.gaps:
        add_gap({"path": str(gap.get("path", "")),
                 "reason": "snapshot-" + str(gap.get("reason", "coverage-gap"))})
    if graph is None and any(rule["match"]["kind"] == "flow-to-sink"
                             for rule in validated["rules"]):
        graph = graph41.build(snapshot)
    graph_valid = bool(graph and graph41.verify_report(graph)[0] and
                       graph.get("snapshot_sha256") == snapshot.snapshot_sha256)
    graph_rows: list[Mapping[str, Any]] = []
    if graph_valid:
        graph_body = graph.get("graph", {})
        candidate_rows = (graph_body.get("taint_witnesses", [])
                          if isinstance(graph_body, Mapping) else None)
        if (isinstance(candidate_rows, list) and
                all(type(row) is dict for row in candidate_rows)):
            graph_rows = candidate_rows
        else:
            graph_valid = False
    coverage = graph.get("coverage", {}) if graph_valid else {}
    if graph_valid and (not isinstance(coverage, Mapping) or
                        not coverage.get("complete", False)):
        add_gap({"reason": "semantic-graph-reported-incomplete-coverage"})
    finding_budget_reached = False
    for rule in validated["rules"]:
        if finding_budget_reached:
            break
        if rule["match"]["kind"] == "flow-to-sink":
            if not graph_valid:
                add_gap({"rule": rule["id"], "reason":
                         "valid-same-snapshot-semantic-graph-required"})
                continue
            for witness in graph_rows:
                sink = witness.get("sink")
                if (not isinstance(sink, Mapping) or
                        not isinstance(sink.get("path"), str) or
                        type(sink.get("line")) is not int or sink["line"] < 1 or
                        not isinstance(witness.get("id"), str) or
                        not isinstance(witness.get("precision"), str)):
                    add_gap({"rule": rule["id"], "reason": "malformed-taint-witness"})
                    continue
                if (sink.get("callee") in rule["match"]["sink_in"] and
                        (not rule["match"].get("cwe_in") or
                         witness.get("cwe") in rule["match"]["cwe_in"])):
                    if len(findings) >= budget.max_findings:
                        finding_budget_reached = True
                        add_gap({"rule": rule["id"], "reason": "finding-budget-reached"})
                        break
                    row = {"rule": rule["id"], "title": rule["title"],
                           "severity": rule["severity"],
                           "path": _terminal_text(sink.get("path", ""), 8_192),
                           "line": sink.get("line", 1),
                           "evidence_id": _terminal_text(witness.get("id", ""), 2_000),
                           "analysis_level": _terminal_text(
                               witness.get("precision", "unknown"), 2_000),
                           "remediation": rule["remediation"]}
                    findings.append(row)
            continue
        for item in snapshot.files:
            if item.language != rule["language"]:
                continue
            if item.language != "python":
                add_gap({"rule": rule["id"], "path": item.path,
                         "reason": "ast-rule-unavailable-for-bounded-structural-adapter"})
                continue
            text, replaced = item.text()
            if replaced:
                add_gap({"rule": rule["id"], "path": item.path,
                         "reason": "invalid-utf8-replaced"})
            try:
                lines = _match_source(rule, text,
                                      max_ast_nodes=budget.max_ast_nodes_per_file)
            except RulePackError:
                add_gap({"rule": rule["id"], "path": item.path,
                         "reason": "parse-or-ast-budget-error"})
                continue
            for line in lines:
                if len(findings) >= budget.max_findings:
                    finding_budget_reached = True
                    add_gap({"rule": rule["id"], "reason": "finding-budget-reached"})
                    break
                row = {"rule": rule["id"], "title": rule["title"],
                       "severity": rule["severity"],
                       "path": _terminal_text(item.path, 8_192),
                       "line": line, "analysis_level": "python-ast-parser-derived",
                       "remediation": rule["remediation"]}
                row["evidence_id"] = "sdk41-ev-" + _sha(row)[:24]
                findings.append(row)
    findings.sort(key=lambda row: (row["path"], row["line"], row["rule"], row["evidence_id"]))
    gaps.sort(key=lambda row: (row.get("path", ""), row.get("rule", ""), row["reason"]))
    if gap_overflow:
        marker = {"reason": "gap-budget-reached"}
        if gaps:
            gaps[-1] = marker
        else:
            gaps.append(marker)
        gaps.sort(key=lambda row: (row.get("path", ""), row.get("rule", ""), row["reason"]))
    body = {"schema": REPORT_SCHEMA, "version": VERSION,
            "analysis_level": "declarative-bounded-semantic-rules",
            "snapshot_sha256": snapshot.snapshot_sha256,
            "pack": {"id": validated["pack_id"], "sha256": validated["pack_sha256"],
                     "authenticated": validated["authenticated"]},
            "findings": findings[:budget.max_findings],
            "coverage": {"complete": not gaps, "gaps": gaps},
            "budgets": {name: getattr(budget, name) for name in budget.__dataclass_fields__},
            "static_contract": dict(_STATIC_CONTRACT)}
    body["report_sha256"] = _sha(body)
    return body


def _display_text_is_valid(value: Any, maximum: int, *, allow_empty: bool = False) -> bool:
    return bool(isinstance(value, str) and len(value) <= maximum and
                (allow_empty or value) and _terminal_text(value, maximum) == value)


def _report_shape_errors(report: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    expected_keys = {
        "schema", "version", "analysis_level", "snapshot_sha256", "pack",
        "findings", "coverage", "budgets", "static_contract", "report_sha256",
    }
    if set(report) != expected_keys:
        errors.append("result fields do not match the semantic result contract")
    if report.get("analysis_level") != "declarative-bounded-semantic-rules":
        errors.append("analysis level is invalid")
    snapshot_sha256 = report.get("snapshot_sha256")
    if not isinstance(snapshot_sha256, str) or not _HEX64.fullmatch(snapshot_sha256):
        errors.append("snapshot digest is invalid")

    pack = report.get("pack")
    if (type(pack) is not dict or set(pack) != {"id", "sha256", "authenticated"} or
            not isinstance(pack.get("id"), str) or not _PACK_ID.fullmatch(pack["id"]) or
            not isinstance(pack.get("sha256"), str) or not _HEX64.fullmatch(pack["sha256"]) or
            type(pack.get("authenticated")) is not bool):
        errors.append("pack evidence is invalid")

    declared_budget: RuleBudget | None = None
    budgets = report.get("budgets")
    budget_fields = set(RuleBudget.__dataclass_fields__)
    if type(budgets) is not dict or set(budgets) != budget_fields:
        errors.append("declared budgets are invalid")
    else:
        try:
            declared_budget = RuleBudget(**budgets)
        except (RulePackError, TypeError, ValueError, OverflowError):
            errors.append("declared budgets are invalid")

    findings = report.get("findings")
    finding_keys = {
        "rule", "title", "severity", "path", "line", "evidence_id",
        "analysis_level", "remediation",
    }
    if type(findings) is not list:
        errors.append("findings are not a list")
    else:
        if declared_budget is not None and len(findings) > declared_budget.max_findings:
            errors.append("finding count exceeds the declared budget")
        for finding in findings:
            if type(finding) is not dict or set(finding) != finding_keys:
                errors.append("finding shape is invalid")
                break
            if (not isinstance(finding.get("rule"), str) or
                    not _ID.fullmatch(finding["rule"]) or
                    finding.get("severity") not in _SEVERITIES or
                    not _display_text_is_valid(finding.get("title"), 2_000) or
                    not _display_text_is_valid(finding.get("remediation"), 2_000) or
                    not _display_text_is_valid(finding.get("path"), 8_192, allow_empty=True) or
                    not _display_text_is_valid(finding.get("evidence_id"), 2_000) or
                    not _display_text_is_valid(finding.get("analysis_level"), 2_000) or
                    type(finding.get("line")) is not int or
                    not 1 <= finding["line"] <= 2_147_483_647):
                errors.append("finding value is invalid")
                break

    coverage = report.get("coverage")
    gaps: Any = None
    if type(coverage) is not dict or set(coverage) != {"complete", "gaps"}:
        errors.append("coverage shape is invalid")
    else:
        gaps = coverage.get("gaps")
        if type(coverage.get("complete")) is not bool or type(gaps) is not list:
            errors.append("coverage value is invalid")
        else:
            if coverage["complete"] != (not gaps):
                errors.append("coverage completeness contradicts its gaps")
            if declared_budget is not None and len(gaps) > declared_budget.max_gaps:
                errors.append("gap count exceeds the declared budget")
            for gap in gaps:
                if (type(gap) is not dict or "reason" not in gap or not set(gap) or
                        not set(gap) <= {"path", "rule", "reason"} or
                        not _display_text_is_valid(gap.get("reason"), 2_000) or
                        ("path" in gap and not _display_text_is_valid(
                            gap["path"], 8_192, allow_empty=True)) or
                        ("rule" in gap and (not isinstance(gap["rule"], str) or
                                            not _ID.fullmatch(gap["rule"])) )):
                    errors.append("coverage gap is invalid")
                    break

    static_contract = report.get("static_contract")
    if (type(static_contract) is not dict or set(static_contract) != set(_STATIC_CONTRACT) or
            any(static_contract.get(key) is not False for key in _STATIC_CONTRACT)):
        errors.append("static execution contract is invalid")
    digest = report.get("report_sha256")
    if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
        errors.append("report digest is invalid")
    return errors


def verify_report(report: Mapping[str, Any]) -> tuple[bool, list[str]]:
    if type(report) is not dict:
        return False, ["report is not a JSON object"]
    errors = _report_shape_errors(report)
    if report.get("schema") != REPORT_SCHEMA or report.get("version") != VERSION:
        errors.append("unsupported result schema or version")
    body = {key: value for key, value in report.items() if key != "report_sha256"}
    try:
        if report.get("report_sha256") != _sha(body):
            errors.append("report digest mismatch")
    except RulePackError:
        errors.append("report is not canonical JSON")
    return not errors, errors


run_pack = evaluate
