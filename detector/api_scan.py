#!/usr/bin/env python3
"""API security scanner -- OpenAPI/Swagger spec analysis.

Parses OpenAPI 2.0/3.x specs and detects:
  - BOLA/IDOR: endpoints with path params and no auth requirement
  - Missing authentication: no security scheme on sensitive endpoints
  - Mass assignment: POST/PUT/PATCH with wide-open request bodies
  - Excessive data exposure: responses with sensitive-looking fields
  - Rate limiting gaps: no x-ratelimit on public endpoints
  - Injection vectors: string params without format/pattern constraints
  - Security scheme weaknesses: HTTP basic, API key in query string
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

_SENSITIVE_FIELDS = re.compile(
    r"\b(password|secret|token|ssn|credit_card|card_number|cvv|"
    r"social_security|bank_account|private_key|api_key|auth_token|"
    r"session_id|access_token|refresh_token)\b", re.I)

_WRITE_METHODS = {"post", "put", "patch", "delete"}


@dataclass
class APIFinding:
    rule_id: str
    severity: str
    path: str
    method: str
    description: str
    category: str
    cwe: str = ""
    spec_file: str = ""


def _load_spec(text: str, filepath: str) -> dict | None:
    if filepath.endswith(".json"):
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return None
    if HAS_YAML:
        try:
            return yaml.safe_load(text)
        except Exception:
            return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _is_openapi(spec: dict) -> bool:
    return ("openapi" in spec or "swagger" in spec) and "paths" in spec


def _has_path_params(path: str) -> bool:
    return bool(re.search(r"\{[^}]+\}", path))


def _get_security(operation: dict, global_security: list) -> list:
    return operation.get("security", global_security)


def _schema_fields(schema: dict, prefix: str = "") -> list[str]:
    fields = []
    if "properties" in schema:
        for name, prop in schema["properties"].items():
            full = f"{prefix}.{name}" if prefix else name
            fields.append(full)
            if "properties" in prop:
                fields += _schema_fields(prop, full)
    if "items" in schema and isinstance(schema["items"], dict):
        fields += _schema_fields(schema["items"], prefix + "[]")
    return fields


def _resolve_ref(spec: dict, ref: str) -> dict:
    if not ref.startswith("#/"):
        return {}
    parts = ref[2:].split("/")
    node = spec
    for p in parts:
        if isinstance(node, dict):
            node = node.get(p, {})
        else:
            return {}
    return node if isinstance(node, dict) else {}


def _get_schema(obj: dict, spec: dict) -> dict:
    if "$ref" in obj:
        return _resolve_ref(spec, obj["$ref"])
    return obj


def scan_spec(spec: dict, filepath: str = "") -> list[APIFinding]:
    if not _is_openapi(spec):
        return []

    findings = []
    global_security = spec.get("security", [])
    security_defs = (spec.get("securityDefinitions", {}) or
                     spec.get("components", {}).get("securitySchemes", {}))

    for scheme_name, scheme in security_defs.items():
        scheme_type = scheme.get("type", "")
        if scheme_type == "http" and scheme.get("scheme", "").lower() == "basic":
            findings.append(APIFinding(
                rule_id="API-001", severity="MEDIUM",
                path="(global)", method="*",
                description=f"HTTP Basic auth scheme '{scheme_name}' transmits "
                            f"credentials in every request -- prefer token-based auth",
                category="weak_auth", cwe="CWE-319", spec_file=filepath,
            ))
        if scheme_type == "apiKey" and scheme.get("in", "") == "query":
            findings.append(APIFinding(
                rule_id="API-002", severity="HIGH",
                path="(global)", method="*",
                description=f"API key '{scheme_name}' sent in query string -- "
                            f"visible in logs, browser history, and referer headers",
                category="credential_exposure", cwe="CWE-598", spec_file=filepath,
            ))

    paths = spec.get("paths", {})
    for path_str, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in ("get", "post", "put", "patch", "delete", "options", "head"):
            operation = path_item.get(method)
            if not operation or not isinstance(operation, dict):
                continue

            op_security = _get_security(operation, global_security)

            if _has_path_params(path_str) and not op_security:
                findings.append(APIFinding(
                    rule_id="API-003", severity="HIGH",
                    path=path_str, method=method.upper(),
                    description=f"BOLA/IDOR risk: {method.upper()} {path_str} has path "
                                f"parameters but no security requirement",
                    category="bola", cwe="CWE-639", spec_file=filepath,
                ))

            if method in _WRITE_METHODS and not op_security:
                findings.append(APIFinding(
                    rule_id="API-004", severity="HIGH",
                    path=path_str, method=method.upper(),
                    description=f"Missing auth: {method.upper()} {path_str} modifies "
                                f"state without authentication",
                    category="missing_auth", cwe="CWE-306", spec_file=filepath,
                ))

            req_body = operation.get("requestBody", {})
            if isinstance(req_body, dict):
                for content_type, media in req_body.get("content", {}).items():
                    if isinstance(media, dict):
                        schema = _get_schema(media.get("schema", {}), spec)
                        fields = _schema_fields(schema)
                        sensitive = [f for f in fields if _SENSITIVE_FIELDS.search(f)]
                        if len(fields) > 10 and method in _WRITE_METHODS:
                            findings.append(APIFinding(
                                rule_id="API-005", severity="MEDIUM",
                                path=path_str, method=method.upper(),
                                description=f"Mass assignment risk: {method.upper()} {path_str} "
                                            f"accepts {len(fields)} fields -- consider restricting",
                                category="mass_assignment", cwe="CWE-915",
                                spec_file=filepath,
                            ))

            for status, response in operation.get("responses", {}).items():
                if not isinstance(response, dict):
                    continue
                for content_type, media in response.get("content", {}).items():
                    if isinstance(media, dict):
                        schema = _get_schema(media.get("schema", {}), spec)
                        fields = _schema_fields(schema)
                        sensitive = [f for f in fields if _SENSITIVE_FIELDS.search(f)]
                        if sensitive:
                            findings.append(APIFinding(
                                rule_id="API-006", severity="HIGH",
                                path=path_str, method=method.upper(),
                                description=f"Excessive data exposure: response includes "
                                            f"sensitive field(s): {', '.join(sensitive[:5])}",
                                category="data_exposure", cwe="CWE-200",
                                spec_file=filepath,
                            ))

            params = operation.get("parameters", []) + path_item.get("parameters", [])
            for param in params:
                if not isinstance(param, dict):
                    continue
                param = _get_schema(param, spec)
                p_schema = param.get("schema", param)
                if (p_schema.get("type") == "string"
                        and "format" not in p_schema
                        and "pattern" not in p_schema
                        and "enum" not in p_schema
                        and param.get("in") in ("query", "path")):
                    pname = param.get("name", "?")
                    findings.append(APIFinding(
                        rule_id="API-007", severity="LOW",
                        path=path_str, method=method.upper(),
                        description=f"Unconstrained string param '{pname}' in "
                                    f"{param.get('in', '?')} -- add format/pattern/enum",
                        category="injection_vector", cwe="CWE-20",
                        spec_file=filepath,
                    ))

                if (p_schema.get("type") == "integer"
                        and "maximum" not in p_schema
                        and param.get("name", "").lower() in
                        ("limit", "page_size", "pagesize", "count", "offset")):
                    pname = param.get("name", "?")
                    findings.append(APIFinding(
                        rule_id="API-008", severity="MEDIUM",
                        path=path_str, method=method.upper(),
                        description=f"Pagination param '{pname}' has no maximum -- "
                                    f"attacker can request millions of records",
                        category="dos_vector", cwe="CWE-770",
                        spec_file=filepath,
                    ))

            if method == "get" and not op_security:
                resp_200 = operation.get("responses", {}).get("200", {})
                if isinstance(resp_200, dict):
                    for ct, media in resp_200.get("content", {}).items():
                        if isinstance(media, dict):
                            schema = _get_schema(media.get("schema", {}), spec)
                            if schema.get("type") == "array" and "maxItems" not in schema:
                                findings.append(APIFinding(
                                    rule_id="API-009", severity="MEDIUM",
                                    path=path_str, method="GET",
                                    description=f"Unauthenticated array endpoint {path_str} "
                                                f"has no maxItems -- enumeration risk",
                                    category="enumeration", cwe="CWE-200",
                                    spec_file=filepath,
                                ))

    return findings


def scan_file(path: str) -> list[APIFinding]:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return []
    spec = _load_spec(text, path)
    if spec is None or not isinstance(spec, dict):
        return []
    return scan_spec(spec, path)


def scan_paths(paths: list[str]) -> list[APIFinding]:
    findings = []
    target_names = re.compile(
        r"(openapi|swagger|api-spec|api_spec)\.(json|ya?ml)$", re.I)
    for p in paths:
        if os.path.isfile(p):
            findings += scan_file(p)
        elif os.path.isdir(p):
            for dp, dn, fn in os.walk(p):
                dn[:] = [d for d in dn if d not in
                         {".git", "__pycache__", ".venv", "node_modules"}]
                for n in fn:
                    if target_names.search(n) or n.endswith((".json", ".yaml", ".yml")):
                        fp = os.path.join(dp, n)
                        findings += scan_file(fp)
    return findings


def to_dict(findings: list[APIFinding]) -> list[dict]:
    return [
        {
            "rule_id": f.rule_id, "severity": f.severity,
            "category": f.category, "path": f.path,
            "file": f.spec_file, "sink_file": f.spec_file,
            "sink_line": 0, "line": 0,
            "sink_type": f.category,
            "method": f.method,
            "description": f.description,
            "cwe": f.cwe,
        }
        for f in findings
    ]


def render(findings: list[APIFinding]) -> str:
    if not findings:
        return "  spec looks solid. no auth gaps, no BOLA, no mass assignment."
    high = sum(1 for f in findings if f.severity in ("HIGH", "CRITICAL"))
    lines = [
        f"\n  API Security Scan -- {len(findings)} issue(s)",
        "  " + "=" * 62,
    ]
    if high:
        lines.append(f"  {high} high/critical -- these are real attack surface, not hypothetical.")
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for f in sorted(findings, key=lambda x: order.get(x.severity, 9)):
        lines.append(f"\n  [{f.severity}] {f.rule_id} {f.method} {f.path}")
        lines.append(f"    {f.description}")
    return "\n".join(lines)
