#!/usr/bin/env python3
"""Threat model generator -- auto-STRIDE from code structure.

Scans code to identify:
  - Entry points (HTTP routes, CLI handlers, message consumers)
  - Data stores (database calls, file I/O, cache access)
  - External services (HTTP clients, API calls, SMTP)
  - Trust boundaries (auth checks, input validation)

Then generates STRIDE threats for each component:
  S - Spoofing (identity/auth bypass)
  T - Tampering (data modification)
  R - Repudiation (audit/logging gaps)
  I - Information Disclosure (data leaks)
  D - Denial of Service (resource exhaustion)
  E - Elevation of Privilege (authz bypass)
"""
from __future__ import annotations

import ast
import os
import re
import sys
from dataclasses import dataclass, field

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


@dataclass
class Component:
    type: str
    name: str
    file: str
    line: int
    details: str = ""


@dataclass
class TrustBoundary:
    name: str
    file: str
    line: int
    kind: str = ""


@dataclass
class Threat:
    stride_category: str
    component: Component
    description: str
    severity: str
    mitigation: str
    cwe: str = ""


_ROUTE_PATTERNS = [
    re.compile(r'@\w+\.(route|get|post|put|delete|patch)\s*\('),
    re.compile(r'app\.(get|post|put|delete|patch|all|use)\s*\('),
]

_DATA_STORE_CALLS = re.compile(
    r"\b(execute|executemany|cursor|query|find|find_one|insert|update|"
    r"delete|save|commit|rollback|open|write|read|redis|cache|"
    r"get_item|put_item|scan|create_table)\s*\(", re.I)

_EXTERNAL_CALLS = re.compile(
    r"\b(requests\.(get|post|put|delete|patch|head)|"
    r"urllib\.request\.urlopen|"
    r"httpx\.(get|post|put|delete)|"
    r"fetch|axios\.(get|post|put)|"
    r"smtplib\.SMTP|"
    r"boto3\.client|"
    r"grpc\.\w+)\s*\(", re.I)

_AUTH_PATTERNS = re.compile(
    r"\b(login_required|requires_auth|authenticate|verify_token|"
    r"check_permission|is_authenticated|has_role|authorize|"
    r"@login_required|@requires_auth|@jwt_required|"
    r"@permission_required)\b", re.I)

_VALIDATION_PATTERNS = re.compile(
    r"\b(validate|sanitize|escape|clean|filter|whitelist|"
    r"Schema\(|validator|marshmallow|pydantic|BaseModel)\b", re.I)

_LOGGING_PATTERNS = re.compile(
    r"\b(logger\.\w+|logging\.\w+|log\.\w+|audit_log|"
    r"print|console\.log)\s*\(", re.I)

_FILE_UPLOAD_PATTERNS = re.compile(
    r"\b(save|upload|store|write_file|put_object|"
    r"request\.files|FileField|FileUpload|multer)\b", re.I)

_CRYPTO_PATTERNS = re.compile(
    r"\b(md5|sha1|DES|RC4|ECB|random\.random|"
    r"random\.randint|pickle\.loads|yaml\.load\b(?!.*Loader))\b", re.I)

_SESSION_PATTERNS = re.compile(
    r"\b(session\[|set_cookie|jwt\.encode|jwt\.decode|"
    r"token.*expire|refresh_token)\b", re.I)


def _extract_py_components(source: str, filepath: str) -> tuple[
        list[Component], list[TrustBoundary]]:
    components = []
    boundaries = []
    lines = source.splitlines()

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return components, boundaries

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                dec_name = ""
                if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                    dec_name = dec.func.attr
                elif isinstance(dec, ast.Attribute):
                    dec_name = dec.attr
                elif isinstance(dec, ast.Name):
                    dec_name = dec.id
                elif isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name):
                    dec_name = dec.func.id

                if dec_name in ("route", "get", "post", "put", "delete", "patch",
                                "api_route", "websocket"):
                    path = ""
                    if isinstance(dec, ast.Call) and dec.args:
                        a0 = dec.args[0]
                        if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                            path = a0.value
                    method = dec_name.upper() if dec_name in (
                        "get", "post", "put", "delete", "patch") else "ROUTE"
                    components.append(Component(
                        type="entry_point", name=f"{method} {path}".strip(),
                        file=filepath, line=node.lineno,
                        details=f"HTTP handler: {node.name}",
                    ))

                if dec_name in ("login_required", "requires_auth", "jwt_required",
                                "permission_required"):
                    boundaries.append(TrustBoundary(
                        name=f"@{dec_name} on {node.name}",
                        file=filepath, line=node.lineno,
                        kind="auth_decorator",
                    ))

    for i, line in enumerate(lines):
        lineno = i + 1
        if _DATA_STORE_CALLS.search(line):
            match = _DATA_STORE_CALLS.search(line)
            components.append(Component(
                type="data_store", name=match.group(1),
                file=filepath, line=lineno,
                details=line.strip()[:80],
            ))
        if _EXTERNAL_CALLS.search(line):
            match = _EXTERNAL_CALLS.search(line)
            components.append(Component(
                type="external_service", name=match.group(0).rstrip("("),
                file=filepath, line=lineno,
                details=line.strip()[:80],
            ))
        if _VALIDATION_PATTERNS.search(line) and not _AUTH_PATTERNS.search(line):
            boundaries.append(TrustBoundary(
                name="input_validation", file=filepath, line=lineno,
                kind="validation",
            ))
        if _FILE_UPLOAD_PATTERNS.search(line):
            components.append(Component(
                type="file_upload", name="file_upload",
                file=filepath, line=lineno,
                details=line.strip()[:80],
            ))
        if _CRYPTO_PATTERNS.search(line):
            match = _CRYPTO_PATTERNS.search(line)
            components.append(Component(
                type="crypto", name=match.group(1),
                file=filepath, line=lineno,
                details=line.strip()[:80],
            ))
        if _SESSION_PATTERNS.search(line):
            components.append(Component(
                type="session_mgmt", name="session",
                file=filepath, line=lineno,
                details=line.strip()[:80],
            ))

    return components, boundaries


def _generate_threats(components: list[Component],
                      boundaries: list[TrustBoundary]) -> list[Threat]:
    threats = []
    boundary_files = {b.file for b in boundaries}
    auth_lines = {(b.file, b.line) for b in boundaries if b.kind == "auth_decorator"}

    for comp in components:
        if comp.type == "entry_point":
            has_auth = any(
                abs(comp.line - al) < 5
                for af, al in auth_lines
                if af == comp.file
            )

            if not has_auth:
                threats.append(Threat(
                    stride_category="Spoofing",
                    component=comp,
                    description=f"Entry point {comp.name} has no visible auth decorator",
                    severity="HIGH",
                    mitigation="Add authentication check (e.g., @login_required)",
                    cwe="CWE-306",
                ))

            threats.append(Threat(
                stride_category="Tampering",
                component=comp,
                description=f"Input to {comp.name} may be tampered with in transit",
                severity="MEDIUM",
                mitigation="Validate all input parameters; use HTTPS",
                cwe="CWE-20",
            ))

            threats.append(Threat(
                stride_category="Denial of Service",
                component=comp,
                description=f"Entry point {comp.name} may lack rate limiting",
                severity="MEDIUM",
                mitigation="Implement rate limiting and request size limits",
                cwe="CWE-770",
            ))

        if comp.type == "data_store":
            threats.append(Threat(
                stride_category="Tampering",
                component=comp,
                description=f"Data store operation '{comp.name}' may accept unsanitized input",
                severity="HIGH",
                mitigation="Use parameterized queries; validate before write",
                cwe="CWE-89",
            ))

            threats.append(Threat(
                stride_category="Information Disclosure",
                component=comp,
                description=f"Data store '{comp.name}' may expose sensitive data in responses",
                severity="MEDIUM",
                mitigation="Filter sensitive fields from query results",
                cwe="CWE-200",
            ))

            threats.append(Threat(
                stride_category="Repudiation",
                component=comp,
                description=f"Data store operation '{comp.name}' may not be logged",
                severity="LOW",
                mitigation="Add audit logging for data modifications",
                cwe="CWE-778",
            ))

        if comp.type == "external_service":
            threats.append(Threat(
                stride_category="Spoofing",
                component=comp,
                description=f"External call to '{comp.name}' may connect to spoofed service",
                severity="MEDIUM",
                mitigation="Verify TLS certificates; pin expected hosts",
                cwe="CWE-295",
            ))

            threats.append(Threat(
                stride_category="Information Disclosure",
                component=comp,
                description=f"Data sent to external service '{comp.name}' may leak secrets",
                severity="MEDIUM",
                mitigation="Review data sent externally; redact sensitive fields",
                cwe="CWE-200",
            ))

            threats.append(Threat(
                stride_category="Elevation of Privilege",
                component=comp,
                description=f"SSRF via '{comp.name}' if URL is user-controlled",
                severity="HIGH",
                mitigation="Validate and allowlist external URLs",
                cwe="CWE-918",
            ))

        if comp.type == "file_upload":
            threats.append(Threat(
                stride_category="Tampering",
                component=comp,
                description=f"File upload at {os.path.basename(comp.file)}:{comp.line} "
                            f"may accept malicious files (webshells, path traversal)",
                severity="HIGH",
                mitigation="Validate file type, size, and name; store outside webroot; "
                           "never execute uploaded content",
                cwe="CWE-434",
            ))

        if comp.type == "crypto":
            threats.append(Threat(
                stride_category="Information Disclosure",
                component=comp,
                description=f"Weak crypto '{comp.name}' at {os.path.basename(comp.file)}:"
                            f"{comp.line}",
                severity="HIGH",
                mitigation="Use SHA-256+, AES-GCM, secrets.token_bytes() instead",
                cwe="CWE-327",
            ))

        if comp.type == "session_mgmt":
            threats.append(Threat(
                stride_category="Spoofing",
                component=comp,
                description=f"Session management at {os.path.basename(comp.file)}:{comp.line} "
                            f"-- verify token expiry, rotation, and secure cookie flags",
                severity="MEDIUM",
                mitigation="Set HttpOnly, Secure, SameSite flags; enforce token expiry",
                cwe="CWE-613",
            ))

    return threats


def analyze_source(source: str, filepath: str = "<string>") -> tuple[
        list[Component], list[TrustBoundary], list[Threat]]:
    comps, bounds = _extract_py_components(source, filepath)
    threats = _generate_threats(comps, bounds)
    return comps, bounds, threats


def scan_paths(paths: list[str]) -> tuple[
        list[Component], list[TrustBoundary], list[Threat]]:
    all_comps = []
    all_bounds = []
    for p in paths:
        if os.path.isfile(p) and p.endswith(".py"):
            try:
                with open(p, encoding="utf-8", errors="replace") as f:
                    c, b = _extract_py_components(f.read(), p)
                    all_comps += c
                    all_bounds += b
            except OSError:
                pass
        elif os.path.isdir(p):
            for dp, dn, fn in os.walk(p):
                dn[:] = [d for d in dn if d not in
                         {".git", "__pycache__", ".venv", "node_modules"}]
                for n in fn:
                    if n.endswith(".py"):
                        fp = os.path.join(dp, n)
                        try:
                            with open(fp, encoding="utf-8", errors="replace") as f:
                                c, b = _extract_py_components(f.read(), fp)
                                all_comps += c
                                all_bounds += b
                        except OSError:
                            pass
    threats = _generate_threats(all_comps, all_bounds)
    return all_comps, all_bounds, threats


def to_dict(threats: list[Threat]) -> list[dict]:
    return [
        {
            "category": t.stride_category.lower().replace(" ", "_"),
            "severity": t.severity, "stride": t.stride_category,
            "file": t.component.file, "path": t.component.file,
            "sink_file": t.component.file, "sink_line": t.component.line,
            "line": t.component.line, "sink_type": t.stride_category.lower(),
            "component_type": t.component.type,
            "component_name": t.component.name,
            "description": t.description,
            "mitigation": t.mitigation, "cwe": t.cwe,
        }
        for t in threats
    ]


def render(comps: list[Component], bounds: list[TrustBoundary],
           threats: list[Threat]) -> str:
    if not comps:
        return "  nothing to model. either this is a library with no entry points, or it's empty."
    high_threats = sum(1 for t in threats if t.severity == "HIGH")
    lines = [
        f"\n  Threat Model (STRIDE)",
        "  " + "=" * 62,
        f"  {len(comps)} component(s) | {len(bounds)} trust boundary(ies) | "
        f"{len(threats)} threat(s) ({high_threats} high)",
    ]

    by_type = {}
    for c in comps:
        by_type.setdefault(c.type, []).append(c)
    for ctype, clist in by_type.items():
        lines.append(f"\n  {ctype.upper()} ({len(clist)}):")
        for c in clist[:10]:
            lines.append(f"    {c.name} at {os.path.basename(c.file)}:{c.line}")

    if bounds:
        lines.append(f"\n  TRUST BOUNDARIES ({len(bounds)}):")
        for b in bounds[:10]:
            lines.append(f"    {b.name} at {os.path.basename(b.file)}:{b.line}")

    by_stride = {}
    for t in threats:
        by_stride.setdefault(t.stride_category, []).append(t)
    order = {"Spoofing": 0, "Tampering": 1, "Repudiation": 2,
             "Information Disclosure": 3, "Denial of Service": 4,
             "Elevation of Privilege": 5}
    for cat in sorted(by_stride, key=lambda x: order.get(x, 9)):
        cat_threats = by_stride[cat]
        lines.append(f"\n  [{cat[0]}] {cat} ({len(cat_threats)} threat(s)):")
        for t in cat_threats:
            lines.append(f"    [{t.severity}] {t.description}")
            lines.append(f"      mitigation: {t.mitigation}")

    return "\n".join(lines)
