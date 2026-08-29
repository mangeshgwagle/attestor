#!/usr/bin/env python3
"""Attack surface mapper -- identifies exposed endpoints, open ports, authentication
boundaries, input entry points, sensitive data flows, and external integrations
in a codebase for threat modeling and security review."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {
    ".git", ".svn", "node_modules", "__pycache__", ".tox", ".venv",
    "venv", "dist", "build", ".next", ".nuxt",
}

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".pyc",
    ".png", ".jpg", ".gif", ".zip", ".tar", ".gz", ".pdf",
}


@dataclass
class SurfaceEntry:
    path: str
    line: int
    category: str
    entry_type: str
    description: str
    risk_level: str
    details: str = ""


ENDPOINT_PATTERNS = [
    # Flask/FastAPI/Django
    (r"@(?:app|router|blueprint)\.(?:route|get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]",
     "http_endpoint", "python_web", "HTTP endpoint"),
    (r"path\s*\(\s*['\"]([^'\"]+)['\"]", "http_endpoint", "django_url", "Django URL pattern"),
    (r"url\s*\(\s*r?['\"]([^'\"]+)['\"]", "http_endpoint", "django_url", "Django URL pattern"),
    # Express.js
    (r"(?:app|router)\.(?:get|post|put|delete|patch|all|use)\s*\(\s*['\"]([^'\"]+)['\"]",
     "http_endpoint", "express", "Express.js endpoint"),
    # Spring
    (r"@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?['\"]([^'\"]+)['\"]",
     "http_endpoint", "spring", "Spring endpoint"),
    # Go
    (r"(?:HandleFunc|Handle|Get|Post|Put|Delete)\s*\(\s*['\"]([^'\"]+)['\"]",
     "http_endpoint", "go_http", "Go HTTP handler"),
    # Generic REST patterns
    (r"/api/v\d+/\w+", "http_endpoint", "api_path", "REST API path"),
]

AUTH_PATTERNS = [
    (r"(?:@login_required|@auth_required|@requires_auth|@jwt_required|@permission_required)",
     "auth_boundary", "decorator", "Authentication decorator"),
    (r"(?:passport\.authenticate|isAuthenticated|ensureAuthenticated|requireAuth)",
     "auth_boundary", "middleware", "Auth middleware"),
    (r"(?:@PreAuthorize|@Secured|@RolesAllowed|@PermitAll)",
     "auth_boundary", "spring_security", "Spring Security annotation"),
    (r"(?:verify_password|check_password|authenticate_user|validate_token)",
     "auth_boundary", "function", "Authentication function"),
    (r"(?:Bearer|JWT|OAuth|SAML|OpenID|Kerberos)\b",
     "auth_protocol", "protocol", "Authentication protocol reference"),
]

INPUT_PATTERNS = [
    (r"request\.(?:args|form|json|data|files|headers|cookies|values)\b",
     "user_input", "flask", "Flask request input"),
    (r"(?:req\.(?:body|params|query|headers|cookies|file|files))\b",
     "user_input", "express", "Express request input"),
    (r"(?:request\.(?:GET|POST|FILES|META|COOKIES|body|data|query_params))\b",
     "user_input", "django", "Django request input"),
    (r"(?:@RequestParam|@PathVariable|@RequestBody|@RequestHeader)\b",
     "user_input", "spring", "Spring parameter binding"),
    (r"(?:stdin|STDIN|sys\.stdin|input\s*\(\s*\))\b",
     "user_input", "stdin", "Standard input"),
    (r"(?:argv|sys\.argv|os\.environ|process\.env|getenv)\b",
     "user_input", "env_args", "Environment/CLI input"),
    (r"(?:file_get_contents|fread|fgets)\s*\(\s*\$_",
     "user_input", "php", "PHP file input from user"),
]

FILE_IO_PATTERNS = [
    (r"(?:open|fopen|file_get_contents|readFile|createReadStream)\s*\(",
     "file_io", "read", "File read operation"),
    (r"(?:write|fwrite|file_put_contents|writeFile|createWriteStream)\s*\(",
     "file_io", "write", "File write operation"),
    (r"(?:upload|multer|FileField|FileUpload)\b",
     "file_io", "upload", "File upload handler"),
    (r"(?:tempfile|mktemp|tmpfile|os\.tmpnam)\b",
     "file_io", "temp", "Temporary file creation"),
]

NETWORK_PATTERNS = [
    (r"(?:socket\.(?:socket|create_connection)|net\.createServer|ServerSocket)\b",
     "network", "socket", "Raw socket operation"),
    (r"(?:requests\.(?:get|post|put)|urllib|http\.client|fetch|axios|HttpClient)\b",
     "network", "http_client", "Outbound HTTP request"),
    (r"(?:smtp|SMTP|sendmail|nodemailer)\b",
     "network", "email", "Email sending capability"),
    (r"(?:DNS|dns\.resolve|nslookup|dig)\b",
     "network", "dns", "DNS query"),
    (r"(?:websocket|ws\.Server|WebSocket|socket\.io)\b",
     "network", "websocket", "WebSocket connection"),
]

DATABASE_PATTERNS = [
    (r"(?:execute|query|raw|cursor|prepare|createQueryBuilder)\s*\(",
     "database", "query", "Database query execution"),
    (r"(?:connect|createConnection|createPool|getConnection)\s*\(",
     "database", "connection", "Database connection"),
    (r"(?:MongoClient|mongoose\.connect|redis\.createClient|memcached)\b",
     "database", "nosql", "NoSQL database connection"),
]

SENSITIVE_DATA_PATTERNS = [
    (r"(?:password|passwd|secret|token|key|credential|auth|ssn|social_security|credit_card)",
     "sensitive_data", "field", "Sensitive data field name"),
    (r"(?:encrypt|decrypt|hash|hmac|cipher|AES|RSA|bcrypt|argon2|scrypt)\b",
     "crypto_operation", "crypto", "Cryptographic operation"),
    (r"(?:cookie|session|localStorage|sessionStorage)\b",
     "client_storage", "storage", "Client-side data storage"),
]

EXTERNAL_INTEGRATION_PATTERNS = [
    (r"(?:stripe|paypal|braintree|square)\.(?:charges|payments|checkout|subscriptions)\b",
     "external_service", "payment", "Payment service integration"),
    (r"(?:twilio|sendgrid|mailgun|ses)\.\w+\b",
     "external_service", "messaging", "Messaging service integration"),
    (r"(?:s3|gcs|blob|cloudinary|firebase\.storage)\.\w+\b",
     "external_service", "storage", "Cloud storage integration"),
    (r"(?:graphql|GraphQL|__schema)\b",
     "external_service", "graphql", "GraphQL endpoint"),
]

_compiled_cache: dict[str, list[tuple[re.Pattern, str, str, str]]] = {}


def _compile_group(patterns, key):
    if key not in _compiled_cache:
        _compiled_cache[key] = [
            (re.compile(p[0], re.IGNORECASE), *p[1:])
            for p in patterns
        ]
    return _compiled_cache[key]


RISK_BY_CATEGORY = {
    "http_endpoint": "HIGH",
    "auth_boundary": "MEDIUM",
    "auth_protocol": "LOW",
    "user_input": "HIGH",
    "file_io": "MEDIUM",
    "network": "HIGH",
    "database": "HIGH",
    "sensitive_data": "MEDIUM",
    "crypto_operation": "LOW",
    "client_storage": "MEDIUM",
    "external_service": "MEDIUM",
}


def scan_file(path: str) -> list[SurfaceEntry]:
    ext = Path(path).suffix.lower()
    if ext in BINARY_EXTENSIONS:
        return []
    entries = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except (OSError, PermissionError):
        return []

    all_pattern_groups = [
        (ENDPOINT_PATTERNS, "endpoints"),
        (AUTH_PATTERNS, "auth"),
        (INPUT_PATTERNS, "input"),
        (FILE_IO_PATTERNS, "file_io"),
        (NETWORK_PATTERNS, "network"),
        (DATABASE_PATTERNS, "database"),
        (SENSITIVE_DATA_PATTERNS, "sensitive"),
        (EXTERNAL_INTEGRATION_PATTERNS, "external"),
    ]

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "/*", "*")):
            continue
        for pattern_group, group_key in all_pattern_groups:
            for pat_tuple in _compile_group(pattern_group, group_key):
                pattern = pat_tuple[0]
                category = pat_tuple[1]
                entry_type = pat_tuple[2]
                description = pat_tuple[3]
                m = pattern.search(stripped)
                if m:
                    details = m.group(1) if m.lastindex else m.group(0)
                    risk = RISK_BY_CATEGORY.get(category, "MEDIUM")
                    entries.append(SurfaceEntry(
                        path=path, line=lineno,
                        category=category, entry_type=entry_type,
                        description=description, risk_level=risk,
                        details=details[:200],
                    ))
    return entries


def scan_directory(root: str) -> list[SurfaceEntry]:
    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            entries.extend(scan_file(fpath))
    return entries


def render(entries: list[SurfaceEntry]) -> str:
    if not entries:
        return "  No attack surface entries detected."
    lines = []
    by_cat = {}
    for e in entries:
        by_cat.setdefault(e.category, []).append(e)

    cat_order = [
        "http_endpoint", "user_input", "auth_boundary", "auth_protocol",
        "database", "network", "file_io", "sensitive_data",
        "crypto_operation", "client_storage", "external_service",
    ]

    lines.append(f"\n  Attack Surface Map ({len(entries)} entries)")
    lines.append(f"  {'='*50}")

    for cat in cat_order:
        group = by_cat.pop(cat, [])
        if not group:
            continue
        label = cat.replace("_", " ").title()
        lines.append(f"\n  [{label}] ({len(group)} entries)")
        seen = set()
        for e in group[:20]:
            key = (e.path, e.line, e.entry_type)
            if key in seen:
                continue
            seen.add(key)
            detail = f" -> {e.details}" if e.details and e.details != e.description else ""
            lines.append(f"    [{e.risk_level}] {e.path}:{e.line}  {e.description}{detail}")
        if len(group) > 20:
            lines.append(f"    ... and {len(group) - 20} more")

    lines.append(f"\n  Summary:")
    lines.append(f"    Total entries:     {len(entries)}")
    lines.append(f"    HTTP endpoints:    {len(by_cat.get('http_endpoint', []) or [e for e in entries if e.category == 'http_endpoint'])}")
    lines.append(f"    User input points: {len([e for e in entries if e.category == 'user_input'])}")
    lines.append(f"    Database queries:  {len([e for e in entries if e.category == 'database'])}")
    lines.append(f"    Network calls:     {len([e for e in entries if e.category == 'network'])}")

    unauth_endpoints = []
    auth_lines = {(e.path, e.line) for e in entries if e.category == "auth_boundary"}
    for e in entries:
        if e.category == "http_endpoint":
            near_auth = any(
                e.path == ap and abs(e.line - al) <= 3
                for ap, al in auth_lines
            )
            if not near_auth:
                unauth_endpoints.append(e)
    if unauth_endpoints:
        lines.append(f"\n  Potentially Unauthenticated Endpoints ({len(unauth_endpoints)}):")
        for e in unauth_endpoints[:10]:
            lines.append(f"    {e.path}:{e.line}  {e.details}")

    return "\n".join(lines)


def to_dict(entries: list[SurfaceEntry]) -> list[dict]:
    return [
        {
            "path": e.path,
            "line": e.line,
            "category": e.category,
            "entry_type": e.entry_type,
            "description": e.description,
            "risk_level": e.risk_level,
            "details": e.details,
        }
        for e in entries
    ]
