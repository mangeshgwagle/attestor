#!/usr/bin/env python3
"""JavaScript/TypeScript security scanner -- detects XSS, prototype pollution,
command injection, SQL injection, path traversal, eval usage, ReDoS,
insecure crypto, open redirects, and SSRF in JS/TS source code."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

SKIP_DIRS = {
    ".git", ".svn", "node_modules", "__pycache__", "dist", "build",
    ".next", ".nuxt", "coverage", ".cache", "vendor",
}

MIN_FILE_SIZE = 1
MAX_FILE_SIZE = 5 * 1024 * 1024


@dataclass
class JSFinding:
    path: str
    line: int
    rule_id: str
    description: str
    severity: str
    category: str
    cwe: str = ""


JS_RULES: list[tuple[str, str, str, str, str, str]] = [
    # (rule_id, category, description, pattern, severity, cwe)

    # === XSS ===
    ("JS-XSS-INNERHTML", "xss", "Direct innerHTML assignment (XSS sink)",
     r"\.innerHTML\s*[+]?=", "HIGH", "CWE-79"),
    ("JS-XSS-OUTERHTML", "xss", "Direct outerHTML assignment (XSS sink)",
     r"\.outerHTML\s*[+]?=", "HIGH", "CWE-79"),
    ("JS-XSS-DOCWRITE", "xss", "document.write usage (XSS sink)",
     r"document\.write(?:ln)?\s*\(", "HIGH", "CWE-79"),
    ("JS-XSS-DANGEROUSLY", "xss", "React dangerouslySetInnerHTML",
     r"dangerouslySetInnerHTML\s*=", "MEDIUM", "CWE-79"),
    ("JS-XSS-INSERTADJ", "xss", "insertAdjacentHTML (XSS sink)",
     r"\.insertAdjacentHTML\s*\(", "HIGH", "CWE-79"),
    ("JS-XSS-JQHTML", "xss", "jQuery .html() with user input",
     r"\$\([^)]*\)\.html\s*\(", "MEDIUM", "CWE-79"),
    ("JS-XSS-DOMPARSER", "xss", "DOMParser with user input",
     r"new\s+DOMParser\(\)\.parseFromString", "MEDIUM", "CWE-79"),

    # === COMMAND INJECTION ===
    ("JS-CMDI-EXEC", "command_injection", "child_process.exec with variable input",
     r"(?:child_process\.)?exec(?:Sync)?\s*\(\s*(?:`|['\"]?\s*\+|\$\{)", "CRITICAL", "CWE-78"),
    ("JS-CMDI-SPAWN", "command_injection", "spawn/execFile with shell option",
     r"(?:spawn|execFile)(?:Sync)?\s*\([^)]*shell\s*:\s*true", "HIGH", "CWE-78"),
    ("JS-CMDI-EVAL-REQ", "command_injection", "exec/eval with request parameters",
     r"(?:exec|eval)\s*\(.*(?:req\.|params\.|query\.|body\.)", "CRITICAL", "CWE-78"),

    # === SQL INJECTION ===
    ("JS-SQLI-CONCAT", "sql_injection", "SQL query built with string concatenation",
     r"(?:query|execute|raw)\s*\(\s*(?:['\"](?:SELECT|INSERT|UPDATE|DELETE|DROP)[^'\"]*['\"]?\s*\+|`[^`]*\$\{)",
     "HIGH", "CWE-89"),
    ("JS-SQLI-TEMPLATE", "sql_injection", "SQL in template literal with user input",
     r"`\s*(?:SELECT|INSERT|UPDATE|DELETE).*\$\{.*(?:req\.|params|input|user)", "CRITICAL", "CWE-89"),

    # === PATH TRAVERSAL ===
    ("JS-PATH-JOIN", "path_traversal", "Path built from user input without sanitization",
     r"(?:path\.join|path\.resolve|fs\.(?:readFile|writeFile|access|stat|unlink))\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
     "HIGH", "CWE-22"),
    ("JS-PATH-DOTDOT", "path_traversal", "Path with potential directory traversal",
     r"(?:readFile|createReadStream|access)\s*\([^)]*\+[^)]*(?:filename|path|file|dir)",
     "MEDIUM", "CWE-22"),

    # === PROTOTYPE POLLUTION ===
    ("JS-PROTO-MERGE", "prototype_pollution", "Deep merge/extend without prototype check",
     r"(?:Object\.assign|_\.(?:merge|extend|defaultsDeep)|deepMerge|deepExtend)\s*\([^)]*(?:req\.|body\.|params\.)",
     "HIGH", "CWE-1321"),
    ("JS-PROTO-BRACKET", "prototype_pollution", "Dynamic property assignment from user input",
     r"\[[^\]]*(?:req\.|body\.|params\.|query\.)[^\]]*\]\s*=", "MEDIUM", "CWE-1321"),
    ("JS-PROTO-CONSTRUCTOR", "prototype_pollution", "Accessing __proto__ or constructor.prototype",
     r"(?:__proto__|constructor\.prototype|Object\.prototype)\s*[\[.]", "HIGH", "CWE-1321"),

    # === EVAL / CODE INJECTION ===
    ("JS-EVAL", "code_injection", "eval() usage",
     r"(?<!\.)eval\s*\(", "HIGH", "CWE-95"),
    ("JS-NEWFUNCTION", "code_injection", "new Function() constructor",
     r"new\s+Function\s*\(", "HIGH", "CWE-95"),
    ("JS-SETINTERVAL-STR", "code_injection", "setTimeout/setInterval with string argument",
     r"(?:setTimeout|setInterval)\s*\(\s*['\"`]", "MEDIUM", "CWE-95"),
    ("JS-VM-RUNIN", "code_injection", "vm.runInNewContext with user input",
     r"vm\.(?:runIn(?:New|This)Context|compileFunction)\s*\(", "HIGH", "CWE-95"),

    # === SSRF ===
    ("JS-SSRF-FETCH", "ssrf", "fetch/axios with user-controlled URL",
     r"(?:fetch|axios\.(?:get|post|put|delete|request))\s*\(\s*(?:req\.|params\.|query\.|body\.|\$\{)",
     "HIGH", "CWE-918"),
    ("JS-SSRF-HTTP", "ssrf", "http.request with user-controlled URL",
     r"(?:http|https)\.(?:request|get)\s*\(\s*(?:req\.|params\.|query\.|\{[^}]*(?:host|hostname|url).*req\.)",
     "HIGH", "CWE-918"),

    # === OPEN REDIRECT ===
    ("JS-REDIR-LOC", "open_redirect", "Open redirect via location assignment",
     r"(?:window\.)?location(?:\.href)?\s*=\s*(?:req\.|params\.|query\.|body\.|\$\{)",
     "MEDIUM", "CWE-601"),
    ("JS-REDIR-RES", "open_redirect", "Express res.redirect with user input",
     r"res\.redirect\s*\(\s*(?:req\.|params\.|query\.|body\.)", "MEDIUM", "CWE-601"),

    # === INSECURE CRYPTO ===
    ("JS-CRYPTO-MD5", "insecure_crypto", "MD5 hash usage (collision-vulnerable)",
     r"(?:createHash|crypto\.(?:subtle\.)?digest)\s*\(\s*['\"]md5['\"]", "MEDIUM", "CWE-328"),
    ("JS-CRYPTO-SHA1", "insecure_crypto", "SHA-1 hash usage (collision-vulnerable)",
     r"(?:createHash|crypto\.(?:subtle\.)?digest)\s*\(\s*['\"]sha1['\"]", "LOW", "CWE-328"),
    ("JS-CRYPTO-RAND", "insecure_crypto", "Math.random() for security-sensitive operation",
     r"Math\.random\s*\(\s*\).*(?:token|secret|password|key|nonce|salt|iv|seed)",
     "HIGH", "CWE-330"),
    ("JS-CRYPTO-DES", "insecure_crypto", "DES/RC4 cipher (weak encryption)",
     r"(?:createCipher|createCipheriv)\s*\(\s*['\"](?:des|rc4|rc2)", "HIGH", "CWE-327"),

    # === ReDoS ===
    ("JS-REDOS-REPEAT", "redos", "Potentially catastrophic regex (nested quantifiers)",
     r"(?:new\s+RegExp|/)\s*.*(?:\+\+|\*\*|\+\*|\*\+|\{\d+,\}\{\d+,\})", "MEDIUM", "CWE-1333"),

    # === SECURITY MISCONFIG ===
    ("JS-CORS-ALL", "misconfiguration", "CORS allowing all origins",
     r"(?:Access-Control-Allow-Origin|cors\s*\(\s*\{[^}]*origin\s*:\s*(?:true|\*|['\"]?\*))",
     "MEDIUM", "CWE-942"),
    ("JS-HELMET-MISSING", "misconfiguration", "Express without helmet (missing security headers)",
     r"app\.(?:use|listen)(?!.*helmet)", "LOW", "CWE-693"),
    ("JS-CSRF-DISABLED", "misconfiguration", "CSRF protection explicitly disabled",
     r"(?:csrf|csurf)\s*\(\s*\{[^}]*cookie\s*:\s*false", "HIGH", "CWE-352"),
    ("JS-COOKIE-NOHTTP", "misconfiguration", "Cookie without httpOnly flag",
     r"(?:cookie|Set-Cookie).*(?!httpOnly|httponly)(?:secure|path|domain|max-?age|expires)",
     "MEDIUM", "CWE-1004"),

    # === INFORMATION DISCLOSURE ===
    ("JS-INFO-STACKTRACE", "information_disclosure", "Stack trace sent to client",
     r"res\.(?:send|json|status\(\d+\)\.send)\s*\(\s*(?:err|error)\.(?:stack|message)",
     "MEDIUM", "CWE-209"),
    ("JS-INFO-CONSOLE", "information_disclosure", "Sensitive data in console.log",
     r"console\.log\s*\(.*(?:password|token|secret|key|credential|apikey)",
     "LOW", "CWE-532"),

    # === DESERIALIZATION ===
    ("JS-DESER-UNSAFE", "deserialization", "Unsafe deserialization (node-serialize/js-yaml)",
     r"(?:unserialize|serialize\.unserialize|yaml\.load\s*\(\s*[^)]*\s*,?\s*\)(?!.*safe))",
     "HIGH", "CWE-502"),
]

_compiled_rules: list[tuple[str, str, str, re.Pattern, str, str]] = []


def _get_rules():
    global _compiled_rules
    if not _compiled_rules:
        _compiled_rules = [
            (rid, cat, desc, re.compile(pat, re.IGNORECASE), sev, cwe)
            for rid, cat, desc, pat, sev, cwe in JS_RULES
        ]
    return _compiled_rules


def scan_file(path: str) -> list[JSFinding]:
    ext = Path(path).suffix.lower()
    if ext not in EXTENSIONS:
        return []
    try:
        size = os.path.getsize(path)
        if size < MIN_FILE_SIZE or size > MAX_FILE_SIZE:
            return []
    except OSError:
        return []
    findings = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("//"):
                    continue
                for rule_id, cat, desc, pattern, severity, cwe in _get_rules():
                    if pattern.search(stripped):
                        findings.append(JSFinding(
                            path=path, line=lineno,
                            rule_id=rule_id, description=desc,
                            severity=severity, category=cat,
                            cwe=cwe,
                        ))
    except (OSError, PermissionError):
        pass
    return findings


def scan_directory(root: str) -> list[JSFinding]:
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if Path(fname).suffix.lower() in EXTENSIONS:
                fpath = os.path.join(dirpath, fname)
                findings.extend(scan_file(fpath))
    return findings


def render(findings: list[JSFinding]) -> str:
    if not findings:
        return "  No JavaScript/TypeScript security issues detected."
    lines = []
    by_cat = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)
    cat_order = [
        "xss", "command_injection", "sql_injection", "code_injection",
        "path_traversal", "prototype_pollution", "ssrf", "open_redirect",
        "insecure_crypto", "redos", "deserialization",
        "misconfiguration", "information_disclosure",
    ]
    for cat in cat_order:
        group = by_cat.pop(cat, [])
        if not group:
            continue
        label = cat.replace("_", " ").title()
        lines.append(f"\n  [{label}] ({len(group)} finding{'s' if len(group) > 1 else ''})")
        for f in sorted(group, key=lambda x: ("CRITICAL", "HIGH", "MEDIUM", "LOW").index(x.severity)):
            cwe = f" ({f.cwe})" if f.cwe else ""
            lines.append(f"    [{f.severity}] {f.path}:{f.line}  {f.rule_id}{cwe}")
            lines.append(f"      {f.description}")
    for cat, group in by_cat.items():
        label = cat.replace("_", " ").title()
        lines.append(f"\n  [{label}] ({len(group)} findings)")
        for f in group:
            lines.append(f"    [{f.severity}] {f.path}:{f.line}  {f.rule_id}")
            lines.append(f"      {f.description}")

    total = len(findings)
    crit = sum(1 for f in findings if f.severity == "CRITICAL")
    lines.append(f"\n  Total: {total} JS/TS issue(s) ({crit} critical)")
    return "\n".join(lines)


def to_dict(findings: list[JSFinding]) -> list[dict]:
    return [
        {
            "path": f.path,
            "line": f.line,
            "rule_id": f.rule_id,
            "description": f.description,
            "severity": f.severity,
            "category": f.category,
            "cwe": f.cwe,
        }
        for f in findings
    ]
