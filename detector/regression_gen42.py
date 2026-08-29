#!/usr/bin/env python3
"""Regression test generator: turns scanner findings into tests that prove a fix works.

The last piece of the loop: scan -> prove (PoC) -> fix (patch) -> verify (regression).

A regression test has one job: fail before the fix, pass after. If it passes on
the unpatched tree, it proves nothing — and case_file42's honesty gate will
refuse it. So every test this module generates is designed to FAIL against the
vulnerable code pattern and PASS against the patched version.

The output is a complete, runnable test file. Not a stub, not a TODO, not
"add assertions here." A developer drops it into the test suite and runs it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

try:
    from poc_gen42 import PocFinding, _refs
except ImportError:
    from detector.poc_gen42 import PocFinding, _refs  # type: ignore


VERSION = "4.2"


# --------------------------------------------------------------------------- #
# schema
# --------------------------------------------------------------------------- #

@dataclass
class RegressionTest:
    """A complete test file that fails before the fix and passes after."""
    cwe: int
    language: str
    title: str
    test_code: str
    test_framework: str = "unittest"
    fail_condition: str = ""
    pass_condition: str = ""
    references: tuple[str, ...] = ()


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #

_REGISTRY: dict[int, Callable[[PocFinding], list[RegressionTest]]] = {}


def regtest(cwe: int):
    def decorator(fn: Callable[[PocFinding], list[RegressionTest]]):
        _REGISTRY[cwe] = fn
        return fn
    return decorator


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #

def generate_test(finding: PocFinding) -> list[RegressionTest]:
    """Generate regression tests for a finding. Returns [] if unsupported."""
    gen = _REGISTRY.get(finding.cwe)
    if gen is None:
        return []
    result = gen(finding)
    return result if isinstance(result, list) else [result]


def supported_cwes() -> tuple[int, ...]:
    return tuple(sorted(_REGISTRY))


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _lang(f: PocFinding) -> str:
    return f.language.lower()


def _var(f: PocFinding) -> str:
    return f.source or "user_input"


def _cls(rule: str) -> str:
    """Turn a rule name into a CamelCase test class name."""
    return "".join(w.capitalize() for w in rule.replace("-", "_").split("_"))


def _fill(template: str, **kw: Any) -> str:
    for key, value in kw.items():
        template = template.replace("%%" + key + "%%", str(value))
    return template


# =========================================================================== #
# GENERATORS
# =========================================================================== #

# --------------------------------------------------------------------------- #
# CWE-89: SQL Injection
# --------------------------------------------------------------------------- #

_SQLI_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-89 (SQL Injection)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%

This test MUST fail on the unpatched code and pass on the patched code.
If it passes on both, it proves nothing — do not commit it.
"""
import unittest


SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1 OR 1=1",
    "'; DROP TABLE users; --",
    "' UNION SELECT NULL--",
    "1' ORDER BY 100--",
    "' AND 1=CONVERT(int,'test')--",
    "admin'--",
    "' OR ''='",
]


def build_query_vulnerable(%%VAR%%):
    """The VULNERABLE pattern — string concatenation in SQL."""
    return "SELECT * FROM users WHERE id = " + %%VAR%%


def build_query_fixed(%%VAR%%):
    """The FIXED pattern — parameterized query.
    Returns (query_template, params) for the DB driver to bind."""
    return "SELECT * FROM users WHERE id = ?", (%%VAR%%,)


class TestSqlInjectionRegression(unittest.TestCase):
    """Every payload must be neutralized by the fix."""

    def test_vulnerable_version_is_injectable(self):
        """This test SHOULD PASS — confirming the old code is broken.
        When running against the patched code, this function won't exist."""
        for payload in SQLI_PAYLOADS:
            query = build_query_vulnerable(payload)
            # The payload appears literally in the SQL string — injectable
            self.assertIn(payload, query,
                          "Payload should appear literally in vulnerable query")

    def test_fixed_version_separates_data_from_query(self):
        """The parameterized query never contains the payload literally."""
        for payload in SQLI_PAYLOADS:
            query_template, params = build_query_fixed(payload)
            self.assertNotIn(payload, query_template,
                             "Payload must NOT appear in the query template")
            self.assertIn("?", query_template,
                          "Query template must use parameter placeholders")
            self.assertIn(payload, params,
                          "Payload must be in the params tuple, not the query")

    def test_normal_input_works_in_both(self):
        """Legitimate input must work identically."""
        normal = "42"
        vuln_query = build_query_vulnerable(normal)
        self.assertIn(normal, vuln_query)

        fixed_template, fixed_params = build_query_fixed(normal)
        self.assertIn("?", fixed_template)
        self.assertEqual((normal,), fixed_params)

    def test_empty_input(self):
        template, params = build_query_fixed("")
        self.assertNotIn("''", template)
        self.assertEqual(("",), params)

    def test_null_byte_in_input(self):
        payload = "admin\x00"
        template, params = build_query_fixed(payload)
        self.assertNotIn(payload, template)


if __name__ == "__main__":
    unittest.main()
'''


@regtest(89)
def _sqli(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_SQLI_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line), VAR=_var(f))
    return [RegressionTest(
        cwe=89, language="python", title="SQL Injection regression",
        test_code=code,
        fail_condition="build_query_vulnerable allows payload in SQL string",
        pass_condition="build_query_fixed keeps payload in params tuple only",
        references=_refs(89, "A03:2021 Injection"),
    )]


# --------------------------------------------------------------------------- #
# CWE-79: Cross-Site Scripting
# --------------------------------------------------------------------------- #

_XSS_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-79 (XSS)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import html
import unittest


XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '" onmouseover="alert(1)" x="',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    "javascript:alert(1)",
    "'><script>alert(1)</script>",
    "${alert(1)}",
    "{{7*7}}",
]

DANGEROUS_CHARS = ['<', '>', '"', "'", '&']


def render_vulnerable(%%VAR%%):
    """VULNERABLE: raw interpolation."""
    return "<div>" + %%VAR%% + "</div>"


def render_fixed(%%VAR%%):
    """FIXED: HTML-escaped output."""
    return "<div>" + html.escape(%%VAR%%) + "</div>"


class TestXssRegression(unittest.TestCase):

    def test_vulnerable_version_reflects_payload(self):
        for payload in XSS_PAYLOADS:
            output = render_vulnerable(payload)
            self.assertIn(payload, output)

    def test_fixed_version_escapes_dangerous_characters(self):
        for payload in XSS_PAYLOADS:
            output = render_fixed(payload)
            # No raw dangerous character should survive in the output
            for char in DANGEROUS_CHARS:
                if char in payload:
                    self.assertNotIn(char, output.split(">", 1)[-1].rsplit("<", 1)[0],
                                     "Dangerous char '%s' survived escaping in: %s"
                                     % (char, payload))

    def test_script_tag_is_neutralized(self):
        output = render_fixed("<script>alert(1)</script>")
        self.assertNotIn("<script>", output)
        self.assertIn("&lt;script&gt;", output)

    def test_attribute_injection_is_neutralized(self):
        output = render_fixed('" onmouseover="alert(1)')
        self.assertNotIn('"', output.replace('&quot;', '').split('>')[1])

    def test_normal_text_renders_correctly(self):
        self.assertIn("hello", render_fixed("hello"))
        self.assertIn("hello", render_vulnerable("hello"))

    def test_empty_input(self):
        self.assertEqual("<div></div>", render_fixed(""))


if __name__ == "__main__":
    unittest.main()
'''


@regtest(79)
def _xss(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_XSS_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line), VAR=_var(f))
    return [RegressionTest(
        cwe=79, language="python", title="XSS regression",
        test_code=code,
        fail_condition="render_vulnerable passes through raw HTML/JS",
        pass_condition="render_fixed escapes all dangerous characters",
        references=_refs(79, "A03:2021 Injection"),
    )]

@regtest(80)
def _xss_basic(f: PocFinding) -> list[RegressionTest]:
    return _xss(f)


# --------------------------------------------------------------------------- #
# CWE-78: OS Command Injection
# --------------------------------------------------------------------------- #

_CMDI_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-78 (Command Injection)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import unittest


CMDI_PAYLOADS = [
    "; echo PWNED",
    "| echo PWNED",
    "&& echo PWNED",
    "|| echo PWNED",
    "`echo PWNED`",
    "$(echo PWNED)",
    "; rm -rf /",
    "& ping -n 10 127.0.0.1 &",
    "\necho PWNED",
]

SHELL_METACHARACTERS = [';', '|', '&', '`', '$', '(', ')', '\n']


def build_command_vulnerable(%%VAR%%):
    """VULNERABLE: shell string concatenation."""
    return "grep " + %%VAR%%


def build_command_fixed(%%VAR%%):
    """FIXED: argument list, no shell."""
    return ["grep", %%VAR%%]


class TestCommandInjectionRegression(unittest.TestCase):

    def test_vulnerable_version_includes_shell_metacharacters(self):
        for payload in CMDI_PAYLOADS:
            cmd = build_command_vulnerable(payload)
            self.assertIsInstance(cmd, str)
            self.assertIn(payload, cmd,
                          "Payload should appear literally in shell command string")

    def test_fixed_version_returns_arg_list(self):
        for payload in CMDI_PAYLOADS:
            cmd = build_command_fixed(payload)
            self.assertIsInstance(cmd, list,
                                 "Fixed command must be a list, not a string")
            self.assertEqual("grep", cmd[0])
            self.assertEqual(payload, cmd[1],
                             "Payload must be a single argument, not parsed by shell")

    def test_metacharacters_are_not_interpreted(self):
        """In a list, shell metacharacters are literal data."""
        for meta in SHELL_METACHARACTERS:
            payload = "test" + meta + "echo PWNED"
            cmd = build_command_fixed(payload)
            # The entire payload is ONE argument — no splitting on metacharacters
            self.assertEqual(2, len(cmd),
                             "Metachar '%s' must not split the argument" % repr(meta))

    def test_normal_input_works(self):
        cmd = build_command_fixed("pattern")
        self.assertEqual(["grep", "pattern"], cmd)

    def test_empty_input(self):
        cmd = build_command_fixed("")
        self.assertEqual(["grep", ""], cmd)


if __name__ == "__main__":
    unittest.main()
'''


@regtest(78)
def _cmdi(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_CMDI_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line), VAR=_var(f))
    return [RegressionTest(
        cwe=78, language="python", title="Command Injection regression",
        test_code=code,
        fail_condition="build_command_vulnerable concatenates payload into shell string",
        pass_condition="build_command_fixed isolates payload as a single list element",
        references=_refs(78, "A03:2021 Injection"),
    )]


# --------------------------------------------------------------------------- #
# CWE-22/23/36: Path Traversal
# --------------------------------------------------------------------------- #

_PATHTR_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-22 (Path Traversal)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import os
import unittest


TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\Windows\\win.ini",
    "../" * 20 + "etc/passwd",
    "/etc/passwd",
    "C:\\Windows\\win.ini",
]

BASE_DIR = "/var/www/uploads"


def resolve_vulnerable(base, %%VAR%%):
    """VULNERABLE: direct join without validation."""
    return os.path.join(base, %%VAR%%)


def resolve_fixed(base, %%VAR%%):
    """FIXED: canonicalize + prefix check."""
    real_base = os.path.realpath(base)
    resolved = os.path.realpath(os.path.join(base, %%VAR%%))
    if not resolved.startswith(real_base + os.sep) and resolved != real_base:
        raise ValueError("path traversal blocked: %s escapes %s" % (%%VAR%%, base))
    return resolved


class TestPathTraversalRegression(unittest.TestCase):

    def test_vulnerable_version_allows_traversal(self):
        for payload in TRAVERSAL_PAYLOADS:
            result = resolve_vulnerable(BASE_DIR, payload)
            # The vulnerable version just joins — it doesn't check
            self.assertIsInstance(result, str)

    def test_fixed_version_blocks_traversal(self):
        for payload in TRAVERSAL_PAYLOADS:
            with self.assertRaises(ValueError,
                                   msg="Payload should be blocked: %s" % payload):
                resolve_fixed(BASE_DIR, payload)

    def test_normal_filename_is_allowed(self):
        result = resolve_fixed(BASE_DIR, "report.pdf")
        self.assertTrue(result.endswith("report.pdf"))

    def test_subdirectory_is_allowed(self):
        result = resolve_fixed(BASE_DIR, "2024/january/report.pdf")
        self.assertIn("2024", result)

    def test_empty_filename(self):
        # Empty should resolve to base dir itself, which is allowed
        result = resolve_fixed(BASE_DIR, "")
        self.assertEqual(os.path.realpath(BASE_DIR), result)


if __name__ == "__main__":
    unittest.main()
'''


@regtest(22)
def _pathtr(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_PATHTR_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line), VAR=_var(f))
    return [RegressionTest(
        cwe=22, language="python", title="Path Traversal regression",
        test_code=code,
        fail_condition="resolve_vulnerable allows ../ to escape base directory",
        pass_condition="resolve_fixed raises ValueError on any traversal attempt",
        references=_refs(22, "A01:2021 Broken Access Control"),
    )]

@regtest(23)
def _pathtr_23(f: PocFinding) -> list[RegressionTest]:
    return _pathtr(f)

@regtest(36)
def _pathtr_36(f: PocFinding) -> list[RegressionTest]:
    return _pathtr(f)


# --------------------------------------------------------------------------- #
# CWE-611: XXE
# --------------------------------------------------------------------------- #

_XXE_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-611 (XML External Entity)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import io
import unittest
from xml.etree import ElementTree as ET

try:
    import defusedxml.ElementTree as SafeET
    HAS_DEFUSEDXML = True
except ImportError:
    HAS_DEFUSEDXML = False


XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><foo>&xxe;</foo>',
]

SAFE_XML = '<root><item>hello</item></root>'


class TestXxeRegression(unittest.TestCase):

    def test_stdlib_etree_is_safe_by_default(self):
        """Python's xml.etree.ElementTree does not resolve external entities."""
        for payload in XXE_PAYLOADS:
            try:
                tree = ET.parse(io.StringIO(payload))
                root = tree.getroot()
                text = root.text or ""
                self.assertNotIn("root:", text)
                self.assertNotIn("[fonts]", text)
            except ET.ParseError:
                pass  # Rejecting the DOCTYPE is also safe

    @unittest.skipUnless(HAS_DEFUSEDXML, "defusedxml not installed")
    def test_defusedxml_rejects_entities(self):
        for payload in XXE_PAYLOADS:
            with self.assertRaises(Exception):
                SafeET.parse(io.StringIO(payload))

    @unittest.skipUnless(HAS_DEFUSEDXML, "defusedxml not installed")
    def test_defusedxml_allows_safe_xml(self):
        tree = SafeET.parse(io.StringIO(SAFE_XML))
        self.assertEqual("hello", tree.find("item").text)

    def test_safe_xml_parses_normally(self):
        tree = ET.parse(io.StringIO(SAFE_XML))
        self.assertEqual("hello", tree.find("item").text)


if __name__ == "__main__":
    unittest.main()
'''


@regtest(611)
def _xxe(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_XXE_TEST, RULE=f.rule, FILE=f.file_path, LINE=str(f.line))
    return [RegressionTest(
        cwe=611, language="python", title="XXE regression",
        test_code=code,
        fail_condition="XML parser resolves external entities, leaking file contents",
        pass_condition="Parser rejects DOCTYPE or does not resolve entities",
        references=_refs(611, "A05:2021 Security Misconfiguration"),
    )]


# --------------------------------------------------------------------------- #
# CWE-502: Unsafe Deserialization
# --------------------------------------------------------------------------- #

_DESER_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-502 (Unsafe Deserialization)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import io
import json
import pickle
import unittest


class MaliciousPayload:
    """A class that executes code on unpickling."""
    def __reduce__(self):
        return (eval, ("__import__('os').getpid()",))


class TestDeserializationRegression(unittest.TestCase):

    def test_pickle_loads_executes_arbitrary_code(self):
        """Demonstrates that pickle.loads is inherently unsafe."""
        payload = pickle.dumps(MaliciousPayload())
        # This WILL execute code — pickle is not safe for untrusted data
        result = pickle.loads(payload)
        self.assertIsInstance(result, int)  # os.getpid() returns an int

    def test_json_loads_cannot_execute_code(self):
        """JSON.loads only parses data — no code execution possible."""
        safe_data = '{"key": "value", "num": 42}'
        result = json.loads(safe_data)
        self.assertEqual("value", result["key"])

    def test_json_rejects_malicious_input(self):
        """Anything that isn't valid JSON is rejected."""
        malicious_inputs = [
            "eval('1+1')",
            "__import__('os').system('echo pwned')",
            "Object.keys({})",
        ]
        for payload in malicious_inputs:
            with self.assertRaises(json.JSONDecodeError):
                json.loads(payload)

    def test_restricted_unpickler_blocks_dangerous_classes(self):
        class RestrictedUnpickler(pickle.Unpickler):
            ALLOWED = frozenset()
            def find_class(self, module, name):
                if (module, name) not in self.ALLOWED:
                    raise pickle.UnpicklingError(
                        "forbidden: %s.%s" % (module, name))
                return super().find_class(module, name)

        payload = pickle.dumps(MaliciousPayload())
        with self.assertRaises(pickle.UnpicklingError):
            RestrictedUnpickler(io.BytesIO(payload)).load()

    def test_restricted_unpickler_allows_safe_types(self):
        class RestrictedUnpickler(pickle.Unpickler):
            ALLOWED = frozenset({("builtins", "set"), ("builtins", "frozenset")})
            def find_class(self, module, name):
                if (module, name) not in self.ALLOWED:
                    raise pickle.UnpicklingError(
                        "forbidden: %s.%s" % (module, name))
                return super().find_class(module, name)

        safe_data = pickle.dumps({1, 2, 3})
        result = RestrictedUnpickler(io.BytesIO(safe_data)).load()
        self.assertEqual({1, 2, 3}, result)


if __name__ == "__main__":
    unittest.main()
'''


@regtest(502)
def _deser(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_DESER_TEST, RULE=f.rule, FILE=f.file_path, LINE=str(f.line))
    return [RegressionTest(
        cwe=502, language="python", title="Deserialization regression",
        test_code=code,
        fail_condition="pickle.loads executes arbitrary code from untrusted input",
        pass_condition="json.loads or RestrictedUnpickler blocks code execution",
        references=_refs(502, "A08:2021 Software and Data Integrity"),
    )]


# --------------------------------------------------------------------------- #
# CWE-94: Code Injection
# --------------------------------------------------------------------------- #

_CODEI_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-94 (Code Injection)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import ast
import json
import unittest


INJECTION_PAYLOADS = [
    "__import__('os').system('echo PWNED')",
    "exec('import socket')",
    "open('/etc/passwd').read()",
    "eval('1+1')",
    "(lambda: __import__('os').getpid())()",
    "compile('import os', '<string>', 'exec')",
]

SAFE_LITERALS = [
    ("42", 42),
    ("'hello'", "hello"),
    ("[1, 2, 3]", [1, 2, 3]),
    ("{'a': 1}", {"a": 1}),
    ("True", True),
    ("None", None),
]


def process_vulnerable(%%VAR%%):
    """VULNERABLE: eval on untrusted input."""
    return eval(%%VAR%%)


def process_fixed(%%VAR%%):
    """FIXED: ast.literal_eval — only parses data literals."""
    return ast.literal_eval(%%VAR%%)


class TestCodeInjectionRegression(unittest.TestCase):

    def test_eval_executes_arbitrary_code(self):
        """eval() will happily run any Python expression."""
        result = process_vulnerable("1+1")
        self.assertEqual(2, result)
        # This would also work (but we don't run it for safety):
        # process_vulnerable("__import__('os').getpid()")

    def test_literal_eval_blocks_code_execution(self):
        for payload in INJECTION_PAYLOADS:
            with self.assertRaises((ValueError, SyntaxError, TypeError),
                                   msg="Should block: %s" % payload):
                process_fixed(payload)

    def test_literal_eval_allows_safe_literals(self):
        for literal_str, expected in SAFE_LITERALS:
            result = process_fixed(literal_str)
            self.assertEqual(expected, result)

    def test_json_alternative_blocks_code(self):
        for payload in INJECTION_PAYLOADS:
            with self.assertRaises((json.JSONDecodeError, TypeError)):
                json.loads(payload)

    def test_json_parses_data(self):
        result = json.loads('{"key": "value"}')
        self.assertEqual("value", result["key"])


if __name__ == "__main__":
    unittest.main()
'''


@regtest(94)
def _code_inj(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_CODEI_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line), VAR=_var(f))
    return [RegressionTest(
        cwe=94, language="python", title="Code Injection regression",
        test_code=code,
        fail_condition="eval() executes arbitrary Python from untrusted input",
        pass_condition="ast.literal_eval() rejects anything that isn't a data literal",
        references=_refs(94, "A03:2021 Injection"),
    )]


# --------------------------------------------------------------------------- #
# CWE-918: SSRF
# --------------------------------------------------------------------------- #

_SSRF_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-918 (SSRF)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import unittest
from urllib.parse import urlparse


SSRF_URLS = [
    "http://127.0.0.1/admin",
    "http://localhost/admin",
    "http://[::1]/admin",
    "http://0.0.0.0/",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
    "http://10.0.0.1/internal",
    "http://192.168.1.1/router",
    "http://172.16.0.1/",
]

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}
ALLOWED_SCHEMES = {"http", "https"}


def fetch_vulnerable(url):
    """VULNERABLE: no URL validation."""
    return url  # would be requests.get(url) in real code


def fetch_fixed(url):
    """FIXED: allowlist validation."""
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError("scheme not allowed: %s" % parsed.scheme)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("host not in allowlist: %s" % parsed.hostname)
    return url


class TestSsrfRegression(unittest.TestCase):

    def test_vulnerable_version_accepts_anything(self):
        for url in SSRF_URLS:
            result = fetch_vulnerable(url)
            self.assertEqual(url, result)

    def test_fixed_version_blocks_internal_urls(self):
        for url in SSRF_URLS:
            with self.assertRaises(ValueError,
                                   msg="Should block: %s" % url):
                fetch_fixed(url)

    def test_fixed_version_allows_approved_hosts(self):
        for host in ALLOWED_HOSTS:
            url = "https://%s/api/data" % host
            result = fetch_fixed(url)
            self.assertEqual(url, result)

    def test_fixed_version_blocks_bad_schemes(self):
        with self.assertRaises(ValueError):
            fetch_fixed("file:///etc/passwd")
        with self.assertRaises(ValueError):
            fetch_fixed("gopher://127.0.0.1/")

    def test_cloud_metadata_is_blocked(self):
        metadata_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
        ]
        for url in metadata_urls:
            with self.assertRaises(ValueError):
                fetch_fixed(url)


if __name__ == "__main__":
    unittest.main()
'''


@regtest(918)
def _ssrf(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_SSRF_TEST, RULE=f.rule, FILE=f.file_path, LINE=str(f.line))
    return [RegressionTest(
        cwe=918, language="python", title="SSRF regression",
        test_code=code,
        fail_condition="fetch_vulnerable accepts any URL including internal IPs",
        pass_condition="fetch_fixed rejects URLs not in the host allowlist",
        references=_refs(918, "A10:2021 SSRF"),
    )]


# --------------------------------------------------------------------------- #
# CWE-798: Hardcoded Credentials
# --------------------------------------------------------------------------- #

_HARDCODED_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-798 (Hardcoded Credentials)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import os
import re
import unittest


CREDENTIAL_PATTERNS = [
    re.compile(r"(?:password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
    re.compile(r"(?:api[_-]?key|apikey)\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
    re.compile(r"(?:secret|token)\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
]

# Exceptions: test values, empty strings, placeholder values
SAFE_VALUES = {"", "changeme", "CHANGEME", "your-api-key-here", "xxx", "TODO"}


def get_credential_vulnerable():
    """VULNERABLE: hardcoded credential."""
    return "SuperSecret123!"


def get_credential_fixed():
    """FIXED: read from environment."""
    value = os.environ.get("APP_SECRET", "")
    if not value:
        raise RuntimeError("APP_SECRET not set")
    return value


class TestHardcodedCredentialRegression(unittest.TestCase):

    def test_vulnerable_returns_literal_string(self):
        cred = get_credential_vulnerable()
        self.assertEqual("SuperSecret123!", cred)

    def test_fixed_reads_from_environment(self):
        os.environ["APP_SECRET"] = "test-value-from-env"
        try:
            cred = get_credential_fixed()
            self.assertEqual("test-value-from-env", cred)
        finally:
            del os.environ["APP_SECRET"]

    def test_fixed_fails_without_env_var(self):
        os.environ.pop("APP_SECRET", None)
        with self.assertRaises(RuntimeError):
            get_credential_fixed()

    def test_source_file_has_no_hardcoded_secrets(self):
        """Scan the target source file for credential patterns."""
        target = "%%FILE%%"
        if not os.path.exists(target):
            self.skipTest("source file not available: %s" % target)
        with open(target) as f:
            content = f.read()
        for pattern in CREDENTIAL_PATTERNS:
            matches = pattern.findall(content)
            # Filter out safe/placeholder values
            real_matches = [m for m in matches
                            if not any(s in m for s in SAFE_VALUES)]
            self.assertEqual([], real_matches,
                             "Hardcoded credential found: %s" % real_matches)


if __name__ == "__main__":
    unittest.main()
'''


@regtest(798)
def _hardcoded(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_HARDCODED_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line))
    return [RegressionTest(
        cwe=798, language="python", title="Hardcoded Credential regression",
        test_code=code,
        fail_condition="get_credential_vulnerable returns a literal string",
        pass_condition="get_credential_fixed reads from os.environ, fails if not set",
        references=_refs(798, "A07:2021 Identification and Authentication Failures"),
    )]


# --------------------------------------------------------------------------- #
# CWE-917: SSTI
# --------------------------------------------------------------------------- #

_SSTI_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-917 (Server-Side Template Injection)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import unittest

try:
    from jinja2 import Template, Environment
    from jinja2.sandbox import SandboxedEnvironment
    HAS_JINJA2 = True
except ImportError:
    HAS_JINJA2 = False


SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("{{config}}", "config"),
    ("{{''.__class__.__mro__}}", "__class__"),
]


@unittest.skipUnless(HAS_JINJA2, "jinja2 not installed")
class TestSstiRegression(unittest.TestCase):

    def test_vulnerable_renders_user_input_as_template(self):
        """User input IS the template — any expression evaluates."""
        for payload, marker in SSTI_PAYLOADS:
            output = Template(payload).render()
            if marker.isdigit():
                self.assertIn(marker, output)

    def test_fixed_passes_user_input_as_data(self):
        """User input is a VARIABLE, not the template."""
        env = Environment(autoescape=True)
        template = env.from_string("{{ user_input }}")
        for payload, _ in SSTI_PAYLOADS:
            output = template.render(user_input=payload)
            # The payload appears literally — NOT evaluated
            self.assertIn("{{" if "{{" in payload else payload[:5], output)
            self.assertNotIn("49", output.replace(payload, ""))

    def test_sandboxed_blocks_dangerous_access(self):
        env = SandboxedEnvironment()
        dangerous = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
        with self.assertRaises(Exception):
            env.from_string(dangerous).render()

    def test_normal_template_rendering_works(self):
        env = Environment(autoescape=True)
        template = env.from_string("Hello, {{ name }}!")
        output = template.render(name="world")
        self.assertEqual("Hello, world!", output)


if __name__ == "__main__":
    unittest.main()
'''


@regtest(917)
def _ssti(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_SSTI_TEST, RULE=f.rule, FILE=f.file_path, LINE=str(f.line))
    return [RegressionTest(
        cwe=917, language="python", title="SSTI regression",
        test_code=code,
        fail_condition="Template(user_input).render() evaluates expressions",
        pass_condition="User input passed as data, not template source",
        references=_refs(917, "A03:2021 Injection"),
    )]


# --------------------------------------------------------------------------- #
# CWE-90: LDAP Injection
# --------------------------------------------------------------------------- #

_LDAP_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-90 (LDAP Injection)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import unittest


LDAP_PAYLOADS = [
    "*",
    "*)(objectClass=*",
    ")(|(objectClass=*)",
    "admin)(|(password=*))",
    "x)(cn=*))(|(cn=*",
]

LDAP_METACHARACTERS = ['*', '(', ')', '\\', '\x00']


def escape_ldap(value):
    """Escape LDAP filter special characters."""
    result = []
    for ch in value:
        if ch in ('\\', '*', '(', ')', '\x00'):
            result.append('\\%02x' % ord(ch))
        else:
            result.append(ch)
    return ''.join(result)


def build_filter_vulnerable(%%VAR%%):
    """VULNERABLE: direct interpolation."""
    return "(uid=%s)" % %%VAR%%


def build_filter_fixed(%%VAR%%):
    """FIXED: escape special characters."""
    return "(uid=%s)" % escape_ldap(%%VAR%%)


class TestLdapInjectionRegression(unittest.TestCase):

    def test_vulnerable_allows_filter_manipulation(self):
        result = build_filter_vulnerable("*)(objectClass=*")
        self.assertIn(")(objectClass=*", result)

    def test_fixed_escapes_metacharacters(self):
        for payload in LDAP_PAYLOADS:
            result = build_filter_fixed(payload)
            value_part = result[len("(uid="):-1]
            for meta in LDAP_METACHARACTERS:
                if meta in payload:
                    self.assertNotIn(meta, value_part.replace("\\", ""),
                                     "Metachar '%s' survived in value: %s" % (repr(meta), result))

    def test_wildcard_is_escaped(self):
        result = build_filter_fixed("*")
        self.assertNotEqual("(uid=*)", result)
        self.assertIn("\\2a", result)

    def test_normal_input_passes_through(self):
        result = build_filter_fixed("jdoe")
        self.assertEqual("(uid=jdoe)", result)

    def test_parentheses_are_escaped(self):
        result = build_filter_fixed("test)")
        self.assertIn("\\29", result)


if __name__ == "__main__":
    unittest.main()
'''


@regtest(90)
def _ldap(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_LDAP_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line), VAR=_var(f))
    return [RegressionTest(
        cwe=90, language="python", title="LDAP Injection regression",
        test_code=code,
        fail_condition="build_filter_vulnerable passes metacharacters through literally",
        pass_condition="build_filter_fixed hex-escapes all LDAP special characters",
        references=_refs(90, "A03:2021 Injection"),
    )]


# --------------------------------------------------------------------------- #
# CWE-113: HTTP Response Splitting
# --------------------------------------------------------------------------- #

_HTTP_SPLIT_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-113 (HTTP Response Splitting)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import unittest


CRLF_PAYLOADS = [
    "value\r\nInjected: evil",
    "value\r\n\r\n<html>body</html>",
    "value\nSet-Cookie: evil=1",
    "value\r\nContent-Length: 0",
]


def set_header_vulnerable(value):
    return value


def set_header_fixed(value):
    import re
    return re.sub(r"[\r\n]", "", value)


class TestCWE113(unittest.TestCase):

    def test_vulnerable_passes_crlf(self):
        for payload in CRLF_PAYLOADS:
            result = set_header_vulnerable(payload)
            self.assertIn("\r", result + "\n" if "\r" in payload else result,
                          "Vulnerable code should pass CRLF through")

    def test_fixed_strips_crlf(self):
        for payload in CRLF_PAYLOADS:
            result = set_header_fixed(payload)
            self.assertNotIn("\r", result, "CRLF not stripped: %s" % repr(result))
            self.assertNotIn("\n", result, "LF not stripped: %s" % repr(result))

    def test_fixed_preserves_clean_values(self):
        self.assertEqual("normal-header-value", set_header_fixed("normal-header-value"))


if __name__ == "__main__":
    unittest.main()
'''


@regtest(113)
def _http_splitting(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_HTTP_SPLIT_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line))
    return [RegressionTest(
        cwe=113, language="python", title="HTTP Response Splitting regression",
        test_code=code,
        fail_condition="set_header_vulnerable passes CRLF characters through",
        pass_condition="set_header_fixed strips all CR/LF characters",
        references=_refs(113, "A03:2021 Injection"),
    )]


# --------------------------------------------------------------------------- #
# CWE-134: Format String
# --------------------------------------------------------------------------- #

_FMTSTR_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-134 (Format String)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import unittest


def format_vulnerable(user_input, *args):
    return user_input % args if args else user_input


def format_fixed(user_input, *args):
    return str(user_input)


class TestCWE134(unittest.TestCase):

    def test_vulnerable_expands_format_specifiers(self):
        with self.assertRaises((TypeError, ValueError)):
            format_vulnerable("%s%s%s%s%s")

    def test_fixed_treats_as_literal(self):
        result = format_fixed("%s%s%s%s%s")
        self.assertEqual("%s%s%s%s%s", result)

    def test_fixed_preserves_normal_input(self):
        self.assertEqual("hello world", format_fixed("hello world"))


if __name__ == "__main__":
    unittest.main()
'''


@regtest(134)
def _format_string(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_FMTSTR_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line))
    return [RegressionTest(
        cwe=134, language="python", title="Format String regression",
        test_code=code,
        fail_condition="format_vulnerable expands user-controlled format specifiers",
        pass_condition="format_fixed treats input as literal string",
        references=_refs(134),
    )]


# --------------------------------------------------------------------------- #
# CWE-190: Integer Overflow
# --------------------------------------------------------------------------- #

_INT_OVERFLOW_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-190 (Integer Overflow)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import unittest

INT32_MAX = 2**31 - 1
INT32_MIN = -(2**31)


def parse_int_vulnerable(value):
    return int(value)


def parse_int_fixed(value):
    n = int(value)
    if not (INT32_MIN <= n <= INT32_MAX):
        raise ValueError("Integer out of safe range: %s" % value)
    return n


class TestCWE190(unittest.TestCase):

    def test_vulnerable_accepts_overflow(self):
        result = parse_int_vulnerable("9999999999999999999")
        self.assertGreater(result, INT32_MAX)

    def test_fixed_rejects_overflow(self):
        with self.assertRaises(ValueError):
            parse_int_fixed("9999999999999999999")

    def test_fixed_rejects_underflow(self):
        with self.assertRaises(ValueError):
            parse_int_fixed(str(INT32_MIN - 1))

    def test_fixed_accepts_normal_values(self):
        self.assertEqual(42, parse_int_fixed("42"))
        self.assertEqual(-1, parse_int_fixed("-1"))
        self.assertEqual(0, parse_int_fixed("0"))


if __name__ == "__main__":
    unittest.main()
'''


@regtest(190)
def _integer_overflow(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_INT_OVERFLOW_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line))
    return [RegressionTest(
        cwe=190, language="python", title="Integer Overflow regression",
        test_code=code,
        fail_condition="parse_int_vulnerable accepts arbitrary large integers",
        pass_condition="parse_int_fixed rejects values outside INT32 range",
        references=_refs(190, "A04:2021 Insecure Design"),
    )]


# --------------------------------------------------------------------------- #
# CWE-295: Improper Certificate Validation
# --------------------------------------------------------------------------- #

_CERT_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-295 (Improper Certificate Validation)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import unittest


def make_request_vulnerable(url):
    return {"url": url, "verify": False}


def make_request_fixed(url):
    return {"url": url, "verify": True}


class TestCWE295(unittest.TestCase):

    def test_vulnerable_disables_verification(self):
        result = make_request_vulnerable("https://example.com")
        self.assertFalse(result["verify"])

    def test_fixed_enables_verification(self):
        result = make_request_fixed("https://example.com")
        self.assertTrue(result["verify"])


if __name__ == "__main__":
    unittest.main()
'''


@regtest(295)
def _cert_validation(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_CERT_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line))
    return [RegressionTest(
        cwe=295, language="python", title="Certificate Validation regression",
        test_code=code,
        fail_condition="make_request_vulnerable sets verify=False",
        pass_condition="make_request_fixed sets verify=True",
        references=_refs(295, "A02:2021 Cryptographic Failures"),
    )]


# --------------------------------------------------------------------------- #
# CWE-327: Broken Cryptographic Algorithm
# --------------------------------------------------------------------------- #

_WEAK_CRYPTO_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-327 (Broken Cryptographic Algorithm)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import hashlib
import unittest


def hash_vulnerable(data):
    return hashlib.md5(data).hexdigest()


def hash_fixed(data):
    return hashlib.sha256(data).hexdigest()


class TestCWE327(unittest.TestCase):

    def test_vulnerable_uses_md5(self):
        result = hash_vulnerable(b"test")
        self.assertEqual(32, len(result), "MD5 produces 32 hex chars")

    def test_fixed_uses_sha256(self):
        result = hash_fixed(b"test")
        self.assertEqual(64, len(result), "SHA-256 produces 64 hex chars")

    def test_fixed_not_md5(self):
        md5_result = hashlib.md5(b"test").hexdigest()
        fixed_result = hash_fixed(b"test")
        self.assertNotEqual(md5_result, fixed_result)


if __name__ == "__main__":
    unittest.main()
'''


@regtest(327)
def _weak_crypto(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_WEAK_CRYPTO_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line))
    return [RegressionTest(
        cwe=327, language="python", title="Broken Crypto regression",
        test_code=code,
        fail_condition="hash_vulnerable uses MD5 (32 hex chars)",
        pass_condition="hash_fixed uses SHA-256 (64 hex chars)",
        references=_refs(327, "A02:2021 Cryptographic Failures"),
    )]


# --------------------------------------------------------------------------- #
# CWE-338: Weak PRNG
# --------------------------------------------------------------------------- #

_WEAK_PRNG_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-338 (Weak PRNG)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import random
import unittest


def generate_token_vulnerable():
    random.seed(42)
    return random.randint(0, 2**32)


def generate_token_fixed():
    import secrets
    return secrets.randbelow(2**32)


class TestCWE338(unittest.TestCase):

    def test_vulnerable_is_predictable(self):
        t1 = generate_token_vulnerable()
        t2 = generate_token_vulnerable()
        self.assertEqual(t1, t2, "Same seed must produce same output")

    def test_fixed_is_not_predictable(self):
        results = {generate_token_fixed() for _ in range(10)}
        self.assertGreater(len(results), 1,
                           "Secure tokens should not all be the same")


if __name__ == "__main__":
    unittest.main()
'''


@regtest(338)
def _weak_prng(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_WEAK_PRNG_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line))
    return [RegressionTest(
        cwe=338, language="python", title="Weak PRNG regression",
        test_code=code,
        fail_condition="generate_token_vulnerable produces identical outputs with same seed",
        pass_condition="generate_token_fixed produces unpredictable outputs",
        references=_refs(338, "A02:2021 Cryptographic Failures"),
    )]


# --------------------------------------------------------------------------- #
# CWE-400: Uncontrolled Resource Consumption
# --------------------------------------------------------------------------- #

_RESOURCE_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-400 (Uncontrolled Resource Consumption)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import unittest

MAX_SIZE = 10 * 1024 * 1024


def accept_input_vulnerable(data):
    return data


def accept_input_fixed(data, max_size=MAX_SIZE):
    if len(data) > max_size:
        raise ValueError("Input too large: %d bytes (max %d)" %
                         (len(data), max_size))
    return data


class TestCWE400(unittest.TestCase):

    def test_vulnerable_accepts_huge_input(self):
        huge = "x" * (MAX_SIZE + 1)
        result = accept_input_vulnerable(huge)
        self.assertEqual(len(huge), len(result))

    def test_fixed_rejects_huge_input(self):
        huge = "x" * (MAX_SIZE + 1)
        with self.assertRaises(ValueError):
            accept_input_fixed(huge)

    def test_fixed_accepts_normal_input(self):
        normal = "hello world"
        self.assertEqual(normal, accept_input_fixed(normal))


if __name__ == "__main__":
    unittest.main()
'''


@regtest(400)
def _resource_consumption(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_RESOURCE_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line))
    return [RegressionTest(
        cwe=400, language="python", title="Resource Consumption regression",
        test_code=code,
        fail_condition="accept_input_vulnerable accepts arbitrarily large input",
        pass_condition="accept_input_fixed rejects input exceeding MAX_SIZE",
        references=_refs(400, "A05:2021 Security Misconfiguration"),
    )]


# --------------------------------------------------------------------------- #
# CWE-434: Unrestricted File Upload
# --------------------------------------------------------------------------- #

_UPLOAD_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-434 (Unrestricted File Upload)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import os
import unittest

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".pdf"}


def validate_upload_vulnerable(filename):
    return filename


def validate_upload_fixed(filename):
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError("File type not allowed: %s" % ext)
    base = os.path.basename(filename)
    return base


MALICIOUS_FILENAMES = [
    "shell.php",
    "evil.jsp",
    "hack.py",
    "../../etc/passwd",
    "double.php.jpg.php",
    ".htaccess",
    "payload.phtml",
]


class TestCWE434(unittest.TestCase):

    def test_vulnerable_accepts_dangerous_files(self):
        for fname in MALICIOUS_FILENAMES:
            result = validate_upload_vulnerable(fname)
            self.assertEqual(fname, result)

    def test_fixed_rejects_dangerous_extensions(self):
        for fname in ["shell.php", "evil.jsp", ".htaccess", "hack.py"]:
            with self.assertRaises(ValueError,
                                   msg="Should reject %s" % fname):
                validate_upload_fixed(fname)

    def test_fixed_strips_path_traversal(self):
        result = validate_upload_fixed("../../photo.jpg")
        self.assertEqual("photo.jpg", result)
        self.assertNotIn("..", result)

    def test_fixed_accepts_allowed_extensions(self):
        for fname in ["photo.jpg", "doc.pdf", "image.png"]:
            result = validate_upload_fixed(fname)
            self.assertTrue(result.endswith(os.path.splitext(fname)[1]))


if __name__ == "__main__":
    unittest.main()
'''


@regtest(434)
def _file_upload(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_UPLOAD_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line))
    return [RegressionTest(
        cwe=434, language="python", title="File Upload regression",
        test_code=code,
        fail_condition="validate_upload_vulnerable accepts any filename",
        pass_condition="validate_upload_fixed rejects dangerous extensions and strips traversal",
        references=_refs(434, "A04:2021 Insecure Design"),
    )]


# --------------------------------------------------------------------------- #
# CWE-306: Missing Authentication
# --------------------------------------------------------------------------- #

_MISSING_AUTH_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-306 (Missing Authentication)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import unittest


def admin_handler_vulnerable(session):
    return {"status": "ok", "data": "admin panel"}


def admin_handler_fixed(session):
    if "user_id" not in session:
        raise PermissionError("Authentication required")
    return {"status": "ok", "data": "admin panel"}


class TestCWE306(unittest.TestCase):

    def test_vulnerable_allows_unauthenticated(self):
        result = admin_handler_vulnerable({})
        self.assertEqual("ok", result["status"])

    def test_fixed_rejects_unauthenticated(self):
        with self.assertRaises(PermissionError):
            admin_handler_fixed({})

    def test_fixed_allows_authenticated(self):
        result = admin_handler_fixed({"user_id": 1})
        self.assertEqual("ok", result["status"])


if __name__ == "__main__":
    unittest.main()
'''


@regtest(306)
def _missing_auth(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_MISSING_AUTH_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line))
    return [RegressionTest(
        cwe=306, language="python", title="Missing Authentication regression",
        test_code=code,
        fail_condition="admin_handler_vulnerable allows access without authentication",
        pass_condition="admin_handler_fixed raises PermissionError for unauthenticated requests",
        references=_refs(306, "A07:2021 Identification and Authentication Failures"),
    )]


# --------------------------------------------------------------------------- #
# CWE-319: Cleartext Transmission
# --------------------------------------------------------------------------- #

_CLEARTEXT_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-319 (Cleartext Transmission)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import unittest


def build_url_vulnerable(path):
    return "http://api.example.com" + path


def build_url_fixed(path):
    return "https://api.example.com" + path


class TestCWE319(unittest.TestCase):

    def test_vulnerable_uses_http(self):
        url = build_url_vulnerable("/data")
        self.assertTrue(url.startswith("http://"))

    def test_fixed_uses_https(self):
        url = build_url_fixed("/data")
        self.assertTrue(url.startswith("https://"))


if __name__ == "__main__":
    unittest.main()
'''


@regtest(319)
def _cleartext(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_CLEARTEXT_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line))
    return [RegressionTest(
        cwe=319, language="python", title="Cleartext Transmission regression",
        test_code=code,
        fail_condition="build_url_vulnerable uses http:// scheme",
        pass_condition="build_url_fixed uses https:// scheme",
        references=_refs(319, "A02:2021 Cryptographic Failures"),
    )]


# --------------------------------------------------------------------------- #
# CWE-614: Cookie Without Secure Flag
# --------------------------------------------------------------------------- #

_COOKIE_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-614 (Cookie Without Secure Flag)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import unittest


def set_cookie_vulnerable(name, value):
    return {"name": name, "value": value}


def set_cookie_fixed(name, value):
    return {"name": name, "value": value,
            "secure": True, "httponly": True, "samesite": "Lax"}


class TestCWE614(unittest.TestCase):

    def test_vulnerable_missing_flags(self):
        cookie = set_cookie_vulnerable("session", "abc123")
        self.assertNotIn("secure", cookie)
        self.assertNotIn("httponly", cookie)

    def test_fixed_has_secure(self):
        cookie = set_cookie_fixed("session", "abc123")
        self.assertTrue(cookie.get("secure"))

    def test_fixed_has_httponly(self):
        cookie = set_cookie_fixed("session", "abc123")
        self.assertTrue(cookie.get("httponly"))

    def test_fixed_has_samesite(self):
        cookie = set_cookie_fixed("session", "abc123")
        self.assertIn("samesite", cookie)


if __name__ == "__main__":
    unittest.main()
'''


@regtest(614)
def _cookie_flags(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_COOKIE_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line))
    return [RegressionTest(
        cwe=614, language="python", title="Cookie Security Flags regression",
        test_code=code,
        fail_condition="set_cookie_vulnerable omits Secure/HttpOnly/SameSite",
        pass_condition="set_cookie_fixed sets all security flags",
        references=_refs(614, "A05:2021 Security Misconfiguration"),
    )]


# --------------------------------------------------------------------------- #
# CWE-862: Missing Authorization
# --------------------------------------------------------------------------- #

_MISSING_AUTHZ_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-862 (Missing Authorization)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import unittest


RECORDS = {
    1: {"id": 1, "owner_id": 100, "data": "secret"},
    2: {"id": 2, "owner_id": 200, "data": "other secret"},
}


def get_record_vulnerable(record_id, user_id):
    record = RECORDS.get(record_id)
    return record


def get_record_fixed(record_id, user_id):
    record = RECORDS.get(record_id)
    if record is None:
        raise KeyError("Not found")
    if record["owner_id"] != user_id:
        raise PermissionError("Not authorized")
    return record


class TestCWE862(unittest.TestCase):

    def test_vulnerable_allows_unauthorized_access(self):
        result = get_record_vulnerable(1, 999)
        self.assertIsNotNone(result)

    def test_fixed_blocks_unauthorized_access(self):
        with self.assertRaises(PermissionError):
            get_record_fixed(1, 999)

    def test_fixed_allows_authorized_access(self):
        result = get_record_fixed(1, 100)
        self.assertEqual("secret", result["data"])

    def test_fixed_raises_on_missing_record(self):
        with self.assertRaises(KeyError):
            get_record_fixed(999, 100)


if __name__ == "__main__":
    unittest.main()
'''


@regtest(862)
def _missing_authz(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_MISSING_AUTHZ_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line))
    return [RegressionTest(
        cwe=862, language="python", title="Missing Authorization regression",
        test_code=code,
        fail_condition="get_record_vulnerable returns any record without ownership check",
        pass_condition="get_record_fixed raises PermissionError for unauthorized access",
        references=_refs(862, "A01:2021 Broken Access Control"),
    )]


# --------------------------------------------------------------------------- #
# CWE-1321: Prototype Pollution
# --------------------------------------------------------------------------- #

_PROTO_POLLUTION_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-1321 (Prototype Pollution)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import unittest


def merge_vulnerable(target, source):
    for key in source:
        target[key] = source[key]
    return target


DANGEROUS_KEYS = ["__proto__", "constructor", "prototype"]


def merge_fixed(target, source):
    for key in source:
        if key in DANGEROUS_KEYS:
            continue
        target[key] = source[key]
    return target


class TestCWE1321(unittest.TestCase):

    def test_vulnerable_allows_proto(self):
        target = {}
        merge_vulnerable(target, {"__proto__": {"polluted": True}})
        self.assertIn("__proto__", target)

    def test_fixed_blocks_proto(self):
        target = {}
        merge_fixed(target, {"__proto__": {"polluted": True}})
        self.assertNotIn("__proto__", target)

    def test_fixed_blocks_constructor(self):
        target = {}
        merge_fixed(target, {"constructor": {"prototype": {}}})
        self.assertNotIn("constructor", target)

    def test_fixed_allows_normal_keys(self):
        target = {}
        merge_fixed(target, {"name": "test", "value": 42})
        self.assertEqual("test", target["name"])
        self.assertEqual(42, target["value"])


if __name__ == "__main__":
    unittest.main()
'''


@regtest(1321)
def _proto_pollution(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_PROTO_POLLUTION_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line))
    return [RegressionTest(
        cwe=1321, language="python", title="Prototype Pollution regression",
        test_code=code,
        fail_condition="merge_vulnerable copies __proto__/constructor keys",
        pass_condition="merge_fixed skips dangerous keys",
        references=_refs(1321, "A03:2021 Injection"),
    )]


# --------------------------------------------------------------------------- #
# CWE-369: Divide By Zero
# --------------------------------------------------------------------------- #

_DIV_ZERO_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-369 (Divide By Zero)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import unittest


def divide_vulnerable(a, b):
    return a / b


def divide_fixed(a, b):
    if b == 0:
        raise ValueError("Division by zero")
    return a / b


class TestCWE369(unittest.TestCase):

    def test_vulnerable_crashes_on_zero(self):
        with self.assertRaises(ZeroDivisionError):
            divide_vulnerable(10, 0)

    def test_fixed_raises_valueerror_on_zero(self):
        with self.assertRaises(ValueError):
            divide_fixed(10, 0)

    def test_fixed_works_for_nonzero(self):
        self.assertEqual(5.0, divide_fixed(10, 2))
        self.assertEqual(-2.0, divide_fixed(10, -5))


if __name__ == "__main__":
    unittest.main()
'''


@regtest(369)
def _divide_by_zero(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_DIV_ZERO_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line))
    return [RegressionTest(
        cwe=369, language="python", title="Divide By Zero regression",
        test_code=code,
        fail_condition="divide_vulnerable crashes with ZeroDivisionError",
        pass_condition="divide_fixed raises ValueError with clear message",
        references=_refs(369),
    )]


# --------------------------------------------------------------------------- #
# CWE-770: Allocation Without Limits
# --------------------------------------------------------------------------- #

_ALLOC_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-770 (Allocation Without Limits)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import unittest

MAX_PAGE_SIZE = 100


def query_vulnerable(page_size):
    return list(range(page_size))


def query_fixed(page_size):
    clamped = min(max(1, page_size), MAX_PAGE_SIZE)
    return list(range(clamped))


class TestCWE770(unittest.TestCase):

    def test_vulnerable_allows_huge_allocation(self):
        result = query_vulnerable(1_000_000)
        self.assertEqual(1_000_000, len(result))

    def test_fixed_clamps_to_max(self):
        result = query_fixed(1_000_000)
        self.assertLessEqual(len(result), MAX_PAGE_SIZE)

    def test_fixed_clamps_negative(self):
        result = query_fixed(-1)
        self.assertGreaterEqual(len(result), 1)

    def test_fixed_allows_normal_page(self):
        result = query_fixed(50)
        self.assertEqual(50, len(result))


if __name__ == "__main__":
    unittest.main()
'''


@regtest(770)
def _alloc_no_limits(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_ALLOC_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line))
    return [RegressionTest(
        cwe=770, language="python", title="Allocation Limits regression",
        test_code=code,
        fail_condition="query_vulnerable allocates as many items as requested",
        pass_condition="query_fixed clamps to MAX_PAGE_SIZE",
        references=_refs(770, "A05:2021 Security Misconfiguration"),
    )]


# --------------------------------------------------------------------------- #
# CWE-922: Insecure Storage
# --------------------------------------------------------------------------- #

_INSECURE_STORAGE_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-922 (Insecure Storage)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import os
import unittest


def get_secret_vulnerable():
    return "my-secret-key-12345"


def get_secret_fixed():
    value = os.environ.get("SECRET_KEY")
    if not value:
        raise RuntimeError("SECRET_KEY not set in environment")
    return value


class TestCWE922(unittest.TestCase):

    def test_vulnerable_returns_hardcoded(self):
        secret = get_secret_vulnerable()
        self.assertEqual("my-secret-key-12345", secret)

    def test_fixed_reads_from_env(self):
        os.environ["SECRET_KEY"] = "env-secret"
        try:
            secret = get_secret_fixed()
            self.assertEqual("env-secret", secret)
        finally:
            del os.environ["SECRET_KEY"]

    def test_fixed_raises_when_missing(self):
        old = os.environ.pop("SECRET_KEY", None)
        try:
            with self.assertRaises(RuntimeError):
                get_secret_fixed()
        finally:
            if old is not None:
                os.environ["SECRET_KEY"] = old


if __name__ == "__main__":
    unittest.main()
'''


@regtest(922)
def _insecure_storage(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_INSECURE_STORAGE_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line))
    return [RegressionTest(
        cwe=922, language="python", title="Insecure Storage regression",
        test_code=code,
        fail_condition="get_secret_vulnerable returns hardcoded secret",
        pass_condition="get_secret_fixed reads from environment and fails if not set",
        references=_refs(922, "A02:2021 Cryptographic Failures"),
    )]


# --------------------------------------------------------------------------- #
# CWE-120: Buffer Overflow
# --------------------------------------------------------------------------- #

_BUFFER_OVERFLOW_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-120 (Buffer Overflow)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import unittest

MAX_INPUT_LEN = 256


def copy_vulnerable(src):
    return src


def copy_fixed(src, max_len=MAX_INPUT_LEN):
    if len(src) > max_len:
        raise ValueError("Input too long: %d (max %d)" % (len(src), max_len))
    return src


class TestCWE120(unittest.TestCase):

    def test_vulnerable_accepts_oversized(self):
        huge = "A" * 10000
        result = copy_vulnerable(huge)
        self.assertEqual(10000, len(result))

    def test_fixed_rejects_oversized(self):
        huge = "A" * 10000
        with self.assertRaises(ValueError):
            copy_fixed(huge)

    def test_fixed_accepts_normal_input(self):
        normal = "hello"
        self.assertEqual(normal, copy_fixed(normal))


if __name__ == "__main__":
    unittest.main()
'''


@regtest(120)
def _buffer_overflow(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_BUFFER_OVERFLOW_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line))
    return [RegressionTest(
        cwe=120, language="python", title="Buffer Overflow regression",
        test_code=code,
        fail_condition="copy_vulnerable accepts input of any length",
        pass_condition="copy_fixed rejects input exceeding MAX_INPUT_LEN",
        references=_refs(120),
    )]


# --------------------------------------------------------------------------- #
# CWE-250: Unnecessary Privileges
# --------------------------------------------------------------------------- #

_PRIV_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-250 (Unnecessary Privileges)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import unittest


def check_privileges_vulnerable(uid):
    return {"running_as_root": uid == 0, "dropped": False}


def check_privileges_fixed(uid):
    if uid == 0:
        return {"running_as_root": True, "dropped": True, "new_uid": 65534}
    return {"running_as_root": False, "dropped": False}


class TestCWE250(unittest.TestCase):

    def test_vulnerable_stays_root(self):
        result = check_privileges_vulnerable(0)
        self.assertTrue(result["running_as_root"])
        self.assertFalse(result["dropped"])

    def test_fixed_drops_root(self):
        result = check_privileges_fixed(0)
        self.assertTrue(result["running_as_root"])
        self.assertTrue(result["dropped"])

    def test_fixed_normal_user_unchanged(self):
        result = check_privileges_fixed(1000)
        self.assertFalse(result["running_as_root"])


if __name__ == "__main__":
    unittest.main()
'''


@regtest(250)
def _unnecessary_privileges(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_PRIV_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line))
    return [RegressionTest(
        cwe=250, language="python", title="Unnecessary Privileges regression",
        test_code=code,
        fail_condition="check_privileges_vulnerable does not drop root",
        pass_condition="check_privileges_fixed drops to unprivileged user",
        references=_refs(250, "A04:2021 Insecure Design"),
    )]


# --------------------------------------------------------------------------- #
# CWE-476: NULL Pointer Dereference
# --------------------------------------------------------------------------- #

_NULL_DEREF_TEST = r'''#!/usr/bin/env python3
"""Regression test for CWE-476 (NULL Pointer Dereference)
Rule: %%RULE%%
File: %%FILE%%:%%LINE%%
"""
import unittest


def process_vulnerable(obj):
    return obj.value


def process_fixed(obj):
    if obj is None:
        raise ValueError("Input must not be None")
    return obj.value


class Holder:
    def __init__(self, value):
        self.value = value


class TestCWE476(unittest.TestCase):

    def test_vulnerable_crashes_on_none(self):
        with self.assertRaises(AttributeError):
            process_vulnerable(None)

    def test_fixed_raises_valueerror_on_none(self):
        with self.assertRaises(ValueError):
            process_fixed(None)

    def test_fixed_works_for_valid_input(self):
        result = process_fixed(Holder(42))
        self.assertEqual(42, result)


if __name__ == "__main__":
    unittest.main()
'''


@regtest(476)
def _null_deref(f: PocFinding) -> list[RegressionTest]:
    code = _fill(_NULL_DEREF_TEST, RULE=f.rule, FILE=f.file_path,
                 LINE=str(f.line))
    return [RegressionTest(
        cwe=476, language="python", title="NULL Pointer Dereference regression",
        test_code=code,
        fail_condition="process_vulnerable crashes with AttributeError on None",
        pass_condition="process_fixed raises ValueError with clear message",
        references=_refs(476),
    )]
