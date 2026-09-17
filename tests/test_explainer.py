"""Tests for finding explainer engine."""
import os
import sys
import tempfile
import shutil
import textwrap

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))
import explainer


def _make_source(root, name, content):
    path = os.path.join(root, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(textwrap.dedent(content))
    return path


def test_explain_sqli():
    finding = {
        "path": "app.py", "line": 10,
        "rule_id": "SQL-INJECTION", "severity": "CRITICAL",
        "description": "SQL query built with string concatenation",
        "cwe": "CWE-89",
    }
    exp = explainer.Explainer()
    result = exp.explain(finding)
    assert "SQL Injection" in result.summary
    assert "parameterized" in result.how_to_fix
    assert result.owasp_category == "A03:2021 Injection"
    assert len(result.references) >= 1


def test_explain_xss():
    finding = {
        "path": "template.py", "line": 5,
        "rule_id": "XSS-REFLECT", "severity": "HIGH",
        "description": "user input rendered without escaping",
        "cwe": "CWE-79",
    }
    exp = explainer.Explainer()
    result = exp.explain(finding)
    assert "Cross-Site Scripting" in result.what
    assert "cookie" in result.how_exploited.lower() or "script" in result.how_exploited.lower()


def test_explain_command_injection():
    finding = {
        "path": "utils.py", "line": 22,
        "rule_id": "CMD-INJECT", "severity": "CRITICAL",
        "description": "os.system called with user input",
        "cwe": "CWE-78",
    }
    exp = explainer.Explainer()
    result = exp.explain(finding)
    assert "Command Injection" in result.summary
    assert "subprocess" in result.how_to_fix.lower()
    assert result.fix_example != ""


def test_explain_hardcoded_secret():
    finding = {
        "path": "config.py", "line": 3,
        "rule_id": "SECRET-HARDCODED", "severity": "HIGH",
        "description": "hardcoded API key found",
        "cwe": "CWE-798",
    }
    exp = explainer.Explainer()
    result = exp.explain(finding)
    assert "Hardcoded" in result.summary or "Credential" in result.summary
    assert "environment" in result.how_to_fix.lower() or "vault" in result.how_to_fix.lower()


def test_explain_unknown_cwe():
    finding = {
        "path": "unknown.py", "line": 1,
        "rule_id": "CUSTOM-RULE-42", "severity": "MEDIUM",
        "description": "something unusual detected",
    }
    exp = explainer.Explainer()
    result = exp.explain(finding)
    assert "CUSTOM-RULE-42" in result.summary
    assert "something unusual" in result.what
    assert result.how_to_fix != ""


def test_explain_no_cwe():
    finding = {
        "path": "test.py", "line": 5,
        "rule_id": "LINT-001", "severity": "LOW",
        "description": "potential issue",
    }
    exp = explainer.Explainer()
    result = exp.explain(finding)
    assert result.summary != ""
    assert result.severity_rationale != ""


def test_explain_cwe_from_rule_id():
    finding = {
        "path": "test.py", "line": 5,
        "rule_id": "TAINT-CWE-89-sqli", "severity": "HIGH",
        "description": "taint flow to SQL",
    }
    exp = explainer.Explainer()
    result = exp.explain(finding)
    assert "SQL Injection" in result.what


def test_full_text():
    finding = {
        "path": "app.py", "line": 10,
        "rule_id": "SSRF", "severity": "HIGH",
        "description": "server fetches user-controlled URL",
        "cwe": "CWE-918",
    }
    exp = explainer.Explainer()
    result = exp.explain(finding)
    text = result.full_text
    assert "## " in text
    assert "What is this?" in text
    assert "Why does it matter?" in text
    assert "How to fix" in text
    assert "SSRF" in text or "Server-Side" in text


def test_code_context():
    root = tempfile.mkdtemp()
    try:
        path = _make_source(root, "vuln.py", """
            import os

            def run_cmd(user_input):
                os.system(user_input)

            def safe_func():
                return 42
        """)
        finding = {"path": path, "line": 5, "severity": "CRITICAL",
                   "rule_id": "CMD", "description": "os.system"}
        exp = explainer.Explainer(context_lines=3)
        result = exp.explain(finding)
        assert "os.system" in result.code_context
        assert ">>" in result.code_context
    finally:
        shutil.rmtree(root)


def test_code_context_missing_file():
    finding = {"path": "/nonexistent/file.py", "line": 5,
               "severity": "LOW", "rule_id": "X", "description": "test"}
    exp = explainer.Explainer()
    result = exp.explain(finding)
    assert result.code_context == ""


def test_explain_batch():
    findings = [
        {"path": "a.py", "line": 1, "severity": "HIGH",
         "rule_id": "A", "description": "issue A", "cwe": "CWE-89"},
        {"path": "b.py", "line": 2, "severity": "LOW",
         "rule_id": "B", "description": "issue B"},
    ]
    exp = explainer.Explainer()
    results = exp.explain_batch(findings)
    assert len(results) == 2
    assert "SQL" in results[0].what
    assert results[1].summary != ""


def test_to_dict():
    finding = {"path": "test.py", "line": 1, "severity": "MEDIUM",
               "rule_id": "R", "description": "desc", "cwe": "CWE-22"}
    exp = explainer.Explainer()
    result = exp.explain(finding)
    d = explainer.to_dict([result])
    assert len(d) == 1
    assert d[0]["summary"] == "Path Traversal"
    assert "how_to_fix" in d[0]
    assert "references" in d[0]
    assert len(d[0]["references"]) >= 1


def test_render():
    finding = {"path": "test.py", "line": 1, "severity": "HIGH",
               "rule_id": "R", "description": "desc", "cwe": "CWE-502"}
    exp = explainer.Explainer()
    result = exp.explain(finding)
    text = explainer.render([result])
    assert "Deserialization" in text
    assert "Finding 1/1" in text


def test_render_empty():
    text = explainer.render([])
    assert "No findings" in text


def test_severity_rationale_all_levels():
    exp = explainer.Explainer()
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        finding = {"path": "x.py", "line": 1, "severity": sev,
                   "rule_id": "X", "description": "test"}
        result = exp.explain(finding)
        assert result.severity_rationale != ""


def test_deserialization_cwe():
    finding = {"path": "x.py", "line": 1, "severity": "HIGH",
               "rule_id": "PICKLE", "description": "pickle.loads",
               "cwe": "CWE-502"}
    exp = explainer.Explainer()
    result = exp.explain(finding)
    assert "pickle" in result.how_to_fix.lower() or "deserializ" in result.how_to_fix.lower()
    assert result.fix_example != ""


def test_xxe_cwe():
    finding = {"path": "x.py", "line": 1, "severity": "HIGH",
               "rule_id": "XXE", "description": "xml parsing",
               "cwe": "CWE-611"}
    exp = explainer.Explainer()
    result = exp.explain(finding)
    assert "XML" in result.summary or "XXE" in result.summary
    assert "defusedxml" in result.fix_example or "defusedxml" in result.how_to_fix


def test_auth_bypass_cwe():
    finding = {"path": "auth.py", "line": 10, "severity": "CRITICAL",
               "rule_id": "AUTH-BYPASS", "description": "auth bypass",
               "cwe": "CWE-287"}
    exp = explainer.Explainer()
    result = exp.explain(finding)
    assert "Authentication" in result.summary
    assert "A07" in result.owasp_category


def test_missing_auth_cwe():
    finding = {"path": "admin.py", "line": 5, "severity": "HIGH",
               "rule_id": "NO-AUTH", "description": "no auth on endpoint",
               "cwe": "CWE-306"}
    exp = explainer.Explainer()
    result = exp.explain(finding)
    assert "Missing Authentication" in result.summary


def test_missing_authz_cwe():
    finding = {"path": "api.py", "line": 20, "severity": "HIGH",
               "rule_id": "IDOR", "description": "insecure direct object ref",
               "cwe": "CWE-862"}
    exp = explainer.Explainer()
    result = exp.explain(finding)
    assert "Authorization" in result.summary


def test_cleartext_storage_cwe():
    finding = {"path": "db.py", "line": 8, "severity": "HIGH",
               "rule_id": "CLEARTEXT", "description": "plaintext password",
               "cwe": "CWE-312"}
    exp = explainer.Explainer()
    result = exp.explain(finding)
    assert "Cleartext" in result.summary or "plaintext" in result.summary.lower()
    assert "bcrypt" in result.fix_example or "bcrypt" in result.how_to_fix


def test_buffer_overflow_cwe():
    finding = {"path": "parser.c", "line": 42, "severity": "CRITICAL",
               "rule_id": "BOF", "description": "strcpy buffer overflow",
               "cwe": "CWE-120"}
    exp = explainer.Explainer()
    result = exp.explain(finding)
    assert "Buffer Overflow" in result.summary
    assert "strncpy" in result.fix_example


def test_integer_overflow_cwe():
    finding = {"path": "calc.c", "line": 15, "severity": "HIGH",
               "rule_id": "INTOVF", "description": "integer overflow",
               "cwe": "CWE-190"}
    exp = explainer.Explainer()
    result = exp.explain(finding)
    assert "Integer Overflow" in result.summary


def test_cors_cwe():
    finding = {"path": "server.py", "line": 3, "severity": "MEDIUM",
               "rule_id": "CORS", "description": "wildcard CORS",
               "cwe": "CWE-942"}
    exp = explainer.Explainer()
    result = exp.explain(finding)
    assert "CORS" in result.summary
    assert "A05" in result.owasp_category


def test_null_deref_cwe():
    finding = {"path": "parser.c", "line": 88, "severity": "HIGH",
               "rule_id": "NULLPTR", "description": "null dereference",
               "cwe": "CWE-476"}
    exp = explainer.Explainer()
    result = exp.explain(finding)
    assert "NULL" in result.summary


def test_all_cwe_db_entries_have_required_fields():
    for cwe_id, info in explainer.CWE_DB.items():
        assert "name" in info, f"{cwe_id} missing name"
        assert "impact" in info, f"{cwe_id} missing impact"
        assert "fix" in info, f"{cwe_id} missing fix"
        assert "owasp" in info, f"{cwe_id} missing owasp"
        assert info["name"], f"{cwe_id} name is empty"
        assert info["fix"], f"{cwe_id} fix is empty"


def test_cwe_db_count():
    assert len(explainer.CWE_DB) >= 22
