"""Tests for the interactive HTML attack dashboard."""
import os
import json

import dashboard


def _sample_findings():
    return [
        {
            "cwe": "CWE-78", "sink_type": "command_injection",
            "sink_file": "app.py", "sink_line": 42,
            "sink_code": "os.system(cmd)", "source_type": "http_param",
            "severity": "CRITICAL", "interprocedural": True,
            "confidence": "high", "language": "python",
            "trace": [
                {"file": "app.py", "line": 30, "note": "source: http_param",
                 "code": "cmd = request.args.get('c')"},
                {"file": "app.py", "line": 42, "note": "reaches sink: command_injection",
                 "code": "os.system(cmd)"},
            ],
        },
        {
            "cwe": "CWE-79", "sink_type": "xss",
            "sink_file": "views.js", "sink_line": 15,
            "sink_code": "el.innerHTML = data", "source_type": "dom_url",
            "severity": "HIGH", "interprocedural": False,
            "confidence": "high", "language": "javascript",
            "trace": [
                {"file": "views.js", "line": 10, "note": "source: dom_url",
                 "code": "const data = location.hash"},
                {"file": "views.js", "line": 15, "note": "reaches sink: xss",
                 "code": "el.innerHTML = data"},
            ],
        },
        {
            "cwe": "CWE-89", "sink_type": "sql_injection",
            "sink_file": "db.py", "sink_line": 88,
            "sink_code": "cursor.execute(q)", "source_type": "http_body",
            "severity": "HIGH", "interprocedural": False,
            "confidence": "high",
            "trace": [],
        },
    ]


def _sample_graph():
    return {
        "nodes": [
            {"id": "v0", "vuln_type": "command_injection", "cwe": "CWE-78",
             "file": "app.py", "line": 42, "severity": "CRITICAL",
             "host": "localhost", "capability": "code_execution"},
            {"id": "v1", "vuln_type": "sql_injection", "cwe": "CWE-89",
             "file": "db.py", "line": 88, "severity": "HIGH",
             "host": "localhost", "capability": "database_access"},
        ],
        "edges": [
            {"src": "v0", "dst": "v1", "label": "host compromised",
             "capability_gained": "database_access", "capability_required": "code_execution"},
        ],
        "paths": [
            {"nodes": ["v0", "v1"],
             "edges": [{"src": "v0", "dst": "v1", "label": "host compromised"}],
             "impact": "full compromise: RCE + data exfiltration", "score": 25.5},
        ],
        "stats": {"total_nodes": 2, "total_edges": 1, "total_paths": 1, "max_depth": 2},
    }


def _sample_validations():
    return [
        {"rule_id": "SEC-GH-PAT", "secret_redacted": "ghp_****abcd",
         "status": "live", "service": "GitHub", "detail": "active token",
         "identity": "testuser", "severity_override": "CRITICAL"},
        {"rule_id": "SEC-SLACK-TOKEN", "secret_redacted": "xoxb****",
         "status": "dead", "service": "Slack", "detail": "revoked",
         "identity": "", "severity_override": ""},
    ]


def test_generate_basic_html():
    html = dashboard.generate(_sample_findings())
    assert "<!DOCTYPE html>" in html
    assert "Attestor Security Dashboard" in html
    assert "CWE-78" in html
    assert "command_injection" in html


def test_severity_counts():
    counts = dashboard._severity_counts(_sample_findings())
    assert counts["CRITICAL"] == 1
    assert counts["HIGH"] == 2


def test_donut_svg():
    counts = {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 1, "LOW": 0, "INFO": 0}
    svg = dashboard._donut_svg(counts)
    assert "<svg" in svg
    assert "circle" in svg


def test_donut_empty():
    svg = dashboard._donut_svg({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0})
    assert "0</text>" in svg


def test_finding_card_with_trace():
    findings = _sample_findings()
    card = dashboard._finding_card(findings[0], 0)
    assert "trace-toggle" in card
    assert "trace-0" in card
    assert "http_param" in card


def test_finding_card_no_trace():
    f = _sample_findings()[2]
    card = dashboard._finding_card(f, 2)
    assert "trace-toggle" not in card


def test_attack_path_svg():
    svg = dashboard._attack_path_svg(_sample_graph())
    assert "<svg" in svg
    assert "command_injection" in svg
    assert "sql_injection" in svg


def test_attack_path_empty():
    result = dashboard._attack_path_svg(None)
    assert "No exploit chains" in result


def test_secret_validation_section():
    section = dashboard._secret_validation_section(_sample_validations())
    assert "Secret Validation" in section
    assert "GitHub" in section
    assert "live" in section.lower()


def test_secret_validation_empty():
    assert dashboard._secret_validation_section(None) == ""
    assert dashboard._secret_validation_section([]) == ""


def test_full_dashboard_with_all_sections():
    html = dashboard.generate(
        _sample_findings(),
        attack_graph=_sample_graph(),
        secret_validations=_sample_validations(),
        title="Test Dashboard",
        target="192.168.1.1",
    )
    assert "Test Dashboard" in html
    assert "192.168.1.1" in html
    assert "Attack Chains" in html
    assert "Secret Validation" in html
    assert "command_injection" in html


def test_filter_controls():
    html = dashboard.generate(_sample_findings())
    assert 'id="sevFilter"' in html
    assert 'id="typeFilter"' in html
    assert 'id="fileFilter"' in html
    assert "filterFindings()" in html


def test_theme_toggle():
    html = dashboard.generate(_sample_findings())
    assert "toggleTheme" in html
    assert "data-theme" in html


def test_write_to_file(tmp_path):
    out = tmp_path / "report.html"
    html = dashboard.generate(_sample_findings())
    out.write_text(html, encoding="utf-8")
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content


def test_to_json():
    j = dashboard.to_json(_sample_findings(), _sample_graph(), _sample_validations())
    data = json.loads(j)
    assert "findings" in data
    assert "attack_graph" in data
    assert "secret_validations" in data
    assert len(data["findings"]) == 3


def test_responsive_meta():
    html = dashboard.generate(_sample_findings())
    assert 'name="viewport"' in html
    assert "max-width" in html


def test_empty_findings():
    html = dashboard.generate([])
    assert "No findings" in html
    assert "0</text>" in html
