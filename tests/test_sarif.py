"""Tests for SARIF 2.1.0 output."""
import json
import os

import sarif_output


def _dataflow_finding():
    return {
        "cwe": "CWE-78", "sink_type": "command_injection",
        "sink_file": "app.py", "sink_line": 42,
        "sink_code": "os.system(cmd)", "source_type": "http_param",
        "severity": "CRITICAL", "interprocedural": True,
        "confidence": "high", "language": "python",
        "trace": [
            {"file": "app.py", "line": 30, "note": "source: http_param",
             "code": "cmd = request.args.get('c')"},
            {"file": "app.py", "line": 42, "note": "reaches sink",
             "code": "os.system(cmd)"},
        ],
    }


def _scanner_finding():
    return {
        "rule_id": "JS-XSS-INNERHTML", "category": "xss",
        "description": "Direct innerHTML assignment",
        "path": "views.js", "line": 15,
        "severity": "HIGH", "cwe": "CWE-79",
        "matched_text": "el.innerHTML = data",
    }


def test_from_findings_valid_sarif():
    sarif = sarif_output.from_findings([_dataflow_finding()])
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].startswith("https://")
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Attestor"
    assert len(run["results"]) == 1


def test_result_has_codeflow():
    sarif = sarif_output.from_findings([_dataflow_finding()])
    result = sarif["runs"][0]["results"][0]
    assert "codeFlows" in result
    cf = result["codeFlows"][0]
    assert len(cf["threadFlows"]) == 1
    assert len(cf["threadFlows"][0]["locations"]) == 2


def test_severity_mapping():
    sarif = sarif_output.from_findings([_dataflow_finding()])
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "error"  # CRITICAL -> error


def test_cwe_in_rule_tags():
    sarif = sarif_output.from_findings([_dataflow_finding()])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "CWE-78" in rule["properties"]["tags"]


def test_scanner_finding_format():
    sarif = sarif_output.from_findings([_scanner_finding()])
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "JS-XSS-INNERHTML"
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "views.js"
    assert loc["region"]["startLine"] == 15


def test_mixed_finding_formats():
    sarif = sarif_output.from_findings([_dataflow_finding(), _scanner_finding()])
    run = sarif["runs"][0]
    assert len(run["results"]) == 2
    assert len(run["tool"]["driver"]["rules"]) == 2


def test_write_and_read(tmp_path):
    out = str(tmp_path / "test.sarif")
    sarif_output.write([_dataflow_finding()], out)
    assert os.path.exists(out)
    with open(out) as f:
        data = json.load(f)
    assert data["version"] == "2.1.0"


def test_round_trip():
    original = [_dataflow_finding()]
    sarif = sarif_output.from_findings(original)
    reimported = sarif_output.from_sarif(sarif)
    assert len(reimported) == 1
    r = reimported[0]
    assert r["sink_type"] == "command_injection"
    assert r["cwe"] == "CWE-78"
    assert len(r["trace"]) == 2


def test_merge():
    s1 = sarif_output.from_findings([_dataflow_finding()])
    s2 = sarif_output.from_findings([_scanner_finding()])
    merged = sarif_output.merge_sarif_runs(s1, s2)
    assert len(merged["runs"]) == 2


def test_summary():
    sarif = sarif_output.from_findings([_dataflow_finding(), _scanner_finding()])
    text = sarif_output.summary(sarif)
    assert "Attestor" in text
    assert "Results: 2" in text


def test_backward_compat_generate_sarif():
    sarif = sarif_output.generate_sarif([_scanner_finding()])
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1


def test_no_trace_no_codeflow():
    f = _dataflow_finding()
    f["trace"] = []
    sarif = sarif_output.from_findings([f])
    result = sarif["runs"][0]["results"][0]
    assert "codeFlows" not in result


def test_empty_findings():
    sarif = sarif_output.from_findings([])
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []
