"""Tests for interactive attack graph visualization."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))
import attack_graph_viz
import killchain


def _sample_chains():
    findings = [
        {"category": "sql_injection", "severity": "HIGH", "cwe": "CWE-89",
         "file": "app.py", "line": 10, "description": "SQL injection"},
        {"category": "command_injection", "severity": "CRITICAL", "cwe": "CWE-78",
         "file": "exec.py", "line": 20, "description": "command injection"},
        {"category": "path_traversal", "severity": "HIGH", "cwe": "CWE-22",
         "file": "upload.py", "line": 8, "description": "path traversal"},
        {"category": "hardcoded_secret", "severity": "HIGH", "cwe": "CWE-798",
         "file": "config.py", "line": 3, "description": "hardcoded secret"},
    ]
    chains = killchain.synthesize(findings)
    return killchain.to_dict(chains)


def test_build_graph_data_empty():
    data = attack_graph_viz._build_graph_data([])
    assert data["nodes"] == []
    assert data["edges"] == []
    assert data["chains"] == []


def test_build_graph_data_single_chain():
    dicts = _sample_chains()
    data = attack_graph_viz._build_graph_data(dicts)
    assert len(data["nodes"]) >= 1
    assert len(data["chains"]) >= 1


def test_build_graph_data_nodes_have_fields():
    dicts = _sample_chains()
    data = attack_graph_viz._build_graph_data(dicts)
    for node in data["nodes"]:
        assert "id" in node
        assert "technique" in node
        assert "phase" in node
        assert "severity" in node
        assert "chains" in node
        assert isinstance(node["chains"], list)


def test_build_graph_data_edges_reference_valid_nodes():
    dicts = _sample_chains()
    data = attack_graph_viz._build_graph_data(dicts)
    node_ids = {n["id"] for n in data["nodes"]}
    for edge in data["edges"]:
        assert edge["from"] in node_ids
        assert edge["to"] in node_ids


def test_build_graph_data_chain_meta():
    dicts = _sample_chains()
    data = attack_graph_viz._build_graph_data(dicts)
    for chain in data["chains"]:
        assert "index" in chain
        assert "name" in chain
        assert "severity" in chain
        assert "impact" in chain


def test_build_graph_data_deduplicates_nodes():
    chain1 = {"name": "c1", "severity": "HIGH", "length": 2, "impact": "test",
              "entry_point": "", "final_objective": "", "files_involved": [],
              "mitre_tactics": [], "steps": [
                  {"phase": "initial_access", "technique": "SQLi", "severity": "HIGH",
                   "cwe": "CWE-89", "file": "app.py", "line": 10, "description": "",
                   "provides": ["db_read"], "preconditions": []},
                  {"phase": "execution", "technique": "RCE", "severity": "CRITICAL",
                   "cwe": "CWE-78", "file": "exec.py", "line": 20, "description": "",
                   "provides": ["code_exec"], "preconditions": []},
              ]}
    chain2 = {"name": "c2", "severity": "HIGH", "length": 2, "impact": "test",
              "entry_point": "", "final_objective": "", "files_involved": [],
              "mitre_tactics": [], "steps": [
                  {"phase": "initial_access", "technique": "SQLi", "severity": "HIGH",
                   "cwe": "CWE-89", "file": "app.py", "line": 10, "description": "",
                   "provides": ["db_read"], "preconditions": []},
                  {"phase": "credential_access", "technique": "Cred", "severity": "HIGH",
                   "cwe": "CWE-798", "file": "config.py", "line": 3, "description": "",
                   "provides": [], "preconditions": []},
              ]}
    data = attack_graph_viz._build_graph_data([chain1, chain2])
    sqli_nodes = [n for n in data["nodes"] if n["technique"] == "SQLi"]
    assert len(sqli_nodes) == 1
    assert 0 in sqli_nodes[0]["chains"]
    assert 1 in sqli_nodes[0]["chains"]


def test_render_html_returns_string():
    dicts = _sample_chains()
    html = attack_graph_viz.render_html(dicts)
    assert isinstance(html, str)
    assert "<!DOCTYPE html>" in html
    assert "Attestor" in html


def test_render_html_contains_data():
    dicts = _sample_chains()
    html = attack_graph_viz.render_html(dicts)
    assert "nodes" in html
    assert "edges" in html
    assert "chains" in html


def test_render_html_empty():
    html = attack_graph_viz.render_html([])
    assert "<!DOCTYPE html>" in html
    assert "No attack chains" in html


def test_render_html_no_external_resources():
    dicts = _sample_chains()
    html = attack_graph_viz.render_html(dicts)
    assert "fonts.googleapis" not in html
    assert "<link" not in html.lower() or "stylesheet" not in html.lower()


def test_write_html_creates_file(tmp_path):
    dicts = _sample_chains()
    out = str(tmp_path / "test-graph.html")
    result = attack_graph_viz.write_html(dicts, out)
    assert os.path.exists(out)
    assert result == os.path.abspath(out)
    with open(out, encoding="utf-8") as f:
        content = f.read()
    assert "<!DOCTYPE html>" in content


def test_write_html_valid_html(tmp_path):
    dicts = _sample_chains()
    out = str(tmp_path / "graph.html")
    attack_graph_viz.write_html(dicts, out)
    with open(out, encoding="utf-8") as f:
        content = f.read()
    assert content.count("<html") == 1
    assert content.count("</html>") == 1
    assert "<canvas" in content
    assert "</script>" in content


def test_render_html_has_phase_colors():
    dicts = _sample_chains()
    html = attack_graph_viz.render_html(dicts)
    assert "initial_access" in html
    assert "execution" in html


def test_render_html_has_severity_colors():
    dicts = _sample_chains()
    html = attack_graph_viz.render_html(dicts)
    assert "CRITICAL" in html
    assert "HIGH" in html


def test_edges_have_capability_label():
    dicts = _sample_chains()
    data = attack_graph_viz._build_graph_data(dicts)
    multi_chain = [c for c in dicts if c["length"] >= 2]
    if multi_chain and data["edges"]:
        has_cap = any(e["capability"] for e in data["edges"])
        assert has_cap
