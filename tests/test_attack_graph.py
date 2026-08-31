"""Tests for the exploit chaining / attack graph engine."""
import attack_graph


def _make_finding(vuln_type, cwe, severity="HIGH", file="app.py", line=10,
                  host="localhost", reachable=True):
    return {
        "sink_type": vuln_type, "cwe": cwe, "severity": severity,
        "sink_file": file, "sink_line": line, "line": line, "file": file,
        "host": host, "reachable": reachable,
    }


def test_ssrf_to_sqli_chain():
    findings = [
        _make_finding("ssrf", "CWE-918", severity="HIGH", file="proxy.py", line=20),
        _make_finding("sql_injection", "CWE-89", severity="HIGH",
                      file="api/db.py", line=45, host="server"),
    ]
    graph = attack_graph.build_graph(findings)
    assert graph.paths, "SSRF → SQLi chain must be found"
    chain = graph.paths[0]
    types = [n.vuln_type for n in chain.nodes]
    assert "ssrf" in types and "sql_injection" in types


def test_rce_enables_collocated():
    findings = [
        _make_finding("command_injection", "CWE-78", severity="CRITICAL"),
        _make_finding("sql_injection", "CWE-89", severity="HIGH"),
    ]
    graph = attack_graph.build_graph(findings)
    chains_with_both = [p for p in graph.paths
                        if len(p.nodes) >= 2]
    assert chains_with_both, "RCE should chain to co-located SQLi"


def test_no_self_chain():
    findings = [_make_finding("xss", "CWE-79")]
    graph = attack_graph.build_graph(findings)
    for p in graph.paths:
        ids = [n.id for n in p.nodes]
        assert len(ids) == len(set(ids)), "no node should appear twice in a path"


def test_unreachable_excluded():
    findings = [
        _make_finding("command_injection", "CWE-78", reachable=False),
        _make_finding("sql_injection", "CWE-89"),
    ]
    graph = attack_graph.build_graph(findings)
    for n in graph.nodes:
        assert n.vuln_type != "command_injection", "unreachable finding excluded"


def test_path_traversal_to_sqli():
    findings = [
        _make_finding("path_traversal", "CWE-22", severity="HIGH"),
        _make_finding("sql_injection", "CWE-89", severity="HIGH"),
    ]
    graph = attack_graph.build_graph(findings)
    chains = [p for p in graph.paths if len(p.nodes) >= 2]
    assert chains, "file read → DB creds chain should exist"


def test_score_ordering():
    findings = [
        _make_finding("command_injection", "CWE-78", severity="CRITICAL"),
        _make_finding("sql_injection", "CWE-89", severity="HIGH"),
        _make_finding("xss", "CWE-79", severity="MEDIUM"),
    ]
    graph = attack_graph.build_graph(findings)
    if len(graph.paths) >= 2:
        assert graph.paths[0].score >= graph.paths[1].score


def test_to_dict():
    findings = [
        _make_finding("ssrf", "CWE-918"),
        _make_finding("command_injection", "CWE-78", host="server"),
    ]
    graph = attack_graph.build_graph(findings)
    d = graph.to_dict()
    assert "nodes" in d and "edges" in d and "paths" in d and "stats" in d
    assert d["stats"]["total_nodes"] == 2


def test_to_engagement_findings():
    findings = [
        _make_finding("command_injection", "CWE-78", severity="CRITICAL"),
        _make_finding("sql_injection", "CWE-89"),
    ]
    graph = attack_graph.build_graph(findings)
    ef = attack_graph.to_engagement_findings(graph)
    assert ef
    assert all("sink_type" in f and "chain_impact" in f for f in ef)


def test_render_output():
    findings = [
        _make_finding("ssrf", "CWE-918"),
        _make_finding("sql_injection", "CWE-89", host="server"),
    ]
    graph = attack_graph.build_graph(findings)
    text = attack_graph.render(graph)
    assert "Attack Graph" in text


def test_empty_findings():
    graph = attack_graph.build_graph([])
    assert graph.nodes == []
    assert graph.paths == []
    text = attack_graph.render(graph)
    assert "No exploit chains" in text
