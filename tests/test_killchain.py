"""Tests for kill chain synthesizer."""
import os
import sys
import textwrap

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))
import killchain


def _sqli(file="app.py", line=10):
    return {"category": "sql_injection", "severity": "HIGH", "cwe": "CWE-89",
            "file": file, "line": line, "description": "SQL injection"}


def _cmdi(file="app.py", line=20):
    return {"category": "command_injection", "severity": "CRITICAL", "cwe": "CWE-78",
            "file": file, "line": line, "description": "command injection"}


def _xss(file="views.py", line=5):
    return {"category": "xss", "severity": "MEDIUM", "cwe": "CWE-79",
            "file": file, "line": line, "description": "XSS"}


def _ssrf(file="api.py", line=15):
    return {"category": "ssrf", "severity": "HIGH", "cwe": "CWE-918",
            "file": file, "line": line, "description": "SSRF"}


def _hardcoded(file="config.py", line=3):
    return {"category": "hardcoded_secret", "severity": "HIGH", "cwe": "CWE-798",
            "file": file, "line": line, "description": "hardcoded secret"}


def _path_trav(file="upload.py", line=8):
    return {"category": "path_traversal", "severity": "HIGH", "cwe": "CWE-22",
            "file": file, "line": line, "description": "path traversal"}


def _deser(file="api.py", line=30):
    return {"category": "deserialization", "severity": "CRITICAL", "cwe": "CWE-502",
            "file": file, "line": line, "description": "insecure deserialization"}


def test_classify_sqli():
    step = killchain.classify_finding(_sqli())
    assert step.phase == killchain.Phase.INITIAL_ACCESS
    assert step.technique == "SQL Injection"
    assert "db_read" in step.provides
    assert "auth_bypass" in step.provides


def test_classify_cmdi():
    step = killchain.classify_finding(_cmdi())
    assert step.phase == killchain.Phase.EXECUTION
    assert step.technique == "OS Command Injection"
    assert "code_exec" in step.provides


def test_classify_xss():
    step = killchain.classify_finding(_xss())
    assert step.phase == killchain.Phase.INITIAL_ACCESS
    assert "session_theft" in step.provides
    assert "user_interaction" in step.preconditions


def test_classify_ssrf():
    step = killchain.classify_finding(_ssrf())
    assert step.phase == killchain.Phase.LATERAL_MOVEMENT
    assert "internal_access" in step.provides


def test_classify_unknown_category():
    f = {"category": "something_new", "severity": "LOW", "cwe": "", "file": "x.py", "line": 1}
    step = killchain.classify_finding(f)
    assert step.technique == "something_new"
    assert step.phase == killchain.Phase.INITIAL_ACCESS


def test_synthesize_empty():
    chains = killchain.synthesize([])
    assert chains == []


def test_synthesize_single_finding():
    chains = killchain.synthesize([_sqli()])
    assert len(chains) == 1
    assert chains[0].length == 1
    assert chains[0].total_severity == "HIGH"


def test_synthesize_chain_two_steps():
    findings = [_sqli(), _cmdi(file="exec.py")]
    chains = killchain.synthesize(findings)
    multi = [c for c in chains if c.length >= 2]
    assert len(multi) >= 1
    chain = multi[0]
    assert chain.length >= 2
    assert chain.impact


def test_synthesize_chain_severity_escalation():
    findings = [_sqli(), _cmdi(file="exec.py"), _path_trav()]
    chains = killchain.synthesize(findings)
    multi = [c for c in chains if c.length >= 2]
    assert len(multi) >= 1
    assert multi[0].total_severity in ("CRITICAL", "HIGH")


def test_chain_name():
    findings = [_sqli(), _cmdi(file="exec.py")]
    chains = killchain.synthesize(findings)
    multi = [c for c in chains if c.length >= 2]
    assert len(multi) >= 1
    assert "→" in multi[0].name


def test_chain_mitre_tactics():
    findings = [_sqli(), _cmdi(file="exec.py")]
    chains = killchain.synthesize(findings)
    multi = [c for c in chains if c.length >= 2]
    assert len(multi) >= 1
    assert len(multi[0].mitre_tactics) >= 1


def test_chain_files_involved():
    findings = [_sqli(file="a.py"), _cmdi(file="b.py")]
    chains = killchain.synthesize(findings)
    multi = [c for c in chains if c.length >= 2]
    assert len(multi) >= 1
    assert len(multi[0].files_involved) >= 2


def test_can_chain_no_preconditions():
    a = killchain.classify_finding(_sqli())
    b = killchain.classify_finding(_cmdi())
    assert killchain._can_chain(a, b)


def test_can_chain_auth_required():
    a = killchain.classify_finding(_sqli())
    bola = {"category": "bola", "severity": "HIGH", "cwe": "CWE-639",
            "file": "api.py", "line": 5}
    b = killchain.classify_finding(bola)
    assert killchain._can_chain(a, b)


def test_capability_enables():
    assert killchain._capability_enables(["internal_access"], "bola")
    assert killchain._capability_enables(["code_exec"], "command_injection")
    assert not killchain._capability_enables(["db_read"], "command_injection")


def test_compute_chain_severity_single():
    steps = [killchain.classify_finding(_sqli())]
    sev = killchain._compute_chain_severity(steps)
    assert sev == "HIGH"


def test_compute_chain_severity_escalates():
    steps = [killchain.classify_finding(_sqli()),
             killchain.classify_finding(_cmdi(file="b.py")),
             killchain.classify_finding(_path_trav())]
    sev = killchain._compute_chain_severity(steps)
    assert sev == "CRITICAL"


def test_compute_chain_severity_empty():
    assert killchain._compute_chain_severity([]) == "LOW"


def test_to_dict_empty():
    assert killchain.to_dict([]) == []


def test_to_dict_structure():
    chains = killchain.synthesize([_sqli(), _cmdi(file="exec.py")])
    dicts = killchain.to_dict(chains)
    assert len(dicts) >= 1
    d = dicts[0]
    assert "name" in d
    assert "severity" in d
    assert "length" in d
    assert "impact" in d
    assert "steps" in d
    assert isinstance(d["steps"], list)
    for step in d["steps"]:
        assert "phase" in step
        assert "technique" in step
        assert "cwe" in step


def test_to_dict_roundtrip_fields():
    chains = killchain.synthesize([_ssrf(), _hardcoded()])
    dicts = killchain.to_dict(chains)
    for d in dicts:
        assert "entry_point" in d
        assert "final_objective" in d
        assert "mitre_tactics" in d
        assert "files_involved" in d


def test_render_empty():
    output = killchain.render([])
    assert "no attack chains" in output


def test_render_with_chains():
    chains = killchain.synthesize([_sqli(), _cmdi(file="exec.py")])
    output = killchain.render(chains)
    assert "Kill Chain" in output
    assert "chain(s)" in output


def test_render_shows_tactics():
    chains = killchain.synthesize([_sqli(), _cmdi(file="exec.py")])
    output = killchain.render(chains)
    assert "tactics:" in output


def test_render_shows_impact():
    chains = killchain.synthesize([_sqli(), _cmdi(file="exec.py")])
    output = killchain.render(chains)
    assert "impact:" in output


def test_render_shows_gains():
    chains = killchain.synthesize([_sqli()])
    output = killchain.render(chains)
    assert "gains:" in output


def test_standalone_high_severity_not_in_chain():
    crit = {"category": "deserialization", "severity": "CRITICAL", "cwe": "CWE-502",
            "file": "isolated.py", "line": 99, "description": "isolated deser"}
    chains = killchain.synthesize([crit])
    assert len(chains) >= 1
    assert any(c.total_severity == "CRITICAL" for c in chains)


def test_normalize_finding_with_sink_type():
    f = {"sink_type": "command_injection", "severity": "HIGH", "cwe": "CWE-78",
         "sink_file": "app.py", "sink_line": 10}
    norm = killchain._normalize_finding(f)
    assert norm["category"] == "command_injection"
    assert norm["file"] == "app.py"
    assert norm["line"] == 10


def test_normalize_finding_missing_fields():
    f = {}
    norm = killchain._normalize_finding(f)
    assert norm["category"] == "unknown"
    assert norm["severity"] == "MEDIUM"
    assert norm["file"] == ""


def test_describe_impact_code_exec():
    chain = killchain.KillChain(name="test", steps=[killchain.classify_finding(_cmdi())])
    impact = killchain._describe_impact(chain)
    assert "remote code execution" in impact


def test_describe_impact_db_access():
    chain = killchain.KillChain(name="test", steps=[killchain.classify_finding(_sqli())])
    impact = killchain._describe_impact(chain)
    assert "database" in impact


def test_describe_impact_ssrf():
    chain = killchain.KillChain(name="test", steps=[killchain.classify_finding(_ssrf())])
    impact = killchain._describe_impact(chain)
    assert "cloud metadata" in impact


def test_sorting_by_severity():
    findings = [
        {"category": "xss", "severity": "LOW", "cwe": "CWE-79", "file": "a.py", "line": 1},
        _cmdi(),
        _sqli(),
    ]
    chains = killchain.synthesize(findings)
    if len(chains) >= 2:
        sevs = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        for i in range(len(chains) - 1):
            assert sevs.get(chains[i].total_severity, 9) <= sevs.get(chains[i+1].total_severity, 9)


def test_complex_chain():
    findings = [
        _path_trav(file="upload.py"),
        _hardcoded(file="config.py"),
        _ssrf(file="internal.py"),
        _sqli(file="db.py"),
        _cmdi(file="exec.py"),
    ]
    chains = killchain.synthesize(findings)
    assert len(chains) >= 1
    longest = max(chains, key=lambda c: c.length)
    assert longest.length >= 2
    assert longest.total_severity in ("CRITICAL", "HIGH")
