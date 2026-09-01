"""Tests for hybrid analysis engine."""
import json
import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))
import hybrid_engine


SAMPLE_FINDINGS = [
    {"path": "app/views.py", "line": 42, "rule_id": "SQL-001",
     "severity": "CRITICAL", "description": "SQL injection via user input",
     "cwe": "CWE-89"},
    {"path": "app/auth.py", "line": 10, "rule_id": "AUTH-001",
     "severity": "HIGH", "description": "Weak password comparison"},
]


def test_parse_verdict_json():
    response = '{"verdict": "EXPLOITABLE", "confidence": 0.95, "reasoning": "direct user input"}'
    v = hybrid_engine._parse_verdict(response)
    assert v["verdict"] == "EXPLOITABLE"
    assert v["confidence"] == 0.95


def test_parse_verdict_json_in_text():
    response = 'Here is my analysis:\n{"verdict": "FALSE_POSITIVE", "confidence": 0.8, "reasoning": "sanitized"}\nDone.'
    v = hybrid_engine._parse_verdict(response)
    assert v["verdict"] == "FALSE_POSITIVE"


def test_parse_verdict_no_json():
    response = "This is clearly EXPLOITABLE because the input is not sanitized."
    v = hybrid_engine._parse_verdict(response)
    assert v["verdict"] == "EXPLOITABLE"


def test_parse_verdict_fp_text():
    response = "This is a FALSE_POSITIVE. The framework handles sanitization."
    v = hybrid_engine._parse_verdict(response)
    assert v["verdict"] == "FALSE_POSITIVE"


def test_parse_verdict_not_exploitable():
    response = "After analysis, this is NOT_EXPLOITABLE due to the ORM layer."
    v = hybrid_engine._parse_verdict(response)
    assert v["verdict"] == "FALSE_POSITIVE"


def test_parse_verdict_uncertain():
    response = "I cannot determine without more context."
    v = hybrid_engine._parse_verdict(response)
    assert v["verdict"] == "UNCERTAIN"


def test_parse_batch_verdicts():
    response = '[{"id": 0, "verdict": "EXPLOITABLE", "confidence": 0.9}, {"id": 1, "verdict": "FALSE_POSITIVE", "confidence": 0.7}]'
    verdicts = hybrid_engine._parse_batch_verdicts(response, 2)
    assert len(verdicts) == 2
    assert verdicts[0]["verdict"] == "EXPLOITABLE"
    assert verdicts[1]["verdict"] == "FALSE_POSITIVE"


def test_parse_batch_verdicts_padded():
    response = '[{"id": 0, "verdict": "EXPLOITABLE"}]'
    verdicts = hybrid_engine._parse_batch_verdicts(response, 3)
    assert len(verdicts) == 3
    assert verdicts[0]["verdict"] == "EXPLOITABLE"
    assert verdicts[2]["verdict"] == "UNCERTAIN"


def test_parse_batch_verdicts_bad_json():
    response = "Finding 0 is EXPLOITABLE. Finding 1 is FALSE_POSITIVE."
    verdicts = hybrid_engine._parse_batch_verdicts(response, 2)
    assert len(verdicts) == 2


def test_judged_finding_dataclass():
    jf = hybrid_engine.JudgedFinding(
        finding=SAMPLE_FINDINGS[0],
        verdict="EXPLOITABLE",
        confidence=0.95,
        reasoning="direct concatenation",
        actual_severity="CRITICAL",
    )
    assert jf.verdict == "EXPLOITABLE"
    assert jf.finding["rule_id"] == "SQL-001"
    assert jf.memory_tags == []


def test_read_context():
    root = tempfile.mkdtemp()
    try:
        src = os.path.join(root, "test.py")
        with open(src, "w") as f:
            for i in range(50):
                f.write(f"line_{i} = {i}\n")
        analyzer = hybrid_engine.HybridAnalyzer(root)
        ctx = analyzer._read_context("test.py", 25)
        assert "line_24" in ctx
        assert " >> " in ctx
    finally:
        shutil.rmtree(root)


def test_read_context_missing_file():
    root = tempfile.mkdtemp()
    try:
        analyzer = hybrid_engine.HybridAnalyzer(root)
        ctx = analyzer._read_context("nonexistent.py", 10)
        assert ctx == ""
    finally:
        shutil.rmtree(root)


def test_memory_context_tags():
    analyzer = hybrid_engine.HybridAnalyzer(".")
    finding = {"memory_confirmed": True, "memory_hotspot": True}
    ctx = analyzer._memory_context(finding)
    assert "true positive" in ctx
    assert "hotspot" in ctx


def test_memory_context_noisy():
    analyzer = hybrid_engine.HybridAnalyzer(".")
    finding = {"memory_low_precision": True}
    ctx = analyzer._memory_context(finding)
    assert "false positive rate" in ctx


def test_memory_context_empty():
    analyzer = hybrid_engine.HybridAnalyzer(".")
    ctx = analyzer._memory_context({})
    assert ctx == ""


def test_render_results():
    results = [
        hybrid_engine.JudgedFinding(
            finding=SAMPLE_FINDINGS[0], verdict="EXPLOITABLE",
            confidence=0.95, reasoning="user input in query",
            actual_severity="CRITICAL", judge_model="owen-coder",
            latency_ms=150),
        hybrid_engine.JudgedFinding(
            finding=SAMPLE_FINDINGS[1], verdict="FALSE_POSITIVE",
            confidence=0.8, reasoning="bcrypt handles timing",
            actual_severity="LOW", judge_model="owen-coder",
            latency_ms=120),
    ]
    text = hybrid_engine.render_results(results)
    assert "EXPLOITABLE" in text
    assert "1 EXPLOITABLE" in text
    assert "1 FALSE POSITIVE" in text


def test_to_dict():
    results = [
        hybrid_engine.JudgedFinding(
            finding=SAMPLE_FINDINGS[0], verdict="EXPLOITABLE",
            confidence=0.9, judge_model="test"),
    ]
    d = hybrid_engine.to_dict(results)
    assert len(d) == 1
    assert d[0]["verdict"] == "EXPLOITABLE"
    assert d[0]["finding"]["rule_id"] == "SQL-001"


def test_sev_rank():
    assert hybrid_engine._sev_rank("CRITICAL") < hybrid_engine._sev_rank("HIGH")
    assert hybrid_engine._sev_rank("HIGH") < hybrid_engine._sev_rank("MEDIUM")
    assert hybrid_engine._sev_rank("MEDIUM") < hybrid_engine._sev_rank("LOW")
    assert hybrid_engine._sev_rank("UNKNOWN") == 4
