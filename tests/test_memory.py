"""Tests for Attestor persistent memory."""
import json
import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))
import memory


def _tmp_memory():
    root = tempfile.mkdtemp(prefix="attestor_mem_test_")
    return memory.Memory(root), root


def _cleanup(root):
    shutil.rmtree(root, ignore_errors=True)


SAMPLE_FINDINGS = [
    {"path": "app/views.py", "line": 42, "rule_id": "SQL-001",
     "severity": "CRITICAL", "description": "SQL injection"},
    {"path": "app/utils.py", "line": 10, "rule_id": "XSS-001",
     "severity": "HIGH", "description": "Reflected XSS"},
    {"path": "app/auth.py", "line": 99, "rule_id": "AUTH-001",
     "severity": "MEDIUM", "description": "Weak password hash"},
]


def test_record_scan():
    mem, root = _tmp_memory()
    try:
        mem.record_scan(SAMPLE_FINDINGS, scan_type="check", paths=["app/"])
        stats = mem.get_stats()
        assert stats["total_scans"] == 1
        assert stats["total_findings"] == 3
        assert "SQL-001" in stats["rule_counts"]
    finally:
        _cleanup(root)


def test_scan_history():
    mem, root = _tmp_memory()
    try:
        mem.record_scan(SAMPLE_FINDINGS[:1])
        mem.record_scan(SAMPLE_FINDINGS[1:])
        history = mem.get_scan_history()
        assert len(history) == 2
        assert history[0]["total_findings"] == 1
        assert history[1]["total_findings"] == 2
    finally:
        _cleanup(root)


def test_feedback_tp():
    mem, root = _tmp_memory()
    try:
        h = memory._finding_hash(SAMPLE_FINDINGS[0])
        mem.feedback(h, "tp", reason="confirmed exploitable")
        summary = mem.get_feedback_summary()
        assert summary["true_positives"] == 1
        assert summary["false_positives"] == 0
    finally:
        _cleanup(root)


def test_feedback_fp():
    mem, root = _tmp_memory()
    try:
        h = memory._finding_hash(SAMPLE_FINDINGS[0])
        mem.feedback(h, "fp", reason="test helper")
        summary = mem.get_feedback_summary()
        assert summary["false_positives"] == 1
    finally:
        _cleanup(root)


def test_feedback_invalid_verdict():
    mem, root = _tmp_memory()
    try:
        try:
            mem.feedback("abc", "invalid")
            assert False, "should have raised"
        except ValueError:
            pass
    finally:
        _cleanup(root)


def test_feedback_finding():
    mem, root = _tmp_memory()
    try:
        mem.record_scan(SAMPLE_FINDINGS)
        mem.feedback_finding(SAMPLE_FINDINGS[0], "tp")
        mem.feedback_finding(SAMPLE_FINDINGS[1], "fp")
        stats = mem.get_stats()
        assert stats["rule_counts"]["SQL-001"]["tp"] == 1
        assert stats["rule_counts"]["XSS-001"]["fp"] == 1
    finally:
        _cleanup(root)


def test_is_suppressed():
    mem, root = _tmp_memory()
    try:
        mem.feedback_finding(SAMPLE_FINDINGS[0], "fp")
        assert mem.is_suppressed(SAMPLE_FINDINGS[0])
        assert not mem.is_suppressed(SAMPLE_FINDINGS[1])
    finally:
        _cleanup(root)


def test_filter_findings_suppresses_fp():
    mem, root = _tmp_memory()
    try:
        mem.feedback_finding(SAMPLE_FINDINGS[0], "fp")
        filtered = mem.filter_findings(SAMPLE_FINDINGS)
        assert len(filtered) == 2
        paths = [f["path"] for f in filtered]
        assert "app/views.py" not in paths
    finally:
        _cleanup(root)


def test_filter_findings_marks_confirmed():
    mem, root = _tmp_memory()
    try:
        mem.feedback_finding(SAMPLE_FINDINGS[0], "tp")
        filtered = mem.filter_findings(SAMPLE_FINDINGS)
        sql_finding = [f for f in filtered if f["rule_id"] == "SQL-001"][0]
        assert sql_finding.get("memory_confirmed") is True
    finally:
        _cleanup(root)


def test_filter_findings_marks_hotspot():
    mem, root = _tmp_memory()
    try:
        for _ in range(5):
            mem.record_scan(SAMPLE_FINDINGS[:1])
        filtered = mem.filter_findings(SAMPLE_FINDINGS[:1])
        assert filtered[0].get("memory_hotspot") is True
    finally:
        _cleanup(root)


def test_filter_findings_marks_noisy_rule():
    mem, root = _tmp_memory()
    try:
        mem.record_scan(SAMPLE_FINDINGS)
        for _ in range(5):
            mem.feedback_finding(
                {"path": f"f{_}.py", "line": _, "rule_id": "XSS-001"},
                "fp")
        filtered = mem.filter_findings(SAMPLE_FINDINGS)
        xss = [f for f in filtered if f["rule_id"] == "XSS-001"][0]
        assert xss.get("memory_low_precision") is True
    finally:
        _cleanup(root)


def test_learn_patterns():
    mem, root = _tmp_memory()
    try:
        pyfile = os.path.join(root, "app.py")
        with open(pyfile, "w") as f:
            f.write("import os\nimport json\nfrom pathlib import Path\n")
        mem.learn_patterns([root])
        patterns = mem.get_patterns()
        assert "python" in patterns.get("frameworks", []) or \
               "os" in patterns.get("top_imports", {})
    finally:
        _cleanup(root)


def test_learn_patterns_detects_node():
    mem, root = _tmp_memory()
    try:
        pkg = os.path.join(root, "package.json")
        with open(pkg, "w") as f:
            json.dump({"dependencies": {"react": "^18"}}, f)
        mem.learn_patterns([root])
        patterns = mem.get_patterns()
        assert "node" in patterns["frameworks"]
        assert "react" in patterns["frameworks"]
    finally:
        _cleanup(root)


def test_hotspot_files():
    mem, root = _tmp_memory()
    try:
        findings = [
            {"path": "a.py", "line": 1, "rule_id": "R1", "severity": "HIGH"},
            {"path": "a.py", "line": 2, "rule_id": "R2", "severity": "HIGH"},
            {"path": "b.py", "line": 1, "rule_id": "R1", "severity": "LOW"},
        ]
        mem.record_scan(findings)
        hotspots = mem.get_hotspot_files()
        assert len(hotspots) >= 1
    finally:
        _cleanup(root)


def test_noisy_rules():
    mem, root = _tmp_memory()
    try:
        mem.record_scan(SAMPLE_FINDINGS)
        for i in range(3):
            mem.feedback_finding(
                {"path": f"x{i}.py", "line": i, "rule_id": "AUTH-001"},
                "fp")
        noisy = mem.get_noisy_rules()
        rules = [n["rule"] for n in noisy]
        assert "AUTH-001" in rules
    finally:
        _cleanup(root)


def test_clear():
    mem, root = _tmp_memory()
    try:
        mem.record_scan(SAMPLE_FINDINGS)
        mem.feedback_finding(SAMPLE_FINDINGS[0], "tp")
        mem.clear()
        assert mem.get_stats() == {}
        assert mem.get_feedback_summary()["total"] == 0
        assert mem.get_scan_history() == []
    finally:
        _cleanup(root)


def test_render():
    mem, root = _tmp_memory()
    try:
        mem.record_scan(SAMPLE_FINDINGS)
        text = mem.render()
        assert "Total scans" in text
        assert "Total findings" in text
    finally:
        _cleanup(root)


def test_to_dict():
    mem, root = _tmp_memory()
    try:
        mem.record_scan(SAMPLE_FINDINGS)
        d = memory.to_dict(mem)
        assert "stats" in d
        assert "feedback" in d
        assert "patterns" in d
        assert "hotspots" in d
        assert "noisy_rules" in d
        assert "recent_scans" in d
    finally:
        _cleanup(root)


def test_finding_hash_deterministic():
    h1 = memory._finding_hash(SAMPLE_FINDINGS[0])
    h2 = memory._finding_hash(SAMPLE_FINDINGS[0])
    assert h1 == h2
    assert len(h1) == 16


def test_finding_hash_different_findings():
    h1 = memory._finding_hash(SAMPLE_FINDINGS[0])
    h2 = memory._finding_hash(SAMPLE_FINDINGS[1])
    assert h1 != h2


def test_persistence():
    root = tempfile.mkdtemp(prefix="attestor_mem_persist_")
    try:
        mem1 = memory.Memory(root)
        mem1.record_scan(SAMPLE_FINDINGS)
        mem1.feedback_finding(SAMPLE_FINDINGS[0], "tp")

        mem2 = memory.Memory(root)
        stats = mem2.get_stats()
        assert stats["total_scans"] == 1
        fb = mem2.get_feedback_summary()
        assert fb["true_positives"] == 1
    finally:
        _cleanup(root)


def test_empty_memory():
    mem, root = _tmp_memory()
    try:
        assert mem.get_stats() == {}
        assert mem.get_feedback_summary()["total"] == 0
        assert mem.get_scan_history() == []
        assert mem.get_patterns() == {}
        assert mem.get_hotspot_files() == []
        assert mem.get_noisy_rules() == []
    finally:
        _cleanup(root)


def test_precision_calculation():
    mem, root = _tmp_memory()
    try:
        mem.record_scan(SAMPLE_FINDINGS)
        mem.feedback_finding(SAMPLE_FINDINGS[0], "tp")
        mem.feedback_finding(SAMPLE_FINDINGS[1], "fp")
        fb = mem.get_feedback_summary()
        assert fb["precision"] == 0.5
    finally:
        _cleanup(root)


def test_does_not_modify_original_findings():
    mem, root = _tmp_memory()
    try:
        original = [dict(f) for f in SAMPLE_FINDINGS]
        mem.filter_findings(SAMPLE_FINDINGS)
        for orig, sample in zip(original, SAMPLE_FINDINGS):
            assert orig == sample
    finally:
        _cleanup(root)
