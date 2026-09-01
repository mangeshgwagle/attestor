"""Tests for feedback-to-training pipeline."""
import json
import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "training"))
import memory
import feedback_to_training as fbt


def _setup_project_with_feedback():
    root = tempfile.mkdtemp(prefix="attestor_fbt_")
    src_dir = os.path.join(root, "app")
    os.makedirs(src_dir)

    with open(os.path.join(src_dir, "views.py"), "w") as f:
        for i in range(50):
            f.write(f"line_{i} = {i}  # code line\n")

    mem = memory.Memory(root)
    finding_tp = {"path": "app/views.py", "line": 25, "rule_id": "SQL-001",
                  "severity": "CRITICAL", "description": "SQL injection",
                  "cwe": "CWE-89", "category": "sql_injection"}
    finding_fp = {"path": "app/views.py", "line": 10, "rule_id": "XSS-001",
                  "severity": "HIGH", "description": "XSS in template",
                  "category": "xss"}

    mem.record_scan([finding_tp, finding_fp])
    mem.feedback_finding(finding_tp, "tp", reason="confirmed via manual test")
    mem.feedback_finding(finding_fp, "fp", reason="auto-escaped by template engine")
    return root, mem


def test_extract_feedback_pairs():
    root, _ = _setup_project_with_feedback()
    try:
        pairs, stats = fbt.extract_feedback_pairs(root)
        assert isinstance(pairs, list)
    finally:
        shutil.rmtree(root)


def test_read_code_context():
    root = tempfile.mkdtemp()
    try:
        src = os.path.join(root, "test.py")
        with open(src, "w") as f:
            for i in range(30):
                f.write(f"x_{i} = {i}\n")
        from pathlib import Path
        code = fbt._read_code_context(Path(root), "test.py", 15)
        assert "x_14" in code
    finally:
        shutil.rmtree(root)


def test_read_code_context_missing():
    root = tempfile.mkdtemp()
    try:
        from pathlib import Path
        code = fbt._read_code_context(Path(root), "missing.py", 10)
        assert code == ""
    finally:
        shutil.rmtree(root)


def test_generate_rule_calibration():
    root = tempfile.mkdtemp()
    try:
        mem = memory.Memory(root)
        findings = [
            {"path": "a.py", "line": i, "rule_id": "NOISE-001",
             "severity": "LOW"} for i in range(10)
        ]
        mem.record_scan(findings)
        for i in range(8):
            mem.feedback_finding(
                {"path": f"x{i}.py", "line": i, "rule_id": "NOISE-001"}, "fp")
        for i in range(2):
            mem.feedback_finding(
                {"path": f"y{i}.py", "line": i, "rule_id": "NOISE-001"}, "tp")

        pairs = fbt.generate_rule_calibration_pairs(root)
        assert len(pairs) >= 1
        assert any("NOISE-001" in p["instruction"] for p in pairs)
        assert any("LOW confidence" in p["output"] for p in pairs)
    finally:
        shutil.rmtree(root)


def test_calibration_no_noisy_rules():
    root = tempfile.mkdtemp()
    try:
        mem = memory.Memory(root)
        pairs = fbt.generate_rule_calibration_pairs(root)
        assert pairs == []
    finally:
        shutil.rmtree(root)


def test_tp_output_format():
    output = fbt.TP_OUTPUT.format(
        category="sql_injection", cwe="CWE-89", severity="CRITICAL",
        description="SQL injection", line=42, reason="confirmed")
    assert "CATEGORY: sql_injection" in output
    assert "CWE: CWE-89" in output
    assert "EXPLOITABLE: YES" in output


def test_fp_output_format():
    output = fbt.FP_OUTPUT.format(
        rule_id="XSS-001", reason="template auto-escapes",
        explanation="uses Django's auto-escaping")
    assert "FALSE POSITIVE" in output
    assert "XSS-001" in output


def test_empty_feedback():
    root = tempfile.mkdtemp()
    try:
        mem = memory.Memory(root)
        pairs, stats = fbt.extract_feedback_pairs(root)
        assert pairs == []
    finally:
        shutil.rmtree(root)
