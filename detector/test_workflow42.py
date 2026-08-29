#!/usr/bin/env python3
import os
import sys
import unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import case_file42 as cf
import workflow42 as wf

class WorkflowHonesty(unittest.TestCase):
    def test_regression_requires_fails_before_fix(self):
        case = wf.create_case(subject_path="a.py", subject_sha256="a"*64, rule="x", summary="t")
        with self.assertRaises(Exception) as cm:
            wf.stage_regression(case, summary="bad", evidence={"passes_after_fix": True})
        self.assertIn("fails_before_fix", str(cm.exception))
        with self.assertRaises(Exception):
            wf.stage_regression(case, summary="bad", evidence={"fails_before_fix": False})

    def test_full_workflow_proven(self):
        case = wf.create_case(subject_path="s.py", subject_sha256="b"*64, rule="py-sql-injection", summary="s")
        case = wf.stage_discovery(case, summary="found", evidence={"status":"observed","finding":"x","unknowns":[]})
        case = wf.stage_validation(case, summary="repro", evidence={"status":"observed","reproduces":True,"unknowns":[]})
        case = wf.stage_remediation(case, summary="fix", evidence={"status":"observed","diff_sha256":"c"*64,"unknowns":[]})
        case = wf.stage_regression(case, summary="reg", evidence={"status":"observed","fails_before_fix":True,"passes_after_fix":True,"unknowns":[]})
        self.assertTrue(cf.is_proven(case))

    def test_exploitability_never_exploitable(self):
        case = wf.create_case(subject_path="s.py", subject_sha256="c"*64, rule="r", summary="t")
        with self.assertRaises(Exception):
            wf.stage_exploitability(case, summary="bad", evidence={"status":"observed","exploitable":True})
        with self.assertRaises(Exception):
            wf.stage_exploitability(case, summary="bad", evidence={"verdict":"exploitable"})

    def test_unknown_is_explicit(self):
        case = wf.create_case(subject_path="s.py", subject_sha256="d"*64, rule="r", summary="t")
        case = wf.stage_discovery(case, summary="no evidence", evidence={})
        self.assertEqual("unknown", case["entries"][0]["evidence"]["status"])
        self.assertTrue(case["entries"][0]["evidence"]["unknowns"])

    def test_orchestrate_chain_intact(self):
        case = wf.create_case(subject_path="s.py", subject_sha256="e"*64, rule="r", summary="t")
        case = wf.orchestrate(case, {
            "discovery": {"summary":"d","evidence":{"status":"observed","finding":"x","unknowns":[]}},
            "validation": {"summary":"v","evidence":{"status":"observed","reproduces":True,"unknowns":[]}},
        })
        ok, _ = cf.verify(case)
        self.assertTrue(ok)

if __name__ == "__main__":
    unittest.main()
