#!/usr/bin/env python3
import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


import detect
import threat_model42 as tm


class ThreatModelValidation(unittest.TestCase):
    def _model(self):
        return tm.model_component(
            name="owen-desktop-4.3",
            description="loopback-only offline cyber analysis desktop",
            boundaries=["loopback-only", "token-bound"],
            assets=["case files", "reports"],
            entry_points=["http://127.0.0.1:8788/?token="],
        )

    def test_model_is_stride_hypothesis(self):
        m = self._model()
        self.assertEqual(m["schema"], tm.MODEL_SCHEMA)
        self.assertEqual(len(m["threats"]), len(tm.STRIDE))
        for t in m["threats"]:
            self.assertEqual(t["basis"], "hypothesis")
            self.assertTrue(t["considered"])

    def test_model_rejects_empty_boundary(self):
        with self.assertRaises(tm.ThreatModelError):
            tm.model_component(name="x", description="d",
                               boundaries=[], assets=["a"], entry_points=["e"])

    def test_model_rejects_bad_id(self):
        with self.assertRaises(tm.ThreatModelError):
            tm.model_component(name="bad id!", description="d",
                               boundaries=["b"], assets=["a"], entry_points=["e"])

    def test_findings_link_to_threats_measured(self):
        m = self._model()
        findings = [
            {"rule": "asm-stack-pivot", "line": 10, "severity": "high"},
            {"rule": "asm-direct-execve", "line": 20, "severity": "critical"},
            {"rule": "cpp-command-injection", "line": 30, "severity": "high"},
        ]
        links = tm.map_findings_to_threats(m, findings)
        cats = {l["category"] for l in links}
        self.assertIn("elevation_of_privilege", cats)
        self.assertIn("tampering", cats)
        for l in links:
            self.assertEqual(l["basis"], "measured")

    def test_investigate_builds_intact_chain(self):
        m = self._model()
        sha = hashlib.sha256(b"sample").hexdigest()
        findings = [{"rule": "asm-direct-execve", "line": 5, "severity": "critical"}]
        result = tm.investigate(model=m, findings=findings,
                                subject_path="asm_challenge_500.asm", subject_sha256=sha)
        self.assertTrue(result["chain_intact"])
        self.assertEqual(result["measured_finding_count"], 1)
        self.assertTrue(result["threat_links"])

    def test_investigate_rejects_non_model(self):
        with self.assertRaises(tm.ThreatModelError):
            tm.map_findings_to_threats({"schema": "wrong"}, [])

    def test_investigate_rejects_bad_sha(self):
        m = self._model()
        with self.assertRaises(tm.ThreatModelError):
            tm.investigate(model=m, findings=[], subject_path="x.asm",
                           subject_sha256="not-a-digest")


class IncidentOnRealFixture(unittest.TestCase):
    def test_cpp_fixture_incident(self):
        import pathlib
        p = pathlib.Path(detect.__file__).parents[3] / "Owen-Desktop-Cyber-4.3" \
            / "challenges" / "cpp_challenge_200.cpp"
        if not p.exists():
            p = pathlib.Path("C:/Users/mange/OneDrive/Documents/Codex/OnlineCompliancePortal/"
                             "Owen-Desktop-Cyber-4.3/challenges/cpp_challenge_200.cpp")
        text = p.read_text(encoding="utf-8")
        sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
        findings = [{"rule": f.rule, "line": f.line, "severity": f.severity}
                    for f in detect.scan_source(text, p.name, "cpp", deep=True)]
        m = tm.model_component(
            name="cpp-challenge", description="synthetic cpp fixture",
            boundaries=["owned"], assets=["fixture"], entry_points=["file"])
        result = tm.investigate(model=m, findings=findings, subject_path=p.name,
                                subject_sha256=sha, title="cpp-fixture-incident")
        self.assertTrue(result["chain_intact"])
        self.assertGreater(result["measured_finding_count"], 0)
        self.assertTrue(result["threat_links"])
        self.assertTrue(
            {l["category"] for l in result["threat_links"]} <= set(tm.STRIDE))


if __name__ == "__main__":
    unittest.main(verbosity=2)
