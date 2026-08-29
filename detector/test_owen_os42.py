#!/usr/bin/env python3
"""Tests for OwenOS -- the self-improving operating system for Attestor."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import owen_os42 as oos  # noqa: E402


def _make_os() -> oos.OwenOS:
    owen = oos.OwenOS()
    owen.boot()
    return owen


def _sample_findings(n: int = 10) -> list[dict]:
    findings = []
    for i in range(n):
        findings.append({
            "rule": "java-sql-injection",
            "cwe": "CWE-89",
            "path": "src/Dao%d.java" % i,
            "line": 42 + i,
            "severity": "HIGH",
            "language": "java",
            "snippet": 'stmt = conn.prepareStatement("SELECT * FROM users WHERE id=" + userId)',
        })
    return findings


# --------------------------------------------------------------------------- #
# Kernel
# --------------------------------------------------------------------------- #

class KernelTests(unittest.TestCase):

    def test_spawn_and_complete(self):
        k = oos.Kernel()
        proc = k.spawn("test-task", "scan")
        self.assertEqual(oos.ProcessState.QUEUED, proc.state)
        k.start(proc.pid)
        self.assertEqual(oos.ProcessState.RUNNING, proc.state)
        k.complete(proc.pid, {"result": "ok"})
        self.assertEqual(oos.ProcessState.COMPLETED, proc.state)
        self.assertIsNotNone(proc.finished_at)

    def test_fail(self):
        k = oos.Kernel()
        proc = k.spawn("bad-task", "scan")
        k.start(proc.pid)
        k.fail(proc.pid, "something broke")
        self.assertEqual(oos.ProcessState.FAILED, proc.state)
        self.assertEqual("something broke", proc.error)

    def test_ps_filters(self):
        k = oos.Kernel()
        k.spawn("a", "scan")
        k.spawn("b", "analyze")
        p3 = k.spawn("c", "scan")
        k.start(p3.pid)
        self.assertEqual(2, len(k.ps(state=oos.ProcessState.QUEUED)))
        self.assertEqual(1, len(k.ps(state=oos.ProcessState.RUNNING)))
        self.assertEqual(2, len(k.ps(kind="scan")))

    def test_generation_advances(self):
        k = oos.Kernel()
        self.assertEqual(0, k.generation)
        k.advance_generation()
        self.assertEqual(1, k.generation)

    def test_stats(self):
        k = oos.Kernel()
        k.spawn("a", "scan")
        k.spawn("b", "scan")
        stats = k.stats()
        self.assertEqual(2, stats["total"])
        self.assertEqual(2, stats["QUEUED"])


class EventBusTests(unittest.TestCase):

    def test_publish_subscribe(self):
        bus = oos.EventBus()
        received = []
        bus.subscribe("test.event", lambda e: received.append(e))
        bus.publish(oos.Event("test.event", "test", {"value": 42}))
        self.assertEqual(1, len(received))
        self.assertEqual(42, received[0].data["value"])

    def test_wildcard_subscriber(self):
        bus = oos.EventBus()
        received = []
        bus.subscribe("*", lambda e: received.append(e))
        bus.publish(oos.Event("a", "test"))
        bus.publish(oos.Event("b", "test"))
        self.assertEqual(2, len(received))

    def test_history(self):
        bus = oos.EventBus()
        bus.publish(oos.Event("a", "test"))
        bus.publish(oos.Event("b", "test"))
        bus.publish(oos.Event("a", "test"))
        self.assertEqual(3, len(bus.history()))
        self.assertEqual(2, len(bus.history(kind="a")))


# --------------------------------------------------------------------------- #
# Knowledge Store
# --------------------------------------------------------------------------- #

class KnowledgeStoreTests(unittest.TestCase):

    def test_add_and_retrieve_finding(self):
        ks = oos.KnowledgeStore()
        sf = oos.StoredFinding(rule="sqli", cwe="CWE-89",
                                file_path="x.java", line=10,
                                severity="HIGH")
        fp = ks.add_finding(sf)
        self.assertIsNotNone(fp)
        self.assertEqual(sf, ks.get_finding(fp))

    def test_mark_verified(self):
        ks = oos.KnowledgeStore()
        sf = oos.StoredFinding(rule="sqli", cwe="CWE-89",
                                file_path="x.java", line=10,
                                severity="HIGH")
        fp = ks.add_finding(sf)
        ks.mark_verified(fp, True)
        self.assertTrue(ks.get_finding(fp).poc_verified)

    def test_mark_false_positive(self):
        ks = oos.KnowledgeStore()
        sf = oos.StoredFinding(rule="sqli", cwe="CWE-89",
                                file_path="x.java", line=10,
                                severity="HIGH")
        fp = ks.add_finding(sf)
        ks.mark_verified(fp, False)
        self.assertTrue(ks.get_finding(fp).false_positive)

    def test_findings_filter(self):
        ks = oos.KnowledgeStore()
        ks.add_finding(oos.StoredFinding(rule="a", cwe="CWE-89",
                                          file_path="a.java", line=1,
                                          severity="HIGH", poc_verified=True))
        ks.add_finding(oos.StoredFinding(rule="b", cwe="CWE-79",
                                          file_path="b.java", line=2,
                                          severity="MEDIUM"))
        self.assertEqual(2, len(ks.findings()))
        self.assertEqual(1, len(ks.findings(cwe="CWE-89")))
        self.assertEqual(1, len(ks.findings(verified_only=True)))

    def test_false_positive_rate(self):
        ks = oos.KnowledgeStore()
        for i in range(8):
            ks.add_finding(oos.StoredFinding(
                rule="r", cwe="CWE-89", file_path="f%d.java" % i,
                line=i, severity="HIGH"))
        for i in range(2):
            ks.add_finding(oos.StoredFinding(
                rule="r", cwe="CWE-89", file_path="fp%d.java" % i,
                line=i, severity="HIGH", false_positive=True))
        self.assertAlmostEqual(0.2, ks.false_positive_rate(), places=2)

    def test_pattern_precision(self):
        ks = oos.KnowledgeStore()
        dp = oos.DetectionPattern(
            pattern_id="test", cwe="CWE-89", language="java",
            regex=r"\bexecute\b", description="test",
            source="mined", hit_count=8, false_positive_count=2)
        ks.add_pattern(dp)
        self.assertAlmostEqual(0.8, dp.precision, places=2)
        self.assertTrue(dp.is_reliable)

    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as td:
            ks = oos.KnowledgeStore(td)
            ks.add_finding(oos.StoredFinding(
                rule="sqli", cwe="CWE-89", file_path="x.java",
                line=10, severity="HIGH"))
            ks.add_pattern(oos.DetectionPattern(
                pattern_id="p1", cwe="CWE-89", language="java",
                regex=r"\bfoo\b", description="test", source="mined"))
            ks.record_metric("accuracy", 0.95)
            ks.save()

            ks2 = oos.KnowledgeStore(td)
            ks2.load()
            self.assertEqual(1, ks2.finding_count())
            self.assertEqual(1, len(ks2.patterns()))
            self.assertEqual(1, len(ks2.get_metrics("accuracy")))

    def test_metric_trend(self):
        ks = oos.KnowledgeStore()
        for v in [0.7, 0.75, 0.8, 0.85, 0.9]:
            ks.record_metric("accuracy", v)
        self.assertEqual("improving", ks.metric_trend("accuracy"))

    def test_coverage_entry(self):
        e = oos.CoverageEntry(cwe="CWE-89", cwe_num=89,
                               has_detection=True, has_poc=True,
                               has_patch=True, has_regression=True)
        self.assertTrue(e.is_complete)
        self.assertEqual(1.0, e.completeness)

    def test_coverage_gaps(self):
        ks = oos.KnowledgeStore()
        ks.update_coverage(oos.CoverageEntry(cwe="CWE-89", cwe_num=89,
                                              has_detection=True))
        ks.update_coverage(oos.CoverageEntry(cwe="CWE-79", cwe_num=79,
                                              has_detection=True, has_poc=True,
                                              has_patch=True, has_regression=True))
        gaps = ks.coverage_gaps()
        self.assertEqual(1, len(gaps))
        self.assertEqual("CWE-89", gaps[0].cwe)


# --------------------------------------------------------------------------- #
# Module Registry
# --------------------------------------------------------------------------- #

class ModuleRegistryTests(unittest.TestCase):

    def test_register_and_get(self):
        reg = oos.ModuleRegistry()

        class FakeModule:
            VERSION = "1.0"

            @staticmethod
            def supported_cwes():
                return (89, 79, 78)

        entry = reg.register("fake", oos.ModuleKind.SCANNER, FakeModule)
        self.assertEqual((89, 79, 78), entry.supported_cwes)
        self.assertEqual(entry, reg.get("fake"))

    def test_by_kind(self):
        reg = oos.ModuleRegistry()

        class FakeScan:
            pass

        class FakePoc:
            pass

        reg.register("scan", oos.ModuleKind.SCANNER, FakeScan)
        reg.register("poc", oos.ModuleKind.POC_GENERATOR, FakePoc)
        self.assertEqual(1, len(reg.by_kind(oos.ModuleKind.SCANNER)))
        self.assertEqual(1, len(reg.by_kind(oos.ModuleKind.POC_GENERATOR)))

    def test_coverage_matrix(self):
        reg = oos.ModuleRegistry()

        class Scan:
            @staticmethod
            def supported_cwes():
                return (89, 79)

        class Poc:
            @staticmethod
            def supported_cwes():
                return (89,)

        reg.register("scan", oos.ModuleKind.SCANNER, Scan)
        reg.register("poc", oos.ModuleKind.POC_GENERATOR, Poc)
        matrix = reg.cwe_coverage_matrix()
        self.assertTrue(matrix[89]["scanner"])
        self.assertTrue(matrix[89]["poc_generator"])
        self.assertTrue(matrix[79]["scanner"])
        self.assertFalse(matrix[79]["poc_generator"])


# --------------------------------------------------------------------------- #
# Gap Analyzer
# --------------------------------------------------------------------------- #

class GapAnalyzerTests(unittest.TestCase):

    def test_finds_missing_poc(self):
        reg = oos.ModuleRegistry()

        class Scan:
            @staticmethod
            def supported_cwes():
                return (89, 79, 200)

        class Poc:
            @staticmethod
            def supported_cwes():
                return (89, 79)

        reg.register("scan", oos.ModuleKind.SCANNER, Scan)
        reg.register("poc", oos.ModuleKind.POC_GENERATOR, Poc)

        ga = oos.GapAnalyzer(reg, oos.KnowledgeStore())
        gaps = ga.analyze()
        poc_gaps = [g for g in gaps if g.gap_type == "no_poc"]
        self.assertTrue(any(g.cwe == 200 for g in poc_gaps))

    def test_finds_missing_patch(self):
        reg = oos.ModuleRegistry()

        class Scan:
            @staticmethod
            def supported_cwes():
                return (89,)

        reg.register("scan", oos.ModuleKind.SCANNER, Scan)

        ga = oos.GapAnalyzer(reg, oos.KnowledgeStore())
        gaps = ga.analyze()
        patch_gaps = [g for g in gaps if g.gap_type == "no_patch"]
        self.assertTrue(any(g.cwe == 89 for g in patch_gaps))

    def test_uncovered_cwes(self):
        reg = oos.ModuleRegistry()

        class Scan:
            @staticmethod
            def supported_cwes():
                return (89,)

        reg.register("scan", oos.ModuleKind.SCANNER, Scan)

        ga = oos.GapAnalyzer(reg, oos.KnowledgeStore())
        uncovered = ga.uncovered_cwes([89, 79, 78])
        self.assertIn(79, uncovered)
        self.assertIn(78, uncovered)
        self.assertNotIn(89, uncovered)


# --------------------------------------------------------------------------- #
# Pattern Miner
# --------------------------------------------------------------------------- #

class PatternMinerTests(unittest.TestCase):

    def test_mines_from_verified_findings(self):
        ks = oos.KnowledgeStore()
        for i in range(5):
            ks.add_finding(oos.StoredFinding(
                rule="sqli", cwe="CWE-89",
                file_path="f%d.java" % i, line=i, severity="HIGH",
                language="java", poc_verified=True,
                snippet='stmt.execute("SELECT * FROM users WHERE id=" + input)'))

        miner = oos.PatternMiner(ks)
        patterns = miner.mine_from_findings("CWE-89")
        self.assertTrue(len(patterns) >= 1)
        for p in patterns:
            self.assertEqual("CWE-89", p.cwe)
            self.assertEqual("mined", p.source)

    def test_needs_minimum_samples(self):
        ks = oos.KnowledgeStore()
        ks.add_finding(oos.StoredFinding(
            rule="sqli", cwe="CWE-89", file_path="f.java",
            line=1, severity="HIGH", poc_verified=True,
            snippet="x"))

        miner = oos.PatternMiner(ks)
        patterns = miner.mine_from_findings("CWE-89")
        self.assertEqual(0, len(patterns))

    def test_extracts_sink_patterns(self):
        ks = oos.KnowledgeStore()
        for i in range(5):
            ks.add_finding(oos.StoredFinding(
                rule="sqli", cwe="CWE-89",
                file_path="f%d.java" % i, line=i, severity="HIGH",
                language="java", poc_verified=True,
                snippet='conn.executeQuery(query)'))

        miner = oos.PatternMiner(ks)
        patterns = miner.mine_from_findings("CWE-89")
        sink_patterns = [p for p in patterns if "sink" in p.pattern_id]
        self.assertTrue(len(sink_patterns) >= 1)


# --------------------------------------------------------------------------- #
# Template Generator
# --------------------------------------------------------------------------- #

class TemplateGeneratorTests(unittest.TestCase):

    def test_generates_poc_skeleton(self):
        reg = oos.ModuleRegistry()
        ks = oos.KnowledgeStore()
        tg = oos.TemplateGenerator(reg, ks)

        code = tg.generate_poc_skeleton(200, [])
        self.assertIn("CWE-200", code)
        self.assertIn("__main__", code)
        self.assertIn("sys.exit", code)

    def test_generates_patch_skeleton(self):
        reg = oos.ModuleRegistry()
        ks = oos.KnowledgeStore()
        tg = oos.TemplateGenerator(reg, ks)

        code = tg.generate_patch_skeleton(200, "java", [])
        self.assertIn("CWE-200", code)
        self.assertIn("java", code)

    def test_generates_regression_skeleton(self):
        reg = oos.ModuleRegistry()
        ks = oos.KnowledgeStore()
        tg = oos.TemplateGenerator(reg, ks)

        code = tg.generate_regression_skeleton(200, [])
        self.assertIn("CWE200", code)
        self.assertIn("unittest", code)
        self.assertIn("__main__", code)

    def test_detection_rule_from_pattern(self):
        reg = oos.ModuleRegistry()
        ks = oos.KnowledgeStore()
        tg = oos.TemplateGenerator(reg, ks)

        dp = oos.DetectionPattern(
            pattern_id="test-rule", cwe="CWE-89", language="java",
            regex=r"\bexecuteQuery\b", description="test",
            source="mined", hit_count=10)
        rule = tg.generate_detection_rule(dp)
        self.assertIn("test-rule", rule)
        self.assertIn("CWE-89", rule)


# --------------------------------------------------------------------------- #
# Self-Test Engine
# --------------------------------------------------------------------------- #

class SelfTestTests(unittest.TestCase):

    def test_valid_pattern(self):
        ks = oos.KnowledgeStore()
        engine = oos.SelfTestEngine(ks)

        dp = oos.DetectionPattern(
            pattern_id="test", cwe="CWE-89", language="java",
            regex=r"\bexecuteQuery\s*\(", description="test",
            source="mined")

        result = engine.test_detection_pattern(
            dp,
            known_vulnerable=["conn.executeQuery(sql)", "stmt.executeQuery(q)"],
            known_safe=["conn.prepareStatement(sql)", "int x = 5"],
        )
        self.assertEqual(oos.SelfTestResult.PASS, result.result)

    def test_invalid_regex_fails(self):
        ks = oos.KnowledgeStore()
        engine = oos.SelfTestEngine(ks)

        dp = oos.DetectionPattern(
            pattern_id="bad", cwe="CWE-89", language="java",
            regex=r"[unterminated", description="bad",
            source="mined")
        result = engine.test_detection_pattern(dp)
        self.assertEqual(oos.SelfTestResult.FAIL, result.result)

    def test_valid_generated_code(self):
        ks = oos.KnowledgeStore()
        engine = oos.SelfTestEngine(ks)

        code = (
            '#!/usr/bin/env python3\n'
            'import sys\n'
            'if __name__ == "__main__":\n'
            '    sys.exit(0)\n'
        )
        result = engine.test_generated_code(code)
        self.assertEqual(oos.SelfTestResult.PASS, result.result)

    def test_syntax_error_fails(self):
        ks = oos.KnowledgeStore()
        engine = oos.SelfTestEngine(ks)

        result = engine.test_generated_code("def broken(")
        self.assertEqual(oos.SelfTestResult.FAIL, result.result)

    def test_unfilled_placeholders_fail(self):
        ks = oos.KnowledgeStore()
        engine = oos.SelfTestEngine(ks)

        code = 'import sys\nprint("%%ENDPOINT%%")\nif __name__ == "__main__":\n    sys.exit(0)\n'
        result = engine.test_generated_code(code)
        self.assertEqual(oos.SelfTestResult.FAIL, result.result)

    def test_pass_rate(self):
        ks = oos.KnowledgeStore()
        engine = oos.SelfTestEngine(ks)

        engine.test_generated_code('import sys\nif __name__ == "__main__":\n    sys.exit(0)\n')
        engine.test_generated_code("def broken(")
        self.assertAlmostEqual(0.5, engine.pass_rate(), places=2)


# --------------------------------------------------------------------------- #
# Improvement Engine
# --------------------------------------------------------------------------- #

class ImprovementEngineTests(unittest.TestCase):

    def test_run_cycle_produces_improvements(self):
        owen = _make_os()
        owen.ingest_findings(_sample_findings(10))
        for fp in list(owen.knowledge._findings.keys())[:5]:
            owen.verify_finding(fp, True)

        improvements = owen.evolve()
        self.assertIsInstance(improvements, list)
        self.assertTrue(owen.kernel.generation >= 1)

    def test_gap_analysis_with_real_modules(self):
        owen = _make_os()
        gaps = owen.gaps()
        self.assertIsInstance(gaps, list)

    def test_improvement_plan(self):
        owen = _make_os()
        plan = owen.improvement_plan(5)
        self.assertTrue(len(plan) <= 5)


# --------------------------------------------------------------------------- #
# Evolution Tracker
# --------------------------------------------------------------------------- #

class EvolutionTests(unittest.TestCase):

    def test_snapshot(self):
        owen = _make_os()
        snap = owen.evolution.snapshot(0)
        self.assertEqual(0, snap.generation)
        self.assertTrue(snap.total_cwes_covered >= 0)

    def test_delta(self):
        owen = _make_os()
        owen.evolution.snapshot(0)
        owen.ingest_findings(_sample_findings(5))
        owen.evolution.snapshot(1)
        delta = owen.evolution.delta(0, 1)
        self.assertIn("findings", delta)

    def test_is_improving_defaults_true(self):
        owen = _make_os()
        self.assertTrue(owen.evolution.is_improving())


# --------------------------------------------------------------------------- #
# OwenOS Integration
# --------------------------------------------------------------------------- #

class OwenOSIntegration(unittest.TestCase):

    def test_boot_loads_modules(self):
        owen = _make_os()
        status = owen.status()
        self.assertTrue(status["modules"] >= 3)

    def test_ingest_findings(self):
        owen = _make_os()
        count = owen.ingest_findings(_sample_findings(5))
        self.assertEqual(5, count)
        self.assertEqual(5, owen.status()["total_findings"])

    def test_coverage_report(self):
        owen = _make_os()
        matrix = owen.coverage_report()
        self.assertIsInstance(matrix, dict)
        if 89 in matrix:
            self.assertIn("poc_generator", matrix[89])

    def test_full_evolution_cycle(self):
        owen = _make_os()
        owen.ingest_findings(_sample_findings(10))
        for fp in list(owen.knowledge._findings.keys()):
            owen.verify_finding(fp, True)

        improvements = owen.evolve()
        status = owen.status()
        self.assertEqual(1, status["generation"])
        self.assertTrue(status["total_findings"] >= 10)

    def test_multiple_generations(self):
        owen = _make_os()
        owen.ingest_findings(_sample_findings(5))
        owen.evolve()
        owen.ingest_findings(_sample_findings(5))
        owen.evolve()
        self.assertEqual(2, owen.kernel.generation)
        self.assertEqual(4, len(owen.evolution.history()))

    def test_event_bus_records_lifecycle(self):
        owen = _make_os()
        events = owen.kernel.bus.history()
        boot_events = [e for e in events if e.kind == "os.boot"]
        self.assertTrue(len(boot_events) >= 1)

    def test_persist_and_restore(self):
        with tempfile.TemporaryDirectory() as td:
            owen = oos.OwenOS(td)
            owen.boot()
            owen.ingest_findings(_sample_findings(3))
            owen.shutdown(persist=True)

            owen2 = oos.OwenOS(td)
            owen2.boot()
            self.assertEqual(3, owen2.knowledge.finding_count())

    def test_repr(self):
        owen = _make_os()
        r = repr(owen)
        self.assertIn("OwenOS", r)
        self.assertIn("gen=", r)

    def test_shutdown_publishes_event(self):
        owen = _make_os()
        owen.shutdown(persist=False)
        events = owen.kernel.bus.history(kind="os.shutdown")
        self.assertTrue(len(events) >= 1)


if __name__ == "__main__":
    unittest.main()
