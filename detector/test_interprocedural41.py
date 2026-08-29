#!/usr/bin/env python3
"""Tests for interprocedural41.py -- taint passed in through arguments.

The direction this module adds is the one semantic_graph41 misses: it already
follows taint *returned* from a callee, so these tests deliberately cover the
opposite flow and assert the two engines stay complementary.
"""
import unittest

import interprocedural41 as ip
import semantic_graph41 as sg


def report(source):
    return ip.analyze(source, "sample.py")


class ArgumentFlowTests(unittest.TestCase):
    def test_one_hop_argument_reaches_a_sink(self):
        source = ("import os\n"
                  "def run(part):\n"
                  "    os.system('ls ' + part)\n"
                  "def go():\n"
                  "    run(input())\n")
        found = report(source)["witnesses"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["cwe"], "CWE-78")
        self.assertEqual(found[0]["parameter"], "part")
        self.assertEqual(found[0]["entered_via"]["callee"], "input")

    def test_multiple_hops(self):
        for depth in (2, 3, 5):
            chain = "import os\ndef f0(v):\n    os.system(v)\n"
            for step in range(1, depth):
                chain += "def f%d(v):\n    f%d(v)\n" % (step, step - 1)
            chain += "def go():\n    f%d(input())\n" % (depth - 1)
            with self.subTest(hops=depth):
                self.assertEqual(len(report(chain)["witnesses"]), 1)

    def test_keyword_arguments_are_seen_at_the_sink(self):
        source = ("import subprocess\n"
                  "def run(part):\n"
                  "    subprocess.run(part)\n"
                  "def go():\n"
                  "    run(input())\n")
        self.assertTrue(report(source)["witnesses"])

    def test_each_modeled_sink_family_is_reachable(self):
        for sink, cwe in (("os.system", "CWE-78"), ("eval", "CWE-95"),
                          ("pickle.loads", "CWE-502")):
            source = ("import os, pickle\n"
                      "def run(part):\n"
                      "    %s(part)\n"
                      "def go():\n"
                      "    run(input())\n" % sink)
            with self.subTest(sink=sink):
                found = report(source)["witnesses"]
                self.assertTrue(found)
                self.assertEqual(found[0]["cwe"], cwe)


class NegativeTests(unittest.TestCase):
    def test_a_sanitised_argument_is_not_reported(self):
        source = ("import os\n"
                  "def run(part):\n"
                  "    os.system('ls ' + str(part))\n"
                  "def go():\n"
                  "    run(int(input()))\n")
        self.assertEqual(report(source)["witnesses"], [])

    def test_a_constant_argument_is_not_reported(self):
        source = ("import os\n"
                  "def run(part):\n"
                  "    os.system('ls ' + part)\n"
                  "def go():\n"
                  "    run('safe')\n")
        self.assertEqual(report(source)["witnesses"], [])

    def test_an_unrelated_parameter_is_not_reported(self):
        source = ("import os\n"
                  "def run(tainted, other):\n"
                  "    os.system('ls ' + other)\n"
                  "def go():\n"
                  "    run(input(), 'safe')\n")
        self.assertEqual(report(source)["witnesses"], [])

    def test_no_sink_means_no_witness(self):
        source = ("def run(part):\n"
                  "    return part.upper()\n"
                  "def go():\n"
                  "    run(input())\n")
        self.assertEqual(report(source)["witnesses"], [])


class TerminationTests(unittest.TestCase):
    def test_direct_recursion_terminates_and_converges(self):
        source = ("import os\n"
                  "def loop(v, n):\n"
                  "    if n:\n"
                  "        loop(v, n - 1)\n"
                  "    os.system(v)\n"
                  "def go():\n"
                  "    loop(input(), 5)\n")
        result = report(source)
        self.assertTrue(result["converged"])
        self.assertTrue(result["witnesses"])

    def test_mutual_recursion_terminates(self):
        source = ("import os\n"
                  "def ping(v):\n"
                  "    pong(v)\n"
                  "def pong(v):\n"
                  "    ping(v)\n"
                  "    os.system(v)\n"
                  "def go():\n"
                  "    ping(input())\n")
        result = report(source)
        self.assertTrue(result["converged"])
        self.assertLessEqual(result["iterations"], ip.0)

    def test_a_non_converged_run_declares_its_gap(self):
        # Verification must refuse a report that hit the bound silently.
        forged = dict(report("def f():\n    pass\n"))
        forged["converged"] = False
        forged.pop("coverage_gap", None)
        ok, errors = ip.verify_report(forged)
        self.assertFalse(ok)
        self.assertTrue(any("coverage gap" in error for error in errors))


class ContractTests(unittest.TestCase):
    def test_report_verifies_and_detects_tampering(self):
        result = report("import os\ndef r(p):\n    os.system(p)\n"
                        "def g():\n    r(input())\n")
        self.assertTrue(ip.verify_report(result)[0])
        result["witnesses"] = []
        self.assertFalse(ip.verify_report(result)[0])

    def test_unparsable_source_is_reported_not_raised(self):
        result = report("def broken(:\n")
        self.assertEqual(result["status"], "unparsed")
        self.assertEqual(result["witnesses"], [])

    def test_oversized_source_is_refused(self):
        with self.assertRaises(ip.InterproceduralError):
            ip.analyze("x = 1\n" * ip.MAX_SOURCE_BYTES)

    def test_non_text_source_is_refused(self):
        for bad in (None, 42, b"bytes"):
            with self.subTest(source=bad):
                with self.assertRaises(ip.InterproceduralError):
                    ip.analyze(bad)

    def test_limitations_never_claim_safety(self):
        result = report("x = 1\n")
        self.assertTrue(any("never that the file is safe" in line
                            for line in result["limitations"]))
        self.assertTrue(any("single module" in line
                            for line in result["limitations"]))


class ComplementarityTests(unittest.TestCase):
    """The two engines must cover opposite directions, not duplicate work."""

    RETURN_FLOW = ("import os\n"
                   "def read_name():\n"
                   "    return input()\n"
                   "def go():\n"
                   "    os.system('ls ' + read_name())\n")
    ARGUMENT_FLOW = ("import os\n"
                     "def run(part):\n"
                     "    os.system('ls ' + part)\n"
                     "def go():\n"
                     "    run(input())\n")

    def graph_witnesses(self, source):
        import os as _os
        import tempfile
        directory = tempfile.mkdtemp()
        with open(_os.path.join(directory, "s.py"), "w",
                  encoding="utf-8") as handle:
            handle.write(source)
        return sg.build(directory)["graph"]["taint_witnesses"]

    def test_return_flow_is_the_graph_engine_s_job(self):
        self.assertTrue(self.graph_witnesses(self.RETURN_FLOW))

    def test_argument_flow_is_this_module_s_job(self):
        self.assertEqual(self.graph_witnesses(self.ARGUMENT_FLOW), [],
                         "semantic_graph41 unexpectedly covers argument flow")
        self.assertTrue(report(self.ARGUMENT_FLOW)["witnesses"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
