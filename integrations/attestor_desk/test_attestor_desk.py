#!/usr/bin/env python3
"""Tests for the desktop companion.

Everything worth testing here is what the little window *claims*. A cute face
over a wrong claim is worse than no face, so the cases below are mostly about
the two ways this could lie: calling a scan clean when it failed to run, and
calling a quiet scan safe.
"""
from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import attestor_desk


FLAWED = ("import subprocess\n"
          "def deploy(tag):\n"
          "    subprocess.run('git push ' + tag, shell=True)\n")


def folder_with(text, name="a.py"):
    folder = pathlib.Path(tempfile.mkdtemp())
    (folder / name).write_text(text, encoding="utf-8")
    return str(folder)


class Counting(unittest.TestCase):
    def test_every_severity_is_present_even_at_zero(self):
        counts = attestor_desk.tally([])
        for level in attestor_desk.SEVERITIES:
            self.assertIn(level, counts)
        self.assertEqual(counts["TOTAL"], 0)

    def test_totals_add_up(self):
        counts = attestor_desk.tally([{"severity": "HIGH"}, {"severity": "LOW"},
                                  {"severity": "HIGH"}])
        self.assertEqual(counts["HIGH"], 2)
        self.assertEqual(counts["LOW"], 1)
        self.assertEqual(counts["TOTAL"], 3)

    def test_an_unknown_severity_still_counts_toward_the_total(self):
        # Losing a finding because its level was spelled oddly would be a
        # silent undercount, which is the one arithmetic error that matters.
        counts = attestor_desk.tally([{"severity": "SPICY"}])
        self.assertEqual(counts["TOTAL"], 1)

    def test_a_missing_severity_is_treated_as_info(self):
        self.assertEqual(attestor_desk.tally([{}])["INFO"], 1)

    def test_worst_picks_the_highest_present(self):
        self.assertEqual(attestor_desk.worst(
            attestor_desk.tally([{"severity": "LOW"}, {"severity": "HIGH"}])),
            "HIGH")
        self.assertIsNone(attestor_desk.worst(attestor_desk.tally([])))


class WhatItSaysOutLoud(unittest.TestCase):
    def test_a_quiet_scan_is_never_called_safe(self):
        said = attestor_desk.remark(attestor_desk.tally([]), "proj").lower()
        self.assertIn("not the same as safe", said)
        for word in ("you're safe", "is safe", "no bugs", "all clear"):
            self.assertNotIn(word, said)

    def test_findings_are_reported_with_their_worst_level(self):
        said = attestor_desk.remark(
            attestor_desk.tally([{"severity": "HIGH"}, {"severity": "LOW"}]),
            "proj")
        self.assertIn("2", said)
        self.assertIn("HIGH", said)

    def test_one_finding_reads_as_one(self):
        said = attestor_desk.remark(attestor_desk.tally([{"severity": "MEDIUM"}]), "p")
        self.assertIn("one thing", said)

    def test_the_face_is_only_happy_when_nothing_came_back(self):
        self.assertEqual(attestor_desk.mood(attestor_desk.tally([])), "clean")
        self.assertEqual(
            attestor_desk.mood(attestor_desk.tally([{"severity": "INFO"}])), "found")


class Scanning(unittest.TestCase):
    def test_a_real_defect_is_returned(self):
        found = attestor_desk.scan(folder_with(FLAWED))
        self.assertTrue(found)
        self.assertTrue(any(f["rule"] == "py-subprocess-shell" for f in found))

    def test_exit_status_two_is_findings_not_failure(self):
        """The mistake that produced empty Terminal-Bench runs.

        `detect.py` exits 2 when it found something. Treating that as an error
        would put a sorry face over a scan that worked perfectly.
        """
        counts = attestor_desk.tally(attestor_desk.scan(folder_with(FLAWED)))
        self.assertGreater(counts["TOTAL"], 0)
        self.assertEqual(attestor_desk.mood(counts), "found")

    def test_a_clean_folder_returns_nothing_without_raising(self):
        self.assertEqual(attestor_desk.scan(folder_with("x = 1\n")), [])

    def test_a_missing_path_is_an_error_not_a_clean_result(self):
        with self.assertRaises(attestor_desk.DeskError):
            attestor_desk.scan(pathlib.Path(tempfile.mkdtemp()) / "nope")

    def test_a_missing_detector_is_an_error(self):
        with self.assertRaises(attestor_desk.DeskError):
            attestor_desk.scan(folder_with("x = 1\n"),
                           detector=tempfile.mkdtemp())

    def test_a_scan_that_overruns_is_reported_as_such(self):
        with self.assertRaises(attestor_desk.DeskError) as caught:
            attestor_desk.scan(folder_with(FLAWED), timeout=0.001)
        self.assertIn("stopped", str(caught.exception))


class Ports(unittest.TestCase):
    def test_free_port_returns_something_bindable(self):
        # Regression: the probe originally set SO_REUSEADDR, which on Windows
        # permits binding a port someone else already holds. It returned 8787
        # while the workbench was answering there, so the launcher would have
        # started a second server onto an occupied port.
        import socket
        port = attestor_desk.free_port(8787)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))

    def test_an_occupied_port_is_stepped_over(self):
        # There is usually an Attestor already running; taking its port would be
        # a rude hello.
        import socket
        with socket.socket() as held:
            held.bind(("127.0.0.1", 0))
            held.listen(1)
            taken = held.getsockname()[1]
            self.assertNotEqual(attestor_desk.free_port(taken), taken)

    def test_workbench_running_detects_a_listener(self):
        import socket
        with socket.socket() as held:
            held.bind(("127.0.0.1", 0))
            held.listen(1)
            port = held.getsockname()[1]
            self.assertTrue(attestor_desk.workbench_running(port))

    def test_workbench_running_is_false_on_a_free_port(self):
        self.assertFalse(attestor_desk.workbench_running(attestor_desk.free_port(9911)))


class ItPointsAtThisDistribution(unittest.TestCase):
    def test_the_detector_it_uses_is_the_one_beside_it(self):
        # The workbench on this machine was found serving 4.1.5 from another
        # tree entirely. The companion should never be ambiguous about which
        # engine answered.
        self.assertTrue((attestor_desk.DETECTOR / "detect.py").is_file())
        # Assert the distribution, not the folder name. The original checked
        # `parent.name == "Owen 4.2"`, which made the test depend on what
        # somebody called the directory -- it broke on the rename and would
        # break again on any checkout, copy, or unpacked archive with a
        # different folder name. The VERSION file beside the detector is the
        # real statement of which distribution answered.
        version = (attestor_desk.DETECTOR.parent / "VERSION")
        self.assertTrue(version.is_file())
        self.assertEqual(version.read_text(encoding="utf-8").strip(), "4.2")


if __name__ == "__main__":
    unittest.main(verbosity=2)
