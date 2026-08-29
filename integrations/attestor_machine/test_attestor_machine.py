from __future__ import annotations

import unittest

import attestor_machine as om


GIB = om.GIB


class Classification(unittest.TestCase):
    """The table in the module docstring, asserted."""

    def test_the_documented_table(self):
        cases = [
            # (cores, GiB, expected)
            (16, 64, "high"),
            (8, 16, "high"),          # exactly on the line is on the line
            (8, 12, "mid"),           # a real 12 GB machine is not high-end
            (6, 32, "mid"),           # cores short, memory irrelevant
            (4, 8, "mid"),
            (4, 6, "low"),
            (2, 64, "low"),           # memory is useless without cores
            (1, 1, "low"),
        ]
        for cores, gib, expected in cases:
            with self.subTest(cores=cores, gib=gib):
                self.assertEqual(om.classify(cores, gib * GIB), expected)

    def test_a_machine_sold_as_16gb_is_high_end(self):
        """The OS never reports the number on the box.

        16 GB of DDR5 reports 15.6 GiB on the Windows machine this was
        written on -- firmware and the integrated GPU take their cut first.
        A threshold of a literal 16 GiB put that machine, and every machine
        marketed as 16 GB, on the free tier. The same applies one step down:
        an 8 GB laptop reports about 7.7 GiB.
        """
        for reported_gib in (15.6, 15.8, 15.9, 16.0):
            with self.subTest(gib=reported_gib):
                self.assertEqual(
                    om.classify(8, int(reported_gib * GIB)), "high")
        for reported_gib in (7.6, 7.7, 7.9):
            with self.subTest(gib=reported_gib):
                self.assertEqual(
                    om.classify(4, int(reported_gib * GIB)), "mid")

    def test_a_12gb_machine_is_still_not_high_end(self):
        """The margin has to clear 16 GB without swallowing 12 GB."""
        for reported_gib in (11.7, 11.9, 12.0, 14.0):
            with self.subTest(gib=reported_gib):
                self.assertEqual(
                    om.classify(8, int(reported_gib * GIB)), "mid")

    def test_both_conditions_are_required_to_move_up(self):
        self.assertEqual(om.classify(64, 4 * GIB), "low")
        self.assertEqual(om.classify(2, 512 * GIB), "low")

    def test_only_high_is_ever_billed(self):
        self.assertEqual(om.BILLED_CLASSES, frozenset({"high"}))
        for cores, gib in ((8, 16), (32, 128)):
            self.assertTrue(om.MachineProfile(
                om.classify(cores, gib * GIB), cores, gib * GIB, "Linux",
                "measured").billed)
        for cores, gib in ((4, 8), (2, 4), (8, 8)):
            self.assertFalse(om.MachineProfile(
                om.classify(cores, gib * GIB), cores, gib * GIB, "Linux",
                "measured").billed)


class UnmeasurableHardwareIsNeverBilled(unittest.TestCase):
    """A failed measurement must not turn into a charge.

    total_memory_bytes() returns 0 when the platform will not answer. If that
    fell through to `high` the service would bill somebody because a syscall
    failed, so the direction of the failure is part of the contract.
    """

    def test_zero_of_either_reading_is_low(self):
        for cores, memory in ((0, 64 * GIB), (16, 0), (0, 0), (-1, -1)):
            with self.subTest(cores=cores, memory=memory):
                self.assertEqual(om.classify(cores, memory), "low")

    def test_a_profile_with_nothing_measured_is_not_billed(self):
        profile = om.MachineProfile("low", 0, 0, "unknown", "unmeasured")
        self.assertFalse(profile.billed)


class ProbeOnThisMachine(unittest.TestCase):
    def test_probe_returns_a_coherent_profile(self):
        profile = om.probe()
        self.assertIn(profile.machine_class, {"low", "mid", "high"})
        self.assertGreaterEqual(profile.cores, 0)
        self.assertGreaterEqual(profile.memory_bytes, 0)
        self.assertEqual(
            profile.machine_class,
            om.classify(profile.cores, profile.memory_bytes))
        self.assertIn(profile.probe_confidence, {"measured", "unmeasured"})

    def test_this_machine_can_actually_be_measured(self):
        """Not a tautology -- it asserts the probe works on the host it runs on.

        If the Windows/Linux/BSD branch breaks, every machine silently becomes
        `low` and nobody is ever billed, which is the kind of failure that
        looks like everything working.
        """
        profile = om.probe()
        self.assertEqual(profile.probe_confidence, "measured",
                         "hardware probe failed on %s" % profile.system)
        self.assertGreater(profile.cores, 0)
        self.assertGreater(profile.memory_bytes, GIB)

    def test_as_dict_is_serialisable_and_carries_the_verdict(self):
        payload = om.probe().as_dict()
        for key in ("machine_class", "cores", "memory_bytes", "system",
                    "probe_confidence", "billed", "memory_gib"):
            self.assertIn(key, payload)
        self.assertIsInstance(payload["billed"], bool)

    def test_explain_names_the_class(self):
        for profile in (
            om.MachineProfile("high", 16, 32 * GIB, "Linux", "measured"),
            om.MachineProfile("mid", 4, 8 * GIB, "Linux", "measured"),
            om.MachineProfile("low", 2, 4 * GIB, "Linux", "measured"),
        ):
            text = profile.explain()
            self.assertTrue(text)
            if profile.billed:
                self.assertIn("bills", text)
            else:
                self.assertIn("free", text)


class MemoryReadingIsSane(unittest.TestCase):
    def test_total_memory_is_a_plausible_size(self):
        total = om.total_memory_bytes()
        self.assertGreater(total, GIB, "less than 1 GiB reported")
        self.assertLess(total, 4096 * GIB, "implausibly large reading")

    def test_logical_cores_is_positive_here(self):
        self.assertGreater(om.logical_cores(), 0)


if __name__ == "__main__":
    unittest.main()
