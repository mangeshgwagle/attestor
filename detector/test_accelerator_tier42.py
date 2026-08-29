#!/usr/bin/env python3
"""The 64 GB accelerator floor: threshold, privacy, and failure direction.

Three properties matter here and only one of them is the arithmetic.

**The threshold is aggregate.** Two 32 GB cards and one 80 GB card both clear a
64 GB floor, because a workload sized to the total does not care how the total
is assembled.

**The verdict stays a boolean.** `hardware_tier` exists so a machine classifies
itself and reports one word rather than shipping an inventory somewhere. A VRAM
figure is closer to a fingerprint than the tier is -- 81,559 MiB names a
specific card -- so the measured size must never reach the returned report.

**Unreadable is not zero, and not "yes".** A machine that cannot answer has not
been shown to be above the floor, so it does not get a capability it may be
unable to run; that is the opposite direction from the billing decision in the
same module, where an unproven machine is deliberately not charged. Both rules
fail toward not taking something from the customer, which is why they point
opposite ways.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import hardware_tier  # noqa: E402


GB = 1024 ** 3


class Threshold(unittest.TestCase):
    def test_the_floor_is_aggregate_across_devices(self):
        for label, total in (("two 32 GB cards", 64 * GB),
                             ("four 24 GB cards", 96 * GB),
                             ("one 80 GB card", 80 * GB)):
            with self.subTest(configuration=label):
                self.assertTrue(hardware_tier.meets_accelerator_floor(total))

    def test_a_single_large_consumer_card_does_not_clear_it(self):
        for total in (24 * GB, 32 * GB, 48 * GB):
            self.assertFalse(hardware_tier.meets_accelerator_floor(total))

    def test_exactly_the_floor_qualifies(self):
        """A >= comparison, not >. 64 GB is the advertised floor, not one byte more."""
        self.assertTrue(hardware_tier.meets_accelerator_floor(
            hardware_tier.ACCELERATOR_MEMORY_GB * GB))
        self.assertFalse(hardware_tier.meets_accelerator_floor(
            hardware_tier.ACCELERATOR_MEMORY_GB * GB - 1))

    def test_the_floor_is_configurable_for_callers_that_need_another(self):
        self.assertTrue(hardware_tier.meets_accelerator_floor(48 * GB, floor_gb=48))
        self.assertFalse(hardware_tier.meets_accelerator_floor(48 * GB, floor_gb=80))


class FailureDirection(unittest.TestCase):
    def test_unreadable_memory_is_not_treated_as_meeting_the_floor(self):
        self.assertFalse(hardware_tier.meets_accelerator_floor(None))

    def test_unreadable_memory_does_not_change_the_cpu_class(self):
        """An unreadable GPU must not perturb the CPU/RAM classification.

        The two measurements answer different questions, and letting a failed
        accelerator probe move the machine class would make the class depend on
        whether a driver happened to answer.
        """
        without = hardware_tier.classify(
            cores=16, memory_bytes=64 * GB, gpu=True,
            vram_bytes=None, probe_vram=False)
        with_gpu = hardware_tier.classify(
            cores=16, memory_bytes=64 * GB, gpu=True,
            vram_bytes=80 * GB, probe_vram=False)
        self.assertEqual(without["tier"], with_gpu["tier"])
        self.assertEqual(without["hardware_class"], with_gpu["hardware_class"])


class Privacy(unittest.TestCase):
    def test_the_report_never_carries_the_measured_size(self):
        verdict = hardware_tier.classify(
            cores=16, memory_bytes=64 * GB, gpu=True,
            vram_bytes=81_559 * 1024 * 1024, probe_vram=False)
        rendered = repr(sorted(verdict.items()))
        self.assertNotIn("81559", rendered)
        self.assertNotIn("81_559", rendered)
        for value in verdict.values():
            self.assertNotEqual(value, 81_559 * 1024 * 1024)

    def test_the_verdict_is_a_boolean_and_a_word(self):
        verdict = hardware_tier.classify(
            cores=16, memory_bytes=64 * GB, gpu=True,
            vram_bytes=80 * GB, probe_vram=False)
        self.assertIs(verdict["meets_accelerator_floor"], True)
        self.assertEqual(verdict["accelerator_class"], hardware_tier.ACCELERATED)
        self.assertEqual(verdict["accelerator_floor_gb"],
                         hardware_tier.ACCELERATOR_MEMORY_GB)


class NoProbeWhenAnswered(unittest.TestCase):
    def test_supplying_vram_does_not_shell_out(self):
        """`probe_vram=False` keeps the decision pure, which is what lets the
        threshold be tested on a machine that has no accelerator at all."""
        called = []
        original = hardware_tier._accelerator_memory_bytes
        hardware_tier._accelerator_memory_bytes = lambda: called.append(1)
        try:
            hardware_tier.classify(cores=16, memory_bytes=64 * GB, gpu=True,
                                   vram_bytes=80 * GB, probe_vram=False)
            hardware_tier.classify(cores=16, memory_bytes=64 * GB, gpu=True,
                                   vram_bytes=None, probe_vram=False)
        finally:
            hardware_tier._accelerator_memory_bytes = original
        self.assertEqual([], called)


class RecommendedNotMinimum(unittest.TestCase):
    """The floor is a recommended requirement: below it you may still run."""

    GB = 1024 ** 3

    def test_meeting_the_floor_is_supported(self):
        verdict = hardware_tier.preflight(vram_bytes=80 * self.GB, probe=False)
        self.assertEqual(hardware_tier.SUPPORTED, verdict["status"])
        self.assertTrue(verdict["supported"])
        self.assertFalse(verdict["may_exhaust_memory"])

    def test_below_the_floor_is_degraded_rather_than_forbidden(self):
        verdict = hardware_tier.preflight(vram_bytes=24 * self.GB, probe=False)
        self.assertEqual(hardware_tier.DEGRADED, verdict["status"])
        self.assertFalse(verdict["supported"])
        self.assertTrue(verdict["may_exhaust_memory"])

    def test_unreadable_memory_is_unknown_not_degraded(self):
        """Distinguishable, because 'we could not tell' is not 'it is too small'."""
        verdict = hardware_tier.preflight(vram_bytes=None, probe=False)
        self.assertEqual(hardware_tier.UNKNOWN, verdict["status"])
        self.assertTrue(verdict["may_exhaust_memory"])

    def test_require_raises_below_the_floor_without_an_opt_in(self):
        for vram in (24 * self.GB, None):
            with self.subTest(vram=vram):
                with self.assertRaises(hardware_tier.UnsupportedHardware):
                    hardware_tier.require_accelerator(
                        allow_below_floor=False, vram_bytes=vram, probe=False)

    def test_require_permits_the_run_when_the_operator_opts_in(self):
        verdict = hardware_tier.require_accelerator(
            allow_below_floor=True, vram_bytes=24 * self.GB, probe=False)
        self.assertTrue(verdict["ran_below_floor"])

    def test_a_supported_run_is_not_marked_as_below_the_floor(self):
        verdict = hardware_tier.require_accelerator(
            allow_below_floor=True, vram_bytes=80 * self.GB, probe=False)
        self.assertFalse(verdict["ran_below_floor"])

    def test_the_opt_in_does_not_change_what_supported_means(self):
        """Opting in accepts a risk; it does not relabel the hardware."""
        forced = hardware_tier.require_accelerator(
            allow_below_floor=True, vram_bytes=24 * self.GB, probe=False)
        self.assertEqual(hardware_tier.DEGRADED, forced["status"])
        self.assertFalse(forced["supported"])


class ScanPathIsolation(unittest.TestCase):
    def test_the_scan_engine_does_not_import_hardware_tier(self):
        """Probing VRAM starts a process; scanning promises it starts none.

        `assurance42` publishes `engine_started_processes: False` and the
        detector's static contract says the same, so the module that shells out
        to nvidia-smi must stay in the billing lane. This asserts the boundary
        rather than trusting it.
        """
        import pathlib

        import detect
        import scanengine
        for module in (detect, scanengine):
            source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
            self.assertNotIn("hardware_tier", source, module.__name__)


if __name__ == "__main__":
    unittest.main()
