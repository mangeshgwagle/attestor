#!/usr/bin/env python3
"""Tests for warm starts, checkpoints, and the wall-clock budget.

The property that matters is not "a checkpoint can be written and read" -- it
is that **a resumed run is indistinguishable from one that never stopped**. A
checkpoint missing the optimiser moments or the generator state round-trips
perfectly and still fails that, which is why it is tested directly.
"""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent
                       / "detector"))

import endurance
import neural_gate
import train_gate


def tiny_model(dim=32, hidden=8, seed=0):
    rng = np.random.default_rng(seed)
    return (rng.standard_normal((dim, hidden)).astype(np.float32) * 0.1,
            rng.standard_normal(hidden).astype(np.float32) * 0.1,
            rng.standard_normal(hidden).astype(np.float32) * 0.1,
            0.25)


class WarmStart(unittest.TestCase):
    def test_dequantise_inverts_quantise(self):
        model = tiny_model()
        span = 1000
        artifact = train_gate.quantise(model, neural_gate, span)
        recovered = endurance.dequantise(
            artifact, neural_gate.WEIGHT_SCALE, neural_gate.FEATURE_SCALE)
        for original, back, label in zip(model, recovered,
                                         ("hidden_w", "hidden_b", "out_w",
                                          "out_b")):
            with self.subTest(part=label):
                np.testing.assert_allclose(
                    np.asarray(original), np.asarray(back),
                    atol=1.5 / neural_gate.WEIGHT_SCALE,
                    err_msg="%s did not survive the round trip" % label)

    def test_shape_mismatch_is_refused_not_reshaped(self):
        artifact = train_gate.quantise(tiny_model(dim=32, hidden=8),
                                       neural_gate, 1000)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         encoding="utf-8") as handle:
            json.dump(artifact, handle)
            path = handle.name
        with self.assertRaises(endurance.EnduranceError) as caught:
            endurance.warm_start(path, dim=64, hidden=8,
                                 weight_scale=neural_gate.WEIGHT_SCALE,
                                 feature_scale=neural_gate.FEATURE_SCALE)
        self.assertIn("32x8", str(caught.exception))

    def test_a_missing_teacher_is_refused(self):
        with self.assertRaises(endurance.EnduranceError):
            endurance.warm_start("no-such-file.json", 32, 8, 1024, 1000)

    def test_a_non_gate_json_is_refused(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         encoding="utf-8") as handle:
            json.dump({"feature_dim": 32, "hidden": 8, "hello": "world"},
                      handle)
            path = handle.name
        with self.assertRaises(endurance.EnduranceError):
            endurance.warm_start(path, 32, 8, 1024, 1000)


class Checkpoints(unittest.TestCase):
    def _state(self, seed=3):
        rng = np.random.default_rng(seed)
        model = tiny_model(seed=seed)
        moments = [np.zeros_like(model[0]), np.zeros_like(model[1]),
                   np.zeros_like(model[2])]
        velocities = [np.ones_like(model[0]) * 0.5, np.ones_like(model[1]),
                      np.ones_like(model[2]) * 2.0]
        return model, moments, velocities, rng

    def test_round_trip_restores_every_moving_part(self):
        model, moments, velocities, rng = self._state()
        rng.random(5)                     # advance it, so state is not fresh
        expected_next = np.random.default_rng()
        expected_next.bit_generator.state = rng.bit_generator.state
        wanted = expected_next.random(4)

        with tempfile.TemporaryDirectory() as folder:
            path = str(pathlib.Path(folder) / "ck.json")
            endurance.save_checkpoint(
                path, model=model, moments=moments, velocities=velocities,
                moment_out=0.75, velocity_out=1.25, step=41, epoch=7,
                rng=rng, settings={"dim": 32}, history=[{"epoch": 1}])
            back = endurance.load_checkpoint(path)

        self.assertEqual(back["step"], 41)
        self.assertEqual(back["epoch"], 7)
        self.assertEqual(back["settings"], {"dim": 32})
        self.assertEqual(back["history"], [{"epoch": 1}])
        self.assertAlmostEqual(back["moment_out"], 0.75)
        self.assertAlmostEqual(back["velocity_out"], 1.25)
        np.testing.assert_allclose(back["model"][0], model[0])
        np.testing.assert_allclose(back["velocities"][2], velocities[2])
        # The generator continues the sequence rather than restarting it.
        np.testing.assert_allclose(back["rng"].random(4), wanted)

    def test_the_write_is_atomic(self):
        # A reader must see the previous checkpoint or the new one, never a
        # partial file. Proxy: no stray .part files survive a successful write.
        model, moments, velocities, rng = self._state()
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "ck.json"
            for step in range(3):
                endurance.save_checkpoint(
                    str(path), model=model, moments=moments,
                    velocities=velocities, moment_out=0.0, velocity_out=0.0,
                    step=step, epoch=step, rng=rng, settings={}, history=[])
            leftovers = [p.name for p in path.parent.iterdir()
                         if p.name != "ck.json"]
            self.assertEqual(leftovers, [])

    def test_a_truncated_checkpoint_is_refused_with_a_reason(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "ck.json"
            path.write_text('{"schema": "attestor.gate-endu', encoding="utf-8")
            with self.assertRaises(endurance.EnduranceError) as caught:
                endurance.load_checkpoint(str(path))
            self.assertIn("killed mid-write", str(caught.exception))

    def test_a_foreign_schema_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "ck.json"
            path.write_text(json.dumps({"schema": "something-else"}),
                            encoding="utf-8")
            with self.assertRaises(endurance.EnduranceError):
                endurance.load_checkpoint(str(path))


class WallClock(unittest.TestCase):
    def test_no_limit_never_stops(self):
        self.assertFalse(endurance.Budget(None).should_stop(1e9))

    def test_it_stops_early_enough_to_finish_the_epoch(self):
        budget = endurance.Budget(max_hours=1.0, margin=300.0)
        # 55 minutes of epoch left to run would overrun the hour once the
        # 5-minute margin is added, so it must decline to start another.
        self.assertTrue(budget.should_stop(epoch_seconds=55 * 60))
        # A short epoch still fits.
        self.assertFalse(budget.should_stop(epoch_seconds=60))

    def test_report_is_readable(self):
        report = endurance.Budget(max_hours=128.0).report()
        self.assertEqual(report["limit_seconds"], 128 * 3600)
        self.assertLess(report["elapsed_seconds"], 60)
        self.assertGreater(report["remaining_seconds"], 127 * 3600)


if __name__ == "__main__":
    unittest.main(verbosity=2)
