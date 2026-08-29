from __future__ import annotations

import contextlib
import io
from pathlib import Path
import tempfile
import unittest

import superattestor


class SuperAttestor22Tests(unittest.TestCase):
    def test_new_maximum_modes_route_naturally(self):
        self.assertEqual(superattestor.decide("hard mayhem .")["action"], "mayhem")
        self.assertEqual(superattestor.decide("security posture .")["action"], "cybermayhem")
        self.assertEqual(superattestor.decide("quality gate .")["action"], "qualitygate")
        patch = superattestor.decide("patch guard app.py :: candidate.py")
        self.assertEqual(patch["action"], "patchguard")
        self.assertEqual(patch["target"], "app.py")

    def test_cybermayhem_perform_uses_advanced_rule_pack(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "app.php").write_text("<?php eval($source);\n", encoding="utf-8")
            text, code = superattestor.perform(
                {"action": "cybermayhem", "path": tmp}, use_cache=False,
                response_style="professional")
        self.assertGreater(code, 0)
        self.assertIn("adv-php-eval", text)
        self.assertTrue(text.startswith("Outcome"))

    def test_quality_gate_and_mayhem_machine_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "app.py").write_text(
                "def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
            quality, _ = superattestor.perform(
                {"action": "qualitygate", "path": tmp}, output_format="json",
                min_grade="F", max_high=99, use_cache=False)
            maximum, _ = superattestor.perform(
                {"action": "mayhem", "path": tmp}, output_format="json",
                min_grade="F", max_high=99, mutation_limit=0, use_cache=False)
        self.assertIn('"schema": "attestor-quality-gate/1"', quality)
        self.assertIn('"schema": "attestor-coding-mayhem/3.0"', maximum)

    def test_main_professional_response_is_outcome_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "app.py").write_text("def value():\n    return 1\n", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = superattestor.main([
                    "--workspace", tmp, "--no-cache", "--response-style", "professional"])
        self.assertIn(code, range(0, 251))
        self.assertTrue(output.getvalue().startswith("Outcome\n"), output.getvalue()[:200])


if __name__ == "__main__":
    unittest.main()
