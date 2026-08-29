from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import superattestor


class SuperAttestor30Tests(unittest.TestCase):
    def test_natural_language_routes_new_engines(self):
        self.assertEqual(superattestor.decide("attestor 3 .")["action"], "attestor3")
        self.assertEqual(superattestor.decide("find errors and improve app.py")["action"], "improve")
        self.assertEqual(superattestor.decide("whole program src")["action"], "semantic")
        self.assertEqual(superattestor.decide("supply chain .")["action"], "supplychain")
        self.assertEqual(superattestor.decide("repository memory .")["action"], "repositorymemory")

    def test_semantic_supply_chain_and_memory_are_exposed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "app.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
            (root / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
            semantic_text, semantic_code = superattestor.perform(
                {"action": "semantic", "path": str(root)}, output_format="json")
            supply_text, supply_code = superattestor.perform(
                {"action": "supplychain", "path": str(root)}, output_format="json")
            memory_text, memory_code = superattestor.perform(
                {"action": "repositorymemory", "path": str(root)}, output_format="json")
            semantic = json.loads(semantic_text)
            supply = json.loads(supply_text)
            memory = json.loads(memory_text)
            self.assertIn(semantic_code, {0, 1})
            self.assertEqual(semantic["version"], "3.0.0")
            self.assertIn(supply_code, {0, 1})
            self.assertEqual(supply["sbom"]["cyclonedx"]["specVersion"], "1.7")
            self.assertEqual(memory_code, 0)
            self.assertFalse(memory["privacy"]["source_code_stored"])
            self.assertNotIn("def f", memory_text)

    def test_improved_output_only_contains_accepted_candidates(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "bad.py").write_text("DEBUG = True\n", encoding="utf-8")
            destination = root / "results"
            text, _ = superattestor.perform(
                {"action": "attestor3", "path": str(root)}, output_format="json",
                use_cache=False, max_improvement_files=1, improved_out=str(destination))
            self.assertIn("wrote 1 verified improved source file", text)
            self.assertEqual((destination / "bad.py").read_text(encoding="utf-8"),
                             "DEBUG = False\n")


if __name__ == "__main__":
    unittest.main()
