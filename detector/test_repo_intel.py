import tempfile
import unittest
from pathlib import Path

import repo_intel


class RepoIntelTests(unittest.TestCase):
    def test_graph_cycles_reachability_config_and_taint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.py").write_text(
                "import b\nfrom flask import request\n\n@app.get('/x')\ndef route():\n"
                "    value = request.args['x']\n    return eval(value)\n\ndef helper():\n    return b.work()\n",
                encoding="utf-8")
            (root / "b.py").write_text("import a\nimport os\ndef work():\n    return os.getenv('TOKEN')\n", encoding="utf-8")
            (root / ".env.example").write_text("TOKEN=placeholder\n", encoding="utf-8")
            report = repo_intel.analyze(tmp)
        self.assertTrue(report["import_cycles"])
        self.assertTrue(report["entrypoints"])
        self.assertTrue(report["unsafe_flows"])
        self.assertFalse(report["config_undeclared"])

    def test_framework_callback_not_called_dead(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "visitor.py"
            path.write_text("class V:\n    def visit_Name(self, node):\n        return node.id\n", encoding="utf-8")
            report = repo_intel.analyze(tmp)
        self.assertFalse(report["unreferenced"])

    def test_unreferenced_public_is_low_confidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "x.py").write_text("def unused():\n    return 1\n", encoding="utf-8")
            report = repo_intel.analyze(tmp)
        self.assertEqual(report["unreferenced"][0]["confidence"], 0.48)


if __name__ == "__main__":
    unittest.main()
