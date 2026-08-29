#!/usr/bin/env python3
"""Tests for detector/reader42.py."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import reader42 as rd  # noqa: E402

VULN_APP = (
    "import os\n"
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n"
    "def run_cmd(c):\n"
    "    return os.system(c)\n"
    "@app.route('/admin')\n"
    "def admin():\n"
    "    cmd = request.args.get('cmd')\n"
    "    return str(run_cmd(cmd))\n"
    "@app.route('/safe')\n"
    "@login_required\n"
    "def safe():\n"
    "    return str(run_cmd('echo hi'))\n"
)

INCONSISTENT = (
    "from flask import Flask, request\n"
    "app2 = Flask(__name__)\n"
    "@app2.route('/a')\n"
    "def ha():\n"
    "    user_id = request.args.get('user_id')\n"
    "    return str(int(user_id))\n"
    "@app2.route('/b')\n"
    "def hb():\n"
    "    user_id = request.args.get('user_id')\n"
    "    return user_id\n"
)

CLEAN = (
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n"
    "@app.route('/ok')\n"
    "@login_required\n"
    "def ok():\n"
    "    return 'fine'\n"
)


class TestReader(unittest.TestCase):
    def read(self, *files):
        with tempfile.TemporaryDirectory() as tmp:
            for name, content in files:
                (Path(tmp) / name).write_text(content, encoding="utf-8")
            return rd.read_repo(tmp)

    def test_q1_finds_unauth_path_to_sink(self):
        report = self.read(("app.py", VULN_APP))
        self.assertGreaterEqual(report["q1_count"], 1)
        hit = report["findings_q1"][0]
        self.assertEqual(hit["route"], "/admin")
        self.assertEqual(hit["sink_kind"], "cmd-exec")
        self.assertEqual(hit["handler"], "admin")

    def test_q2_finds_inconsistent_validation(self):
        report = self.read(("misc.py", INCONSISTENT))
        params = {f["param"] for f in report["findings_q2"]}
        self.assertIn("user_id", params)

    def test_authed_route_not_flagged(self):
        report = self.read(("app.py", CLEAN))
        self.assertEqual(report["q1_count"], 0)

    def test_trust_matrix_counts(self):
        report = self.read(("app.py", VULN_APP))
        matrix = report["trust_matrix"]
        self.assertEqual(matrix["routes_total"], 2)
        self.assertEqual(matrix["routes_with_auth_markers"], 1)

    def test_narrative_explains(self):
        report = self.read(("app.py", VULN_APP))
        self.assertIn("/admin", report["narrative"])
        self.assertIn("cmd-exec", report["narrative"])

    def test_digest_pinned_and_deterministic(self):
        import json
        first = self.read(("app.py", VULN_APP))
        second = self.read(("app.py", VULN_APP))
        self.assertEqual(first["report_sha256"],
                         second["report_sha256"])
        self.assertEqual(len(first["report_sha256"]), 64)

    def test_selftest_passes(self):
        result = rd.run_selftest()
        self.assertTrue(result["passed"], result["checks_failed"])


if __name__ == "__main__":
    unittest.main()
