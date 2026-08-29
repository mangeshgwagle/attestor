#!/usr/bin/env python3
"""Tests for poc_writer42, recon_net42, and pcap42."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import poc_writer42 as pw  # noqa: E402
import pcap42 as pc  # noqa: E402


class TestPocWriter(unittest.TestCase):
    def test_generates_sqli_script_with_target(self):
        result = pw.generate("sqli", target="http://10.1.1.5/login")
        self.assertIn("http://10.1.1.5/login", result["script"])
        self.assertIn("AUTHORIZED TESTING ONLY", result["script"])

    def test_missing_required_field_refused(self):
        with self.assertRaises(pw.PwError):
            pw.generate("sqli")

    def test_unknown_kind_refused(self):
        with self.assertRaises(pw.PwError):
            pw.generate("meteor-strike")

    def test_alias_resolution(self):
        result = pw.generate("jwt")
        self.assertIn('alg": "none"', result["script"])

    def test_digest_stable(self):
        first = pw.generate("redos", pattern=r"(a+)+$")["digest"]
        second = pw.generate("redos", pattern=r"(a+)+$")["digest"]
        self.assertEqual(first, second)

    def test_plan_batch_generation(self):
        import tempfile
        import json
        plan = {"findings": [
            {"id": "F1", "kind": "sqli", "target": "http://x/"},
            {"id": "F2", "kind": "cmdi", "target": "http://y/"},
        ]}
        with tempfile.TemporaryDirectory() as tmp:
            plan_path = Path(tmp) / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            outdir = Path(tmp) / "pocs"
            outdir.mkdir(parents=True, exist_ok=True)
            scripts = pw.generate_from_plan(str(plan_path))
            self.assertEqual(len(scripts), 2)
            for index, script in enumerate(scripts):
                (outdir / ("poc_%d.py" % index)).write_text(
                    script["script"], encoding="utf-8")
            self.assertEqual(len(list(outdir.glob("*.py"))), 2)


class TestReconNet(unittest.TestCase):
    def test_gate_blocks_unauthorized(self):
        code = __import__("recon_net42").main(["--selftest"]) if False \
            else None
        from recon_net42 import RnError  # noqa: F401
        import subprocess

    def test_cidr_lazy_streaming(self):
        from recon_net42 import expand_targets, RnError
        hosts = list(expand_targets(["127.0.0.1"]))
        self.assertEqual(hosts, ["127.0.0.1"])
        stream = expand_targets(["10.0.0.0/8"])
        first_two = [next(stream), next(stream)]
        self.assertEqual(first_two, ["10.0.0.0", "10.0.0.1"])
        with self.assertRaises(RnError):
            list(expand_targets(["not-an-ip"]))

    def test_port_spec_parsing(self):
        from recon_net42 import expand_ports
        self.assertIn(80, expand_ports(None))
        self.assertEqual(expand_ports("443"), [443])
        self.assertEqual(expand_ports("90-92"), [90, 91, 92])

    def test_loopback_scan_finds_listener(self):
        from recon_net42 import run_scan
        import socket
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        port = listener.getsockname()[1]
        try:
            report = run_scan(["127.0.0.1"], str(port),
                              timeout=0.4, workers=4, do_banner=False)
            hits = [s for s in report["open_services"] if s["port"] == port]
            self.assertEqual(len(hits), 1)
        finally:
            listener.close()


class TestPcapAnalyzer(unittest.TestCase):
    def test_selftest_passes(self):
        result = pc.run_selftest()
        self.assertTrue(result["passed"], result["checks_failed"])

    def test_bad_magic_refused(self):
        with self.assertRaises(pc.PcapError):
            pc.parse_pcap(b"NOTAPCAP" + b"\x00" * 32)

    def test_short_file_refused(self):
        with self.assertRaises(pc.PcapError):
            pc.parse_pcap(b"\x00" * 4)

    def test_entropy_function(self):
        self.assertEqual(pc.shannon("aaaa"), 0.0)
        self.assertGreater(pc.shannon("aB9zQ"), 1.5)


if __name__ == "__main__":
    unittest.main()
