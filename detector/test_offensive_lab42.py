#!/usr/bin/env python3
"""Tests for detector/offensive_lab42.py and detector/offensive_fuzz42.py."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import offensive_lab42 as lab  # noqa: E402
import offensive_fuzz42 as fuzz  # noqa: E402


class TestRedos(unittest.TestCase):
    def test_nested_quantifier_confirmed(self):
        report = lab.analyze_redos(r"(a+)+$", lengths=(6, 9, 12), cap=200_000)
        self.assertEqual(report["shape"], "nested-quantifier")
        self.assertTrue(report["confirmed"])

    def test_alternation_overlap_confirmed(self):
        report = lab.analyze_redos(r"^(a|aa)+$", lengths=(6, 9, 12), cap=200_000)
        self.assertEqual(report["shape"], "alternation-overlap")
        self.assertTrue(report["confirmed"])

    def test_clean_pattern_stays_clean(self):
        for pattern in (r"^a+b$", r"[a-z]+@[a-z]+\.(com|org)", r"\d{4}-\d{2}"):
            report = lab.analyze_redos(pattern)
            self.assertIsNone(report["shape"], pattern)
            self.assertFalse(report["confirmed"], pattern)

    def test_measurements_grow(self):
        report = lab.analyze_redos(r"(a+)+b", lengths=(6, 9), cap=200_000)
        steps = [m["steps"] for m in report["measurements"]]
        self.assertGreater(steps[-1], steps[0])


class TestJwt(unittest.TestCase):
    @staticmethod
    def _token(secret="shhhh", payload=None):
        head = lab.b64u_encode(json.dumps(
            {"alg": "HS256", "typ": "JWT"}).encode())
        body = lab.b64u_encode(json.dumps(
            payload or {"sub": "demo"}).encode())
        import hashlib
        import hmac
        sig = lab.b64u_encode(hmac.new(
            secret.encode(), ("%s.%s" % (head, body)).encode(),
            hashlib.sha256).digest())
        return "%s.%s.%s" % (head, body, sig)

    def test_decode_roundtrip(self):
        decoded = lab.jwt_decode(self._token(payload={"sub": "abc"}))
        self.assertEqual(decoded["payload"]["sub"], "abc")
        self.assertEqual(decoded["alg"], "HS256")
        self.assertFalse(decoded["verified"])

    def test_none_forge_variants(self):
        forged = lab.jwt_none_forge(self._token())
        self.assertEqual(len(forged["variants"]), 4)
        for variant in forged["variants"]:
            self.assertTrue(variant.endswith("."))

    def test_crack_finds_bundled_secret(self):
        result = lab.jwt_crack(self._token("shhhh"), lab.BUNDLED_WORDLIST)
        self.assertTrue(result["cracked"])
        self.assertEqual(result["secret"], "shhhh")

    def test_crack_rejects_non_hmac_alg(self):
        with self.assertRaises(lab.LabError):
            lab.jwt_crack("x.y.z", [])

    def test_confusion_artifact_structure(self):
        confused = lab.jwt_confusion(self._token(), b"PUBLIC-KEY-BYTES")
        parts = confused["forged_token"].split(".")
        self.assertEqual(len(parts), 3)
        header = json.loads(lab.b64u_decode(parts[0]))
        self.assertEqual(header["alg"], "HS256")


class TestEcdsa(unittest.TestCase):
    def test_demo_recovers_exact_key(self):
        demo = lab.ecdsa_demo()
        self.assertTrue(demo["recovery_exact"])
        self.assertEqual(demo["recovered_private_key_hex"],
                         demo["demo_private_key_hex"])

    def test_direct_vector_recovery(self):
        order = 1000003
        d, k, r = 123456, 654321, 777
        z1, z2 = 11111, 99999
        k_inv = pow(k, -1, order)
        s1 = k_inv * (z1 + r * d) % order
        s2 = k_inv * (z2 + r * d) % order
        nonce, private = lab.recover_key(r, s1, s2, z1, z2, order)
        self.assertEqual(nonce, k % order)
        self.assertEqual(private, d)

    def test_same_signature_refused(self):
        with self.assertRaises(lab.LabError):
            lab.recover_key(7, 100, 100, 5, 9, 1000003)


class TestTemplateScan(unittest.TestCase):
    SAMPLE = ("<html>\n"
              "<!-- {{comment_marker}} -->\n"
              '<a href="{{url}}">x</a>\n'
              '<div title="{{t}}">hi</div>\n'
              '<span th:utext="${content}">y</span>\n'
              "<script>var s = \"{{js}}\";</script>\n"
              "</html>\n")

    def setUp(self):
        self.hits = lab.scan_template(self.SAMPLE)
        self.contexts = {hit["context"] for hit in self.hits}

    def test_expected_contexts(self):
        self.assertIn("html-comment", self.contexts)
        self.assertIn("url-attribute-double", self.contexts)
        self.assertIn("attribute-double", self.contexts)
        self.assertIn("attribute-value", self.contexts)
        self.assertIn("script-block", self.contexts)

    def test_url_attr_classified_by_name(self):
        href_hits = [h for h in self.hits if h["context"] == "url-attribute-double"]
        self.assertTrue(href_hits)
        self.assertTrue(any("javascript:" in p
                            for h in href_hits for p in h["payload_candidates"]))

    def test_ssti_probes_attached(self):
        brace_hits = [h for h in self.hits if h["marker"] == "{{"]
        self.assertTrue(brace_hits)
        self.assertTrue(all(h["ssti_probes"] for h in brace_hits))

    def test_line_numbers_positive(self):
        self.assertTrue(all(hit["line"] >= 1 for hit in self.hits))


class TestSsrf(unittest.TestCase):
    def test_ip_encodings_enumerated(self):
        report = lab.ssrf_reason("http://127.0.0.1/admin")
        variants = {c["variant"] for c in report["candidates"]}
        self.assertIn("decimal", variants)
        decimal = next(c["url"] for c in report["candidates"]
                       if c["variant"] == "decimal")
        self.assertEqual(decimal, "http://2130706433/admin")

    def test_userinfo_bypass_for_exact_validator(self):
        report = lab.ssrf_reason("http://internal.api/x",
                                 allowlist="internal.api",
                                 validator="exact",
                                 evil_host="169.254.169.254")
        classes = {c["class"] for c in report["candidates"]}
        self.assertIn("userinfo-trick", classes)

    def test_suffix_validator_confusables(self):
        report = lab.ssrf_reason("http://api.corp/x",
                                 allowlist="api.corp",
                                 validator="suffix")
        classes = {c["class"] for c in report["candidates"]}
        self.assertIn("suffix-confusable", classes)

    def test_metadata_note(self):
        report = lab.ssrf_reason("http://169.254.169.254/latest/meta-data/")
        self.assertTrue(report["notes"])

    def test_no_network_side_effects_shape(self):
        report = lab.ssrf_reason("http://10.0.0.5/")
        self.assertEqual(report["boundary"],
                         "static reasoning output; nothing was contacted")


class TestArena(unittest.TestCase):
    def test_deputy_defect_planted_and_replayable(self):
        report = lab.run_arena("confused-deputy")
        self.assertTrue(report["planted_defect_confirmed"])
        self.assertTrue(report["replay_verified"])
        self.assertTrue(report["vulnerable_path_pre_fix"])

    def test_csrf_defect_planted_and_replayable(self):
        report = lab.run_arena("csrf-binding")
        self.assertTrue(report["planted_defect_confirmed"])
        self.assertTrue(report["replay_verified"])

    def test_patch_denies_defective_transition(self):
        fixed = lab.run_arena("confused-deputy", with_fix=True)
        self.assertEqual(fixed["paths_post_fix"], [])
        self.assertNotEqual(fixed["vulnerable_path_pre_fix"], [])

    def test_unknown_scenario_refused(self):
        with self.assertRaises(lab.LabError):
            lab.run_arena("not-a-scenario")


class TestPaddingOracle(unittest.TestCase):
    def test_feistel_roundtrip(self):
        block = bytes(range(16))
        self.assertEqual(lab.feistel_decrypt_block(
            lab.feistel_encrypt_block(block)), block)

    def test_cbc_roundtrip(self):
        iv = bytes(range(16))
        message = b"roundtrip check"
        self.assertEqual(lab.cbc_decrypt(lab.cbc_encrypt(message, iv), iv),
                         lab.pkcs7_pad(message))

    def test_demo_exact_recovery_within_budget(self):
        demo = lab.padding_oracle_demo()
        self.assertTrue(demo["exact_recovery"])
        self.assertLessEqual(demo["queries_used"], demo["query_budget"])

    def test_custom_message_recovery(self):
        demo = lab.padding_oracle_demo(b"short")
        self.assertTrue(demo["exact_recovery"])


class TestGadgetChains(unittest.TestCase):
    def test_dangerous_chains_found(self):
        report = lab.find_gadget_chains(lab.BUNDLED_GADGET_GRAPH)
        sinks = {chain["sink"] for chain in report["chains"]}
        self.assertTrue({"builtins.eval", "os.system"} <= sinks)

    def test_benign_sink_excluded(self):
        report = lab.find_gadget_chains(lab.BUNDLED_GADGET_GRAPH)
        sinks = {chain["sink"] for chain in report["chains"]}
        self.assertNotIn("logger.info", sinks)

    def test_chain_is_contiguous(self):
        report = lab.find_gadget_chains(lab.BUNDLED_GADGET_GRAPH)
        edges = {(src, dst) for src, dst in lab.BUNDLED_GADGET_GRAPH["edges"]}
        for chain in report["chains"]:
            for a, b in zip(chain["chain"], chain["chain"][1:]):
                self.assertIn((a, b), edges, chain)

    def test_custom_graph_uncapped(self):
        big = {"entries": ["e%d" % i for i in range(17)], "edges": [],
               "sinks": {}}
        report = lab.find_gadget_chains(big)
        self.assertEqual(report["graph_stats"]["entries"], 17)

    def test_unknown_sink_kind_refused(self):
        bad = {"entries": ["e"], "edges": [["e", "s"]],
               "sinks": {"s": "laser"}}
        with self.assertRaises(lab.LabError):
            lab.find_gadget_chains(bad)


class TestPocVerify(unittest.TestCase):
    PLAN = {"findings": [
        {"id": "FP-SQL", "fixture": "sqli-sqlite", "poc": "' OR '1'='1"},
        {"id": "FP-XSS", "fixture": "xss-sanitizer",
         "poc": "<scr<script>ipt>alert(1)</scr</script>ipt>"},
        {"id": "FP-CMD", "fixture": "cmd-echo",
         "poc": "echo hi; cat /etc/hostname"},
    ]}

    def test_all_fixtures_confirm(self):
        report = lab.run_poc_plan(self.PLAN, authorized=True)
        self.assertEqual(report["confirmed_count"], 3)
        labels = {r["finding_id"]: r["synthetic_confirmed"]
                  for r in report["results"]}
        self.assertEqual(set(labels.values()), {True})

    def test_clean_poc_not_confirmed(self):
        plan = {"findings": [
            {"id": "X", "fixture": "sqli-sqlite", "poc": "alice"}]}
        report = lab.run_poc_plan(plan, authorized=True)
        self.assertEqual(report["confirmed_count"], 0)

    def test_runs_without_ceremony(self):
        report = lab.run_poc_plan(self.PLAN, authorized=False)
        self.assertEqual(report["confirmed_count"], 3)

    def test_unknown_fixture_refused(self):
        plan = {"findings": [{"fixture": "nope", "poc": "x"}]}
        with self.assertRaises(lab.LabError):
            lab.run_poc_plan(plan, authorized=True)


class TestSelfTest(unittest.TestCase):
    def test_selftest_passes(self):
        result = lab.run_selftest()
        self.assertTrue(result["passed"], result["checks_failed"])
        self.assertGreaterEqual(result["checks_total"], 15)


class TestFuzzHarness(unittest.TestCase):
    def test_crash_found_and_minimized(self):
        def target(data):
            if data.startswith(b"A" * 8):
                raise RuntimeError("boom")

        report = fuzz.run_fuzz(target, iterations=2000, seconds=10.0, seed=1,
                               corpus=[b"A" * 16])
        self.assertGreaterEqual(report["crashes_found"], 1)
        crash = report["crashes"][0]
        small = bytes.fromhex(crash["input_hex"])
        self.assertLessEqual(len(small), 32)
        with self.assertRaises(RuntimeError):
            target(small)

    def test_clean_target_stays_clean(self):
        def target(data):
            len(data)

        report = fuzz.run_fuzz(target, iterations=200, seconds=5.0, seed=0)
        self.assertEqual(report["crashes_found"], 0)

    def test_gen_input_unbounded(self):
        import random
        rng = random.Random(0)
        for _ in range(20):
            data = fuzz.gen_input(rng, [b"x" * 5000])
            self.assertIsInstance(data, bytes)


if __name__ == "__main__":
    unittest.main()
