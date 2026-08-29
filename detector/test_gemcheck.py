#!/usr/bin/env python3
"""Tests for gemcheck.py -- the Gemini key doctor. Offline: only pure logic."""
import unittest

import gemcheck


class AdviseTests(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(gemcheck.advise(200, ""), "OK.")

    def test_bad_key_400(self):
        tip = gemcheck.advise(400, "API key not valid. Please pass a valid API key.")
        self.assertIn("aistudio.google.com", tip)

    def test_403_points_at_api_enablement(self):
        self.assertIn("Generative Language API", gemcheck.advise(403, ""))

    def test_404_points_at_model_name(self):
        tip = gemcheck.advise(404, "")
        self.assertIn("v1beta", tip)

    def test_429_says_use_flash(self):
        self.assertIn("flash", gemcheck.advise(429, ""))

    def test_5xx_is_transient(self):
        self.assertIn("Transient", gemcheck.advise(503, ""))


class HelperTests(unittest.TestCase):
    def test_error_message_extraction(self):
        self.assertEqual(
            gemcheck._error_message({"error": {"message": "boom"}}), "boom")
        self.assertEqual(gemcheck._error_message({}), "")

    def test_retry_delay_parsed(self):
        body = {"error": {"details": [
            {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "37s"}]}}
        self.assertEqual(gemcheck._retry_delay(body), 37.0)
        self.assertIsNone(gemcheck._retry_delay({"error": {}}))

    def test_quota_metric_reveals_per_day(self):
        body = {"error": {"details": [
            {"@type": "type.googleapis.com/google.rpc.QuotaFailure",
             "violations": [{"quotaMetric": "generate_requests_per_model_per_day"}]}]}}
        self.assertIn("per_day", gemcheck._quota_metric(body))

    def test_generatable_puts_flash_first_and_drops_non_generators(self):
        body = {"models": [
            {"name": "models/gemini-1.5-pro",
             "supportedGenerationMethods": ["generateContent"]},
            {"name": "models/gemini-2.0-flash",
             "supportedGenerationMethods": ["generateContent"]},
            {"name": "models/text-embedding-004",
             "supportedGenerationMethods": ["embedContent"]},
        ]}
        names = gemcheck._generatable(body)
        self.assertEqual(names, ["gemini-2.0-flash", "gemini-1.5-pro"])
        self.assertNotIn("text-embedding-004", names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
