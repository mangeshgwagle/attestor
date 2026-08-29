#!/usr/bin/env python3
"""Tests for brain.py -- provider routing (fallback/compare). Offline: no network.

The live provider HTTP can't be verified here (no working key + restricted egress);
what's tested is the routing that runs several models 'alongside' each other.
"""
import os
import unittest
from unittest import mock

import brain


class FakeProvider(brain.Provider):
    def __init__(self, name, answer=None, error=None):
        self.name = name
        self._answer = answer
        self._error = error

    def generate(self, prompt):
        if self._error:
            raise brain.ProviderError(self._error)
        return self._answer


class RoutingTests(unittest.TestCase):
    def test_fallback_returns_first_success(self):
        b = brain.Brain([FakeProvider("gemini", error="429 quota"),
                         FakeProvider("openai", answer="def f():\n    return 1")])
        self.assertEqual(b.generate("x"), "def f():\n    return 1")

    def test_fallback_all_fail_raises(self):
        b = brain.Brain([FakeProvider("a", error="down"),
                         FakeProvider("b", error="down")])
        with self.assertRaises(brain.ProviderError):
            b.generate("x")

    def test_compare_asks_every_provider(self):
        b = brain.Brain([FakeProvider("gemini", answer="AAA"),
                         FakeProvider("openai", error="401 bad key")],
                        mode="compare")
        out = b.generate("x")
        self.assertEqual(out["gemini"], "AAA")
        self.assertIn("failed", out["openai"])

    def test_strip_fences(self):
        self.assertEqual(brain.strip_fences("```python\nx = 1\n```"), "x = 1")
        self.assertEqual(brain.strip_fences("no fence here"), "no fence here")

    def test_available_and_names(self):
        b = brain.Brain([FakeProvider("gemini"), FakeProvider("openai")])
        self.assertTrue(b.available())
        self.assertEqual(b.provider_names(), ["gemini", "openai"])
        self.assertFalse(brain.Brain([]).available())


class FromEnvTests(unittest.TestCase):
    KEYS = ("GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY", "GROQ_API_KEY",
            "OPENROUTER_API_KEY", "MISTRAL_API_KEY", "OLLAMA_MODEL", "OLLAMA_HOST",
            "ATTESTOR_ALLOW_REMOTE_OLLAMA",
            "GEMINI_MODEL", "OPENAI_MODEL", "GROQ_MODEL", "OPENROUTER_MODEL",
            "MISTRAL_MODEL")

    def setUp(self):
        self._saved = {k: os.environ.pop(k, None) for k in self.KEYS}

    def tearDown(self):
        for k, v in self._saved.items():
            if v is not None:
                os.environ[k] = v

    def test_no_keys_means_unavailable(self):
        self.assertFalse(brain.from_env().available())

    def test_fallback_order_is_reliable_free_first(self):
        for key in ("GROQ_API_KEY", "OPENROUTER_API_KEY", "MISTRAL_API_KEY",
                    "GEMINI_API_KEY", "OPENAI_API_KEY"):
            os.environ[key] = "fake"
        b = brain.from_env()
        # sturdy free tiers first, flaky Gemini later, paid OpenAI last
        self.assertEqual(b.provider_names(),
                         ["groq", "openrouter", "mistral", "gemini", "openai"])

    def test_openrouter_and_mistral_alone(self):
        os.environ["OPENROUTER_API_KEY"] = "fake"
        os.environ["MISTRAL_API_KEY"] = "fake"
        self.assertEqual(brain.from_env().provider_names(), ["openrouter", "mistral"])

    def test_ollama_is_the_local_backstop_and_sits_last(self):
        os.environ["GROQ_API_KEY"] = "fake"
        os.environ["OLLAMA_MODEL"] = "llama3.2"       # naming a local model enables it
        names = brain.from_env().provider_names()
        self.assertEqual(names, ["groq", "ollama"])    # local sits after the cloud tiers
        ollama = brain.from_env().providers()[-1]
        self.assertIn("localhost:11434", ollama._url)

    def test_remote_ollama_host_is_blocked_by_default(self):
        os.environ["OLLAMA_MODEL"] = "qwen2.5-coder"
        os.environ["OLLAMA_HOST"] = "http://192.168.1.5:11434"
        bus = brain.from_env()
        self.assertFalse(bus.available())
        self.assertIn("remote OLLAMA_HOST blocked", bus.configuration_errors()[0])

    def test_remote_ollama_requires_explicit_trust_opt_in(self):
        os.environ["OLLAMA_MODEL"] = "qwen2.5-coder"
        os.environ["OLLAMA_HOST"] = "http://192.168.1.5:11434"
        os.environ["ATTESTOR_ALLOW_REMOTE_OLLAMA"] = "1"
        self.assertIn("192.168.1.5", brain.from_env().providers()[0]._url)

    def test_ollama_rejects_credentials_and_paths(self):
        for host in ("http://user:pass@localhost:11434",
                     "http://localhost:11434/attacker",
                     "file:///tmp/socket"):
            with self.subTest(host=host):
                with self.assertRaises(brain.ProviderConfigurationError):
                    brain.OllamaProvider(host=host)

    def test_localhost_must_resolve_only_to_loopback(self):
        answers = [
            (2, 1, 6, "", ("127.0.0.1", 11434)),
            (2, 1, 6, "", ("8.8.8.8", 11434)),
        ]
        with mock.patch("brain.socket.getaddrinfo", return_value=answers):
            with self.assertRaises(brain.ProviderConfigurationError):
                brain.OllamaProvider(host="http://localhost:11434")

    def test_groq_alone(self):
        os.environ["GROQ_API_KEY"] = "fake-groq"
        b = brain.from_env()
        self.assertEqual(b.provider_names(), ["groq"])

    def test_openai_model_is_configurable(self):
        os.environ["OPENAI_API_KEY"] = "fake"
        os.environ["OPENAI_MODEL"] = "gpt-5.5"     # whatever string is real for you
        b = brain.from_env()
        self.assertEqual(b._providers[0]._model, "gpt-5.5")

    def test_groq_model_is_configurable_to_qwen(self):
        os.environ["GROQ_API_KEY"] = "fake"
        os.environ["GROQ_MODEL"] = "qwen/qwen3-32b"   # the actual sibling
        b = brain.from_env()
        self.assertEqual(b._providers[0]._model, "qwen/qwen3-32b")
        self.assertEqual(b._providers[0].name, "groq")

    def test_model_override_pins_every_provider(self):
        # "just qwen and attestor": one Groq key + a model override
        os.environ["GROQ_API_KEY"] = "fake"
        b = brain.from_env(model="qwen/qwen3-32b")
        self.assertEqual(b.provider_names(), ["groq"])
        self.assertEqual(b._providers[0]._model, "qwen/qwen3-32b")

    def test_model_id_cannot_inject_a_query_or_control_character(self):
        os.environ["OPENAI_API_KEY"] = "fake"
        os.environ["OPENAI_MODEL"] = "good?key=steal"
        bus = brain.from_env()
        self.assertFalse(bus.available())
        self.assertTrue(bus.configuration_errors())

    def test_cloud_endpoint_validation_is_exact(self):
        self.assertEqual(
            brain._validate_endpoint("https://api.openai.com/v1/chat/completions",
                                     {"api.openai.com"}),
            "https://api.openai.com/v1/chat/completions")
        with self.assertRaises(brain.ProviderConfigurationError):
            brain._validate_endpoint("https://api.openai.com.attacker.invalid/v1",
                                     {"api.openai.com"})
        with self.assertRaises(brain.ProviderConfigurationError):
            brain._validate_endpoint("http://api.openai.com/v1",
                                     {"api.openai.com"})

    def test_cloud_dns_must_not_resolve_to_a_private_address(self):
        answers = [
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ]
        with mock.patch("brain.socket.getaddrinfo", return_value=answers):
            with self.assertRaises(brain.ProviderError):
                brain._validate_cloud_resolution("api.openai.com")


if __name__ == "__main__":
    unittest.main(verbosity=2)
