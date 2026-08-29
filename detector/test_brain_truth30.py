#!/usr/bin/env python3
"""Truth/provenance tests for brain.py. Offline: no provider network calls."""
from dataclasses import FrozenInstanceError
import hashlib
import unittest

import brain


class FakeProvider(brain.Provider):
    def __init__(self, name="fake", model="model-1", answer=None, error=None):
        self.name = name
        self._model = model
        self.answer = answer
        self.error = error
        self.calls = 0

    def generate(self, _prompt):
        self.calls += 1
        if self.error:
            raise brain.ProviderError(self.error)
        return self.answer


def digest(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


class TypedGenerationTests(unittest.TestCase):
    def test_success_records_provider_model_and_content_hashes(self):
        prompt = "write a precise parser"
        content = "def parse(value):\n    return value"
        bus = brain.Brain([FakeProvider("groq", "qwen/code", content)])

        result = bus.generate_result(prompt)

        self.assertIsInstance(result, brain.GenerationResult)
        self.assertEqual(result.status, brain.GenerationStatus.SUCCESS)
        self.assertTrue(result.success)
        self.assertFalse(result.failed)
        self.assertFalse(result.abstained)
        self.assertEqual((result.provider, result.model), ("groq", "qwen/code"))
        self.assertEqual(result.content, content)
        self.assertEqual(result.prompt_sha256, digest(prompt))
        self.assertEqual(result.response_sha256, digest(content))
        self.assertEqual(result.require_content(), content)

    def test_evidence_is_content_free_json_safe_and_immutable(self):
        prompt = "private prompt body"
        content = "private response body"
        result = brain.Brain([FakeProvider(answer=content)]).generate_result(prompt)

        evidence = result.evidence
        record = result.evidence_dict()
        self.assertEqual(record["schema"], "attestor-generation-evidence/1")
        self.assertEqual(record["status"], "success")
        self.assertEqual(record["prompt_sha256"], digest(prompt))
        self.assertEqual(record["response_sha256"], digest(content))
        self.assertNotIn(prompt, repr(record))
        self.assertNotIn(content, repr(record))
        with self.assertRaises(FrozenInstanceError):
            evidence.provider = "changed"

    def test_provider_failure_is_typed_and_never_becomes_content(self):
        bus = brain.Brain([FakeProvider("openai", "gpt-test", error="401 bad key")],
                          mode="compare")

        legacy = bus.generate("prompt")
        failed = legacy["openai"]

        self.assertIsInstance(failed, brain.GenerationResult)
        self.assertEqual(failed.status, brain.GenerationStatus.FAILED)
        self.assertTrue(failed.failed)
        self.assertIsNone(failed.content)
        self.assertIsNone(failed.response_sha256)
        self.assertEqual(str(failed), "")
        self.assertFalse(failed)
        self.assertIn("failed", failed)  # compatibility with the original API test
        with self.assertRaises(brain.ProviderError):
            failed.require_content()
        with self.assertRaises(brain.ProviderError):
            brain.strip_fences(failed)

    def test_empty_provider_response_is_an_explicit_abstention(self):
        result = brain.Brain([FakeProvider(answer="  \n")]).generate_result("prompt")

        self.assertEqual(result.status, brain.GenerationStatus.ABSTAINED)
        self.assertTrue(result.abstained)
        self.assertIsNone(result.content)
        self.assertIsNone(result.response_sha256)
        self.assertEqual(str(result), "")

    def test_fallback_preserves_every_attempt_until_success(self):
        failed = FakeProvider("first", "one", error="quota")
        abstained = FakeProvider("second", "two", answer=None)
        succeeded = FakeProvider("third", "three", answer="```python\nx = 1\n```")
        unused = FakeProvider("fourth", "four", answer="x = 2")
        bus = brain.Brain([failed, abstained, succeeded, unused])

        self.assertEqual(bus.generate("prompt"), "x = 1")
        results = bus.last_generation_results()

        self.assertEqual(
            [item.status for item in results],
            [brain.GenerationStatus.FAILED, brain.GenerationStatus.ABSTAINED,
             brain.GenerationStatus.SUCCESS])
        self.assertEqual([item.provider for item in results], ["first", "second", "third"])
        self.assertEqual(unused.calls, 0)
        self.assertEqual(
            tuple(item.as_dict() for item in bus.generation_evidence()),
            tuple(item.evidence_dict() for item in results))

    def test_compare_keeps_success_strings_but_failure_as_typed_state(self):
        bus = brain.Brain([
            FakeProvider("good", "m1", answer="answer"),
            FakeProvider("down", "m2", error="offline"),
            FakeProvider("quiet", "m3", answer=""),
        ], mode="compare")

        answers = bus.generate("prompt")

        self.assertEqual(answers["good"], "answer")
        self.assertIsInstance(answers["down"], brain.GenerationResult)
        self.assertIsInstance(answers["quiet"], brain.GenerationResult)
        candidates = [value for value in answers.values() if isinstance(value, str)]
        self.assertEqual(candidates, ["answer"])
        self.assertFalse(any(value.startswith("[failed:") for value in candidates))

    def test_no_provider_is_abstention_in_typed_api_and_error_in_legacy_api(self):
        bus = brain.Brain([])
        result = bus.generate_result("prompt")

        self.assertTrue(result.abstained)
        self.assertEqual(result.provider, "brain")
        self.assertEqual(result.prompt_sha256, digest("prompt"))
        with self.assertRaises(brain.ProviderError):
            bus.generate("prompt")

    def test_inconsistent_result_cannot_claim_false_response_hash(self):
        with self.assertRaises(ValueError):
            brain.GenerationResult(
                "provider", "model", "success", "actual", digest("prompt"),
                digest("invented"))

    def test_hashes_are_stable_for_unicode(self):
        prompt = "explain café 🔐"
        content = "résultat ✓"
        one = brain.Brain([FakeProvider(answer=content)]).generate_result(prompt)
        two = brain.Brain([FakeProvider(answer=content)]).generate_result(prompt)
        self.assertEqual(one.evidence, two.evidence)
        self.assertEqual(one.prompt_sha256, digest(prompt))
        self.assertEqual(one.response_sha256, digest(content))


if __name__ == "__main__":
    unittest.main(verbosity=2)
