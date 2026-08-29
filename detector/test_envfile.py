#!/usr/bin/env python3
"""Tests for envfile.py -- the keys.env loader. Offline; cleans up env + files."""
import os
import tempfile
import unittest

import envfile

SAMPLE = '''\
# a comment
GROQ_API_KEY=gsk_fromfile
export OPENROUTER_API_KEY="sk-or-quoted"
MISTRAL_MODEL = 'codestral-latest'

BADLINE_NO_EQUALS
GROQ_MODEL=qwen/qwen3-32b=weird=value
OPENAI_BASE_URL=https://attacker.invalid/v1
PYTHONPATH=/attacker/code
lowercase_name=ignored
'''

KEYS = ("GROQ_API_KEY", "OPENROUTER_API_KEY", "MISTRAL_MODEL", "GROQ_MODEL",
        "ATTESTOR_ENV_FILE", "OPENAI_BASE_URL", "PYTHONPATH")


class EnvfileTests(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.pop(k, None) for k in KEYS}
        fd, self._path = tempfile.mkstemp(suffix=".env")
        with os.fdopen(fd, "w") as fh:
            fh.write(SAMPLE)
        os.environ["ATTESTOR_ENV_FILE"] = self._path

    def tearDown(self):
        os.remove(self._path)
        for k in KEYS:
            os.environ.pop(k, None)
        for k, v in self._saved.items():
            if v is not None:
                os.environ[k] = v

    def test_parses_comments_quotes_and_export(self):
        pairs = envfile._parse(SAMPLE)
        self.assertEqual(pairs["GROQ_API_KEY"], "gsk_fromfile")
        self.assertEqual(pairs["OPENROUTER_API_KEY"], "sk-or-quoted")   # quotes stripped
        self.assertEqual(pairs["MISTRAL_MODEL"], "codestral-latest")     # export + quotes
        self.assertNotIn("BADLINE_NO_EQUALS", pairs)

    def test_value_may_contain_equals(self):
        self.assertEqual(envfile._parse(SAMPLE)["GROQ_MODEL"], "qwen/qwen3-32b=weird=value")

    def test_only_exact_allowlisted_provider_variables_are_parsed(self):
        pairs = envfile._parse(SAMPLE)
        self.assertNotIn("OPENAI_BASE_URL", pairs)
        self.assertNotIn("PYTHONPATH", pairs)
        self.assertNotIn("lowercase_name", pairs)

    def test_load_sets_the_environment(self):
        loaded = envfile.load()
        self.assertIn("GROQ_API_KEY", loaded)
        self.assertEqual(os.environ["GROQ_API_KEY"], "gsk_fromfile")

    def test_real_env_var_wins_over_the_file(self):
        os.environ["GROQ_API_KEY"] = "gsk_from_shell"
        envfile.load()
        self.assertEqual(os.environ["GROQ_API_KEY"], "gsk_from_shell")   # not overridden

    def test_override_true_forces_the_file(self):
        os.environ["GROQ_API_KEY"] = "gsk_from_shell"
        envfile.load(override=True)
        self.assertEqual(os.environ["GROQ_API_KEY"], "gsk_fromfile")

    def test_missing_file_is_a_no_op(self):
        os.environ.pop("ATTESTOR_ENV_FILE", None)
        # from a temp cwd with no keys.env / .env
        d = tempfile.mkdtemp()
        old = os.getcwd()
        try:
            os.chdir(d)
            # find() also checks next to the scripts; only assert it doesn't crash
            self.assertIsInstance(envfile.load("/no/such/file.env"), list)
        finally:
            os.chdir(old)
            os.rmdir(d)

    def test_untrusted_cwd_dotenv_is_never_discovered(self):
        os.environ.pop("ATTESTOR_ENV_FILE", None)
        with tempfile.TemporaryDirectory() as directory:
            with open(os.path.join(directory, ".env"), "w", encoding="utf-8") as fh:
                fh.write("GROQ_API_KEY=gsk_from_untrusted_repo\n")
            old = os.getcwd()
            try:
                os.chdir(directory)
                self.assertEqual(envfile.find(), "")
                self.assertEqual(envfile.load(), [])
                self.assertNotIn("GROQ_API_KEY", os.environ)
            finally:
                os.chdir(old)

    def test_explicit_file_does_not_load_endpoint_override_variables(self):
        loaded = envfile.load()
        self.assertNotIn("OPENAI_BASE_URL", loaded)
        self.assertNotIn("OPENAI_BASE_URL", os.environ)


class BrainIntegrationTests(unittest.TestCase):
    def test_from_env_reads_the_key_file(self):
        import brain
        for k in ("GROQ_API_KEY", "GROQ_MODEL", "ATTESTOR_ENV_FILE"):
            os.environ.pop(k, None)
        fd, path = tempfile.mkstemp(suffix=".env")
        with os.fdopen(fd, "w") as fh:
            fh.write("GROQ_API_KEY=gsk_viafile\n")
        os.environ["ATTESTOR_ENV_FILE"] = path
        try:
            self.assertIn("groq", brain.from_env().provider_names())
        finally:
            os.remove(path)
            for k in ("GROQ_API_KEY", "ATTESTOR_ENV_FILE"):
                os.environ.pop(k, None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
