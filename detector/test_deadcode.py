#!/usr/bin/env python3
"""Tests for deadcode.py -- project-wide unreferenced-symbol detection. Offline."""
import os
import tempfile
import unittest

import deadcode


SAMPLE = ("def _used():\n    return 1\n\n"
          "def _dead():\n    return 2\n\n"
          "def api():\n    return _used()\n\n"
          "class _DeadClass:\n    pass\n\n"
          "def main():\n    return api()\n")


def _tmp(src):
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as fh:
        fh.write(src)
    return path


class DeadCodeTests(unittest.TestCase):
    def _find(self, src, **kw):
        path = _tmp(src)
        try:
            return {(d.name, d.kind) for d in deadcode.find_dead([path], **kw)}
        finally:
            os.remove(path)

    def test_flags_unreferenced_private_defs(self):
        found = self._find(SAMPLE)
        self.assertIn(("_dead", "function"), found)
        self.assertIn(("_DeadClass", "class"), found)

    def test_spares_referenced_and_exempt_names(self):
        found = {name for name, _kind in self._find(SAMPLE)}
        self.assertNotIn("_used", found)      # called by api()
        self.assertNotIn("api", found)        # called by main()
        self.assertNotIn("main", found)       # exempt entrypoint

    def test_decorated_defs_are_not_flagged(self):
        src = "import app\n\n@app.route('/')\ndef handler():\n    return 1\n"
        self.assertEqual(self._find(src), set())    # decorator may register it

    def test_dunder_all_export_spares_a_name(self):
        src = "__all__ = ['widget']\n\ndef widget():\n    return 1\n"
        self.assertEqual(self._find(src), set())

    def test_string_reference_spares_a_name(self):
        # dynamic dispatch: getattr(mod, "plugin") -- the string counts as a use
        src = "def plugin():\n    return 1\n\ndef run(mod):\n    return getattr(mod, 'plugin')\n"
        self.assertNotIn("plugin", {n for n, _k in self._find(src)})

    def test_private_only_filter(self):
        src = "def _hidden():\n    return 1\n\ndef exposed():\n    return 2\n"
        pub = {n for n, _k in self._find(src)}
        priv = {n for n, _k in self._find(src, private_only=True)}
        self.assertIn("exposed", pub)
        self.assertIn("_hidden", pub)
        self.assertEqual(priv, {"_hidden"})   # public dropped under --private


if __name__ == "__main__":
    unittest.main(verbosity=2)
