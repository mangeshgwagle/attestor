#!/usr/bin/env python3
"""The scan path follows taint between files, and caches that correctly.

`detect.java_cross_file_taint` and `scan_project` existed and worked, but
`scanengine` scanned each file on its own, so a flow whose source and sink live
in different files was invisible to every caller of the engine -- which is the
CLI, and which is how controllers and data-access layers are actually written.

Two properties are asserted here, and the second is the one that bites.

**Detection.** A tainted parameter read in one class and concatenated into SQL
in another must be reported. Neither file alone contains the defect.

**Cache correctness.** A finding now depends on bytes outside its own file, so
the per-file cache key has to include the project-wide seed. Without that,
editing the *source* file leaves the *sink* file matching a stale entry and the
flow silently stops being reported -- a false negative that appears only on a
warm cache, which is the worst way for a scanner to be wrong.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import detect  # noqa: E402
import scanengine  # noqa: E402


TAINTED_CALLER = """\
public class Controller {
    public void handle(HttpServletRequest req) throws Exception {
        String name = req.getParameter("name");
        Dao.lookup(name);
    }
}
"""

CONSTANT_CALLER = """\
public class Controller {
    public void handle() throws Exception {
        Dao.lookup("a constant");
    }
}
"""

SINK = """\
public class Dao {
    public static void lookup(String value) throws Exception {
        Statement st = conn.createStatement();
        st.executeQuery("SELECT * FROM users WHERE n='" + value + "'");
    }
}
"""


def workspace(caller: str) -> Path:
    root = Path(tempfile.mkdtemp())
    (root / "Controller.java").write_text(caller, encoding="utf-8")
    (root / "Dao.java").write_text(SINK, encoding="utf-8")
    return root


def rules(result) -> set[str]:
    return {issue.rule for issue in result.issues}


class FlowsAcrossFiles(unittest.TestCase):
    def test_neither_file_alone_contains_the_defect(self):
        """The premise: this is why a per-file scan could not see it."""
        for name, source in (("Controller.java", TAINTED_CALLER), ("Dao.java", SINK)):
            with self.subTest(file=name):
                found = {row.rule for row
                         in detect.scan_source(source, name, "java", deep=True)}
                self.assertNotIn("java-sql-injection", found)

    def test_the_engine_reports_the_split_flow(self):
        root = workspace(TAINTED_CALLER)
        result = scanengine.scan([str(root)], jobs=1, use_cache=False)
        self.assertIn("java-sql-injection", rules(result))

    def test_a_constant_argument_is_not_reported(self):
        """The seed must carry taint, not merely connect two files."""
        root = workspace(CONSTANT_CALLER)
        result = scanengine.scan([str(root)], jobs=1, use_cache=False)
        self.assertNotIn("java-sql-injection", rules(result))

    def test_the_finding_lands_on_the_sink(self):
        root = workspace(TAINTED_CALLER)
        result = scanengine.scan([str(root)], jobs=1, use_cache=False)
        sink = [issue for issue in result.issues
                if issue.rule == "java-sql-injection"]
        self.assertTrue(sink)
        self.assertTrue(sink[0].path.endswith("Dao.java"), sink[0].path)


class CacheStaysCorrect(unittest.TestCase):
    def test_editing_one_file_invalidates_the_other(self):
        """The subtle one: Dao.java is byte-identical throughout.

        Its result depends on Controller.java, so its cache entry must not
        survive a change there. If the seed were left out of the key this test
        would still report the finding after the taint was removed.
        """
        root = workspace(TAINTED_CALLER)
        cache = str(root / "cache.json")

        first = scanengine.scan([str(root)], jobs=1, use_cache=True, cache_path=cache)
        self.assertIn("java-sql-injection", rules(first))

        warm = scanengine.scan([str(root)], jobs=1, use_cache=True, cache_path=cache)
        self.assertGreater(warm.cache_hits, 0, "second scan should hit the cache")
        self.assertIn("java-sql-injection", rules(warm))

        # Remove the taint in the *caller*; the sink file is untouched.
        (root / "Controller.java").write_text(CONSTANT_CALLER, encoding="utf-8")
        after = scanengine.scan([str(root)], jobs=1, use_cache=True, cache_path=cache)
        self.assertNotIn("java-sql-injection", rules(after))

    def test_a_warm_cache_agrees_with_a_cold_one(self):
        root = workspace(TAINTED_CALLER)
        cache = str(root / "cache.json")
        cold = scanengine.scan([str(root)], jobs=1, use_cache=False)
        scanengine.scan([str(root)], jobs=1, use_cache=True, cache_path=cache)
        warm = scanengine.scan([str(root)], jobs=1, use_cache=True, cache_path=cache)
        self.assertEqual(rules(cold), rules(warm))


class OtherLanguagesAreUnaffected(unittest.TestCase):
    def test_a_tree_without_java_has_no_seed(self):
        """No Java means no seed, so existing cache entries stay valid."""
        root = Path(tempfile.mkdtemp())
        (root / "a.py").write_text("x = 1\n", encoding="utf-8")
        seed, identity = scanengine._java_cross_file_seed(
            [root / "a.py"], scanengine.DEFAULT_MAX_BYTES)
        self.assertEqual("", identity)
        self.assertFalse(getattr(seed, "received", frozenset()))

    def test_a_single_java_file_has_no_seed(self):
        """One file cannot carry a flow between files."""
        root = workspace(TAINTED_CALLER)
        seed, identity = scanengine._java_cross_file_seed(
            [root / "Dao.java"], scanengine.DEFAULT_MAX_BYTES)
        self.assertEqual("", identity)
        self.assertFalse(getattr(seed, "received", frozenset()))

    def test_the_digest_changes_only_when_the_seed_does(self):
        data = b"public class A {}"
        plain = scanengine._digest(data, False, False, "")
        seeded = scanengine._digest(data, False, False, "abc123")
        other = scanengine._digest(data, False, False, "def456")
        self.assertNotEqual(plain, seeded)
        self.assertNotEqual(seeded, other)
        self.assertEqual(plain, scanengine._digest(data, False, False, ""))


if __name__ == "__main__":
    unittest.main()
