"""Tests for SWE-bench Verified benchmark harness."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bench"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))
import swe_bench


SAMPLE_PATCH = """\
diff --git a/django/db/models/query.py b/django/db/models/query.py
index abc1234..def5678 100644
--- a/django/db/models/query.py
+++ b/django/db/models/query.py
@@ -1200,6 +1200,8 @@ class QuerySet:
     def _filter_or_exclude(self, negate, args, kwargs):
+        if not args and not kwargs:
+            raise ValueError("Cannot filter with empty arguments")
         clone = self._clone()
diff --git a/tests/queries/test_query.py b/tests/queries/test_query.py
index 111aaa..222bbb 100644
--- a/tests/queries/test_query.py
+++ b/tests/queries/test_query.py
@@ -50,6 +50,12 @@ class QueryTests(TestCase):
+    def test_empty_filter(self):
+        with self.assertRaises(ValueError):
+            MyModel.objects.filter()
"""

SECURITY_PATCH = """\
diff --git a/app/views.py b/app/views.py
index aaa..bbb 100644
--- a/app/views.py
+++ b/app/views.py
@@ -42,7 +42,7 @@ def search(request):
-    query = f"SELECT * FROM items WHERE name = '{request.GET['q']}'"
+    query = "SELECT * FROM items WHERE name = %s"
"""


def test_extract_patch_files():
    files = swe_bench._extract_patch_files(SAMPLE_PATCH)
    assert "django/db/models/query.py" in files
    assert "tests/queries/test_query.py" in files


def test_extract_patch_locations():
    locs = swe_bench._extract_patch_locations(SAMPLE_PATCH)
    assert len(locs) == 2
    assert locs[0].file == "django/db/models/query.py"
    assert locs[0].functions == ["_filter_or_exclude"]
    assert 1200 in locs[0].lines_changed


def test_extract_patch_locations_no_function():
    locs = swe_bench._extract_patch_locations(SECURITY_PATCH)
    assert len(locs) == 1
    assert locs[0].file == "app/views.py"


def test_score_findings_hit():
    findings = [
        {"file": "django/db/models/query.py", "line": 1202, "rule": "test"},
        {"file": "other.py", "line": 5, "rule": "noise"},
    ]
    locs = swe_bench._extract_patch_locations(SAMPLE_PATCH)
    scores = swe_bench._score_findings(findings, locs)
    assert scores["file_hit"] is True
    assert scores["in_patched_files"] == 1
    assert scores["total"] == 2


def test_score_findings_miss():
    findings = [
        {"file": "unrelated.py", "line": 10, "rule": "test"},
    ]
    locs = swe_bench._extract_patch_locations(SAMPLE_PATCH)
    scores = swe_bench._score_findings(findings, locs)
    assert scores["file_hit"] is False
    assert scores["in_patched_files"] == 0


def test_score_findings_empty():
    locs = swe_bench._extract_patch_locations(SAMPLE_PATCH)
    scores = swe_bench._score_findings([], locs)
    assert scores["file_hit"] is False
    assert scores["total"] == 0


def test_score_line_proximity():
    findings = [
        {"file": "django/db/models/query.py", "line": 1205, "rule": "test"},
    ]
    locs = swe_bench._extract_patch_locations(SAMPLE_PATCH)
    scores = swe_bench._score_findings(findings, locs)
    assert scores["line_proximate"] == 1


def test_score_line_too_far():
    findings = [
        {"file": "django/db/models/query.py", "line": 50, "rule": "test"},
    ]
    locs = swe_bench._extract_patch_locations(SAMPLE_PATCH)
    scores = swe_bench._score_findings(findings, locs)
    assert scores["line_proximate"] == 0


def test_security_filter():
    assert any(kw in "sql injection in query builder" for kw in swe_bench.SECURITY_KEYWORDS)
    assert not any(kw in "add typing support for generics" for kw in swe_bench.SECURITY_KEYWORDS)


def test_is_python_repo():
    assert swe_bench._is_python_repo({"patch": SAMPLE_PATCH})
    assert not swe_bench._is_python_repo(
        {"patch": "diff --git a/foo.rs b/foo.rs\n"})


def test_bench_result_defaults():
    r = swe_bench.BenchResult(
        instance_id="test", repo="test/repo",
        patch_locations=[])
    assert r.findings_total == 0
    assert r.file_hit is False
    assert r.error == ""
    assert r.council_verdict == ""


def test_patch_location_dataclass():
    loc = swe_bench.PatchLocation(
        file="a.py",
        functions=["foo", "bar"],
        lines_changed=[10, 20])
    assert loc.file == "a.py"
    assert len(loc.functions) == 2


def test_compute_summary():
    r1 = swe_bench.BenchResult(
        instance_id="a", repo="r", patch_locations=[],
        findings_total=5, findings_in_patched_files=2,
        file_hit=True, scan_time_ms=100)
    r2 = swe_bench.BenchResult(
        instance_id="b", repo="r", patch_locations=[],
        findings_total=3, findings_in_patched_files=0,
        file_hit=False, scan_time_ms=200)
    r3 = swe_bench.BenchResult(
        instance_id="c", repo="r", patch_locations=[],
        error="clone failed")

    summary = swe_bench._compute_summary([r1, r2, r3])
    assert summary["total_instances"] == 3
    assert summary["evaluated"] == 2
    assert summary["errors"] == 1
    assert summary["file_hits"] == 1
    assert summary["file_recall"] == 0.5
    assert summary["total_findings"] == 8
    assert summary["findings_in_patched_files"] == 2
    assert summary["avg_scan_ms"] == 150.0


def test_compute_summary_empty():
    summary = swe_bench._compute_summary([])
    assert summary["total_instances"] == 0
    assert summary["file_recall"] == 0.0
    assert summary["precision"] == 0.0


def test_result_to_dict():
    loc = swe_bench.PatchLocation(file="x.py")
    r = swe_bench.BenchResult(
        instance_id="test__1", repo="org/repo",
        patch_locations=[loc], findings_total=3,
        file_hit=True, scan_time_ms=50)
    d = swe_bench._result_to_dict(r)
    assert d["instance_id"] == "test__1"
    assert d["patch_files"] == ["x.py"]
    assert d["file_hit"] is True


def test_extract_multiple_hunks():
    patch = """\
diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -10,3 +10,5 @@ def foo():
+    pass
@@ -30,3 +32,5 @@ def bar():
+    pass
"""
    locs = swe_bench._extract_patch_locations(patch)
    assert len(locs) == 1
    assert set(locs[0].functions) == {"foo", "bar"}
    assert 10 in locs[0].lines_changed
    assert 32 in locs[0].lines_changed
