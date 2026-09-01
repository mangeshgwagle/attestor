"""Tests for SWE-bench training data generator."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "training"))
import generate_swebench_data as gen


SAMPLE_PATCH = """\
diff --git a/django/db/models/query.py b/django/db/models/query.py
index abc..def 100644
--- a/django/db/models/query.py
+++ b/django/db/models/query.py
@@ -1200,6 +1200,8 @@ class QuerySet:
     def _filter_or_exclude(self, negate, args, kwargs):
-        clone = self._clone()
+        if not args and not kwargs:
+            raise ValueError("Cannot filter with empty arguments")
+        clone = self._clone()
"""

SQL_PATCH = """\
diff --git a/app/views.py b/app/views.py
--- a/app/views.py
+++ b/app/views.py
@@ -42,7 +42,7 @@ def search(request):
-    query = f"SELECT * FROM items WHERE name = '{request.GET['q']}'"
+    query = "SELECT * FROM items WHERE name = %s"
"""


def test_extract_functions_from_patch():
    funcs = gen._extract_functions_from_patch(SAMPLE_PATCH)
    assert len(funcs) >= 1
    names = [f["function"] for f in funcs]
    assert "_filter_or_exclude" in names


def test_extract_functions_deduplicates():
    patch = """\
diff --git a/a.py b/a.py
@@ -10,3 +10,5 @@ def foo():
+    pass
@@ -30,3 +32,5 @@ def foo():
+    pass
"""
    funcs = gen._extract_functions_from_patch(patch)
    names = [f["function"] for f in funcs]
    assert names.count("foo") == 1


def test_extract_changed_code():
    chunks = gen._extract_changed_code(SAMPLE_PATCH)
    assert len(chunks) == 1
    assert chunks[0]["file"] == "django/db/models/query.py"
    assert "clone = self._clone()" in chunks[0]["before"]


def test_extract_changed_code_sql():
    chunks = gen._extract_changed_code(SQL_PATCH)
    assert len(chunks) == 1
    assert "SELECT" in chunks[0]["before"]
    assert "%s" in chunks[0]["after"]


def test_extract_changed_code_no_diff():
    chunks = gen._extract_changed_code("")
    assert chunks == []


def test_guess_cwe():
    assert gen._guess_cwe("sql injection in query") == "CWE-89"
    assert gen._guess_cwe("path traversal via symlink") == "CWE-22"
    assert gen._guess_cwe("XSS in template rendering") == "CWE-79"
    assert gen._guess_cwe("CSRF token bypass") == "CWE-352"
    assert gen._guess_cwe("dangerous eval usage") == "CWE-95"
    assert gen._guess_cwe("nothing special here") == ""


def test_guess_category():
    assert gen._guess_category("sql injection attack") == "sql_injection"
    assert gen._guess_category("xss in search results") == "xss"
    assert gen._guess_category("path traversal") == "path_traversal"
    assert gen._guess_category("something unknown") == "logic_error"


def test_guess_severity():
    assert gen._guess_severity("sql injection in login") == "CRITICAL"
    assert gen._guess_severity("XSS in search results") == "HIGH"
    assert gen._guess_severity("open redirect in callback") == "MEDIUM"
    assert gen._guess_severity("typo in variable name") == "LOW"


def test_generate_from_patches():
    instances = [{
        "instance_id": "django__django-12345",
        "repo": "django/django",
        "patch": SQL_PATCH,
        "problem_statement": "SQL injection in search view",
        "base_commit": "abc123",
    }]
    pairs, stats = gen.generate_from_patches(instances)
    assert len(pairs) >= 2
    types = [p["_meta"]["type"] for p in pairs]
    assert "detect" in types
    assert "fix" in types
    assert pairs[0]["_meta"]["source"] == "swebench"


def test_generate_from_patches_empty():
    pairs, stats = gen.generate_from_patches([])
    assert pairs == []


def test_generate_from_patches_no_patch():
    instances = [{"instance_id": "test", "repo": "r", "patch": "",
                  "problem_statement": "bug"}]
    pairs, stats = gen.generate_from_patches(instances)
    assert pairs == []
    assert stats["no_patch"] == 1


def test_detect_pair_format():
    instances = [{
        "instance_id": "django__django-99999",
        "repo": "django/django",
        "patch": SQL_PATCH,
        "problem_statement": "SQL injection vulnerability",
        "base_commit": "abc",
    }]
    pairs, _ = gen.generate_from_patches(instances)
    detect_pairs = [p for p in pairs if p["_meta"]["type"] == "detect"]
    assert len(detect_pairs) >= 1
    p = detect_pairs[0]
    assert "CATEGORY:" in p["output"]
    assert "CWE:" in p["output"]
    assert "SEVERITY:" in p["output"]
    assert "DESCRIPTION:" in p["output"]


def test_fix_pair_format():
    instances = [{
        "instance_id": "test__1",
        "repo": "test/repo",
        "patch": SQL_PATCH,
        "problem_statement": "SQL injection in query",
        "base_commit": "abc",
    }]
    pairs, _ = gen.generate_from_patches(instances)
    fix_pairs = [p for p in pairs if p["_meta"]["type"] == "fix"]
    assert len(fix_pairs) >= 1
    assert "```python" in fix_pairs[0]["output"]


def test_meta_fields():
    instances = [{
        "instance_id": "django__django-12345",
        "repo": "django/django",
        "patch": SQL_PATCH,
        "problem_statement": "SQL injection",
        "base_commit": "abc",
    }]
    pairs, _ = gen.generate_from_patches(instances)
    for p in pairs:
        meta = p["_meta"]
        assert "instance_id" in meta
        assert "repo" in meta
        assert "type" in meta
        assert "category" in meta
        assert "severity" in meta
        assert meta["source"] == "swebench"
