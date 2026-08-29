#!/usr/bin/env python3
"""Tests for the GitHub ingestion pipeline."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import github_ingest42 as gi  # noqa: E402


# =========================================================================== #
#  URL PARSING                                                                 #
# =========================================================================== #

class URLParsingTests(unittest.TestCase):

    def test_https_url(self):
        owner, name = gi.parse_github_url("https://github.com/user/repo")
        self.assertEqual("user", owner)
        self.assertEqual("repo", name)

    def test_https_url_with_git_suffix(self):
        owner, name = gi.parse_github_url("https://github.com/user/repo.git")
        self.assertEqual("user", owner)
        self.assertEqual("repo", name)

    def test_ssh_url(self):
        owner, name = gi.parse_github_url("git@github.com:user/repo.git")
        self.assertEqual("user", owner)
        self.assertEqual("repo", name)

    def test_shorthand(self):
        owner, name = gi.parse_github_url("user/repo")
        self.assertEqual("user", owner)
        self.assertEqual("repo", name)

    def test_url_with_tree_path(self):
        owner, name = gi.parse_github_url(
            "https://github.com/user/repo/tree/main/src")
        self.assertEqual("user", owner)
        self.assertEqual("repo", name)

    def test_whitespace_stripped(self):
        owner, name = gi.parse_github_url("  user/repo  ")
        self.assertEqual("user", owner)
        self.assertEqual("repo", name)

    def test_normalize(self):
        self.assertEqual(
            "https://github.com/user/repo",
            gi.normalize_github_url("git@github.com:user/repo.git"))

    def test_is_github_url_positive(self):
        self.assertTrue(gi.is_github_url("https://github.com/user/repo"))
        self.assertTrue(gi.is_github_url("git@github.com:user/repo.git"))
        self.assertTrue(gi.is_github_url("user/repo"))

    def test_is_github_url_negative(self):
        self.assertFalse(gi.is_github_url("https://gitlab.com/user/repo"))


# =========================================================================== #
#  REPO ENTRY                                                                  #
# =========================================================================== #

class RepoEntryTests(unittest.TestCase):

    def test_creation(self):
        entry = gi.RepoEntry(url="https://github.com/owner/repo")
        self.assertEqual("owner", entry.owner)
        self.assertEqual("repo", entry.name)
        self.assertEqual("owner/repo", entry.full_name)
        self.assertEqual(gi.RepoStatus.QUEUED, entry.status)

    def test_repo_id_is_deterministic(self):
        e1 = gi.RepoEntry(url="https://github.com/a/b")
        e2 = gi.RepoEntry(url="https://github.com/a/b")
        self.assertEqual(e1.repo_id, e2.repo_id)

    def test_repo_id_is_case_insensitive(self):
        e1 = gi.RepoEntry(url="https://github.com/User/Repo")
        e2 = gi.RepoEntry(url="https://github.com/user/repo")
        self.assertEqual(e1.repo_id, e2.repo_id)


# =========================================================================== #
#  REPO QUEUE                                                                  #
# =========================================================================== #

class RepoQueueTests(unittest.TestCase):

    def test_add_and_len(self):
        q = gi.RepoQueue()
        q.add("https://github.com/a/b")
        q.add("https://github.com/c/d")
        self.assertEqual(2, len(q))

    def test_dedup(self):
        q = gi.RepoQueue()
        q.add("https://github.com/a/b")
        q.add("https://github.com/a/b.git")
        q.add("git@github.com:a/b.git")
        self.assertEqual(1, len(q))

    def test_add_many(self):
        q = gi.RepoQueue()
        count = q.add_many([
            "https://github.com/a/b",
            "https://github.com/c/d",
            "# comment",
            "",
            "https://github.com/e/f",
        ])
        self.assertEqual(3, count)
        self.assertEqual(3, len(q))

    def test_contains(self):
        q = gi.RepoQueue()
        q.add("https://github.com/a/b")
        self.assertIn("a/b", q)
        self.assertNotIn("x/y", q)

    def test_queued_returns_only_queued(self):
        q = gi.RepoQueue()
        e1 = q.add("a/b")
        e2 = q.add("c/d")
        e1.status = gi.RepoStatus.DONE
        queued = q.queued()
        self.assertEqual(1, len(queued))
        self.assertEqual("c/d", queued[0].full_name)


# =========================================================================== #
#  FILE WALKER                                                                 #
# =========================================================================== #

class FileWalkerTests(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        for name, content in [
            ("main.py", "print('hello')"),
            ("util.js", "console.log('hi')"),
            ("readme.md", "# readme"),
            ("image.png", b"\x89PNG\r\n\x1a\n"),
        ]:
            path = os.path.join(self._tmpdir, name)
            mode = "w" if isinstance(content, str) else "wb"
            with open(path, mode) as f:
                f.write(content)

        node_dir = os.path.join(self._tmpdir, "node_modules", "pkg")
        os.makedirs(node_dir)
        with open(os.path.join(node_dir, "index.js"), "w") as f:
            f.write("module.exports = {}")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_finds_scannable_files(self):
        files = list(gi.walk_source_files(self._tmpdir))
        paths = [os.path.basename(p) for p, _ in files]
        self.assertIn("main.py", paths)
        self.assertIn("util.js", paths)

    def test_skips_binaries(self):
        files = list(gi.walk_source_files(self._tmpdir))
        paths = [os.path.basename(p) for p, _ in files]
        self.assertNotIn("image.png", paths)

    def test_skips_node_modules(self):
        files = list(gi.walk_source_files(self._tmpdir))
        paths = [os.path.basename(p) for p, _ in files]
        self.assertNotIn("index.js", paths)

    def test_respects_max_files(self):
        files = list(gi.walk_source_files(self._tmpdir, max_files=1))
        self.assertEqual(1, len(files))

    def test_detect_languages(self):
        langs = gi.detect_languages(self._tmpdir)
        self.assertIn("python", langs)
        self.assertIn("javascript", langs)


# =========================================================================== #
#  FALLBACK SCANNER                                                            #
# =========================================================================== #

class FallbackScannerTests(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write(self, name, content):
        path = os.path.join(self._tmpdir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def test_detects_eval(self):
        path = self._write("bad.py", "x = eval(input())\n")
        findings = gi._fallback_scan(path, "python")
        self.assertTrue(any(f["cwe"] == "CWE-94" for f in findings))

    def test_detects_shell_true(self):
        path = self._write("cmd.py",
                           "subprocess.Popen(cmd, shell=True)\n")
        findings = gi._fallback_scan(path, "python")
        self.assertTrue(any(f["cwe"] == "CWE-78" for f in findings))

    def test_detects_innerHTML(self):
        path = self._write("xss.js",
                           'el.innerHTML = userInput;\n')
        findings = gi._fallback_scan(path, "javascript")
        self.assertTrue(any(f["cwe"] == "CWE-79" for f in findings))

    def test_detects_hardcoded_password(self):
        path = self._write("cred.py",
                           'password = "hunter2"\n')
        findings = gi._fallback_scan(path, "python")
        self.assertTrue(any(f["cwe"] == "CWE-798" for f in findings))

    def test_no_findings_on_clean_code(self):
        path = self._write("clean.py",
                           "def add(a, b):\n    return a + b\n")
        findings = gi._fallback_scan(path, "python")
        self.assertEqual([], findings)


# =========================================================================== #
#  SCAN RESULT & REPORT                                                        #
# =========================================================================== #

class IngestReportTests(unittest.TestCase):

    def test_summary_format(self):
        report = gi.IngestReport(
            total_repos=10,
            repos_scanned=8,
            repos_failed=1,
            repos_skipped=1,
            total_files=500,
            total_findings=42,
            findings_by_severity={"HIGH": 10, "MEDIUM": 20, "LOW": 12},
            findings_by_cwe={"CWE-79": 15, "CWE-89": 10},
            languages_seen={"python", "javascript"},
            elapsed=30.5,
        )
        s = report.summary()
        self.assertIn("8 scanned", s)
        self.assertIn("1 failed", s)
        self.assertIn("42", s)
        self.assertIn("HIGH: 10", s)
        self.assertIn("CWE-79", s)
        self.assertIn("python", s)
        self.assertIn("30.5s", s)


# =========================================================================== #
#  GITHUB API CLIENT                                                           #
# =========================================================================== #

class GitHubAPITests(unittest.TestCase):

    def test_unauthenticated_by_default(self):
        with patch.dict(os.environ, {}, clear=True):
            api = gi.GitHubAPI(token=None)
            api._has_gh = False
            self.assertFalse(api.authenticated)

    def test_authenticated_with_token(self):
        api = gi.GitHubAPI(token="ghp_test123")
        self.assertTrue(api.authenticated)

    def test_headers_include_token(self):
        api = gi.GitHubAPI(token="ghp_test123")
        headers = api._headers()
        self.assertEqual("token ghp_test123", headers["Authorization"])

    def test_headers_without_token(self):
        api = gi.GitHubAPI(token="")
        api._token = ""
        headers = api._headers()
        self.assertNotIn("Authorization", headers)


# =========================================================================== #
#  REPO SCANNER                                                                #
# =========================================================================== #

class RepoScannerTests(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        with open(os.path.join(self._tmpdir, "vuln.py"), "w",
                  encoding="utf-8") as f:
            f.write("x = eval(input())\n")
        with open(os.path.join(self._tmpdir, "safe.py"), "w",
                  encoding="utf-8") as f:
            f.write("print('hello')\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_scan_finds_files(self):
        entry = gi.RepoEntry(url="https://github.com/test/repo")
        entry.local_path = self._tmpdir
        scanner = gi.RepoScanner()
        result = scanner.scan(entry)
        self.assertEqual(2, result.files_scanned)
        self.assertIn("python", result.languages_found)

    def test_scan_nonexistent_path(self):
        entry = gi.RepoEntry(url="https://github.com/test/repo")
        entry.local_path = "/nonexistent/path/xyz"
        scanner = gi.RepoScanner()
        result = scanner.scan(entry)
        self.assertEqual(0, result.files_scanned)
        self.assertTrue(len(result.errors) > 0)


# =========================================================================== #
#  GITHUB INGEST PIPELINE                                                      #
# =========================================================================== #

class GitHubIngestTests(unittest.TestCase):

    def test_add_repo(self):
        ingest = gi.GitHubIngest()
        entry = ingest.add_repo("https://github.com/owner/repo")
        self.assertEqual("owner", entry.owner)
        self.assertEqual("repo", entry.name)
        self.assertEqual(1, ingest.queue_size())

    def test_add_repos(self):
        ingest = gi.GitHubIngest()
        count = ingest.add_repos([
            "https://github.com/a/b",
            "https://github.com/c/d",
        ])
        self.assertEqual(2, count)
        self.assertEqual(2, ingest.queue_size())

    def test_add_repos_dedup(self):
        ingest = gi.GitHubIngest()
        ingest.add_repo("https://github.com/a/b")
        count = ingest.add_repos([
            "https://github.com/a/b",
            "https://github.com/c/d",
        ])
        self.assertEqual(2, count)
        self.assertEqual(2, ingest.queue_size())

    def test_add_repos_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                         delete=False, encoding="utf-8") as f:
            f.write("# comment\n")
            f.write("https://github.com/a/b\n")
            f.write("\n")
            f.write("https://github.com/c/d\n")
            f.write("https://github.com/e/f\n")
            path = f.name
        try:
            ingest = gi.GitHubIngest()
            count = ingest.add_repos_from_file(path)
            self.assertEqual(3, count)
        finally:
            os.unlink(path)

    def test_run_with_no_repos(self):
        ingest = gi.GitHubIngest()
        report = ingest.run()
        self.assertEqual(0, report.total_repos)
        self.assertEqual(0, report.repos_scanned)

    def test_save_and_load_queue(self):
        ingest = gi.GitHubIngest()
        ingest.add_repo("https://github.com/a/b")
        ingest.add_repo("https://github.com/c/d")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                         delete=False, encoding="utf-8") as f:
            path = f.name
        try:
            ingest.save_queue(path)
            ingest2 = gi.GitHubIngest()
            loaded = ingest2.load_queue(path)
            self.assertEqual(2, loaded)
            self.assertEqual(2, ingest2.queue_size())
        finally:
            os.unlink(path)


# =========================================================================== #
#  INTEGRATION: SCAN LOCAL FILES                                               #
# =========================================================================== #

class LocalScanIntegration(unittest.TestCase):
    """Test the pipeline with a temp directory instead of fetching from GitHub."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        with open(os.path.join(self._tmpdir, "app.py"), "w",
                  encoding="utf-8") as f:
            f.write("import os\n")
            f.write("os.system(user_input)\n")
            f.write("x = eval(data)\n")
        with open(os.path.join(self._tmpdir, "safe.py"), "w",
                  encoding="utf-8") as f:
            f.write("def greet(name):\n")
            f.write("    return 'Hello ' + name\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_fallback_scan_finds_vulnerabilities(self):
        path = os.path.join(self._tmpdir, "app.py")
        findings = gi._fallback_scan(path, "python")
        self.assertGreater(len(findings), 0)
        cwes = {f["cwe"] for f in findings}
        self.assertTrue(cwes & {"CWE-78", "CWE-94"},
                        "expected command injection or code injection findings")

    def test_scan_result_structure(self):
        entry = gi.RepoEntry(url="https://github.com/test/repo")
        entry.local_path = self._tmpdir
        scanner = gi.RepoScanner()
        result = scanner.scan(entry)
        self.assertEqual(2, result.files_scanned)
        self.assertIn("python", result.languages_found)

    def test_findings_have_repo_metadata(self):
        entry = gi.RepoEntry(url="https://github.com/test/repo")
        entry.local_path = self._tmpdir
        entry.owner = "test"
        entry.name = "repo"

        with patch("github_ingest42.scan_file", side_effect=lambda p, l, r="": [
            {"rule": "test", "cwe": "CWE-78", "path": p, "file_path": p,
             "line": 1, "severity": "HIGH", "message": "test",
             "fix": "", "snippet": "", "language": l, "confidence": 1.0}
        ]):
            scanner = gi.RepoScanner()
            result = scanner.scan(entry)
            self.assertGreater(len(result.findings), 0)
            for f in result.findings:
                self.assertEqual("test/repo", f["repo"])
                self.assertEqual("https://github.com/test/repo", f["repo_url"])


# =========================================================================== #
#  CONSTANTS                                                                   #
# =========================================================================== #

class ConstantsTests(unittest.TestCase):

    def test_version(self):
        self.assertEqual("4.2", gi.VERSION)

    def test_scannable_extensions_include_python(self):
        self.assertIn(".py", gi.SCANNABLE_EXTENSIONS)

    def test_skip_dirs_include_node_modules(self):
        self.assertIn("node_modules", gi.SKIP_DIRS)

    def test_lang_map_covers_common_languages(self):
        for ext in [".py", ".java", ".js", ".ts", ".go", ".rs", ".rb"]:
            self.assertIn(ext, gi.LANG_MAP, "missing: %s" % ext)


if __name__ == "__main__":
    unittest.main()
