from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import git_intelligence35 as git35
import polyglot_ir35


def _run_git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments], capture_output=True,
        text=True, check=True, timeout=20,
    )
    return completed.stdout.strip()


def _commit(root: Path, message: str) -> str:
    _run_git(root, "add", "--all")
    _run_git(root, "commit", "-m", message)
    return _run_git(root, "rev-parse", "HEAD")


class TemporaryGitRepository:
    def __enter__(self) -> Path:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        _run_git(self.root, "init", "--quiet")
        _run_git(self.root, "config", "user.name", "Attestor Test")
        _run_git(self.root, "config", "user.email", "attestor@example.invalid")
        return self.root

    def __exit__(self, exc_type, exc, traceback):
        self.temporary.cleanup()


class GitReadOnlyTests(unittest.TestCase):
    def test_diff_and_name_status_handle_option_like_hostile_paths_as_data(self):
        with TemporaryGitRepository() as root:
            (root / "app.js").write_text("old();\n", encoding="utf-8")
            base = _commit(root, "base")
            hostile = "--danger;not-a-shell-command.js"
            (root / hostile).write_text("added();\n", encoding="utf-8")
            (root / "app.js").write_text("new_call();\n", encoding="utf-8")
            head = _commit(root, "change")
            reader = git35.GitRepository(root)
            changes = reader.changed_files(base, head)
            patch = reader.diff(base, head, paths=[hostile], context=1)
        self.assertEqual(changes, [
            {"path": hostile, "status": "A", "change": "added"},
            {"path": "app.js", "status": "M", "change": "modified"},
        ])
        self.assertIn(hostile, patch["patch"])
        self.assertRegex(patch["patch_sha256"], r"^[0-9a-f]{64}$")
        self.assertFalse(patch["truncated"])

    def test_hostile_paths_and_revision_options_are_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            calls = []

            def executor(argv, cwd, timeout, max_output):
                calls.append(argv)
                return git35.CommandResult(0, b"", b"")

            reader = git35.GitRepository(folder, executor=executor)
            for path in ("../outside.py", "/absolute.py", ".git/config", "bad\0name"):
                with self.subTest(path=path), self.assertRaises(git35.GitDataError):
                    reader.blame(path, start=1, end=1)
            for revision in ("--exec=bad", "HEAD..evil", "HEAD:file", "HEAD@{1}", "bad ref"):
                with self.subTest(revision=revision), self.assertRaises(git35.GitDataError):
                    reader.changed_files(revision)
        self.assertEqual(calls, [])

    def test_blame_and_introducing_candidates_return_attribution_not_source_or_proof(self):
        secret_line = "const unique_secret_source = 'never-return-this-source';"
        with TemporaryGitRepository() as root:
            path = root / "app.js"
            path.write_text("const first = 1;\nconst second = 2;\n", encoding="utf-8")
            _commit(root, "base")
            path.write_text("const first = 1;\n" + secret_line + "\n", encoding="utf-8")
            changed_commit = _commit(root, "introduce selected line")
            reader = git35.GitRepository(root)
            records = reader.blame("app.js", start=2, end=2)
            result = reader.introducing_commit_candidates("app.js", [2])
        self.assertEqual(records[0]["commit"], changed_commit)
        self.assertFalse(records[0]["source_stored"])
        self.assertNotIn(secret_line, json.dumps(records))
        self.assertEqual(result["candidates"][0]["commit"], changed_commit)
        self.assertFalse(result["candidates"][0]["proven_introducing_commit"])
        self.assertIn("no historical build", result["limitation"])

    def test_executor_receives_only_an_argv_and_read_only_allowlisted_subcommands(self):
        with tempfile.TemporaryDirectory() as folder:
            calls = []

            def executor(argv, cwd, timeout, max_output):
                calls.append((argv, cwd, timeout, max_output))
                subcommand = next(item for item in argv if item in {"diff", "blame", "rev-parse"})
                if subcommand == "diff":
                    return git35.CommandResult(0, b"M\0--hostile;literal.js\0", b"")
                return git35.CommandResult(0, b"a" * 40 + b"\n", b"")

            reader = git35.GitRepository(folder, executor=executor)
            self.assertEqual(reader.changed_files("HEAD~1"), [{
                "path": "--hostile;literal.js", "status": "M", "change": "modified"
            }])
            self.assertEqual(reader.resolve_commit(), "a" * 40)
        self.assertEqual(len(calls), 2)
        for argv, cwd, timeout, max_output in calls:
            self.assertIsInstance(argv, list)
            self.assertIn(Path(argv[0]).name.casefold(), {"git", "git.exe"})
            self.assertNotIn("bisect", argv)
            self.assertNotIn("checkout", argv)
            self.assertNotIn("commit", argv)
            self.assertNotIn("merge", argv)
            self.assertIn(next(item for item in argv if item in {"diff", "rev-parse"}),
                          {"diff", "rev-parse"})

    def test_malformed_hostile_git_output_is_refused(self):
        outputs = [
            b"M\0../escape.js\0",
            b"M\0only-path-without-pair",
            b"R100\0old.js\0new.js\0",
            b"M\0invalid-\xff.js\0",
        ]
        with tempfile.TemporaryDirectory() as folder:
            for output in outputs:
                with self.subTest(output=output):
                    reader = git35.GitRepository(
                        folder, executor=lambda argv, cwd, timeout, maximum, data=output:
                        git35.CommandResult(0, data, b""))
                    with self.assertRaises(git35.GitDataError):
                        reader.changed_files("HEAD~1")

    def test_timeout_and_oversized_custom_executor_output_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            def timeout_executor(argv, cwd, timeout, maximum):
                raise git35.GitTimeoutError("simulated timeout")

            timed = git35.GitRepository(folder, executor=timeout_executor)
            with self.assertRaises(git35.GitTimeoutError):
                timed.changed_files("HEAD~1")
            oversized = git35.GitRepository(
                folder, max_output=1024,
                executor=lambda argv, cwd, timeout, maximum:
                git35.CommandResult(0, b"x" * 1025, b""))
            with self.assertRaises(git35.GitOutputLimitError):
                oversized.changed_files("HEAD~1")

    def test_process_boundary_explicitly_disables_shell(self):
        class FinishedProcess:
            returncode = 0

            def __init__(self, *args, **kwargs):
                kwargs["stdout"].write(b"git version test")
                kwargs["stdout"].flush()

            def poll(self):
                return 0

            def wait(self, timeout=None):
                return 0

            def kill(self):
                raise AssertionError("finished fake process must not be killed")

        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(git35.subprocess, "Popen", side_effect=FinishedProcess) as popen:
            result = git35._execute_argv(["git", "--version"], Path(folder), 1, 1024)
        self.assertEqual(result.stdout, b"git version test")
        arguments, keywords = popen.call_args
        self.assertIsInstance(arguments[0], list)
        self.assertIs(keywords["shell"], False)
        self.assertIs(keywords["stdin"], subprocess.DEVNULL)


class SemanticDatabaseTests(unittest.TestCase):
    @staticmethod
    def _project(root: Path) -> dict:
        (root / "a.js").write_text("import './b.js';\nexport function a(){ b(); }\n",
                                    encoding="utf-8")
        (root / "b.js").write_text("import './c.js';\nexport function b(){ c(); }\n",
                                    encoding="utf-8")
        (root / "c.js").write_text("export function c(){ return 1; }\n", encoding="utf-8")
        return polyglot_ir35.analyze(root)

    def test_incremental_database_builds_transitive_reverse_dependencies(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ir = self._project(root)
            database = git35.SemanticDatabase(root)
            first = database.update(ir)
            (root / "c.js").write_text("export function c(){ return 2; }\n", encoding="utf-8")
            second = database.update(polyglot_ir35.analyze(root))
        self.assertEqual(first["added"], ["a.js", "b.js", "c.js"])
        self.assertEqual(database.reverse_dependencies["c.js"], ["b.js"])
        self.assertEqual(database.reverse_dependencies["b.js"], ["a.js"])
        self.assertEqual(database.impact(["c.js"]), ["a.js", "b.js"])
        self.assertEqual(second["changed"], ["c.js"])
        self.assertEqual(second["requires_analysis"], ["a.js", "b.js", "c.js"])

    def test_cache_is_deterministic_content_addressed_source_free_and_loadable(self):
        secret = "source-secret-must-not-be-cached"
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "a.js").write_text(
                "export function a(){ return '" + secret + "'; }\n", encoding="utf-8")
            ir = polyglot_ir35.analyze(root)
            first = git35.SemanticDatabase(root)
            second = git35.SemanticDatabase(root)
            first.update(ir)
            second.update(ir)
            path = root / "semantic.json"
            first.save(path)
            stored = path.read_text(encoding="utf-8")
            loaded = git35.SemanticDatabase.load(path, root)
        self.assertEqual(first.to_document(), second.to_document())
        self.assertEqual(first.to_document(), loaded.to_document())
        self.assertNotIn(secret, stored)
        self.assertNotIn(str(root), stored)
        self.assertTrue(loaded.verify())
        for record in loaded.records.values():
            self.assertRegex(record["record_id"], r"^[0-9a-f]{64}$")
            self.assertFalse(record["source_stored"])

    def test_corrupt_cache_hash_schema_identity_and_unknown_fields_are_refused(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as other:
            root = Path(folder)
            database = git35.SemanticDatabase(root)
            database.update(self._project(root))
            valid = database.to_document()
            path = root / "semantic.json"

            cases = []
            corrupt_hash = json.loads(json.dumps(valid))
            corrupt_hash["database_sha256"] = "0" * 64
            cases.append(corrupt_hash)
            wrong_schema = json.loads(json.dumps(valid))
            wrong_schema["schema_version"] = 99
            cases.append(wrong_schema)
            smuggled_source = json.loads(json.dumps(valid))
            smuggled_source["records"]["a.js"]["source"] = "do not admit this"
            record = smuggled_source["records"]["a.js"]
            body = {key: value for key, value in record.items() if key != "record_id"}
            record["record_id"] = hashlib.sha256(json.dumps(
                body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            document_body = {key: value for key, value in smuggled_source.items()
                             if key != "database_sha256"}
            smuggled_source["database_sha256"] = hashlib.sha256(json.dumps(
                document_body, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False).encode()).hexdigest()
            cases.append(smuggled_source)

            for value in cases:
                with self.subTest(value=value.get("schema_version")):
                    path.write_text(json.dumps(value), encoding="utf-8")
                    with self.assertRaises(git35.SemanticCacheError):
                        git35.SemanticDatabase.load(path, root)
            path.write_text("{not-json", encoding="utf-8")
            with self.assertRaises(git35.SemanticCacheError):
                git35.SemanticDatabase.load(path, root)
            path.write_text(json.dumps(valid), encoding="utf-8")
            with self.assertRaises(git35.SemanticCacheError):
                git35.SemanticDatabase.load(path, other)

    def test_failed_atomic_replace_preserves_old_cache_and_cleans_temporary_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            database = git35.SemanticDatabase(root)
            database.update(self._project(root))
            path = root / "semantic.json"
            path.write_text("old-cache", encoding="utf-8")
            with mock.patch.object(git35.os, "replace", side_effect=OSError("replace failed")):
                with self.assertRaises(OSError):
                    database.save(path)
            temporary = list(root.glob(".attestor-semantic-*.tmp"))
            self.assertEqual(path.read_text(encoding="utf-8"), "old-cache")
            self.assertEqual(temporary, [])

    def test_cache_symlinks_are_refused(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as outside:
            root = Path(folder)
            database = git35.SemanticDatabase(root)
            database.update(self._project(root))
            target = Path(outside) / "target.json"
            target.write_text("outside", encoding="utf-8")
            link = root / "semantic.json"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("file symlinks are unavailable")
            with self.assertRaises(git35.SemanticCacheError):
                database.save(link)
            with self.assertRaises(git35.SemanticCacheError):
                git35.SemanticDatabase.load(link, root)
            self.assertEqual(target.read_text(encoding="utf-8"), "outside")

    def test_real_git_change_impact_combines_diff_with_cached_reverse_edges(self):
        with TemporaryGitRepository() as root:
            database = git35.SemanticDatabase(root)
            database.update(self._project(root))
            base = _commit(root, "base")
            (root / "c.js").write_text("export function c(){ return 2; }\n", encoding="utf-8")
            head = _commit(root, "change leaf")
            result = git35.change_impact(root, database, base, head)
        self.assertEqual(result["changed_paths"], ["c.js"])
        self.assertEqual(result["impacted_paths"], ["a.js", "b.js", "c.js"])
        self.assertEqual(result["analysis_scope"], ["a.js", "b.js", "c.js"])
        self.assertIn("not runtime reachability proof", result["limitations"][1])

    def test_nested_project_impact_is_scoped_and_remapped_to_semantic_paths(self):
        with TemporaryGitRepository() as root:
            project = root / "services" / "api"
            project.mkdir(parents=True)
            (project / "a.js").write_text(
                "import { b } from './b.js';\nexport function a(){ return b(); }\n",
                encoding="utf-8")
            (project / "b.js").write_text(
                "import { c } from './c.js';\nexport function b(){ return c(); }\n",
                encoding="utf-8")
            (project / "c.js").write_text(
                "export function c(){ return 1; }\n", encoding="utf-8")
            (root / "outside.js").write_text("export const outside = 1;\n", encoding="utf-8")
            database = git35.SemanticDatabase(project)
            database.update(polyglot_ir35.analyze(project))
            base = _commit(root, "nested base")
            (project / "c.js").write_text(
                "export function c(){ return 2; }\n", encoding="utf-8")
            (root / "outside.js").write_text("export const outside = 2;\n", encoding="utf-8")
            head = _commit(root, "nested and outside changes")
            result = git35.change_impact(
                git35.GitRepository(project), database, base, head)
        self.assertEqual(result["repository_scope_prefix"], "services/api/")
        self.assertEqual(result["repository_changes_observed"], 2)
        self.assertEqual(result["changes_outside_scope"], 1)
        self.assertEqual(result["changed_paths"], ["c.js"])
        self.assertEqual(result["changes"][0]["repository_path"], "services/api/c.js")
        self.assertEqual(result["impacted_paths"], ["a.js", "b.js", "c.js"])
        self.assertEqual(result["analysis_scope"], ["a.js", "b.js", "c.js"])
        self.assertEqual(result["path_namespace"], "semantic-database-root-relative")


if __name__ == "__main__":
    unittest.main()
