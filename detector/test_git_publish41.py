#!/usr/bin/env python3
"""Tests for git_publish41.py.

Every test here runs against a throwaway repository created in a temporary
directory, with a bare repo standing in for the remote. Nothing touches a real
project.

The cases that matter are the refusals. This is the first module allowed to
write to a repository, and the failure that would hurt is not a crash -- it is
a commit that quietly contains more than Attestor repaired.
"""
import json
import os
import subprocess
import tempfile
import unittest

import git_publish41 as publish
import planner41


def git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True,
                          text=True, check=True).stdout


class RepoCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = os.path.join(self.tmp.name, "work")
        self.remote = os.path.join(self.tmp.name, "remote.git")
        os.makedirs(self.repo)
        subprocess.run(["git", "init", "--bare", "-b", "main", self.remote],
                       capture_output=True, check=True)
        git(self.repo, "init", "-b", "main")
        git(self.repo, "config", "user.email", "attestor@example.invalid")
        git(self.repo, "config", "user.name", "Attestor")
        git(self.repo, "remote", "add", "origin", self.remote)
        self.write("fixed.py", "value = 1\n")
        self.write("untouched.py", "other = 1\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-m", "initial")
        git(self.repo, "push", "-u", "origin", "main")

    def write(self, name, text):
        path = os.path.join(self.repo, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)

    def plan_and_result(self, *, applied=("fixed.py",), authorized=True):
        findings = [{"path": name, "rule": "py-eq-none", "line": 1}
                    for name in applied]
        plan = planner41.plan(self.repo, findings)
        result = planner41.execute(
            plan, verify=lambda root, path, f: {"accepted": True},
            apply_fix=lambda v: {"ok": True}, rescan=lambda path: [],
            authorized=authorized)
        return plan, result


class CommitScopeTests(RepoCase):
    def test_only_the_repaired_file_is_committed(self):
        # The whole point: a working tree under active work is full of
        # unrelated edits, and none of them belong in Attestor's commit.
        self.write("fixed.py", "value = 2\n")
        self.write("untouched.py", "other = 999\n")
        self.write("scratch.tmp", "junk\n")
        plan, result = self.plan_and_result()
        report = publish.publish(self.repo, plan, result, push=False)
        self.assertTrue(report["committed"])
        self.assertEqual(report["staged"], ["fixed.py"])
        self.assertIn("untouched.py", git(self.repo, "status", "--porcelain"))
        self.assertIn("scratch.tmp", git(self.repo, "status", "--porcelain"))

    def test_the_commit_message_names_the_findings_and_the_plan(self):
        self.write("fixed.py", "value = 2\n")
        plan, result = self.plan_and_result()
        publish.publish(self.repo, plan, result, push=False)
        message = git(self.repo, "log", "-1", "--pretty=%B")
        self.assertIn("py-eq-none", message)
        self.assertIn("fixed.py", message)
        self.assertIn(plan["plan_sha256"], message)

    def test_nothing_applied_means_nothing_committed(self):
        # An authorised run where every verification was refused: there is
        # nothing to commit, and that is not an error.
        plan = planner41.plan(self.repo, [{"path": "fixed.py",
                                           "rule": "py-eq-none", "line": 1}])
        result = planner41.execute(
            plan, verify=lambda root, path, f: {"accepted": False,
                                                "reason": "no candidate"},
            apply_fix=lambda v: {}, rescan=lambda path: [], authorized=True)
        report = publish.publish(self.repo, plan, result, push=False)
        self.assertFalse(report["committed"])
        self.assertIn("nothing was applied", report["reason"])

    def test_an_unchanged_file_produces_no_empty_commit(self):
        plan, result = self.plan_and_result()          # file never edited
        report = publish.publish(self.repo, plan, result, push=False)
        self.assertFalse(report["committed"])
        self.assertIn("already match HEAD", report["reason"])


class RefusalTests(RepoCase):
    def test_a_preexisting_staged_change_is_never_committed(self):
        self.write("untouched.py", "other = 'already staged'\n")
        git(self.repo, "add", "--", "untouched.py")
        self.write("fixed.py", "value = 2\n")
        plan, result = self.plan_and_result()

        before = git(self.repo, "rev-parse", "HEAD").strip()
        with self.assertRaises(publish.PublishError) as raised:
            publish.publish(self.repo, plan, result, push=False)

        self.assertIn("non-empty index", str(raised.exception))
        self.assertEqual(git(self.repo, "rev-parse", "HEAD").strip(), before)
        self.assertEqual(git(self.repo, "diff", "--cached", "--name-only").strip(),
                         "untouched.py")

    def test_a_dry_run_is_never_published(self):
        self.write("fixed.py", "value = 2\n")
        plan, result = self.plan_and_result(authorized=False)
        result["outcomes"][0]["status"] = "applied"     # claim without doing
        with self.assertRaises(publish.PublishError):
            publish.publish(self.repo, plan, result, push=False)

    def test_a_tampered_result_is_refused(self):
        self.write("fixed.py", "value = 2\n")
        plan, result = self.plan_and_result()
        result["applied"] = 99
        with self.assertRaises(publish.PublishError) as raised:
            publish.publish(self.repo, plan, result, push=False)
        self.assertIn("unverified", str(raised.exception))

    def test_a_result_from_another_plan_is_refused(self):
        self.write("fixed.py", "value = 2\n")
        plan, result = self.plan_and_result()
        other = planner41.plan(self.repo, [{"path": "elsewhere.py",
                                            "rule": "r", "line": 1}])
        with self.assertRaises(publish.PublishError):
            publish.publish(self.repo, other, result, push=False)

    def test_publishing_onto_a_branch_we_are_not_on_is_refused(self):
        self.write("fixed.py", "value = 2\n")
        plan, result = self.plan_and_result()
        with self.assertRaises(publish.PublishError) as raised:
            publish.publish(self.repo, plan, result, branch="release",
                            push=False)
        self.assertIn("does not switch branches", str(raised.exception))

    def test_implausible_branch_and_remote_names_are_refused(self):
        plan, result = self.plan_and_result()
        for bad in ("--upload-pack=evil", "", "-x", "a" * 200):
            with self.subTest(name=bad):
                with self.assertRaises(publish.PublishError):
                    publish.publish(self.repo, plan, result, branch=bad)
                with self.assertRaises(publish.PublishError):
                    publish.publish(self.repo, plan, result, remote=bad)

    def test_a_path_outside_the_repository_is_refused(self):
        outside = os.path.join("..", "..", "etc", "passwd")
        findings = [{"path": outside, "rule": "r", "line": 1}]
        plan = planner41.plan(self.repo, findings)
        result = planner41.execute(
            plan, verify=lambda root, path, f: {"accepted": True},
            apply_fix=lambda v: {}, rescan=lambda path: [], authorized=True)
        with self.assertRaises(publish.PublishError) as raised:
            publish.publish(self.repo, plan, result, push=False)
        self.assertIn("outside the repository", str(raised.exception))

    def test_only_allow_listed_git_verbs_are_reachable(self):
        for verb in ("reset", "rebase", "clean", "checkout", "filter-branch"):
            with self.subTest(verb=verb):
                with self.assertRaises(publish.PublishError):
                    publish._git(self.repo, verb, "--help")


class PushTests(RepoCase):
    def test_a_push_reaches_the_remote(self):
        self.write("fixed.py", "value = 2\n")
        plan, result = self.plan_and_result()
        report = publish.publish(self.repo, plan, result, push=True)
        self.assertTrue(report["pushed"])
        remote_head = git(self.remote, "rev-parse", "main").strip()
        self.assertEqual(remote_head, report["commit"])

    def test_committing_without_push_leaves_the_remote_alone(self):
        before = git(self.remote, "rev-parse", "main").strip()
        self.write("fixed.py", "value = 2\n")
        plan, result = self.plan_and_result()
        report = publish.publish(self.repo, plan, result, push=False)
        self.assertTrue(report["committed"])
        self.assertFalse(report["pushed"])
        self.assertEqual(git(self.remote, "rev-parse", "main").strip(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
