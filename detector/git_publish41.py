#!/usr/bin/env python3
"""Commit and push the repairs Attestor verified. Nothing else, ever.

Why this module is narrow
-------------------------
`git_intelligence35.py` is read-only by design and admits exactly three verbs:
diff, blame, rev-parse. This is the first place Attestor is allowed to *write* to a
repository, so the surface stays as small as the job requires: `add` on named
paths, `commit`, `push`. No hooks, no rebase, no reset, no force, no
history rewriting of any kind.

What it will not do
-------------------
* **It never stages by wildcard.** Only paths a verified plan reports as
  applied are added. A repository under work has unrelated edits in it -- this
  one had 95 at the time of writing -- and `git add -A` would sweep every one
  of them into a commit Attestor did not make and cannot vouch for.
* **It refuses to publish an unverified result.** `planner41.verify_result`
  must pass, and the plan digest it names is written into the commit message so
  the change can be traced back to the plan that produced it.
* **It never force-pushes and never rewrites.** If the remote has moved, the
  push fails and stays failed; resolving that is a human's job.

The target branch is a caller's decision. `main` is the default because that is
what this deployment asked for; a project that would rather review first passes
its own branch name instead.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from typing import Any, Mapping, Sequence

SCHEMA = "attestor.git-publish/1.0"
VERSION = "4.1.4"

GIT = "git"
COMMIT_TIMEOUT = 120
PUSH_TIMEOUT = 300
MAX_FILES = 500
# Only these verbs are ever assembled into a command line here.
ALLOWED_VERBS = ("rev-parse", "status", "add", "commit", "push",
                 "config", "diff")
_SAFE_BRANCH = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._/-]{0,100}\Z")


class PublishError(RuntimeError):
    """The result, the repository, or the git invocation is unusable."""


def _git(repo: str, *args: str, timeout: int = COMMIT_TIMEOUT,
         hooks_dir: str | None = None) -> str:
    if not args or args[0] not in ALLOWED_VERBS:
        raise PublishError("refusing a git verb outside the allow-list: %r"
                           % (args[0] if args else None))
    try:
        command = [GIT, "-C", repo]
        if hooks_dir is not None:
            command.extend(["-c", "core.hooksPath=" + hooks_dir])
        command.extend(args)
        done = subprocess.run(
            command, capture_output=True, text=True,
            timeout=timeout, shell=False,
            # Hooks and interactive prompts are both ways for a repository to
            # run code or block during what should be a mechanical publish.
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0",
                 "GIT_OPTIONAL_LOCKS": "0"})
    except (OSError, subprocess.SubprocessError) as error:
        raise PublishError("git %s failed: %s" % (args[0], error)) from error
    if done.returncode != 0:
        raise PublishError("git %s exited %d: %s"
                           % (args[0], done.returncode,
                              (done.stderr or done.stdout or "")[-400:]))
    return done.stdout


def repository_root(path: str) -> str:
    root = _git(path, "rev-parse", "--show-toplevel").strip()
    if not root:
        raise PublishError("%s is not inside a git repository" % path[:120])
    return os.path.normpath(root)


def applied_paths(result: Mapping[str, Any]) -> list[str]:
    """The files a plan result says it actually changed."""
    out = []
    for row in result.get("outcomes", []):
        if isinstance(row, Mapping) and row.get("status") == "applied":
            path = row.get("path")
            if isinstance(path, str) and path.strip():
                out.append(path.strip())
    return sorted(set(out))


def commit_message(plan: Mapping[str, Any],
                   result: Mapping[str, Any]) -> str:
    """The findings themselves, so the commit explains what it repaired."""
    applied = [row for row in result.get("outcomes", [])
               if isinstance(row, Mapping) and row.get("status") == "applied"]
    subject = ("attestor: repair %d verified finding%s"
               % (len(applied), "" if len(applied) == 1 else "s"))
    lines = [subject, ""]
    for row in applied:
        lines.append("- %s at %s:%s" % (row.get("rule"), row.get("path"),
                                        row.get("line")))
    lines.extend([
        "",
        "Each change was verified before it was applied and re-scanned after,",
        "and any that did not remove its finding was rolled back.",
        "",
        "plan-sha256: %s" % plan.get("plan_sha256", "?"),
        "result-sha256: %s" % result.get("result_sha256", "?"),
    ])
    return "\n".join(lines)


def publish(repo_path: str, plan: Mapping[str, Any],
            result: Mapping[str, Any], *, branch: str = "main",
            push: bool = False, remote: str = "origin") -> dict[str, Any]:
    """Commit the verified repairs, and push them when asked to.

    `push` defaults to false so that importing this module cannot, by itself,
    put anything on a remote. Attestor's own pipeline passes it explicitly.
    """
    import planner41

    if not _SAFE_BRANCH.match(branch or ""):
        raise PublishError("refusing an implausible branch name")
    if not _SAFE_BRANCH.match(remote or ""):
        raise PublishError("refusing an implausible remote name")

    ok, problems = planner41.verify_result(result, plan)
    if not ok:
        raise PublishError("refusing to publish an unverified result: %s"
                           % "; ".join(problems[:3]))
    if not result.get("authorized"):
        raise PublishError("refusing to publish a dry run")

    paths = applied_paths(result)
    if not paths:
        return {"schema": SCHEMA, "version": VERSION, "committed": False,
                "reason": "nothing was applied, so there is nothing to commit",
                "paths": [], "pushed": False}
    if len(paths) > MAX_FILES:
        raise PublishError("refusing to commit %d files in one change"
                           % len(paths))

    root = repository_root(repo_path)
    inside = []
    for relative in paths:
        absolute = os.path.normpath(os.path.join(repo_path, relative))
        if os.path.commonpath([absolute, root]) != root:
            raise PublishError("plan touched a path outside the repository: %s"
                               % relative[:120])
        inside.append(os.path.relpath(absolute, root).replace("\\", "/"))

    current = _git(root, "rev-parse", "--abbrev-ref", "HEAD").strip()
    if current != branch:
        raise PublishError(
            "checked out on %r but asked to publish %r; this module does not "
            "switch branches" % (current, branch))

    # Git commits the complete index, not merely the paths in the preceding
    # `git add`. Refuse an index that already contains user work so an Attestor
    # commit cannot absorb unrelated staged changes or secrets.
    pre_staged = _git(root, "diff", "--cached", "--name-only").strip()
    if pre_staged:
        raise PublishError(
            "refusing to publish with a non-empty index; commit or unstage "
            "these paths first: %s" % ", ".join(pre_staged.splitlines()[:5]))

    # Named paths only. Never a wildcard, never -A.
    _git(root, "add", "--", *inside)
    staged = _git(root, "diff", "--cached", "--name-only").strip()
    if not staged:
        return {"schema": SCHEMA, "version": VERSION, "committed": False,
                "reason": "the applied files already match HEAD",
                "paths": inside, "pushed": False}

    staged_paths = staged.splitlines()
    unexpected = sorted(set(staged_paths) - set(inside))
    if unexpected:
        raise PublishError("git staged paths outside the verified repair set: %s"
                           % ", ".join(unexpected[:5]))

    # `--no-verify` does not disable post-commit or pre-push hooks. Point Git at
    # a newly-created empty directory for both operations so repository-owned
    # code cannot execute under Attestor's authority.
    with tempfile.TemporaryDirectory(prefix="attestor-disabled-hooks-") as no_hooks:
        _git(root, "commit", "--no-verify", "-m",
             commit_message(plan, result), hooks_dir=no_hooks)
        head = _git(root, "rev-parse", "HEAD").strip()

        if push:
            _git(root, "push", "--no-verify", remote,
                 "HEAD:refs/heads/" + branch,
                 timeout=PUSH_TIMEOUT, hooks_dir=no_hooks)

    report = {"schema": SCHEMA, "version": VERSION, "committed": True,
              "commit": head, "branch": branch, "paths": inside,
              "staged": staged_paths, "pushed": False,
              "limitations": [
                  "only files a verified plan reported as applied are in this "
                  "commit; unrelated working-tree changes are untouched",
                  "no force, no rebase, no history rewriting -- a rejected "
                  "push stays rejected",
              ]}
    if push:
        report["pushed"] = True
        report["remote"] = remote
    return report


def main(argv: Sequence[str] | None = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("repo")
    parser.add_argument("plan_json", help="a planner41 plan report")
    parser.add_argument("result_json", help="its execution result")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--push", action="store_true",
                        help="actually push; without it this only commits")
    args = parser.parse_args(argv)

    try:
        with open(args.plan_json, encoding="utf-8") as handle:
            plan = json.load(handle)
        with open(args.result_json, encoding="utf-8") as handle:
            result = json.load(handle)
        report = publish(args.repo, plan, result, branch=args.branch,
                         push=args.push, remote=args.remote)
    except (PublishError, OSError, ValueError) as error:
        print("error: %s" % error)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
