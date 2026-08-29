#!/usr/bin/env python3
"""Git hooks manager -- installs and manages pre-commit hooks for Attestor
to automatically scan code before commits."""
from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

PRE_COMMIT_HOOK = """#!/bin/sh
# Attestor pre-commit hook -- scans staged files for security issues
# Installed by: attestor hooks install

set -e

echo "[Attestor] Scanning staged files..."

# Get list of staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
    exit 0
fi

# Determine attestor command
ATTESTOR_CMD=""
if command -v attestor >/dev/null 2>&1; then
    ATTESTOR_CMD="attestor"
elif command -v python >/dev/null 2>&1; then
    DETECTOR_DIR="$(git rev-parse --show-toplevel)/detector"
    if [ -f "$DETECTOR_DIR/cli.py" ]; then
        ATTESTOR_CMD="python $DETECTOR_DIR/cli.py"
    fi
fi

if [ -z "$ATTESTOR_CMD" ]; then
    echo "[Attestor] Warning: attestor not found, skipping security scan"
    exit 0
fi

# Check for secrets in staged files
SECRETS_FOUND=0
for file in $STAGED_FILES; do
    if [ -f "$file" ]; then
        RESULT=$($ATTESTOR_CMD secrets "$file" --json 2>/dev/null || true)
        if echo "$RESULT" | grep -q '"severity": "CRITICAL"'; then
            echo "[Attestor] CRITICAL secret found in: $file"
            SECRETS_FOUND=1
        fi
    fi
done

if [ "$SECRETS_FOUND" -eq 1 ]; then
    echo ""
    echo "[Attestor] COMMIT BLOCKED: Critical secrets detected in staged files!"
    echo "[Attestor] Run 'attestor secrets <path>' for details."
    echo "[Attestor] Use 'git commit --no-verify' to skip (NOT RECOMMENDED)."
    exit 1
fi

# Run exploit detection on staged files
PY_FILES=""
JS_FILES=""
for file in $STAGED_FILES; do
    case "$file" in
        *.py) PY_FILES="$PY_FILES $file" ;;
        *.js|*.jsx|*.ts|*.tsx) JS_FILES="$JS_FILES $file" ;;
    esac
done

EXIT_CODE=0

if [ -n "$PY_FILES" ]; then
    for file in $PY_FILES; do
        if [ -f "$file" ]; then
            $ATTESTOR_CMD scan "$file" --pass {pass_grade} >/dev/null 2>&1 || EXIT_CODE=1
        fi
    done
fi

if [ "$EXIT_CODE" -eq 1 ]; then
    echo "[Attestor] Warning: Some files have security findings."
    echo "[Attestor] Run 'attestor scan <path>' for details."
    {block_on_fail}
fi

echo "[Attestor] Pre-commit scan complete."
exit 0
"""

PRE_PUSH_HOOK = """#!/bin/sh
# Attestor pre-push hook -- runs full scan before push
# Installed by: attestor hooks install --pre-push

set -e

echo "[Attestor] Running pre-push security scan..."

ATTESTOR_CMD=""
if command -v attestor >/dev/null 2>&1; then
    ATTESTOR_CMD="attestor"
elif command -v python >/dev/null 2>&1; then
    DETECTOR_DIR="$(git rev-parse --show-toplevel)/detector"
    if [ -f "$DETECTOR_DIR/cli.py" ]; then
        ATTESTOR_CMD="python $DETECTOR_DIR/cli.py"
    fi
fi

if [ -z "$ATTESTOR_CMD" ]; then
    echo "[Attestor] Warning: attestor not found, skipping pre-push scan"
    exit 0
fi

ROOT=$(git rev-parse --show-toplevel)
RESULT=$($ATTESTOR_CMD secrets "$ROOT" --json 2>/dev/null || true)

if echo "$RESULT" | grep -q '"severity": "CRITICAL"'; then
    echo ""
    echo "[Attestor] PUSH BLOCKED: Critical secrets found in repository!"
    echo "[Attestor] Run 'attestor secrets .' for details."
    exit 1
fi

echo "[Attestor] Pre-push scan passed."
exit 0
"""


def find_git_root(start: str = ".") -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, cwd=start,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except FileNotFoundError:
        pass
    return None


def get_hooks_dir(git_root: str) -> str:
    hooks_dir = os.path.join(git_root, ".git", "hooks")
    core_hooks = subprocess.run(
        ["git", "config", "core.hooksPath"],
        capture_output=True, text=True, cwd=git_root,
    )
    if core_hooks.returncode == 0 and core_hooks.stdout.strip():
        custom = core_hooks.stdout.strip()
        if os.path.isabs(custom):
            hooks_dir = custom
        else:
            hooks_dir = os.path.join(git_root, custom)
    return hooks_dir


def install_hook(
    hook_type: str = "pre-commit",
    pass_grade: str = "C",
    block_on_fail: bool = False,
    git_root: str | None = None,
) -> str:
    if git_root is None:
        git_root = find_git_root()
    if not git_root:
        return "error: not a git repository"

    hooks_dir = get_hooks_dir(git_root)
    os.makedirs(hooks_dir, exist_ok=True)
    hook_path = os.path.join(hooks_dir, hook_type)

    if os.path.exists(hook_path):
        with open(hook_path, encoding="utf-8", errors="replace") as f:
            content = f.read()
        if "Attestor" in content:
            return f"Attestor {hook_type} hook already installed at {hook_path}"
        backup = hook_path + ".backup"
        os.rename(hook_path, backup)

    if hook_type == "pre-commit":
        block_line = "exit 1" if block_on_fail else "# exit 1  # Uncomment to block commits"
        hook_content = PRE_COMMIT_HOOK.format(
            pass_grade=pass_grade,
            block_on_fail=block_line,
        )
    elif hook_type == "pre-push":
        hook_content = PRE_PUSH_HOOK
    else:
        return f"error: unsupported hook type '{hook_type}'"

    with open(hook_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(hook_content)

    st = os.stat(hook_path)
    os.chmod(hook_path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    return f"Installed {hook_type} hook at {hook_path}"


def uninstall_hook(hook_type: str = "pre-commit", git_root: str | None = None) -> str:
    if git_root is None:
        git_root = find_git_root()
    if not git_root:
        return "error: not a git repository"

    hooks_dir = get_hooks_dir(git_root)
    hook_path = os.path.join(hooks_dir, hook_type)

    if not os.path.exists(hook_path):
        return f"No {hook_type} hook found"

    with open(hook_path, encoding="utf-8", errors="replace") as f:
        content = f.read()
    if "Attestor" not in content:
        return f"{hook_type} hook exists but was not installed by Attestor"

    os.remove(hook_path)

    backup = hook_path + ".backup"
    if os.path.exists(backup):
        os.rename(backup, hook_path)
        return f"Removed Attestor {hook_type} hook, restored backup"

    return f"Removed Attestor {hook_type} hook"


def status(git_root: str | None = None) -> str:
    if git_root is None:
        git_root = find_git_root()
    if not git_root:
        return "Not in a git repository"

    hooks_dir = get_hooks_dir(git_root)
    lines = [f"\n  Git hooks directory: {hooks_dir}"]

    for hook_type in ("pre-commit", "pre-push"):
        hook_path = os.path.join(hooks_dir, hook_type)
        if os.path.exists(hook_path):
            with open(hook_path, encoding="utf-8", errors="replace") as f:
                content = f.read()
            is_attestor = "Attestor" in content
            is_exec = os.access(hook_path, os.X_OK)
            status_str = "installed" if is_attestor else "exists (not Attestor)"
            exec_str = "executable" if is_exec else "NOT executable"
            lines.append(f"  {hook_type}: {status_str} ({exec_str})")
        else:
            lines.append(f"  {hook_type}: not installed")

    return "\n".join(lines)
