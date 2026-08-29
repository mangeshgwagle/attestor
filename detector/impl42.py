#!/usr/bin/env python3
"""impl42 -- paste a GitHub link, Owen implements it into itself.

    clone -> detect package type -> pip install -> verify import -> done

After this, whatever the repo provides becomes importable by every other
Owen module. It's in Owen's environment now.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else ".")

REPOS = Path(__file__).resolve().parent.parent / "repos"


def parse_url(url):
    url = url.strip().rstrip("/")
    m = re.match(r"https?://github\.com/([\w.-]+)/([\w.-]+)", url)
    if not m:
        raise ValueError("not a GitHub URL: %s" % url)
    return m.group(1), m.group(2)


def sh(cmd, cwd=None, timeout=300):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                       timeout=timeout)
    return r.returncode, r.stdout[-2000:], r.stderr[-2000:]


def find_package_type(repo_path):
    """Detect what kind of installable package this is."""
    p = Path(repo_path)
    checks = [
        ("setup.py", "pip install ."),
        ("pyproject.toml", "pip install ."),
        ("setup.cfg", "pip install ."),
        ("requirements.txt", "pip install -r requirements.txt"),
        ("package.json", None),  # npm -- not auto-installed
        ("Cargo.toml", None),     # cargo -- not auto-installed
        ("go.mod", None),         # go -- not auto-installed
    ]
    for filename, install_cmd in checks:
        if (p / filename).exists():
            return {"file": filename, "cmd": install_cmd,
                    "language": "python" if install_cmd else filename}
    # even bare .py repos can be imported if they're on sys.path
    py_files = list(p.rglob("*.py"))[:1]
    if py_files:
        return {"file": "*.py", "cmd": "__path__",
                "language": "python-raw"}
    return {"file": None, "cmd": None, "language": "unknown"}


def implement(url):
    owner, repo_name = parse_url(url)
    repo_dir = REPOS / ("%s-%s" % (owner, repo_name))

    # 1. clone
    if repo_dir.exists():
        print("already cloned: %s" % repo_dir)
    else:
        REPOS.mkdir(parents=True, exist_ok=True)
        git_url = "https://github.com/%s/%s.git" % (owner, repo_name)
        print("cloning %s..." % git_url)
        rc, out, err = sh(["git", "clone", "--depth", "1", git_url,
                           str(repo_dir)])
        if rc != 0:
            raise RuntimeError("clone failed: %s" % err[:300])
        print("cloned to %s" % repo_dir)

    # 2. detect package type
    pkg = find_package_type(str(repo_dir))
    print("package type: %s (%s)" % (pkg["language"], pkg["file"]))

    # 3. install
    installed = False
    if pkg["cmd"] and pkg["cmd"].startswith("pip"):
        print("running: pip %s" % pkg["cmd"].replace("pip ", "", 1))
        rc, out, err = sh(["pip"] + pkg["cmd"].split()[1:] + [str(repo_dir)],
                          timeout=600)
        installed = rc == 0
        if not installed:
            # try with --user fallback
            print("global install failed, trying --user...")
            rc2, _, _ = sh(["pip", "install", "--user"] +
                           pkg["cmd"].split()[1:] + [str(repo_dir)],
                           timeout=600)
            installed = rc2 == 0
        print("installed:", installed)
    elif pkg["cmd"] == "__path__":
        installed = True  # raw python files are importable via sys.path
        print("raw python repo -- importable via sys.path")
    elif pkg["language"] != "python":
        print("non-python package detected (%s); cloned but not "
              "auto-installed" % pkg["language"])

    # 4. verify import
    imported, module_name = False, None
    if pkg["language"].startswith("python"):
        candidates = [repo_name.replace("-", "_"), repo_name]
        for candidate in candidates:
            try:
                test = subprocess.run(
                    [sys.executable, "-c", "import %s; "
                     "print('ok')" % candidate],
                    capture_output=True, text=True, timeout=30)
                if test.returncode == 0 and "ok" in test.stdout:
                    imported = True
                    module_name = candidate
                    break
            except Exception:  # noqa: BLE001
                continue
        if not imported:
            # check if any .py file in the repo is directly importable
            init = repo_dir / "__init__.py"
            if init.exists():
                module_name = repo_dir.name
                imported = True

    result = {
        "tool": "impl42",
        "url": url,
        "repo_path": str(repo_dir),
        "package_type": pkg,
        "installed": installed,
        "importable": imported,
        "module_name": module_name,
        "status": ("implemented" if imported else
                   "installed-but-not-importable" if installed else
                   "cloned-only"),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(
        prog="impl42",
        description="Paste a GitHub link, Owen implements it into itself")
    parser.add_argument("url")
    args = parser.parse_args(argv)
    try:
        result = implement(args.url)
        status = result["status"]
        print("\n=== %s ===" % status.upper())
        return 0 if result["imported"] else 1
    except Exception as exc:  # noqa: BLE001
        print("impl42: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
