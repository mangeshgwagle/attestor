#!/usr/bin/env python3
"""implement42 -- paste a GitHub link, Owen clones + installs + wires it.

    python implement42.py "https://github.com/Gallopsled/pwntools"
    python implement42.py "https://github.com/eriklindernoren/PyTorch-YOLOv3"

Clones into repos/, pip-installs it, verifies the import works.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

IMPL_SCHEMA = "attestor-implement-4.2"
REPOS_DIR = Path(__file__).resolve().parent.parent / "repos"


def parse_url(url):
    url = url.strip().rstrip("/")
    m = re.match(r"https?://github\.com/([\w.-]+)/([\w.-]+)", url)
    if not m:
        raise ValueError("not a GitHub URL")
    return m.group(1), m.group(2)


def run(cmd, **kw):
    result = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=600, **kw)
    return result.returncode == 0, result.stdout[-500:], result.stderr[-500:]


def guess_import_name(repo_name):
    """Guess the import name from the repo name."""
    common = {
        "pwntools": "pwn", "pwn": "pwn",
        "scikit-learn": "sklearn", "scikit-image": "skimage",
        "PyTorch-YOLOv3": "models", "opencv-python": "cv2",
        "Pillow": "PIL", "python-dateutil": "dateutil",
        "beautifulsoup4": "bs4", "python-dotenv": "dotenv",
        "python-telegram-bot": "telegram",
    }
    if repo_name.lower() in common:
        return common[repo_name.lower()]
    clean = repo_name.replace("-", "_").replace(".", "_")
    return clean


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="implement42", description="Clone + install + wire a GitHub repo")
    parser.add_argument("url")
    args = parser.parse_args(argv)

    owner, repo = parse_url(args.url)
    dest = REPOS_DIR / ("%s-%s" % (owner, repo))
    dest.mkdir(parents=True, exist_ok=True)

    print("[1/5] cloning %s/%s..." % (owner, repo))
    ok, out, err = run(["git", "clone", "--depth", "1",
                        "https://github.com/%s/%s.git" % (owner, repo),
                        str(dest)])
    if not ok:
        if "already exists" in err or "already exists" in out:
            print("  already cloned, pulling latest...")
            run(["git", "pull"], cwd=str(dest))
        else:
            print("  clone failed: %s" % err[:200])
            return 1
    print("  -> %s" % dest)

    print("[2/5] checking for setup.py / pyproject.toml...")
    has_setup = (dest / "setup.py").exists() or \
                (dest / "pyproject.toml").exists() or \
                (dest / "setup.cfg").exists()

    if has_setup:
        print("[3/5] pip installing...")
        ok, out, err = run([sys.executable, "-m", "pip", "install",
                            str(dest), "--quiet"])
        print("  installed:", ok)
        if not ok:
            print("  pip error:", err[:200])
    else:
        print("[3/5] no setup.py -- adding to sys.path instead")

    print("[4/5] verifying import...")
    import_name = guess_import_name(repo)

    test_code = (
        "import sys\n"
        "sys.path.insert(0, r'%s')\n"
        "try:\n"
        "    __import__('%s')\n"
        "    print('OK')\n"
        "except ImportError as e:\n"
        "    print('FAIL:', e)\n"
    ) % (str(dest), import_name)

    result = subprocess.run([sys.executable, "-c", test_code],
                            capture_output=True, text=True, timeout=60)
    imported = "OK" in result.stdout

    # try alternative import names
    if not imported:
        for alt in [import_name.lower(), import_name.replace("_", ""),
                    repo.replace("-", "_")]:
            alt_test = test_code.replace(
                "'%s'" % import_name, "'%s'" % alt)
            result = subprocess.run([sys.executable, "-c", alt_test],
                                    capture_output=True, text=True,
                                    timeout=60)
            if "OK" in result.stdout:
                import_name = alt
                imported = True
                break

    print("  import '%s': %s" % (import_name,
                                 "WORKS" if imported else "not found"))

    print("[5/5] wiring into Owen...")
    wire = {
        "schema": IMPL_SCHEMA,
        "tool": "implement42",
        "repo": "%s/%s" % (owner, repo),
        "local_path": str(dest),
        "import_name": import_name if imported else None,
        "pip_installed": has_setup,
        "status": "implemented" if imported else "cloned-only",
    }

    # write an init file so owen can always find it
    init_path = dest / "__init__.py"
    if not init_path.exists():
        init_path.write_text("", encoding="utf-8")

    print(json.dumps(wire, indent=2, sort_keys=True))

    if imported:
        print("\nIMPLEMENTED. Owen can now:")
        print("  import %s" % import_name)
        print("  from %s import *" % import_name)
        print("  (usable in autofix42, directed_fuzz42, msf_lite, etc.)")
        return 0
    else:
        print("\nCLONED but import failed.")
        print("  try: cd %s && pip install -e ." % dest)
        return 1


if __name__ == "__main__":
    sys.exit(main())
