#!/usr/bin/env python3
"""owen_edit -- dolphin edits Owen's code because YOU told it to.

    chat> /edit detector\\synth42.py add a hex-decode cache
    chat> /undo detector\\synth42.py          revert to the backup

Flow: file + your instruction -> dolphin returns the modified file ->
unified diff shown -> y applies (original auto-backed-up) -> n discards.
You approve every write. /undo reverses it. Full control, reversible.
"""

from __future__ import annotations

import argparse
import difflib
import json
import sys
import time
import urllib.request
from pathlib import Path

BACKUP_DIR = Path(__file__).resolve().parent / ".owen_backups"
OLLAMA = "http://127.0.0.1:11434"

EDIT_PROMPT = ("Apply this instruction to the code. Return ONLY the "
               "complete modified file content -- no commentary, no "
               "markdown fences.\n\nINSTRUCTION: {instruction}\n\n"
               "CURRENT FILE:\n{code}")


def chat_api(messages, model, base=OLLAMA):
    request = urllib.request.Request(
        base + "/api/chat",
        data=json.dumps({"model": model, "messages": messages,
                         "stream": False}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=1800) as response:
        return json.loads(response.read().decode("utf-8"))


def strip_fences(text):
    text = text.lstrip("\ufeff").strip()
    if text.startswith("```"):
        first_newline = text.find("\n")
        if first_newline != -1:
            text = text[first_newline + 1:]
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
    return text.rstrip() + "\n"


def backup_file(path: Path):
    BACKUP_DIR.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    target = BACKUP_DIR / ("%s.%s.bak" % (path.name, stamp))
    target.write_bytes(path.read_bytes())
    return target


def show_diff(old_text, new_text, path):
    diff = difflib.unified_diff(
        old_text.splitlines(), new_text.splitlines(),
        fromfile="current/" + path.name, tofile="edited/" + path.name,
        lineterm="")
    lines = list(diff)
    print("\n".join(lines[:80]))
    if len(lines) > 80:
        print("... (%d more diff lines)" % (len(lines) - 80))
    return len(lines)


def edit_file(path_str, instruction, model, base=OLLAMA, assume_yes=False):
    path = Path(path_str)
    if not path.is_file():
        print("no such file:", path)
        return False
    original = path.read_text(encoding="utf-8", errors="replace")

    print("asking %s to: %s" % (model, instruction), flush=True)
    result = chat_api(
        [{"role": "user",
          "content": EDIT_PROMPT.format(instruction=instruction,
                                        code=original)}],
        model, base)
    edited = strip_fences(result["message"]["content"])

    if edited == original:
        print("dolphin returned the file unchanged.")
        return False

    n_lines = show_diff(original, edited, path)
    if not assume_yes:
        answer = input("\napply this edit? [y/N] ").strip().lower()
        if answer != "y":
            print("discarded.")
            return False
    backup = backup_file(path)
    path.write_text(edited, encoding="utf-8")
    print("applied. backup: %s (%d diff lines)"
          % (backup.name, n_lines))
    return True


def undo_file(path_str):
    path = Path(path_str)
    if not BACKUP_DIR.is_dir():
        print("no backups exist.")
        return
    candidates = sorted(BACKUP_DIR.glob(path.name + ".*.bak"))
    if not candidates:
        print("no backups for", path.name)
        return
    latest = candidates[-1]
    backup_file(path)  # snapshot current state before revert
    path.write_bytes(latest.read_bytes())
    print("reverted %s <- %s" % (path.name, latest.name))


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(
        prog="owen_edit", description="dolphin edits code on your order")
    parser.add_argument("--model", default="dolphin3:8b")
    parser.add_argument("--yes", action="store_true",
                        help="skip the y/N confirm")
    parser.add_argument("file")
    parser.add_argument("instruction")
    args = parser.parse_args(argv)
    ok = edit_file(args.file, args.instruction, model=args.model,
                   assume_yes=args.yes)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
