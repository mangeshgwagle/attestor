#!/usr/bin/env python3
"""owen_chat -- YOUR interactive console to the local brain.

You type the prompts. Full control. No pipeline decides anything.

    chat> /model dolphin3:8b          switch brains
    chat> /file path\\to\\code.py      attach a file to the conversation
    chat> /dir path\\to\\dir --max 5   attach several files
    chat> /clear                      wipe conversation
    chat> /exit                       leave

Everything else you type goes straight to the model. Files you attach
are read by this console and placed into the conversation -- the model
never touches the disk itself.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

CHAT_SCHEMA = "attestor-chat-4.2"
OLLAMA = "http://127.0.0.1:11434"
CODE_EXTS = {".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".hpp",
             ".go", ".rs", ".md", ".json", ".sql", ".sh", ".ps1", ".bat"}


def chat_api(messages, model, base=OLLAMA):
    request = urllib.request.Request(
        base + "/api/chat",
        data=json.dumps({"model": model, "messages": messages,
                         "stream": False}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=600) as response:
        return json.loads(response.read().decode("utf-8"))


def read_file(path):
    return Path(path).read_text(encoding="utf-8", errors="replace")


def dir_files(root, max_files):
    root_path = Path(root)
    out = []
    if root_path.is_file():
        return [root_path]
    for path in sorted(root_path.rglob("*")):
        if not path.is_file():
            continue
        if any(part in (".git", "__pycache__", ".venv", "node_modules")
               for part in path.parts):
            continue
        if path.suffix.lower() in CODE_EXTS:
            out.append(path)
            if len(out) >= max_files:
                break
    return out


def repl(model, base=OLLAMA):
    messages = []
    attach = ""
    print("owen_chat -- model: %s | /help for commands" % model)
    while True:
        try:
            line = input("chat> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue

        if line == "/exit":
            break
        if line == "/clear":
            messages = []
            print("conversation cleared.")
            continue
        if line == "/help":
            print("/model NAME | /file PATH | /dir PATH [--max N] | "
                  "/zip PATH.ZIP [--max N] | /clear | /exit")
            continue
        if line.startswith("/model "):
            model = line.split(None, 1)[1].strip()
            print("model ->", model)
            continue

        if line.startswith("/file "):
            path = line.split(None, 1)[1].strip()
            try:
                attach = "\n\n[FILE %s]\n%s" % (path, read_file(path))
                print("attached:", path, "(%d chars)" % len(attach))
            except OSError as exc:
                print("cannot read:", exc)
            continue
        if line.startswith("/zip "):
            import zipfile
            rest = line[5:].strip()
            max_files = 5
            zip_path = rest
            if "--max" in rest:
                idx = rest.index("--max")
                max_files = int(rest[idx + 5:].strip().split()[0])
                zip_path = rest[:idx].strip()
            zip_path = zip_path.strip('"').strip("'")
            extract_to = Path(zip_path).stem + "_extracted"
            extract_path = Path.cwd() / extract_to
            try:
                with zipfile.ZipFile(zip_path, "r") as zf:
                    zf.extractall(extract_path)
                files = dir_files(str(extract_path), max_files)
                attach = ""
                attached = 0
                for path in files:
                    try:
                        attach += "\n\n[FILE %s]\n%s" % (
                            path, read_file(path))
                        attached += 1
                    except OSError:
                        continue
                print("extracted to %s | attached %d files"
                      % (extract_path, attached))
            except (zipfile.BadZipFile, OSError) as exc:
                print("zip error:", exc)
            continue
        if line.startswith("/dir "):
            rest = line[5:].strip()
            max_files = 5
            root = rest
            if "--max" in rest:
                idx = rest.index("--max")
                max_files = int(rest[idx + 5:].strip().split()[0])
                root = rest[:idx].strip()
            root = root.strip('"').strip("'")
            attached = 0
            for path in dir_files(root, max_files):
                try:
                    attach += "\n\n[FILE %s]\n%s" % (path,
                                                     read_file(path))
                    attached += 1
                except OSError:
                    continue
            print("attached %d files from %s" % (attached, root))
            continue

        messages.append({"role": "user",
                         "content": (attach + "\n\n" + line).strip()})
        attach = ""
        try:
            result = chat_api(messages, model, base)
            answer = result["message"]["content"]
        except Exception as exc:  # noqa: BLE001
            print("error:", str(exc)[:200])
            messages.pop()
            continue
        messages.append({"role": "assistant", "content": answer})
        print("\ndolphin>\n" + answer + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="owen_chat", description="Your console to the local brain")
    parser.add_argument("--model", default="dolphin3:8b")
    parser.add_argument("--base", default=OLLAMA)
    args = parser.parse_args(argv)

    if not sys.stdin.isatty():
        # piped mode: each non-empty line is a prompt, /commands work
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            messages = [{"role": "user", "content": line}]
            try:
                result = chat_api(messages, args.model, args.base)
                print("dolphin>", result["message"]["content"])
            except Exception as exc:  # noqa: BLE001
                print("error:", str(exc)[:200])
        return 0

    repl(args.model, args.base)
    return 0


if __name__ == "__main__":
    sys.exit(main())
