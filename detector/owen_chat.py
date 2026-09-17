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

CHAT_SCHEMA = "attestor-chat-4.3"
OLLAMA = "http://127.0.0.1:11434"
CODE_EXTS = {".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".hpp",
             ".go", ".rs", ".md", ".json", ".sql", ".sh", ".ps1", ".bat",
             ".asm", ".s", ".rb", ".php", ".lua", ".zig", ".nim", ".kt",
             ".swift", ".dart", ".r", ".jl", ".ml", ".hs", ".ex", ".sol"}

# Import the model loader — the fine-tuned owen-coder-43 brain
_MODEL_LOADER = None
def _get_loader():
    global _MODEL_LOADER
    if _MODEL_LOADER is not None:
        return _MODEL_LOADER
    try:
        loader_path = Path(__file__).resolve().parent / "model_loader43.py"
        if loader_path.exists():
            import importlib.util
            spec = importlib.util.spec_from_file_location("model_loader43", loader_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            _MODEL_LOADER = mod
            return mod
    except Exception:
        pass
    return None


def chat_api(messages, model, base=OLLAMA, stream=False):
    loader = _get_loader()
    if loader:
        backend = loader.get_model(prefer=model if model != "qwythos-9b" else None)
        if backend.available():
            strip = [m for m in messages if m["role"] != "system"]
            answer = backend.chat(strip)
            if stream:
                sys.stdout.write(answer)
                sys.stdout.flush()
            return {"message": {"content": answer}}

    # Fallback: direct Ollama API
    sys_prompt = loader.SYSTEM_PROMPT if loader else (
        "You are Owen Coder 4.3, a security-focused code analysis model.")
    if not any(m["role"] == "system" for m in messages):
        messages = [{"role": "system", "content": sys_prompt}] + messages
    request = urllib.request.Request(
        base + "/api/chat",
        data=json.dumps({"model": model, "messages": messages,
                         "stream": stream}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    if stream:
        full = []
        with urllib.request.urlopen(request, timeout=1800) as response:
            for line in response:
                try:
                    chunk = json.loads(line.decode("utf-8"))
                    token = chunk.get("message", {}).get("content", "")
                    full.append(token)
                    sys.stdout.write(token)
                    sys.stdout.flush()
                except json.JSONDecodeError:
                    continue
        return {"message": {"content": "".join(full)}}
    with urllib.request.urlopen(request, timeout=1800) as response:
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


def repl(model, base=OLLAMA, stream=True):
    loader = _get_loader()
    backend_name = "ollama (fallback)"
    if loader:
        backend = loader.get_model(prefer=model if model != "qwythos-9b" else None)
        if backend.available():
            backend_name = f"{backend.name}: {backend.model_id}"
    messages = [{"role": "system", "content":
                 loader.SYSTEM_PROMPT if loader else "You are Owen Coder 4.3."}]
    attach = ""
    print("owen_chat 4.3 -- backend: %s | /help for commands" % backend_name)
    print("  capabilities: code, math, security, reasoning")
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
            loader = _get_loader()
            messages = [{"role": "system", "content":
                         loader.SYSTEM_PROMPT if loader else "You are Owen Coder 4.3."}]
            print("conversation cleared.")
            continue
        if line == "/help":
            print("/model NAME | /file PATH | /dir PATH [--max N] | "
                  "/zip PATH.ZIP [--max N] | /stream | /nostream | "
                  "/reason PROMPT | /code PROMPT | /math EXPR | /clear | /exit")
            continue
        if line.startswith("/model "):
            model = line.split(None, 1)[1].strip()
            print("model ->", model)
            continue
        if line == "/stream":
            stream = True
            print("streaming: ON")
            continue
        if line == "/nostream":
            stream = False
            print("streaming: OFF")
            continue
        if line.startswith("/reason "):
            line = "Think step by step, then answer:\n\n" + line[8:]
        if line.startswith("/code "):
            line = "Write complete, runnable code for:\n\n" + line[6:]
        if line.startswith("/math "):
            line = "Solve this math problem step by step:\n\n" + line[6:]

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
            if stream:
                print("\nowen>")
            result = chat_api(messages, model, base, stream=stream)
            answer = result["message"]["content"]
        except Exception as exc:  # noqa: BLE001
            print("error:", str(exc)[:200])
            messages.pop()
            continue
        messages.append({"role": "assistant", "content": answer})
        if not stream:
            print("\nowen>\n" + answer + "\n")
        else:
            print("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="owen_chat", description="Owen Coder — chat, code, math, security")
    parser.add_argument("--model", default="qwythos-9b")
    parser.add_argument("--base", default=OLLAMA)
    parser.add_argument("--no-stream", action="store_true")
    parser.add_argument("prompt", nargs="*", help="One-shot prompt (non-interactive)")
    args = parser.parse_args(argv)

    loader = _get_loader()
    _sys = loader.SYSTEM_PROMPT if loader else "You are Owen Coder 4.3."

    if args.prompt:
        prompt = " ".join(args.prompt)
        messages = [{"role": "system", "content": _sys},
                    {"role": "user", "content": prompt}]
        try:
            result = chat_api(messages, args.model, args.base,
                              stream=not args.no_stream)
            if args.no_stream:
                print(result["message"]["content"])
        except Exception as exc:
            print("error:", str(exc)[:200])
        return 0

    if not sys.stdin.isatty():
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            messages = [{"role": "system", "content": _sys},
                        {"role": "user", "content": line}]
            try:
                result = chat_api(messages, args.model, args.base)
                print("owen>", result["message"]["content"])
            except Exception as exc:
                print("error:", str(exc)[:200])
        return 0

    repl(args.model, args.base, stream=not args.no_stream)
    return 0


if __name__ == "__main__":
    sys.exit(main())
