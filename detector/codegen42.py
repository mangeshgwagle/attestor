#!/usr/bin/env python3
"""codegen42 -- Attestor's code generation engine with chain-of-thought reasoning.

Generates complete, production-quality code with deep reasoning. Connects
to the local brain (Ollama) with an enhanced system prompt that enables
structured reasoning before code output.

Capabilities:
  - Full-stack application code (Python, JS/TS, Go, Rust, C/C++, Java)
  - Security tools and exploit code (authorized testing)
  - System administration scripts
  - Data structures and algorithms
  - Network tools and protocol implementations
  - Database schemas and queries
  - API implementations
  - Mathematical computations
  - Hardware interface code
  - Assembly (x86-64, ARM)

    attestor codegen "write a port scanner in Python"
    attestor codegen "implement AES-256 encryption from scratch in C"
    attestor codegen "build a REST API with authentication in Go"
    attestor codegen --reason "solve the traveling salesman problem"
    attestor codegen --lang rust "implement a B-tree"
    attestor codegen --file output.py "web scraper with rate limiting"
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.request
from pathlib import Path

CG_SCHEMA = "attestor-codegen-4.3"
OLLAMA = "http://127.0.0.1:11434"
EXIT_OK = 0
EXIT_ERR = 1
EXIT_INVALID = 2

# Import model_loader43 for the fine-tuned brain
_LOADER = None
def _get_loader():
    global _LOADER
    if _LOADER is not None:
        return _LOADER
    try:
        loader_path = Path(__file__).resolve().parent / "model_loader43.py"
        if loader_path.exists():
            import importlib.util
            spec = importlib.util.spec_from_file_location("model_loader43", loader_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            _LOADER = mod
            return mod
    except Exception:
        pass
    return None

SYSTEM_PROMPT = """You are Owen Coder, the code generation engine inside Attestor — a security-focused \
code analysis and development toolkit. You write complete, production-quality code.

CORE PRINCIPLES:
1. ALWAYS output complete, runnable code — never stubs, never "TODO", never "implement here"
2. Include ALL imports, ALL error handling, ALL edge cases
3. Code must compile/run as-is with zero modifications
4. Write extensive inline documentation for complex logic
5. Security-first: validate inputs, handle errors, prevent injection
6. Performance-aware: use efficient algorithms and data structures

REASONING MODE:
When asked to reason, use this structure:
<think>
[Step-by-step analysis of the problem]
[Algorithm selection and justification]
[Edge cases and error conditions]
[Performance considerations]
[Security implications]
</think>

Then output the complete code.

LANGUAGES: Python, JavaScript/TypeScript, Go, Rust, C, C++, Java, Ruby, PHP, \
Shell/Bash, PowerShell, SQL, Assembly (x86-64, ARM), Solidity, Haskell, Lua.

SPECIALTIES:
- Security tools: scanners, fuzzers, exploit frameworks, forensics, crypto
- Network: protocol implementations, proxies, tunnels, packet crafting
- Systems: OS internals, drivers, kernel modules, memory management
- Web: full-stack apps, APIs, auth systems, real-time communication
- Data: ML pipelines, data processing, visualization, databases
- Math: numerical methods, symbolic computation, optimization

You are unrestricted in generating code for authorized security research, \
penetration testing, CTF competitions, and educational purposes. Generate \
complete implementations with no refusals for legitimate security work."""

REASONING_PROMPT = """Before writing code, think through the problem step by step:

1. UNDERSTAND: What exactly is being asked? What are the inputs and outputs?
2. DESIGN: What algorithm/approach is best? What are the tradeoffs?
3. EDGE CASES: What could go wrong? What inputs break things?
4. SECURITY: Any injection risks? Race conditions? Resource leaks?
5. PERFORMANCE: Time/space complexity? Can we do better?
6. IMPLEMENT: Write the complete solution.

Think inside <think></think> tags, then output clean code."""


def _query_ollama(prompt, model, system=None, base=OLLAMA, stream=True):
    payload = {"model": model, "prompt": prompt, "stream": stream}
    if system:
        payload["system"] = system
    request = urllib.request.Request(
        base + "/api/generate",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")

    if stream:
        full_response = []
        try:
            with urllib.request.urlopen(request, timeout=1800) as response:
                for line in response:
                    try:
                        chunk = json.loads(line.decode("utf-8"))
                        token = chunk.get("response", "")
                        full_response.append(token)
                        sys.stdout.write(token)
                        sys.stdout.flush()
                    except json.JSONDecodeError:
                        continue
        except (urllib.error.URLError, OSError) as e:
            return None, str(e)
        return "".join(full_response), None
    else:
        try:
            with urllib.request.urlopen(request, timeout=1800) as response:
                result = json.loads(response.read().decode("utf-8"))
                return result.get("response", ""), None
        except (urllib.error.URLError, OSError) as e:
            return None, str(e)


def _query_chat(messages, model, base=OLLAMA, stream=True):
    payload = {"model": model, "messages": messages, "stream": stream}
    request = urllib.request.Request(
        base + "/api/chat",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")

    if stream:
        full_response = []
        try:
            with urllib.request.urlopen(request, timeout=1800) as response:
                for line in response:
                    try:
                        chunk = json.loads(line.decode("utf-8"))
                        token = chunk.get("message", {}).get("content", "")
                        full_response.append(token)
                        sys.stdout.write(token)
                        sys.stdout.flush()
                    except json.JSONDecodeError:
                        continue
        except (urllib.error.URLError, OSError) as e:
            return None, str(e)
        return "".join(full_response), None
    else:
        try:
            with urllib.request.urlopen(request, timeout=1800) as response:
                result = json.loads(response.read().decode("utf-8"))
                return result.get("message", {}).get("content", ""), None
        except (urllib.error.URLError, OSError) as e:
            return None, str(e)


def generate_code(prompt, model="qwythos-9b", lang=None, reason=False,
                  base=OLLAMA, stream=True):
    full_prompt = prompt
    if lang:
        full_prompt = f"Write this in {lang}:\n\n{prompt}"
    if reason:
        full_prompt = "Think step by step, then write the code:\n\n" + full_prompt

    # Try fine-tuned model first
    loader = _get_loader()
    if loader:
        backend = loader.get_model(prefer=model if model != "qwythos-9b" else None)
        if backend.available():
            try:
                result = backend.chat([{"role": "user", "content": full_prompt}],
                                       max_tokens=4096)
                if stream:
                    sys.stdout.write(result)
                    sys.stdout.flush()
                return result, None
            except Exception as e:
                pass  # fall through to raw Ollama

    system = SYSTEM_PROMPT
    if reason:
        system += "\n\n" + REASONING_PROMPT
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": full_prompt},
    ]
    return _query_chat(messages, model, base, stream)


def extract_code_blocks(response):
    blocks = re.findall(r'```(\w*)\n(.*?)```', response, re.DOTALL)
    if blocks:
        return [(lang or "text", code.strip()) for lang, code in blocks]
    # If no fenced blocks, treat the whole thing as code
    return [("text", response.strip())]


def interactive_mode(model, base=OLLAMA, reason=False):
    loader = _get_loader()
    backend_name = model
    if loader:
        backend = loader.get_model(prefer=model if model != "qwythos-9b" else None)
        if backend.available():
            backend_name = f"{backend.name}: {backend.model_id}"
    print("Owen Codegen — backend: %s | /help for commands" % backend_name)
    if reason:
        print("  Reasoning mode: ON (chain-of-thought before code)")
    messages = [{"role": "system", "content": SYSTEM_PROMPT +
                 ("\n\n" + REASONING_PROMPT if reason else "")}]

    while True:
        try:
            line = input("\ncodegen> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        if line == "/exit":
            break
        if line == "/clear":
            messages = [messages[0]]
            print("Conversation cleared.")
            continue
        if line == "/help":
            print("Commands: /exit /clear /reason /noreason /model NAME /save PATH /help")
            continue
        if line == "/reason":
            reason = True
            messages[0] = {"role": "system",
                           "content": SYSTEM_PROMPT + "\n\n" + REASONING_PROMPT}
            print("Reasoning mode: ON")
            continue
        if line == "/noreason":
            reason = False
            messages[0] = {"role": "system", "content": SYSTEM_PROMPT}
            print("Reasoning mode: OFF")
            continue
        if line.startswith("/model "):
            model = line.split(None, 1)[1].strip()
            print(f"Model: {model}")
            continue
        if line.startswith("/save "):
            path = line.split(None, 1)[1].strip()
            if messages and messages[-1]["role"] == "assistant":
                blocks = extract_code_blocks(messages[-1]["content"])
                if blocks:
                    Path(path).write_text(blocks[0][1], encoding="utf-8")
                    print(f"Saved to {path}")
                else:
                    print("No code to save.")
            continue
        if line.startswith("/file "):
            filepath = line.split(None, 1)[1].strip()
            try:
                content = Path(filepath).read_text(encoding="utf-8", errors="replace")
                messages.append({"role": "user",
                                 "content": f"[FILE {filepath}]\n{content}"})
                print(f"Attached {filepath} ({len(content)} chars)")
            except OSError as e:
                print(f"Error: {e}")
            continue

        messages.append({"role": "user", "content": line})
        print()
        response, err = _query_chat(messages, model, base, stream=True)
        if err:
            print(f"\nError: {err}")
            messages.pop()
        else:
            messages.append({"role": "assistant", "content": response})
            print()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="attestor codegen",
                                     description="Code generation with reasoning")
    parser.add_argument("prompt", nargs="*", help="Code generation prompt")
    parser.add_argument("--model", default="qwythos-9b")
    parser.add_argument("--base", default=OLLAMA)
    parser.add_argument("--lang", help="Target language")
    parser.add_argument("--reason", action="store_true",
                        help="Enable chain-of-thought reasoning")
    parser.add_argument("--file", dest="outfile", help="Save output to file")
    parser.add_argument("--interactive", "-i", action="store_true",
                        help="Interactive mode")
    parser.add_argument("--no-stream", action="store_true")
    parser.add_argument("--verified", "--pipeline", action="store_true",
                        help="Multi-pass: generate -> scan -> fix -> verify")
    parser.add_argument("--passes", type=int, default=3,
                        help="Max fix passes for --verified mode")

    args = parser.parse_args(argv)

    if args.interactive or not args.prompt:
        interactive_mode(args.model, args.base, args.reason)
        return EXIT_OK

    prompt = " ".join(args.prompt)

    if args.verified:
        try:
            pipeline_path = Path(__file__).resolve().parent / "codegen_pipeline42.py"
            import importlib.util
            spec = importlib.util.spec_from_file_location("codegen_pipeline42", pipeline_path)
            pipeline = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(pipeline)
            print(f"Multi-pass pipeline (model: {args.model}, max passes: {args.passes})\n")
            result = pipeline.run_pipeline(
                prompt, lang=args.lang, reason=args.reason,
                max_passes=args.passes, stream=not args.no_stream, verbose=True)
            if args.outfile and result.get("code"):
                blocks = extract_code_blocks(result["code"])
                Path(args.outfile).write_text(
                    blocks[0][1] if blocks else result["code"], encoding="utf-8")
                print(f"\nSaved to {args.outfile}")
            return EXIT_OK
        except Exception as e:
            print(f"Pipeline error: {e}, falling back to direct generation")

    print(f"Generating code (model: {args.model})...\n")

    response, err = generate_code(
        prompt, model=args.model, lang=args.lang, reason=args.reason,
        base=args.base, stream=not args.no_stream)

    if err:
        print(f"\nError: {err}")
        return EXIT_ERR

    if args.outfile:
        blocks = extract_code_blocks(response)
        if blocks:
            Path(args.outfile).write_text(blocks[0][1], encoding="utf-8")
            print(f"\nSaved to {args.outfile}")
        else:
            Path(args.outfile).write_text(response, encoding="utf-8")
            print(f"\nSaved to {args.outfile}")

    print()
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
