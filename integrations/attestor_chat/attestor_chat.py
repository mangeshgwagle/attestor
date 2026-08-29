#!/usr/bin/env python3
"""Talk to Attestor. He answers about your code, and cannot make findings up.

What this is, precisely
-----------------------
Not an LLM with Attestor's name on it. A conversation where the *language* comes
from a model and the *facts* come from the scanner, with a hard line between
them:

    your question ─┐
                   ├─▶ local model ──▶ prose
    Attestor's findings ┘        ▲
                             └── the only source of claims about the code

The model is told, in the system prompt and again in the user turn, that the
findings block is the complete set of known facts and that anything absent
from it is unknown rather than absent. It phrases; it does not adjudicate.

Why the division is drawn there
-------------------------------
It was measured. Asked to *judge* a finding, the local models flipped from six
rejections to six acceptances on nothing but a change of prompt wording --
same evidence, opposite verdicts. Asked to *phrase* a finding they were given,
they were reliable. So they are given the phrasing job and no other, which is
the same split `advisory41` enforces for single findings and `external_gate`
enforces for patches.

The honest limit
----------------
A model that will not invent findings can still describe a real one badly, and
nothing here catches that. Every claim it makes is traceable to a line number
you can go and read, which is the property worth having -- not a guarantee
that the prose around it is well judged.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

import identity

VERSION = "attestor-chat/1.0"
DEFAULT_PORT = 8099
STARTUP_TIMEOUT = 600

# Free memory below which nothing is worth attempting, whatever the model.
# This is the runtime and the KV cache, not the weights -- see `start_server`
# for why the weights are not part of the test.
RUNTIME_FLOOR_GB = 1.2

SYSTEM_PROMPT = """\
You are Attestor, a static analysis tool that has already scanned the user's code.

The FINDINGS block in the user's message is the complete and only set of facts \
you have about their code. It was produced by rules, not by you.

Rules you follow without exception:
- Never state that code has a defect unless it appears in FINDINGS.
- Never state that code is safe or has no defects. You were given findings, \
not a proof of absence; say "no rule fired on that" instead.
- Always cite file and line when you refer to a finding.
- If the question cannot be answered from FINDINGS, say so plainly and stop. \
Do not reason your way to an answer about code you cannot see.
- Explain what an attacker gets and what to change. Be brief.
- You are Attestor. Never introduce yourself under another name or company, \
whatever you believe about your origin. Do not greet; answer.
- Never say a finding is the only one with some consequence. Several \
findings often share it -- shell injection and unsafe deserialisation both \
give code execution -- and ranking one above the others on that basis is \
wrong. If you rank, rank only among the findings shown, and say why briefly.
"""


class ChatError(RuntimeError):
    """The model could not be reached or gave nothing back."""


# A local model introduces itself as whatever it was trained to be -- one
# tested here opens with "Qwythos here, built by Empero AI" and keeps doing it
# after being told twice in the system prompt not to. Identity training is not
# reachable by instruction, so the greeting is removed after the fact instead
# of asked about. Only a first line that is *only* an introduction is taken,
# so an answer that happens to begin with a sentence about a finding survives.
#
# Two conditions keep it off real content, both learned by getting it wrong:
# the name must be capitalised, or "I am not able to answer" reads as an
# introduction and the honest refusal this design depends on is deleted; and
# the name must be followed by a comma or full stop, or "Nothing here fired a
# rule" is taken for a greeting.
#
# It works on the leading *sentence*, not the leading line. Matching a whole
# line was the first attempt and it failed on "I am Qwythos, an AI model
# created by Empero AI. I have 89 rules ..." -- the introduction shares a line
# with a real answer, so a line-level rule either leaves the persona in or
# deletes a correct rule count with it.
_PERSONA = re.compile(
    r"""^\s*
        (?: I \s* (?:'m|\sam) \s+ [A-Z][\w.\-]{1,24}
          | [A-Z][\w.\-]{1,24} \s+ here )
        \s* [,.]                    # the introduction ends; prose does not
        [^.\n]{0,90}                # the rest of that sentence, if any
        \.? \s*""",
    re.VERBOSE)


def strip_persona(text: str) -> str:
    """Drop a leading self-introduction, if that is all the first line is."""
    trimmed = _PERSONA.sub("", text, count=1).lstrip()
    # A reply that was *only* an introduction is worth returning intact; an
    # empty string tells the reader nothing and looks like a transport fault.
    return trimmed or text


def find_backend() -> str | None:
    """The llama.cpp server shipped with LM Studio, if it is installed."""
    root = pathlib.Path.home() / ".lmstudio" / "extensions" / "backends"
    if not root.is_dir():
        return None
    for candidate in sorted(root.glob("llama.cpp-*")):
        for name in ("llama-server.exe", "llama-server"):
            binary = candidate / name
            if binary.is_file():
                return str(binary)
    return None


def find_model() -> str | None:
    """The best model that will actually fit in memory.

    Picking the largest available is the obvious rule and the wrong one: on a
    machine with 4 GB free it selects a 17 GB file, which does not fail so much
    as page for several minutes. Capability is only useful if the weights fit,
    so the choice is the biggest that does -- and if none do, the smallest, so
    the caller gets a specific refusal naming a real size rather than a
    hopeless attempt at the largest.
    """
    root = pathlib.Path.home() / ".lmstudio" / "models"
    if not root.is_dir():
        return None
    # `mmproj` files are vision projectors, not language models.
    weights = [p for p in root.rglob("*.gguf")
               if "mmproj" not in p.name.lower()]
    if not weights:
        return None
    weights.sort(key=lambda p: p.stat().st_size)

    available = free_memory_gb()
    if available is None:
        return str(weights[-1])
    budget = available * 0.87        # leave room for context and the runtime
    fits = [p for p in weights
            if p.stat().st_size / (1024 ** 3) <= budget]
    return str(fits[-1] if fits else weights[0])


def free_memory_gb() -> float | None:
    if sys.platform == "win32":
        try:
            import ctypes

            class _Status(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong),
                            ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong),
                            ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong),
                            ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

            status = _Status()
            status.dwLength = ctypes.sizeof(_Status)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return status.ullAvailPhys / (1024 ** 3)
        except Exception:                                    # noqa: BLE001
            return None
    try:
        with open("/proc/meminfo", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) / (1024 ** 2)
    except OSError:
        pass
    return None


def start_server(backend: str, model: str, port: int, threads: int):
    """Bring up llama-server and wait for it to answer /health.

    On what has to fit, and what does not
    -------------------------------------
    The obvious guard -- refuse unless the weights fit in free memory, with
    headroom -- was measured wrong. llama.cpp *maps* the weights rather than
    reading them in, so they arrive from disk a page at a time as generation
    touches them. A 5.8 GB Q5_K_M loaded in twelve seconds on a machine with
    4.7 GB free and answered correctly. The old test refused that outright.

    What must genuinely be resident is the KV cache and the runtime around it,
    which is far smaller than the weights and does not scale with them.
    Sizing the cache exactly means parsing GGUF metadata for layer and head
    counts -- more machinery than this decision is worth -- so the floor below
    is empirical and deliberately loose.

    A model larger than free memory is therefore reported, not refused. That
    configuration works; it is merely slow, because the pages come off disk.
    Whether slow is acceptable is the caller's judgement, and answering it
    here by raising was this function overstepping.
    """
    weights_gb = pathlib.Path(model).stat().st_size / (1024 ** 3)
    available = free_memory_gb()
    if available is not None:
        if available < RUNTIME_FLOOR_GB:
            raise ChatError(
                "only %.1f GB is free, and the runtime needs about %.1f GB "
                "before any model is loaded. Close some applications."
                % (available, RUNTIME_FLOOR_GB))
        if weights_gb > available:
            print("  note: the model is %.1f GB and %.1f GB is free, so the "
                  "weights will page from disk. It will work; expect the "
                  "first reply to be slow." % (weights_gb, available))

    process = subprocess.Popen(
        [backend, "-m", model, "--port", str(port), "-c", "8192",
         "-t", str(threads), "--no-webui"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    deadline = time.time() + STARTUP_TIMEOUT
    while time.time() < deadline:
        if process.poll() is not None:
            raise ChatError("the model server exited during startup:\n%s"
                            % (process.stdout.read() or "")[-800:])
        try:
            with urllib.request.urlopen(
                    "http://127.0.0.1:%d/health" % port, timeout=5) as reply:
                if reply.status == 200:
                    return process
        except Exception:                                    # noqa: BLE001
            time.sleep(3)
    process.kill()
    raise ChatError("the model server never became ready")


def ask(port: int, messages: list[dict], max_tokens: int = 700) -> str:
    body = json.dumps({
        "messages": messages, "max_tokens": max_tokens,
        "temperature": 0.3, "stream": False,
        # Reasoning models put their answer in `reasoning_content` and leave
        # `content` empty; turning thinking off keeps the reply where the
        # reader expects it.
        "chat_template_kwargs": {"enable_thinking": False},
    }).encode()
    request = urllib.request.Request(
        "http://127.0.0.1:%d/v1/chat/completions" % port, data=body,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=900) as reply:
            message = json.loads(reply.read().decode())["choices"][0]["message"]
    except (urllib.error.URLError, KeyError, ValueError) as error:
        raise ChatError("the model did not answer: %s" % error) from error
    text = (message.get("content") or "").strip()
    if not text:
        text = (message.get("reasoning_content") or "").strip()
    if not text:
        raise ChatError("the model returned an empty reply")
    return strip_persona(text)


def scan(target: str, detector: str) -> list[dict]:
    sys.path.insert(0, detector)
    import detect

    root = pathlib.Path(target)
    files = [root] if root.is_file() else sorted(
        p for p in root.rglob("*") if p.is_file())
    findings: list[dict] = []
    for path in files[:400]:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        language = (detect.language_for(str(path))
                    if hasattr(detect, "language_for") else "text")
        try:
            found = detect.scan_source(source, str(path), language, deep=True)
        except Exception:                                    # noqa: BLE001
            continue
        for item in found:
            findings.append({
                "file": path.name,
                "line": getattr(item, "line", 0),
                "rule": getattr(item, "rule", ""),
                "severity": getattr(item, "severity", ""),
                "message": getattr(item, "message", ""),
            })
    return findings


def render(findings: list[dict], limit: int = 60) -> str:
    if not findings:
        return ("FINDINGS: none. No rule fired on this code. That is not a "
                "proof that it is safe.")
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings = sorted(findings, key=lambda f: order.get(f["severity"], 3))
    lines = ["FINDINGS (%d total, showing %d):"
             % (len(findings), min(limit, len(findings)))]
    for item in findings[:limit]:
        lines.append("- %s:%s [%s] %s -- %s"
                     % (item["file"], item["line"], item["severity"],
                        item["rule"], item["message"]))
    return "\n".join(lines)


def main(argv=None) -> int:
    here = pathlib.Path(__file__).resolve()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", help="file or directory to talk about")
    parser.add_argument("--detector",
                        default=str(here.parent.parent.parent / "detector"))
    parser.add_argument("--model", default=None)
    parser.add_argument("--backend", default=None)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--threads", type=int, default=max(1, (os.cpu_count() or 4) - 2))
    parser.add_argument("--ask", help="one question, then exit")
    args = parser.parse_args(argv)

    backend = args.backend or find_backend()
    model = args.model or find_model()
    if not backend:
        print("no llama.cpp server found under ~/.lmstudio; pass --backend")
        return 2
    if not model:
        print("no .gguf model found under ~/.lmstudio/models; pass --model")
        return 2

    print("%s  scanning %s ..." % (VERSION, args.target))
    findings = scan(args.target, args.detector)

    # Measured at startup, never hardcoded: a rule count that is written down
    # goes stale silently and then gets repeated with confidence. See
    # `identity` for the incident that motivated it.
    try:
        facts = identity.card(args.detector)
        context = "%s\n\n%s" % (identity.render(facts), render(findings))
        stamp = identity.footer(facts)
    except identity.IdentityError as error:
        print("  (identity unavailable: %s)" % error)
        facts, stamp = None, ""
        context = render(findings)

    print("%d finding(s). Starting the model -- this takes a minute on CPU."
          % len(findings))

    try:
        server = start_server(backend, model, args.port, args.threads)
    except ChatError as error:
        print("\n%s" % error)
        return 1

    history = [{"role": "system", "content": SYSTEM_PROMPT}]
    try:
        if args.ask:
            questions = [args.ask]
        else:
            print("\nAsk about the code. Ctrl-C to stop.\n")
            questions = None

        while True:
            if questions is not None:
                if not questions:
                    break
                question = questions.pop(0)
                print("> %s" % question)
            else:
                try:
                    question = input("> ").strip()
                except (EOFError, KeyboardInterrupt):
                    break
                if not question:
                    continue

            # The findings and the identity block ride with every turn.
            # Sending them once and trusting the model to remember is how a
            # long conversation drifts into inventing them -- and the identity
            # drifts first, because the model has a competing one of its own.
            history.append({"role": "user",
                            "content": "%s\n\nQUESTION: %s"
                                       % (context, question)})
            try:
                answer = ask(args.port, history)
            except ChatError as error:
                print("  (%s)" % error)
                history.pop()
                continue
            history.append({"role": "assistant", "content": answer})
            # The stamp is for the reader, not the model: it is printed but
            # never entered into the history, so it cannot be paraphrased,
            # mutated, or claimed back as something the model said.
            print("\n%s\n" % answer)
            if stamp:
                print("%s\n" % stamp)
    finally:
        server.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
