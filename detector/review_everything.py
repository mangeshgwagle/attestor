#!/usr/bin/env python3
"""review_everything -- dolphin reads 100% of Owen's code. No skips.

- walks every .py in the detector tree
- chunks large files at ~90KB (fits 32k context with room to answer)
- reviews EVERY chunk via the local Ollama API (num_ctx=32768)
- appends to reviews_full.txt with file/chunk headers
- RESUMES: already-reviewed chunks are skipped if you stop and restart
"""

import json
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "reviews_full.txt"
STATE = ROOT / "reviews_state.json"
MODEL = "dolphin3:8b"
NUM_CTX = 32768
CHUNK_CHARS = 90_000
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules",
             ".pytest_cache"}

PROMPT = ("You are reviewing part of a large security toolkit. Review "
          "this code section thoroughly: bugs, security vulnerabilities, "
          "design flaws, dead code, risky patterns. Severity each finding "
          "(HIGH/MED/LOW). End with ONE line: overall assessment of this "
          "section.\n\nCODE SECTION:\n")


def load_state():
    if STATE.exists():
        return set(json.loads(STATE.read_text()))
    return set()


def save_state(state):
    STATE.write_text(json.dumps(sorted(state)))


def ask_dolphin(chunk):
    payload = {
        "model": MODEL,
        "prompt": PROMPT + chunk,
        "stream": False,
        "options": {"num_ctx": NUM_CTX, "temperature": 0.3},
    }
    request = urllib.request.Request(
        "http://127.0.0.1:11434/api/generate",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=1800) as response:
        return json.loads(response.read().decode("utf-8")).get(
            "response", "")


def main(limit_chunks=None):
    files = []
    for path in sorted(ROOT.rglob("*.py")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name in ("reviews_full.txt", "reviews_state.json",
                         "all_code.txt"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if text.strip():
            files.append((path, text))

    chunks = []
    for path, text in files:
        rel = path.relative_to(ROOT)
        if len(text) <= CHUNK_CHARS:
            chunks.append((rel, 0, 1, text))
        else:
            parts = [text[i:i + CHUNK_CHARS]
                     for i in range(0, len(text), CHUNK_CHARS)]
            for i, part in enumerate(parts, 1):
                chunks.append((rel, i, len(parts), part))

    done = load_state()
    pending = [c for c in chunks
               if "%s#%d" % (c[0], c[1]) not in done]
    total = len(chunks)
    print("sections: %d total | %d already reviewed | %d to go"
          % (total, total - len(pending), len(pending)))
    if limit_chunks:
        pending = pending[:limit_chunks]
        print("(limited run: %d)" % len(pending))

    started = time.time()
    done_count = 0
    with open(OUT, "a", encoding="utf-8") as log:
        for rel, part_i, part_n, text in pending:
            key = "%s#%d" % (rel, part_i)
            label = str(rel) if part_n == 1 else "%s [part %d/%d]" % (
                rel, part_i, part_n)
            header = ("\n\n" + "=" * 70 + "\n## %s\n" % label + "=" * 70
                      + "\n")
            log.write(header)
            log.flush()
            try:
                answer = ask_dolphin(text)
                log.write(answer + "\n")
                log.flush()
                done.add(key)
                save_state(done)
                done_count += 1
                elapsed = time.time() - started
                rate = done_count / max(elapsed, 1)
                eta = (len(pending) - done_count) / max(rate, 1e-9) / 60
                print("[%d/%d] %s -- done (%.1f min left)"
                      % (done_count, len(pending), label, eta),
                      flush=True)
            except Exception as exc:  # noqa: BLE001
                log.write("REVIEW ERROR: %s\n" % str(exc)[:200])
                print("[%d/%d] %s -- ERROR %s"
                      % (done_count + 1, len(pending), label,
                         str(exc)[:100]), flush=True)

    print("session complete: %d reviewed this run | %d/%d total"
          % (done_count, len(done), total))
    print("full log:", OUT)


if __name__ == "__main__":
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None
    main(limit)
