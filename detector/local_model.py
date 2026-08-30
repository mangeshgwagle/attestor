#!/usr/bin/env python3
"""Embedded local model -- the 'raw inside' brain.

Runs a GGUF language model INSIDE Attestor's own process via llama-cpp-python.
No Ollama, no server, no network, no provider. Fully self-contained and
air-gappable: the weights are a file on disk, inference happens in-process.

Putting weights in Attestor (two ways):
  1. Drop a `.gguf` file into  detector/models/   -- Attestor auto-loads the
     first one it finds.
  2. Or set the env var        ATTESTOR_MODEL=/abs/path/to/model.gguf

Any GGUF works: a small open instruct model today (e.g. Qwen2.5-Coder-3B q4),
and your own Owen Coder GGUF once training finishes -- same code, better brain.

If llama-cpp-python isn't installed or no weights are present, is_available()
returns False and callers (adjudicate.py) fall back gracefully.
"""
from __future__ import annotations

import glob
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(_HERE, "models")

_llm = None          # lazily-loaded singleton
_load_error = ""


def find_weights() -> str | None:
    """Locate a GGUF: env var wins, else first file in detector/models/."""
    env = os.environ.get("ATTESTOR_MODEL")
    if env and os.path.isfile(env):
        return env
    if os.path.isdir(MODEL_DIR):
        hits = sorted(glob.glob(os.path.join(MODEL_DIR, "*.gguf")))
        if hits:
            return hits[0]
    return None


def _have_llama_cpp() -> bool:
    try:
        import llama_cpp  # noqa: F401
        return True
    except Exception:
        return False


def is_available() -> bool:
    """True only if the runtime AND a weights file are both present."""
    return _have_llama_cpp() and find_weights() is not None


def _load():
    """Load the GGUF into memory once (in-process)."""
    global _llm, _load_error
    if _llm is not None:
        return _llm
    path = find_weights()
    if not path:
        _load_error = "no .gguf weights found (see local_model docstring)"
        return None
    try:
        from llama_cpp import Llama
        _llm = Llama(
            model_path=path,
            n_ctx=int(os.environ.get("ATTESTOR_MODEL_CTX", "4096")),
            n_threads=os.cpu_count() or 4,
            n_gpu_layers=int(os.environ.get("ATTESTOR_MODEL_GPU_LAYERS", "0")),
            verbose=False,
        )
        return _llm
    except Exception as exc:
        _load_error = f"failed to load {path}: {exc}"
        return None


def generate(prompt: str, *, system: str | None = None,
             max_tokens: int = 512, temperature: float = 0.1) -> str:
    """Run inference in-process and return the model's text."""
    llm = _load()
    if llm is None:
        return ""
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    try:
        out = llm.create_chat_completion(
            messages=messages, max_tokens=max_tokens, temperature=temperature)
        return out["choices"][0]["message"]["content"].strip()
    except Exception:
        # fall back to raw completion for base (non-chat) models
        try:
            out = llm(prompt, max_tokens=max_tokens, temperature=temperature)
            return out["choices"][0]["text"].strip()
        except Exception as exc:
            return f"[local_model error: {str(exc)[:120]}]"


def info() -> dict:
    return {
        "runtime_installed": _have_llama_cpp(),
        "weights": find_weights(),
        "loaded": _llm is not None,
        "model_dir": MODEL_DIR,
        "load_error": _load_error,
    }


def status_line() -> str:
    i = info()
    if not i["runtime_installed"]:
        return ("  local model: llama-cpp-python NOT installed  "
                "(pip install 'attestor[ai]'  or  pip install llama-cpp-python)")
    if not i["weights"]:
        return (f"  local model: runtime ready, but NO weights.\n"
                f"    -> drop a .gguf in {MODEL_DIR}\n"
                f"    -> or set ATTESTOR_MODEL=/path/to/model.gguf")
    return f"  local model: READY  ({os.path.basename(i['weights'])}, in-process)"


if __name__ == "__main__":
    print(status_line())
    if is_available():
        q = sys.argv[1] if len(sys.argv) > 1 else "Say READY in one word."
        print(generate(q, max_tokens=32))
