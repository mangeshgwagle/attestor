#!/usr/bin/env python3
"""Load Attestor provider settings from one explicitly trusted key file.

Attestor deliberately does *not* discover ``.env`` files in the current working
directory.  A repository being reviewed is untrusted input: allowing its
``.env`` to choose providers or proxy settings could send source code or API
keys somewhere the repository author controls.

Trusted lookup order:

1. the ``path`` argument supplied by the caller;
2. ``ATTESTOR_ENV_FILE`` supplied by the parent process;
3. ``keys.env`` beside Attestor's detector scripts.

Only the exact provider variables in :data:`ALLOWED_KEYS` are accepted.  Shell
and CI variables still win unless ``override=True`` is explicitly requested.
"""
from __future__ import annotations

import os
import re


ALLOWED_KEYS = frozenset({
    "GROQ_API_KEY",
    "GROQ_MODEL",
    "OPENROUTER_API_KEY",
    "OPENROUTER_MODEL",
    "MISTRAL_API_KEY",
    "MISTRAL_MODEL",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_MODEL",
    "OPENAI_API_KEY",
    "OPENAI_MODEL",
    "OLLAMA_MODEL",
    "OLLAMA_HOST",
    # Remote Ollama is off by default. This is intentionally a conspicuous,
    # explicit opt-in rather than accepting arbitrary endpoint variables.
    "ATTESTOR_ALLOW_REMOTE_OLLAMA",
})

_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _parse(text: str) -> dict[str, str]:
    """Parse an env file, dropping malformed and non-allowlisted entries."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if not _KEY_RE.fullmatch(key) or key not in ALLOWED_KEYS:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        # Environment values cannot contain NUL. Newlines would also allow a
        # confusing value to masquerade as another setting in diagnostics.
        if "\x00" in value or "\r" in value or "\n" in value:
            continue
        out[key] = value
    return out


def _candidate(path: str) -> str:
    return os.path.abspath(os.path.expanduser(path)) if path else ""


def find(explicit: str = "") -> str:
    """Return a trusted key-file path, or ``""`` when none is configured.

    The current directory is intentionally absent from this search.
    """
    if explicit:
        path = _candidate(explicit)
        return path if os.path.isfile(path) else ""

    configured = os.environ.get("ATTESTOR_ENV_FILE", "").strip()
    if configured:
        path = _candidate(configured)
        return path if os.path.isfile(path) else ""

    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "keys.env")
    return path if os.path.isfile(path) else ""


def load(path: str = "", override: bool = False) -> list[str]:
    """Load allowlisted settings from a trusted file.

    Supplying ``path`` or ``ATTESTOR_ENV_FILE`` is the explicit trust decision.  For
    backwards-compatible desktop use, ``keys.env`` beside Attestor is also treated
    as application configuration. Missing or unreadable files are a no-op.
    Returned values are variable *names* only, never secrets.
    """
    found = find(path)
    if not found:
        return []
    try:
        with open(found, encoding="utf-8", errors="replace") as fh:
            pairs = _parse(fh.read())
    except OSError:
        return []

    loaded: list[str] = []
    for key, value in pairs.items():
        if override or key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded


if __name__ == "__main__":
    names = load()
    where = find()
    if names:
        print("loaded allowlisted settings from " + where + ": " + ", ".join(names))
    elif where:
        print("trusted key file contained no new allowlisted settings: " + where)
    else:
        print("no trusted keys.env configured; copy keys.env.example beside Attestor "
              "or set ATTESTOR_ENV_FILE explicitly")
