# Attestor provider-key setup (no secrets)

This file is documentation only. Never paste a real API key into Markdown or
commit one to source control.

1. Copy `keys.env.example` to `keys.env` in this `detector` directory, or put it
   elsewhere and set `ATTESTOR_ENV_FILE` to that exact trusted path.
2. Uncomment only the providers you use and replace the placeholder locally.
3. Keep `keys.env` untracked. Shell/CI environment variables take precedence.
4. If a real key was ever committed, shared, or packaged, revoke it at the
   provider immediately and create a new one. Deleting the visible line does not
   remove a secret from Git history or old ZIP files.

Example placeholders:

```dotenv
GROQ_API_KEY=gsk_replace_me
GROQ_MODEL=qwen/qwen3-32b

OPENROUTER_API_KEY=sk-or-v1-replace_me
OPENROUTER_MODEL=meta-llama/llama-3.3-70b-instruct:free

MISTRAL_API_KEY=replace_me
MISTRAL_MODEL=codestral-latest

GEMINI_API_KEY=replace_me
GEMINI_MODEL=gemini-2.0-flash

OPENAI_API_KEY=sk-replace_me
OPENAI_MODEL=gpt-4o-mini

# Local Ollama is keyless and loopback-only by default.
OLLAMA_MODEL=qwen2.5-coder
OLLAMA_HOST=http://localhost:11434
```

Attestor intentionally ignores `.env` files in the current project directory and
loads only allowlisted provider variables. Remote Ollama endpoints are blocked
unless `ATTESTOR_ALLOW_REMOTE_OLLAMA=1` is explicitly set for a trusted server.
