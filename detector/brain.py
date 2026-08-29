#!/usr/bin/env python3
"""
brain.py -- an OPTIONAL real-LLM backend for Attestor, with pluggable providers.

nl.py is a deterministic intent parser: no understanding. This adds the real
thing IF (and only if) you supply a working key. It can hold several providers at
once (Groq, OpenRouter, Mistral, Gemini, OpenAI, Ollama) and run them "alongside"
each other two ways:

  - fallback (default): try each provider in order, return the first that answers.
    Gemini 429s? it falls through to OpenAI; all down? nl.py's parser still works.
  - compare: ask EVERY configured provider and return all answers side by side,
    so you can eyeball which model wrote the better code.

No SDKs -- raw HTTPS via urllib, every call bounded by a timeout. Keys come from
the environment, never source:

    GROQ_API_KEY        (+ optional GROQ_MODEL)
    OPENROUTER_API_KEY  (+ optional OPENROUTER_MODEL)
    MISTRAL_API_KEY     (+ optional MISTRAL_MODEL)
    GEMINI_API_KEY      (+ optional GEMINI_MODEL, default gemini-2.0-flash)
    OPENAI_API_KEY      (+ optional OPENAI_MODEL)
    OLLAMA_MODEL        (+ optional OLLAMA_HOST, for a local model)

Honesty: the provider calls are wired to each API's current REST shape but cannot
be live-verified in this sandbox (no working key + restricted egress). The
routing -- fallback, compare, graceful failure -- is fully tested offline.

    python3 brain.py "write a python function that reverses a linked list"
    python3 brain.py "..." --compare       # ask every configured provider
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from enum import Enum
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

_CA = (os.environ.get("SSL_CERT_FILE")
       or ("/root/.ccr/ca-bundle.crt" if os.path.exists("/root/.ccr/ca-bundle.crt") else None))
_TIMEOUT = 30
_MAX_RESPONSE_BYTES = 10_000_000
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
_CLOUD_HOSTS = frozenset({
    "api.groq.com",
    "openrouter.ai",
    "api.mistral.ai",
    "generativelanguage.googleapis.com",
    "api.openai.com",
})


class ProviderError(Exception):
    """A provider could not answer (network, quota, bad key, odd response)."""


class ProviderConfigurationError(ProviderError):
    """A provider endpoint/model setting failed Attestor's safety policy."""


class GenerationStatus(str, Enum):
    """The outcome of one provider attempt.

    A provider failure is deliberately a state, not response text.  This keeps
    quota/network/configuration messages out of code and prose candidates.
    """

    SUCCESS = "success"
    FAILED = "failed"
    ABSTAINED = "abstained"


@dataclass(frozen=True)
class GenerationEvidence:
    """Content-free, deterministic provenance for one generation attempt."""

    provider: str
    model: str
    status: GenerationStatus
    prompt_sha256: str
    response_sha256: str | None
    schema: str = "attestor-generation-evidence/1"

    def as_dict(self) -> dict:
        """Return a JSON-safe evidence record without prompt or response text."""
        return {
            "schema": self.schema,
            "provider": self.provider,
            "model": self.model,
            "status": self.status.value,
            "prompt_sha256": self.prompt_sha256,
            "response_sha256": self.response_sha256,
        }


@dataclass(frozen=True)
class GenerationResult:
    """Typed result for one provider attempt.

    ``content`` exists only for ``SUCCESS``.  Failure and abstention details
    live in ``error`` and can therefore never masquerade as model output.
    Prompt text is intentionally not retained; evidence stores its digest.
    """

    provider: str
    model: str
    status: GenerationStatus
    content: str | None
    prompt_sha256: str
    response_sha256: str | None
    error: str | None = None

    def __post_init__(self) -> None:
        try:
            status = GenerationStatus(self.status)
        except ValueError as exc:
            raise ValueError("unknown generation status") from exc
        object.__setattr__(self, "status", status)
        if not _is_sha256(self.prompt_sha256):
            raise ValueError("prompt_sha256 must be a lowercase SHA-256 digest")
        if self.status is GenerationStatus.SUCCESS:
            if not self.content:
                raise ValueError("successful generation must contain model output")
            expected = _sha256_text(self.content)
            if self.response_sha256 != expected:
                raise ValueError("response_sha256 does not match model output")
            if self.error is not None:
                raise ValueError("successful generation cannot contain an error")
        else:
            if self.content is not None or self.response_sha256 is not None:
                raise ValueError("failed/abstained generation cannot contain model output")
        if self.status is GenerationStatus.FAILED and not self.error:
            raise ValueError("failed generation must contain a safe error summary")

    @property
    def success(self) -> bool:
        return self.status is GenerationStatus.SUCCESS

    @property
    def failed(self) -> bool:
        return self.status is GenerationStatus.FAILED

    @property
    def abstained(self) -> bool:
        return self.status is GenerationStatus.ABSTAINED

    @property
    def evidence(self) -> GenerationEvidence:
        return GenerationEvidence(
            provider=self.provider,
            model=self.model,
            status=self.status,
            prompt_sha256=self.prompt_sha256,
            response_sha256=self.response_sha256,
        )

    def evidence_dict(self) -> dict:
        return self.evidence.as_dict()

    def require_content(self) -> str:
        """Return verified response text or fail instead of inventing content."""
        if not self.success or self.content is None:
            detail = (": " + self.error) if self.error else ""
            raise ProviderError(
                f"{self.provider} generation {self.status.value}{detail}")
        return self.content

    def __bool__(self) -> bool:
        return self.success

    def __str__(self) -> str:
        # This is intentionally empty for non-success states.  Older callers
        # commonly use ``str(value).strip()`` before treating it as a candidate.
        return self.content if self.success and self.content is not None else ""

    def __contains__(self, value: object) -> bool:
        """Small compatibility bridge for legacy ``'failed' in value`` checks."""
        if not isinstance(value, str):
            return False
        if self.success:
            return value in (self.content or "")
        return value in self.status.value or value in (self.error or "")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _safe_detail(value: object, limit: int = 500) -> str:
    """Bound a provider diagnostic and remove control characters."""
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value)).strip()
    return text[:limit] or "provider failed without a diagnostic"


def _provider_identity(provider) -> tuple[str, str]:
    name = _safe_detail(getattr(provider, "name", "provider"), 80)
    model = getattr(provider, "model", None)
    if callable(model):
        model = model()
    if not model:
        model = getattr(provider, "_model", None)
    return name, _safe_detail(model or "unspecified", 200)


def _validate_model(model: str) -> str:
    model = (model or "").strip()
    if not _MODEL_RE.fullmatch(model):
        raise ProviderConfigurationError(
            "model id must contain only letters, digits, '.', '_', ':', '/', or '-' "
            "and be at most 200 characters")
    return model


def _validate_secret(value: str, label: str = "API key") -> str:
    if not value or any(ch in value for ch in "\x00\r\n"):
        raise ProviderConfigurationError(label + " is empty or contains control characters")
    return value


def _validate_endpoint(url: str, allowed_hosts, allow_http: bool = False) -> str:
    """Fail closed unless an endpoint has the expected scheme and exact host."""
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ProviderConfigurationError("invalid provider endpoint") from exc
    host = (parsed.hostname or "").rstrip(".").lower()
    expected = {str(item).rstrip(".").lower() for item in allowed_hosts}
    if parsed.username is not None or parsed.password is not None:
        raise ProviderConfigurationError("provider endpoint must not contain credentials")
    if host not in expected:
        raise ProviderConfigurationError("provider endpoint host is not allowlisted: " + (host or "(none)"))
    if parsed.scheme != "https" and not (allow_http and parsed.scheme == "http"):
        raise ProviderConfigurationError("provider endpoint must use HTTPS")
    if parsed.scheme == "https" and port not in (None, 443):
        raise ProviderConfigurationError("cloud provider endpoint must use HTTPS port 443")
    if parsed.fragment or any(ch in url for ch in "\x00\r\n"):
        raise ProviderConfigurationError("invalid provider endpoint")
    return url


def _validate_cloud_resolution(host: str, port: int = 443) -> None:
    """Reject cloud-provider DNS answers that point at a local/special address."""
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ProviderError("provider host could not be resolved safely") from exc
    addresses = set()
    for _family, _kind, _proto, _canon, sockaddr in answers:
        try:
            address = ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
        except ValueError:
            continue
        mapped = getattr(address, "ipv4_mapped", None)
        addresses.add(mapped or address)
    if not addresses or any(not address.is_global for address in addresses):
        raise ProviderError("provider host resolved to a non-public address")


def _loopback_host(host: str) -> bool:
    host = host.rstrip(".").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_loopback_resolution(host: str, port: int) -> None:
    """Ensure a named local endpoint cannot be redirected by hosts/DNS config."""
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        try:
            answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise ProviderConfigurationError("local OLLAMA_HOST could not be resolved") from exc
        addresses = set()
        for _family, _kind, _proto, _canon, sockaddr in answers:
            try:
                addresses.add(ipaddress.ip_address(sockaddr[0].split("%", 1)[0]))
            except ValueError:
                continue
        if not addresses or any(not address.is_loopback for address in addresses):
            raise ProviderConfigurationError("local OLLAMA_HOST did not resolve only to loopback")
    else:
        if not literal.is_loopback:
            raise ProviderConfigurationError("local OLLAMA_HOST is not loopback")


def _validate_ollama_host(host: str, allow_remote: bool = False) -> str:
    """Validate an Ollama base URL and return a normalized value.

    Local loopback endpoints are the safe default. A remote endpoint requires
    the explicit ``ATTESTOR_ALLOW_REMOTE_OLLAMA=1`` trust decision.
    """
    raw = (host or "http://localhost:11434").strip()
    try:
        parsed = urllib.parse.urlsplit(raw)
        _ = parsed.port
    except ValueError as exc:
        raise ProviderConfigurationError("invalid OLLAMA_HOST") from exc
    hostname = (parsed.hostname or "").rstrip(".").lower()
    if parsed.scheme not in ("http", "https") or not hostname:
        raise ProviderConfigurationError("OLLAMA_HOST must be a full http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ProviderConfigurationError("OLLAMA_HOST must not contain credentials")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ProviderConfigurationError("OLLAMA_HOST must not contain a path, query, or fragment")
    if any(ch in raw for ch in "\x00\r\n"):
        raise ProviderConfigurationError("invalid OLLAMA_HOST")
    if not _loopback_host(hostname) and not allow_remote:
        raise ProviderConfigurationError(
            "remote OLLAMA_HOST blocked; set ATTESTOR_ALLOW_REMOTE_OLLAMA=1 only for a trusted server")
    if _loopback_host(hostname):
        _validate_loopback_resolution(
            hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    return raw.rstrip("/")


class _NoProviderRedirect(urllib.request.HTTPRedirectHandler):
    """Provider credentials are never forwarded through HTTP redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _post_json(url: str, payload: dict, headers: dict, timeout: int = _TIMEOUT,
               *, allowed_hosts=_CLOUD_HOSTS, allow_http: bool = False) -> dict:
    _validate_endpoint(url, allowed_hosts, allow_http=allow_http)
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme == "https" and parsed.hostname in _CLOUD_HOSTS:
        _validate_cloud_resolution(parsed.hostname, parsed.port or 443)
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    for key, value in headers.items():
        req.add_header(key, value)
    context = ssl.create_default_context(cafile=_CA) if _CA else ssl.create_default_context()
    # Ignore ambient proxy variables and reject redirects. This prevents a
    # repository-controlled environment/proxy or 30x response from receiving a
    # provider Authorization header.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        _NoProviderRedirect(),
    )
    with opener.open(req, timeout=max(1, min(int(timeout), 120))) as resp:
        raw = resp.read(_MAX_RESPONSE_BYTES + 1)
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise ProviderError("provider response exceeded 10 MB")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderError("provider returned invalid JSON") from exc


class Provider:
    name = "provider"

    def generate(self, prompt: str) -> str:
        raise NotImplementedError


class GeminiProvider(Provider):
    name = "gemini"
    _allowed_hosts = frozenset({"generativelanguage.googleapis.com"})

    def __init__(self, api_key: str, model: str = "gemini-2.0-flash", timeout: int = _TIMEOUT):
        self._key = _validate_secret(api_key)
        self._model = _validate_model(model)
        self._timeout = timeout

    def generate(self, prompt: str) -> str:
        url = ("https://generativelanguage.googleapis.com/v1beta/models/"
               + self._model + ":generateContent?key="
               + urllib.parse.quote(self._key, safe=""))
        body = {"contents": [{"parts": [{"text": prompt}]}]}
        try:
            data = _post_json(url, body, {}, self._timeout,
                              allowed_hosts=self._allowed_hosts)
        except urllib.error.HTTPError as exc:
            raise ProviderError(f"gemini HTTP {exc.code} "
                                "(404=bad model/version, 429=quota)") from exc
        except Exception as exc:                # noqa: BLE001 -- net failure -> provider failure
            raise ProviderError(f"gemini unreachable: {type(exc).__name__}") from exc
        try:
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError("gemini: unexpected response shape") from exc


class OpenAIProvider(Provider):
    """OpenAI-compatible chat/completions. Groq speaks the same protocol, so its
    provider is just this with a different URL and default model."""
    name = "openai"
    _url = "https://api.openai.com/v1/chat/completions"
    _allowed_hosts = frozenset({"api.openai.com"})
    _allow_http = False

    def __init__(self, api_key: str, model: str = "gpt-4o-mini", timeout: int = _TIMEOUT):
        self._key = _validate_secret(api_key)
        self._model = _validate_model(model)
        self._timeout = timeout

    def generate(self, prompt: str) -> str:
        body = {"model": self._model,
                "messages": [{"role": "user", "content": prompt}]}
        headers = {"Authorization": "Bearer " + self._key}
        try:
            data = _post_json(
                self._url, body, headers, self._timeout,
                allowed_hosts=self._allowed_hosts, allow_http=self._allow_http)
        except urllib.error.HTTPError as exc:
            raise ProviderError(f"{self.name} HTTP {exc.code} "
                                "(404=bad model, 429=quota, 401=bad key)") from exc
        except Exception as exc:                # noqa: BLE001
            raise ProviderError(f"{self.name} unreachable: {type(exc).__name__}") from exc
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError(f"{self.name}: unexpected response shape") from exc


class GroqProvider(OpenAIProvider):
    """Groq -- an OpenAI-compatible endpoint that serves open models (Qwen, Llama,
    ...) fast and with a far more generous free tier than Gemini. Set GROQ_MODEL to
    a Qwen id (e.g. 'qwen/qwen3-32b') to run the actual sibling."""
    name = "groq"
    _url = "https://api.groq.com/openai/v1/chat/completions"
    _allowed_hosts = frozenset({"api.groq.com"})

    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile",
                 timeout: int = _TIMEOUT):
        super().__init__(api_key, model, timeout)


class OpenRouterProvider(OpenAIProvider):
    """OpenRouter -- an aggregator with one OpenAI-compatible endpoint over dozens
    of models. Free models carry a ':free' tag; set OPENROUTER_MODEL to e.g.
    'qwen/qwen-2.5-coder-32b-instruct:free' or 'deepseek/deepseek-r1:free'."""
    name = "openrouter"
    _url = "https://openrouter.ai/api/v1/chat/completions"
    _allowed_hosts = frozenset({"openrouter.ai"})

    def __init__(self, api_key: str,
                 model: str = "meta-llama/llama-3.3-70b-instruct:free",
                 timeout: int = _TIMEOUT):
        super().__init__(api_key, model, timeout)


class MistralProvider(OpenAIProvider):
    """Mistral La Plateforme -- OpenAI-compatible; set MISTRAL_MODEL to
    'codestral-latest' for the code-specialized model."""
    name = "mistral"
    _url = "https://api.mistral.ai/v1/chat/completions"
    _allowed_hosts = frozenset({"api.mistral.ai"})

    def __init__(self, api_key: str, model: str = "mistral-small-latest",
                 timeout: int = _TIMEOUT):
        super().__init__(api_key, model, timeout)


class OllamaProvider(OpenAIProvider):
    """Ollama -- models running LOCALLY on your own machine: no key, no rate
    limit, fully private, and it never 429s. Needs `ollama serve` running with
    the model pulled (`ollama pull llama3.2`). OLLAMA_MODEL picks it; OLLAMA_HOST
    relocates the server. Local generation is slower, so it gets a longer timeout
    and sits last in the chain -- the backstop that always answers."""
    name = "ollama"

    def __init__(self, model: str = "llama3.2",
                 host: str = "http://localhost:11434", timeout: int = 120,
                 allow_remote: bool = False):
        host = _validate_ollama_host(host, allow_remote=allow_remote)
        super().__init__("ollama", model, timeout)   # key unused; the Bearer is harmless
        self._url = host.rstrip("/") + "/v1/chat/completions"
        parsed = urllib.parse.urlsplit(host)
        self._allowed_hosts = frozenset({parsed.hostname.lower()})
        self._allow_http = parsed.scheme == "http"


def strip_fences(text: str | GenerationResult) -> str:
    """Pull code from a fence, rejecting non-content generation states."""
    if isinstance(text, GenerationResult):
        text = text.require_content()
    if not isinstance(text, str):
        raise TypeError("model output must be text")
    m = re.search(r"```(?:\w+)?\n(.*?)```", text, re.S)
    return m.group(1).strip() if m else text.strip()


def _attempt_generation(provider, prompt: str) -> GenerationResult:
    """Call one provider and convert every expected outcome to typed evidence."""
    provider_name, model_name = _provider_identity(provider)
    prompt_sha256 = _sha256_text(prompt)
    try:
        raw = provider.generate(prompt)
    except ProviderError as exc:
        return GenerationResult(
            provider_name, model_name, GenerationStatus.FAILED, None,
            prompt_sha256, None, _safe_detail(exc))
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return GenerationResult(
            provider_name, model_name, GenerationStatus.ABSTAINED, None,
            prompt_sha256, None, "provider returned no content")
    if not isinstance(raw, str):
        return GenerationResult(
            provider_name, model_name, GenerationStatus.FAILED, None,
            prompt_sha256, None, "provider returned non-text content")
    content = strip_fences(raw)
    if not content:
        return GenerationResult(
            provider_name, model_name, GenerationStatus.ABSTAINED, None,
            prompt_sha256, None, "provider returned an empty fenced response")
    return GenerationResult(
        provider_name, model_name, GenerationStatus.SUCCESS, content,
        prompt_sha256, _sha256_text(content))


class Brain:
    def __init__(self, providers, mode: str = "fallback", configuration_errors=()):
        self._providers = list(providers)
        self._mode = mode
        self._configuration_errors = list(configuration_errors)
        self._last_generation_results: tuple[GenerationResult, ...] = ()

    def available(self) -> bool:
        return bool(self._providers)

    def provider_names(self):
        return [p.name for p in self._providers]

    def providers(self):
        return list(self._providers)

    def configuration_errors(self):
        """Return safe configuration messages (never API-key values)."""
        return list(self._configuration_errors)

    def generate_results(self, prompt: str) -> tuple[GenerationResult, ...]:
        """Return typed attempts with provenance and no failure-content sentinel.

        Fallback mode stops at its first successful result. Compare mode records
        every provider. Expected provider errors are represented in-band as
        ``FAILED`` results so callers can distinguish evidence from content.
        """
        if not isinstance(prompt, str):
            raise TypeError("prompt must be text")
        results = []
        if not self._providers:
            results.append(GenerationResult(
                "brain", "unspecified", GenerationStatus.ABSTAINED, None,
                _sha256_text(prompt), None, "no providers configured"))
        else:
            for provider in self._providers:
                result = _attempt_generation(provider, prompt)
                results.append(result)
                if self._mode != "compare" and result.success:
                    break
        self._last_generation_results = tuple(results)
        return self._last_generation_results

    def generate_result(self, prompt: str) -> GenerationResult:
        """Return the selected typed result; use ``generate_results`` for all attempts."""
        results = self.generate_results(prompt)
        return next((result for result in results if result.success), results[-1])

    def last_generation_results(self) -> tuple[GenerationResult, ...]:
        """Return immutable provenance from the most recent generation call."""
        return self._last_generation_results

    def generation_evidence(self) -> tuple[GenerationEvidence, ...]:
        """Return content-free evidence from the most recent generation call."""
        return tuple(result.evidence for result in self._last_generation_results)

    def generate(self, prompt: str):
        """Backwards-compatible content API backed by typed generation results.

        Fallback still returns a string or raises ``ProviderError``. Compare
        still returns a provider mapping; successful values are strings, while
        failure/abstention values are falsey ``GenerationResult`` records. This
        preserves status inspection without ever turning a diagnostic into
        apparent model content.
        """
        results = self.generate_results(prompt)
        if self._mode == "compare":
            if not self._providers:
                return {}
            return {
                result.provider: result.require_content() if result.success else result
                for result in results
            }
        for result in results:
            if result.success:
                return result.require_content()
        errors = [result.error for result in results if result.failed and result.error]
        if errors:
            raise ProviderError("all providers failed: " + "; ".join(errors))
        if not self._providers:
            raise ProviderError("no providers configured")
        raise ProviderError("all providers abstained")


def from_env(mode: str = "fallback", model: str = "", exclude=()) -> Brain:
    """Build a Brain from whatever keys are in the environment.

    `model`, if given, overrides the model on every configured provider -- handy
    for a single-provider setup (e.g. just Groq running Qwen). `exclude` drops
    providers by name (e.g. exclude=("gemini",) to bench Google AI Studio).
    Keys in a `keys.env` file are loaded first (a real env var still wins).
    """
    import envfile
    envfile.load()
    providers = []
    configuration_errors = []

    def add(name, factory):
        try:
            providers.append(factory())
        except ProviderConfigurationError as exc:
            configuration_errors.append(name + ": " + str(exc))

    # Order = reliability of the free tier: the sturdy ones first, flaky Gemini
    # later, paid OpenAI last. In fallback mode a 429 on any one cascades to the
    # next, so this is the "escape Google's 429s" chain, automatic.
    groq_key = os.environ.get("GROQ_API_KEY")
    if groq_key:
        add("groq", lambda: GroqProvider(
            groq_key, os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")))
    openrouter_key = os.environ.get("OPENROUTER_API_KEY")
    if openrouter_key:
        add("openrouter", lambda: OpenRouterProvider(
            openrouter_key,
            os.environ.get("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct:free")))
    mistral_key = os.environ.get("MISTRAL_API_KEY")
    if mistral_key:
        add("mistral", lambda: MistralProvider(
            mistral_key, os.environ.get("MISTRAL_MODEL", "mistral-small-latest")))
    gemini_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if gemini_key:
        add("gemini", lambda: GeminiProvider(
            gemini_key, os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")))
    openai_key = os.environ.get("OPENAI_API_KEY")
    if openai_key:
        add("openai", lambda: OpenAIProvider(
            openai_key, os.environ.get("OPENAI_MODEL", "gpt-4o-mini")))
    # Ollama last: local, keyless, never rate-limited -- the backstop that answers
    # when every cloud tier is throttled. Enabled by naming a local model.
    ollama_model = os.environ.get("OLLAMA_MODEL")
    if ollama_model:
        allow_remote = os.environ.get("ATTESTOR_ALLOW_REMOTE_OLLAMA", "").strip().lower() in {
            "1", "true", "yes", "on"
        }
        add("ollama", lambda: OllamaProvider(
            ollama_model, os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
            allow_remote=allow_remote))
    if exclude:
        providers = [p for p in providers if p.name not in exclude]
    if model:
        try:
            checked_model = _validate_model(model)
        except ProviderConfigurationError as exc:
            configuration_errors.append("model override: " + str(exc))
            providers = []
        else:
            for provider in providers:
                provider._model = checked_model
    return Brain(providers, mode, configuration_errors)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("prompt", nargs="+", help="what to ask the model(s)")
    ap.add_argument("--compare", action="store_true",
                    help="ask every configured provider and show all answers")
    args = ap.parse_args(argv)

    brain = from_env("compare" if args.compare else "fallback")
    for error in brain.configuration_errors():
        print("configuration blocked: " + error)
    if not brain.available():
        print("no LLM configured. set GROQ_API_KEY, OPENROUTER_API_KEY, "
              "MISTRAL_API_KEY, GEMINI_API_KEY, OPENAI_API_KEY, or OLLAMA_MODEL.")
        return 1
    print("providers: " + ", ".join(brain.provider_names()))
    try:
        result = brain.generate(" ".join(args.prompt))
    except ProviderError as exc:
        print(f"all providers failed: {exc}")
        return 2
    if isinstance(result, dict):
        for name, answer in result.items():
            if isinstance(answer, GenerationResult):
                detail = (": " + answer.error) if answer.error else ""
                print(f"\n----- {name} -----\n"
                      f"[{answer.status.value}{detail}]")
            else:
                print(f"\n----- {name} -----\n{answer}")
    else:
        print("\n" + result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
