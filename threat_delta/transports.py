"""Concrete LLM transports for the model-driven stages (pipeline step 6).

The spec targets a local ~4B model on a CPU-only runner with temperature=0 and a
*capped per-stage reasoning budget* (spec §2, §11: reasoning is ON but bounded so
an uncapped 4B does not ramble and burn CPU wall-clock). This module ships a real
transport against any OpenAI-compatible chat-completions endpoint — llama.cpp
server, Ollama's ``/v1`` shim, vLLM and LM Studio all expose this shape — using
only the Python standard library (``urllib``); no third-party dependencies.

The reasoning budget is mapped to the portable ``reasoning_effort`` hint plus an
``extra_body`` escape hatch, because exact reasoning-API support varies by server
and model. The hard caps that *always* apply regardless of server support are
``temperature`` and ``max_tokens``.

HTTP is injected via the ``http_post`` callable so the whole transport is fully
testable offline, with no network.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Callable

from .llm import LLMClient, LLMConfig, LLMError, ScriptedLLMClient


# Signature of the injectable transport function.
HttpPost = Callable[[str, dict, bytes, float], bytes]


def _urllib_post(url: str, headers: dict, body: bytes, timeout: float) -> bytes:
    """POST ``body`` to ``url`` with ``headers`` and return the raw response bytes.

    The real, network-backed implementation of the :data:`HttpPost` contract,
    built on :mod:`urllib`. ``urllib.error.URLError`` / ``HTTPError`` are allowed
    to propagate so the caller (:meth:`OpenAICompatibleClient._raw_complete`) can
    wrap them in :class:`LLMError`. ``timeout`` is honored.
    """
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _read_http_error(exc: urllib.error.HTTPError) -> str:
    """Best-effort read of an HTTPError's response body for diagnostics."""
    try:
        return exc.read().decode("utf-8", "replace").strip()
    except Exception:  # pragma: no cover - body already consumed / unreadable
        return ""


class OpenAICompatibleClient(LLMClient):
    """LLM transport for any OpenAI-compatible ``/chat/completions`` server.

    Works with llama.cpp server, Ollama's ``/v1`` shim, vLLM and LM Studio. Local
    servers usually need no auth, so a harmless placeholder bearer token is sent
    by default.
    """

    def __init__(
        self,
        *,
        base_url: str = "http://localhost:8080/v1",
        model: str | None = None,
        api_key: str | None = None,
        config: LLMConfig | None = None,
        extra_body: dict | None = None,
        http_post: HttpPost | None = None,
    ) -> None:
        super().__init__(config)
        # Strip a trailing slash so f"{base_url}/chat/completions" is well-formed.
        self.base_url = base_url.rstrip("/")
        self.model = model or self.config.model
        self.api_key = api_key
        self.extra_body = dict(extra_body) if extra_body else {}
        self.http_post: HttpPost = http_post or _urllib_post
        # Reasoning hints are best-effort: some servers/models (e.g. a
        # non-thinking gemma4:e4b on Ollama) reject `reasoning_effort` with a 400.
        # We send it by default but disable it for this client after the first
        # such rejection, then retry without it.
        self._reasoning_enabled = True

    @staticmethod
    def _reasoning_effort(budget: int) -> str:
        """Map a reasoning-token ``budget`` to a coarse ``reasoning_effort`` level."""
        if budget <= 128:
            return "low"
        if budget <= 256:
            return "medium"
        return "high"

    def _build_body(self, system: str, prompt: str, *, reasoning_budget: int) -> dict:
        body: dict = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": False,
        }
        # Bounded reasoning (spec §2/§11). The temperature and max_tokens caps
        # always apply; the reasoning hint is best-effort and its exact support
        # depends on the server/model. A budget of 0 (or a degraded client) omits
        # the hint entirely.
        if reasoning_budget > 0:
            body["reasoning_effort"] = self._reasoning_effort(reasoning_budget)
            body.update(self.extra_body)
        return body

    def _raw_complete(
        self, system: str, prompt: str, *, stage: str | None = None
    ) -> str:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key or 'sk-no-key'}",
        }
        url = f"{self.base_url}/chat/completions"

        budget = self.config.budget_for(stage) if self._reasoning_enabled else 0
        sent_reasoning = budget > 0
        payload = json.dumps(self._build_body(system, prompt, reasoning_budget=budget))

        try:
            raw = self.http_post(url, headers, payload.encode("utf-8"), self.config.timeout_s)
        except urllib.error.HTTPError as exc:
            detail = _read_http_error(exc)
            # Graceful degrade: a 400 while sending a reasoning hint usually means
            # the model doesn't support it. Disable it for this client and retry.
            if exc.code == 400 and sent_reasoning:
                self._reasoning_enabled = False
                retry = json.dumps(self._build_body(system, prompt, reasoning_budget=0))
                try:
                    raw = self.http_post(
                        url, headers, retry.encode("utf-8"), self.config.timeout_s
                    )
                except (urllib.error.HTTPError, urllib.error.URLError) as exc2:
                    extra = _read_http_error(exc2) if isinstance(exc2, urllib.error.HTTPError) else ""
                    raise LLMError(
                        f"LLM HTTP request to {url} failed after dropping reasoning: "
                        f"{exc2} {extra}".strip()
                    ) from exc2
            else:
                raise LLMError(
                    f"LLM HTTP request to {url} failed: HTTP {exc.code} {detail}".strip()
                ) from exc
        except urllib.error.URLError as exc:
            raise LLMError(f"LLM HTTP request to {url} failed: {exc}") from exc

        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            raise LLMError(f"LLM returned non-JSON HTTP response: {exc}") from exc

        try:
            message = data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(
                f"LLM response missing choices[0].message: {data!r:.200}"
            ) from exc

        content = (message.get("content") or "").strip()
        if not content:
            # Thinking models (e.g. gemma4:e4b on Ollama) can return an empty
            # `content` and put their output in a reasoning channel instead. Fall
            # back to that — parse_json_object still recovers the JSON object from
            # the surrounding chain-of-thought.
            content = (
                message.get("reasoning_content") or message.get("reasoning") or ""
            ).strip()
        if not content:
            raise LLMError(f"LLM returned empty message content: {message!r:.200}")
        return content


class OllamaClient(OpenAICompatibleClient):
    """:class:`OpenAICompatibleClient` preset for Ollama's ``/v1`` endpoint.

    Defaults to Ollama's local port and a Gemma-class model.
    """

    def __init__(
        self,
        *,
        base_url: str = "http://localhost:11434/v1",
        model: str | None = None,
        api_key: str | None = None,
        config: LLMConfig | None = None,
        extra_body: dict | None = None,
        http_post: HttpPost | None = None,
    ) -> None:
        super().__init__(
            base_url=base_url,
            model=model or "gemma4:e4b",
            api_key=api_key,
            config=config,
            extra_body=extra_body,
            http_post=http_post,
        )


def build_client(
    kind: str = "stub",
    *,
    base_url: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
    config: LLMConfig | None = None,
) -> LLMClient:
    """Construct an :class:`LLMClient` of the given ``kind``.

    ``"stub"`` -> :class:`ScriptedLLMClient` (offline default, empty responses);
    ``"openai"`` -> :class:`OpenAICompatibleClient`; ``"ollama"`` ->
    :class:`OllamaClient`. Raises :class:`ValueError` on an unknown ``kind``.
    """
    if kind == "stub":
        return ScriptedLLMClient(default={}, config=config)
    if kind == "openai":
        kwargs: dict = {"model": model, "api_key": api_key, "config": config}
        if base_url is not None:
            kwargs["base_url"] = base_url
        return OpenAICompatibleClient(**kwargs)
    if kind == "ollama":
        kwargs = {"model": model, "api_key": api_key, "config": config}
        if base_url is not None:
            kwargs["base_url"] = base_url
        return OllamaClient(**kwargs)
    raise ValueError(f"unknown client kind: {kind!r}")
