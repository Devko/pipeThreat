"""Tests for the OpenAI-compatible LLM transports (offline, via injected POST)."""

from __future__ import annotations

import json
import urllib.error

import pytest

from threat_delta.llm import LLMConfig, LLMError
from threat_delta.transports import (
    OllamaClient,
    OpenAICompatibleClient,
    build_client,
)


def _canned(content: str = '{"new_entry_point": true}') -> bytes:
    return json.dumps({"choices": [{"message": {"content": content}}]}).encode("utf-8")


class RecordingPost:
    """Fake http_post that records the call and returns a canned response."""

    def __init__(self, response: bytes | None = None):
        self.response = response if response is not None else _canned()
        self.url: str | None = None
        self.headers: dict | None = None
        self.body: bytes | None = None
        self.timeout: float | None = None

    def __call__(self, url, headers, body, timeout):
        self.url = url
        self.headers = headers
        self.body = body
        self.timeout = timeout
        return self.response

    def sent_json(self) -> dict:
        assert self.body is not None
        return json.loads(self.body.decode("utf-8"))


def test_raw_complete_returns_inner_content():
    post = RecordingPost()
    client = OpenAICompatibleClient(http_post=post)
    out = client._raw_complete("sys", "hello", stage="classify")
    assert out == '{"new_entry_point": true}'


def test_complete_json_parses_dict():
    post = RecordingPost()
    client = OpenAICompatibleClient(http_post=post)
    result = client.complete_json("hello", stage="classify")
    assert result == {"new_entry_point": True}


def test_request_body_shape():
    post = RecordingPost()
    client = OpenAICompatibleClient(http_post=post, model="gemma-4-e4b")
    client._raw_complete("the-system", "the-prompt", stage="classify")
    body = post.sent_json()
    assert body["model"] == "gemma-4-e4b"
    assert body["messages"] == [
        {"role": "system", "content": "the-system"},
        {"role": "user", "content": "the-prompt"},
    ]
    assert body["temperature"] == 0.0
    assert body["max_tokens"] == 512
    assert body["stream"] is False


def test_url_and_headers():
    post = RecordingPost()
    client = OpenAICompatibleClient(http_post=post)
    client._raw_complete("s", "p", stage="classify")
    assert post.url == "http://localhost:8080/v1/chat/completions"
    assert post.headers["Content-Type"] == "application/json"
    assert post.headers["Authorization"] == "Bearer sk-no-key"


@pytest.mark.parametrize(
    "stage,effort",
    [("classify", "low"), ("stride", "medium"), ("assumptions", "high")],
)
def test_reasoning_effort_levels(stage, effort):
    post = RecordingPost()
    client = OpenAICompatibleClient(http_post=post)
    client._raw_complete("s", "p", stage=stage)
    assert post.sent_json()["reasoning_effort"] == effort


def test_reasoning_disabled_omits_hint():
    post = RecordingPost()
    client = OpenAICompatibleClient(http_post=post, config=LLMConfig(reasoning=False))
    client._raw_complete("s", "p", stage="stride")
    assert "reasoning_effort" not in post.sent_json()


def test_extra_body_merged_when_reasoning_on():
    post = RecordingPost()
    client = OpenAICompatibleClient(
        http_post=post, extra_body={"think": True}
    )
    client._raw_complete("s", "p", stage="stride")
    assert post.sent_json()["think"] is True


def test_urlerror_wrapped_in_llmerror():
    def boom(url, headers, body, timeout):
        raise urllib.error.URLError("connection refused")

    client = OpenAICompatibleClient(http_post=boom)
    with pytest.raises(LLMError):
        client._raw_complete("s", "p", stage="classify")


def test_missing_choices_raises_llmerror():
    post = RecordingPost(response=json.dumps({"object": "error"}).encode("utf-8"))
    client = OpenAICompatibleClient(http_post=post)
    with pytest.raises(LLMError):
        client._raw_complete("s", "p", stage="classify")


def test_empty_content_raises_llmerror():
    post = RecordingPost(response=_canned(""))
    client = OpenAICompatibleClient(http_post=post)
    with pytest.raises(LLMError):
        client._raw_complete("s", "p", stage="classify")


def test_build_client_ollama():
    client = build_client("ollama")
    assert isinstance(client, OllamaClient)
    assert "11434" in client.base_url
    assert client.model == "gemma3:4b"


def test_build_client_stub_default():
    from threat_delta.llm import ScriptedLLMClient

    client = build_client("stub")
    assert isinstance(client, ScriptedLLMClient)


def test_build_client_openai_custom():
    client = build_client("openai", base_url="http://host:9000/v1", model="m")
    assert isinstance(client, OpenAICompatibleClient)
    assert client.base_url == "http://host:9000/v1"
    assert client.model == "m"


def test_build_client_bogus():
    with pytest.raises(ValueError):
        build_client("bogus")
