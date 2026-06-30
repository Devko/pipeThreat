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
    client = OpenAICompatibleClient(http_post=post, model="gemma4:e4b")
    client._raw_complete("the-system", "the-prompt", stage="classify")
    body = post.sent_json()
    assert body["model"] == "gemma4:e4b"
    assert body["messages"] == [
        {"role": "system", "content": "the-system"},
        {"role": "user", "content": "the-prompt"},
    ]
    assert body["temperature"] == 0.0
    assert body["max_tokens"] == 1536
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
    assert client.model == "gemma4:e2b"


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


def test_reasoning_400_degrades_and_retries():
    """A 400 while sending reasoning_effort disables it and retries without it
    (mirrors gemma4:e4b on Ollama rejecting the hint)."""
    import io
    import json as _json
    import urllib.error

    from threat_delta.transports import OpenAICompatibleClient

    bodies = []

    def fake_post(url, headers, body, timeout):
        payload = _json.loads(body)
        bodies.append(payload)
        if "reasoning_effort" in payload:
            raise urllib.error.HTTPError(
                url, 400, "Bad Request", {}, io.BytesIO(b'{"error":"model does not support reasoning"}')
            )
        return _json.dumps({"choices": [{"message": {"content": '{"ok": true}'}}]}).encode()

    client = OpenAICompatibleClient(http_post=fake_post)
    out = client.complete_json("hello", stage="assumptions")
    assert out == {"ok": True}
    # First attempt carried the hint (rejected); retry dropped it.
    assert "reasoning_effort" in bodies[0]
    assert "reasoning_effort" not in bodies[1]
    # The client stays degraded, so the next call skips reasoning entirely.
    client.complete_json("again", stage="assumptions")
    assert "reasoning_effort" not in bodies[2]


def test_non_reasoning_400_surfaces_body():
    """A 400 that is not about reasoning surfaces the server's error body."""
    import io
    import urllib.error

    import pytest

    from threat_delta.llm import LLMError
    from threat_delta.transports import OpenAICompatibleClient

    def fake_post(url, headers, body, timeout):
        raise urllib.error.HTTPError(
            url, 400, "Bad Request", {}, io.BytesIO(b'{"error":"bad model name"}')
        )

    # reasoning disabled so the 400 is not retried — the body must be surfaced.
    from threat_delta.llm import LLMConfig

    client = OpenAICompatibleClient(http_post=fake_post, config=LLMConfig(reasoning=False))
    with pytest.raises(LLMError, match="bad model name"):
        client.complete_json("hi", stage="classify")


def test_empty_content_falls_back_to_reasoning_channel():
    """A thinking model (gemma4:e4b) may return empty `content` and put the
    answer in a reasoning channel — we must still recover the JSON."""
    import json as _json

    from threat_delta.transports import OpenAICompatibleClient

    def fake_post(url, headers, body, timeout):
        return _json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "content": "",
                            "reasoning": 'Let me think... {"new_entry_point": true}',
                        }
                    }
                ]
            }
        ).encode()

    client = OpenAICompatibleClient(http_post=fake_post)
    assert client.complete_json("hi", stage="classify") == {"new_entry_point": True}


def test_truly_empty_message_errors():
    import json as _json

    import pytest

    from threat_delta.llm import LLMError
    from threat_delta.transports import OpenAICompatibleClient

    def fake_post(url, headers, body, timeout):
        return _json.dumps({"choices": [{"message": {"content": ""}}]}).encode()

    client = OpenAICompatibleClient(http_post=fake_post)
    with pytest.raises(LLMError, match="empty message content"):
        client.complete_json("hi", stage="classify")


def _ollama_canned(content: str = '{"new_entry_point": true}') -> bytes:
    return json.dumps({"message": {"role": "assistant", "content": content}}).encode()


def test_ollama_uses_native_api_and_toggles_think():
    """OllamaClient hits the native /api/chat endpoint and sets think from the
    reasoning config (off by default for fast, direct answers on CPU)."""
    from threat_delta.llm import LLMConfig
    from threat_delta.transports import OllamaClient

    off = RecordingPost(response=_ollama_canned())
    c_off = OllamaClient(http_post=off, config=LLMConfig(reasoning=False))
    out = c_off._raw_complete("s", "p", stage="classify")
    assert out == '{"new_entry_point": true}'
    assert off.url == "http://localhost:11434/api/chat"  # native, not /v1
    body_off = off.sent_json()
    assert body_off["think"] is False
    assert body_off["options"]["temperature"] == 0.0
    assert "reasoning_effort" not in body_off

    on = RecordingPost(response=_ollama_canned())
    c_on = OllamaClient(http_post=on, config=LLMConfig(reasoning=True))
    c_on._raw_complete("s", "p", stage="classify")
    assert on.sent_json()["think"] is True


def test_ollama_complete_json_parses_native_response():
    from threat_delta.transports import OllamaClient

    client = OllamaClient(http_post=RecordingPost(response=_ollama_canned()))
    assert client.complete_json("hi", stage="classify") == {"new_entry_point": True}


def test_parser_recovers_answer_from_chain_of_thought():
    """parse_json_object picks the keyed/last object out of thinking prose."""
    from threat_delta.llm import parse_json_object

    cot = (
        'Thinking... maybe {"stride":"x"} is an example. '
        'Final: {"deltas":[{"stride":"InformationDisclosure","reason":"leak"}]}'
    )
    out = parse_json_object(cot, prefer_keys=("deltas",))
    assert out["deltas"][0]["stride"] == "InformationDisclosure"
