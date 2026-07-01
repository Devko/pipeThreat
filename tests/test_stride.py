"""Tests for Stage 3 (threat_delta.stride)."""

from __future__ import annotations

from threat_delta.llm import ScriptedLLMClient
from threat_delta.models import Component, Flags, Hunk, Stride
from threat_delta.stride import stride_deltas


def _comp() -> Component:
    return Component(id="user_service", name="User Service", trust_zone="internal")


def test_parses_deltas_and_maps_enum():
    llm = ScriptedLLMClient(
        responses={
            "user_service": {
                "deltas": [
                    {"stride": "Tampering", "reason": "unvalidated input to db"},
                    {"stride": "InformationDisclosure", "reason": "pii logged"},
                ]
            }
        }
    )
    out = stride_deltas(_comp(), [Hunk(content="x")], Flags(new_entry_point=True), llm)
    assert [d.stride for d in out] == [Stride.TAMPERING, Stride.INFORMATION_DISCLOSURE]
    assert out[0].reason == "unvalidated input to db"


def test_drops_invalid_stride_string():
    llm = ScriptedLLMClient(
        responses={
            "user_service": {
                "deltas": [
                    {"stride": "Tampering", "reason": "ok"},
                    {"stride": "NotARealCategory", "reason": "hallucinated"},
                ]
            }
        }
    )
    out = stride_deltas(_comp(), [Hunk(content="x")], Flags(control_change=True), llm)
    assert len(out) == 1
    assert out[0].stride is Stride.TAMPERING


def test_low_confidence_propagates():
    llm = ScriptedLLMClient(
        responses={
            "user_service": {
                "low_confidence": True,
                "deltas": [{"stride": "Spoofing", "reason": "r"}],
            }
        }
    )
    out = stride_deltas(_comp(), [Hunk(content="x")], Flags(new_entry_point=True), llm)
    assert out[0].low_confidence is True


def test_no_positive_flags_returns_empty_without_call():
    llm = ScriptedLLMClient(responses={"user_service": {"deltas": [{"stride": "Spoofing", "reason": "r"}]}})
    out = stride_deltas(_comp(), [Hunk(content="x")], Flags(), llm)
    assert out == []
    assert llm.calls == []


def test_oversized_hunk_truncated_in_prompt():
    big = "A" * 5000
    llm = ScriptedLLMClient(responses={"user_service": {"deltas": []}})
    stride_deltas(
        _comp(),
        [Hunk(content=big)],
        Flags(new_entry_point=True),
        llm,
        max_hunk_chars=100,
    )
    assert len(llm.calls) == 1
    sent = llm.calls[0]
    assert "... [truncated]" in sent
    # only the first 100 chars of the body reached the model
    assert "A" * 100 in sent
    assert "A" * 101 not in sent


def test_non_list_deltas_returns_empty():
    llm = ScriptedLLMClient(responses={"user_service": {"deltas": "oops"}})
    out = stride_deltas(_comp(), [Hunk(content="x")], Flags(new_entry_point=True), llm)
    assert out == []


def test_coerce_stride_tolerates_formatting_variants():
    from threat_delta.stride import coerce_stride
    from threat_delta.models import Stride

    # Exact, spaced, cased, punctuated, synonym, and single-letter forms.
    assert coerce_stride("InformationDisclosure") == Stride.INFORMATION_DISCLOSURE
    assert coerce_stride("Information Disclosure") == Stride.INFORMATION_DISCLOSURE
    assert coerce_stride("information_disclosure") == Stride.INFORMATION_DISCLOSURE
    assert coerce_stride("Elevation of Privilege") == Stride.ELEVATION_OF_PRIVILEGE
    assert coerce_stride("privilege escalation") == Stride.ELEVATION_OF_PRIVILEGE
    assert coerce_stride("DoS") == Stride.DENIAL_OF_SERVICE
    assert coerce_stride("I") == Stride.INFORMATION_DISCLOSURE
    # Unknown still rejected.
    assert coerce_stride("Banana") is None
    assert coerce_stride("") is None
    assert coerce_stride(None) is None


def test_stride_deltas_accepts_spaced_labels():
    from threat_delta.llm import ScriptedLLMClient
    from threat_delta.models import Component, Flags, Hunk, Stride
    from threat_delta.stride import stride_deltas

    comp = Component(id="comp.x", name="X", trust_zone="edge", code_paths=("src/**",))
    llm = ScriptedLLMClient(
        default={"deltas": [{"stride": "Information Disclosure", "reason": "leak"}]}
    )
    out = stride_deltas(comp, [Hunk(content="+code")], Flags(new_entry_point=True), llm)
    assert [d.stride for d in out] == [Stride.INFORMATION_DISCLOSURE]
