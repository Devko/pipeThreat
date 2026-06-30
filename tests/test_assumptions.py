"""Tests for stage 6d (threat_delta.assumptions)."""

from __future__ import annotations

from threat_delta.assumptions import assumption_check
from threat_delta.llm import ScriptedLLMClient
from threat_delta.models import Assumption, ChangedFile, Diff, FileAnnotation, Hunk


def _diff() -> Diff:
    return Diff(pr="PR-1", files=[ChangedFile(path="a.py", hunks=[Hunk(header="@@", content="x")])])


def _ann() -> list[FileAnnotation]:
    return [FileAnnotation(path="a.py", sinks=["db"])]


def _assumptions() -> list[Assumption]:
    return [
        Assumption(id="a1", statement="Input is validated at the edge."),
        Assumption(id="a2", statement="TLS terminates at the gateway."),
    ]


def test_empty_assumptions_returns_empty_without_call():
    llm = ScriptedLLMClient(responses={"a1": {"violations": [{"assumption_id": "a1", "violated": True, "reason": "r"}]}})
    out = assumption_check([], _diff(), _ann(), llm)
    assert out == []
    assert llm.calls == []


def test_filters_violated_true_only():
    llm = ScriptedLLMClient(
        responses={
            "a1": {
                "violations": [
                    {"assumption_id": "a1", "violated": True, "reason": "edge bypass"},
                    {"assumption_id": "a2", "violated": False, "reason": "fine"},
                ]
            }
        }
    )
    out = assumption_check(_assumptions(), _diff(), _ann(), llm)
    assert len(out) == 1
    assert out[0].assumption_id == "a1"
    assert out[0].violated is True
    assert out[0].reason == "edge bypass"


def test_drops_unknown_assumption_id():
    llm = ScriptedLLMClient(
        responses={
            "a1": {
                "violations": [
                    {"assumption_id": "a1", "violated": True, "reason": "real"},
                    {"assumption_id": "ghost", "violated": True, "reason": "hallucinated"},
                ]
            }
        }
    )
    out = assumption_check(_assumptions(), _diff(), _ann(), llm)
    assert [v.assumption_id for v in out] == ["a1"]


def test_low_confidence_propagates():
    llm = ScriptedLLMClient(
        responses={
            "a1": {
                "low_confidence": True,
                "violations": [{"assumption_id": "a1", "violated": True, "reason": "r"}],
            }
        }
    )
    out = assumption_check(_assumptions(), _diff(), _ann(), llm)
    assert out[0].low_confidence is True


def test_truthy_string_violated_coerced():
    llm = ScriptedLLMClient(
        responses={"a1": {"violations": [{"assumption_id": "a2", "violated": "true", "reason": "r"}]}}
    )
    out = assumption_check(_assumptions(), _diff(), _ann(), llm)
    assert [v.assumption_id for v in out] == ["a2"]
