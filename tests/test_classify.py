"""Tests for stage 6b (threat_delta.classify)."""

from __future__ import annotations

from threat_delta.classify import classify_change
from threat_delta.llm import ScriptedLLMClient
from threat_delta.models import (
    ChangedFile,
    Component,
    Diff,
    FileAnnotation,
    Hunk,
    Slice,
)


def _slice() -> Slice:
    return Slice(
        components=[Component(id="user_service", name="User Service", trust_zone="internal")]
    )


def _diff() -> Diff:
    return Diff(pr="PR-1", files=[ChangedFile(path="a.py", hunks=[Hunk(header="@@", content="x")])])


def _ann() -> list[FileAnnotation]:
    return [FileAnnotation(path="a.py", entry_points=["e"])]


def test_maps_flags_true():
    llm = ScriptedLLMClient(
        responses={
            "user_service": {
                "new_entry_point": True,
                "new_data_flow": False,
                "trust_boundary_crossing": True,
                "asset_handling_change": False,
                "control_change": True,
            }
        }
    )
    flags = classify_change(_slice(), _diff(), _ann(), llm)
    assert flags.new_entry_point is True
    assert flags.new_data_flow is False
    assert flags.trust_boundary_crossing is True
    assert flags.asset_handling_change is False
    assert flags.control_change is True
    assert flags.low_confidence is False
    assert flags.any_positive is True


def test_missing_keys_default_false():
    llm = ScriptedLLMClient(responses={"user_service": {"new_entry_point": True}})
    flags = classify_change(_slice(), _diff(), _ann(), llm)
    assert flags.new_entry_point is True
    assert flags.new_data_flow is False
    assert flags.control_change is False


def test_low_confidence_honored():
    llm = ScriptedLLMClient(
        responses={"user_service": {"new_entry_point": False, "low_confidence": True}}
    )
    flags = classify_change(_slice(), _diff(), _ann(), llm)
    assert flags.low_confidence is True
    assert flags.any_positive is False


def test_truthy_strings_coerced():
    llm = ScriptedLLMClient(
        responses={"user_service": {"new_entry_point": "true", "new_data_flow": "no"}}
    )
    flags = classify_change(_slice(), _diff(), _ann(), llm)
    assert flags.new_entry_point is True
    assert flags.new_data_flow is False
