"""Tests for the detection/output improvements.

Covers self-consistency voting (6b/6c), evidence-based confidence, region-level
SARIF locations, and incremental ``--since`` subtraction.
"""

from __future__ import annotations

import json

from threat_delta.baseline import parse_baseline
from threat_delta.classify import classify_change
from threat_delta.diff import parse_unified_diff
from threat_delta.llm import LLMClient, LLMConfig, ScriptedLLMClient
from threat_delta.models import Confidence, DeltaType, Diff, Slice
from threat_delta.severity import confidence_from_evidence
from threat_delta.step import run_step


class SequenceLLMClient(LLMClient):
    """Returns queued raw JSON strings in order — one per ``_raw_complete`` call.

    Lets a test simulate a real model that gives *different* answers across
    self-consistency samples (the scripted client is deterministic by design).
    """

    def __init__(self, payloads, config=None):
        super().__init__(config)
        self._queue = [json.dumps(p) for p in payloads]
        self._i = 0

    def _raw_complete(self, system, prompt, *, stage=None, temperature=None):
        payload = self._queue[min(self._i, len(self._queue) - 1)]
        self._i += 1
        return payload


def _slice() -> Slice:
    return Slice()


# --------------------------------------------------------------------------- #
# Voting
# --------------------------------------------------------------------------- #

def test_classify_majority_keeps_agreed_flag():
    # 3 votes: entry_point {true, true, false} -> majority true; data_flow all
    # false. The split on entry_point marks low_confidence.
    client = SequenceLLMClient(
        [
            {"new_entry_point": True, "new_data_flow": False},
            {"new_entry_point": True, "new_data_flow": False},
            {"new_entry_point": False, "new_data_flow": False},
        ],
        config=LLMConfig(votes=3),
    )
    flags = classify_change(_slice(), Diff(), [], client)
    assert flags.new_entry_point is True
    assert flags.new_data_flow is False
    assert flags.low_confidence is True  # the 2:1 split is a weak signal


def test_classify_minority_flag_dropped():
    client = SequenceLLMClient(
        [
            {"control_change": True},
            {"control_change": False},
            {"control_change": False},
        ],
        config=LLMConfig(votes=3),
    )
    flags = classify_change(_slice(), Diff(), [], client)
    assert flags.control_change is False  # 1:2 -> not a majority


# --------------------------------------------------------------------------- #
# Confidence
# --------------------------------------------------------------------------- #

def test_combined_baseline_update_kind_matches_representative_type():
    # Regression: the proposed-update kind must match the delta's representative
    # (highest-severity) signal, not merely the first present flag.
    from threat_delta.models import Component, DeltaType
    from threat_delta.pipeline import _combined_baseline_update

    comp = Component(id="comp.x", name="X", trust_zone="edge")
    # control_change is first in flag order, but asset_exposure is the rep type.
    upd = _combined_baseline_update(
        comp,
        [DeltaType.CONTROL_CHANGE, DeltaType.ASSET_EXPOSURE],
        [],
        DeltaType.ASSET_EXPOSURE,
    )
    assert upd.kind == "component_asset_handling_changed"
    assert upd.target == "comp.x"


def test_confidence_rules():
    assert confidence_from_evidence(low_confidence=False, corroborated=True) == Confidence.HIGH
    assert confidence_from_evidence(low_confidence=False, corroborated=False) == Confidence.MEDIUM
    assert confidence_from_evidence(low_confidence=True, corroborated=True) == Confidence.LOW
    # A split vote (agreement below the threshold) is LOW even if corroborated.
    assert (
        confidence_from_evidence(low_confidence=False, corroborated=True, agreement=0.5)
        == Confidence.LOW
    )


# --------------------------------------------------------------------------- #
# Region-level SARIF + incremental subtraction (end to end)
# --------------------------------------------------------------------------- #

_BASELINE = {
    "system": {"name": "svc", "version": "1"},
    "assets": [{"id": "asset.pii", "name": "PII", "sensitivity": "high"}],
    "trust_boundaries": [],
    "components": [
        {"id": "comp.api", "name": "API", "trust_zone": "edge",
         "code_paths": ["src/api/**"], "handles_assets": ["asset.pii"],
         "entry_points": ["http"]},
    ],
    "assumptions": [{"id": "asm.authn", "statement": "All requests authenticated."}],
}

_DIFF = (
    "diff --git a/src/api/handler.py b/src/api/handler.py\n"
    "new file mode 100644\n"
    "--- /dev/null\n+++ b/src/api/handler.py\n"
    "@@ -0,0 +1,3 @@\n"
    "+def handler(req):\n"
    "+    return read(req.path)\n"
)


def _llm():
    return ScriptedLLMClient(
        responses={
            "is it plausibly introduced": {"new_entry_point": True},
            "asm.authn": {"assumption_id": "asm.authn", "violated": True, "reason": "no token"},
        },
        default={},
    )


def test_region_level_sarif_anchors_to_changed_line():
    result = run_step(baseline=parse_baseline(_BASELINE), diff=parse_unified_diff(_DIFF, pr="1"), pr="1", llm=_llm())
    component = next(d for d in result.deltas if d.type == DeltaType.NEW_ENTRY_POINT)
    region = component.evidence["regions"]["src/api/handler.py"]
    assert region == 1

    loc = result.sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    # Some result carries the region; find the one for the component delta file.
    all_locs = [
        l["physicalLocation"]
        for r in result.sarif["runs"][0]["results"]
        for l in r["locations"]
    ]
    regioned = [p for p in all_locs if "region" in p]
    assert any(p["region"]["startLine"] == 1 for p in regioned)


def test_since_suppresses_unchanged_deltas():
    first = run_step(baseline=parse_baseline(_BASELINE), diff=parse_unified_diff(_DIFF, pr="1"), pr="1", llm=_llm())
    assert first.deltas  # something to subtract

    # Re-run with the first run as the prior -> everything is unchanged -> empty.
    again = run_step(
        baseline=parse_baseline(_BASELINE), diff=parse_unified_diff(_DIFF, pr="1"), pr="1", llm=_llm(), prior=first.to_dict()
    )
    assert again.deltas == []


def test_since_keeps_new_deltas():
    # Prior contains only the assumption violation; the component delta is new.
    prior = {
        "pr": "1",
        "deltas": [
            {
                "type": "assumption_violation",
                "affected_elements": ["comp.api"],
                "contradicts_assumption": "asm.authn",
                "evidence": {"files": ["src/api/handler.py"]},
            }
        ],
    }
    result = run_step(baseline=parse_baseline(_BASELINE), diff=parse_unified_diff(_DIFF, pr="1"), pr="1", llm=_llm(), prior=prior)
    types = {d.type for d in result.deltas}
    assert DeltaType.NEW_ENTRY_POINT in types
    assert DeltaType.ASSUMPTION_VIOLATION not in types  # already reported
