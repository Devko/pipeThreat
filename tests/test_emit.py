"""Tests for the SARIF + PR-comment emitters."""

from __future__ import annotations

import json

from threat_delta.emit import build_comment, build_sarif, write_outputs
from threat_delta.models import (
    Confidence,
    Delta,
    DeltaType,
    ProposedBaselineUpdate,
    Severity,
    Stride,
)


def _delta(
    *,
    delta_id: str = "d1",
    type: DeltaType = DeltaType.NEW_ENTRY_POINT,
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.MEDIUM,
    affected_elements=None,
    stride=None,
    contradicts_assumption=None,
    description: str = "A new entry point was added.",
    recommended_action: str = "Review the new entry point.",
    requires_human_review: bool = False,
    evidence=None,
    proposed_baseline_update=None,
    low_confidence: bool = False,
) -> Delta:
    return Delta(
        delta_id=delta_id,
        pr="PR-1",
        type=type,
        affected_elements=affected_elements or ["component:api"],
        severity=severity,
        confidence=confidence,
        description=description,
        recommended_action=recommended_action,
        requires_human_review=requires_human_review,
        stride=stride or [Stride.ELEVATION_OF_PRIVILEGE],
        contradicts_assumption=contradicts_assumption,
        evidence=evidence or {},
        proposed_baseline_update=proposed_baseline_update,
        low_confidence=low_confidence,
    )


# --------------------------------------------------------------------------- #
# build_sarif
# --------------------------------------------------------------------------- #

def test_sarif_version_and_schema():
    log = build_sarif([_delta()])
    assert log["version"] == "2.1.0"
    assert "$schema" in log


def test_sarif_one_result_per_delta():
    deltas = [_delta(delta_id="a"), _delta(delta_id="b", type=DeltaType.CONTROL_CHANGE)]
    log = build_sarif(deltas)
    assert len(log["runs"][0]["results"]) == 2


def test_sarif_level_never_error():
    deltas = [
        _delta(delta_id="h", severity=Severity.HIGH),
        _delta(delta_id="m", severity=Severity.MEDIUM, type=DeltaType.CONTROL_CHANGE),
        _delta(delta_id="l", severity=Severity.LOW, type=DeltaType.UNTRACKED_PATH),
    ]
    log = build_sarif(deltas)
    levels = {r["ruleId"]: r["level"] for r in log["runs"][0]["results"]}
    assert levels[DeltaType.NEW_ENTRY_POINT.value] == "warning"
    assert levels[DeltaType.CONTROL_CHANGE.value] == "warning"
    assert levels[DeltaType.UNTRACKED_PATH.value] == "note"
    for r in log["runs"][0]["results"]:
        assert r["level"] != "error"


def test_sarif_rules_deduped_by_type():
    deltas = [
        _delta(delta_id="a", type=DeltaType.NEW_ENTRY_POINT),
        _delta(delta_id="b", type=DeltaType.NEW_ENTRY_POINT),
        _delta(delta_id="c", type=DeltaType.CONTROL_CHANGE),
    ]
    log = build_sarif(deltas)
    rules = log["runs"][0]["results"]  # noqa: F841
    rule_ids = [r["id"] for r in log["runs"][0]["tool"]["driver"]["rules"]]
    assert rule_ids == [DeltaType.NEW_ENTRY_POINT.value, DeltaType.CONTROL_CHANGE.value]


def test_sarif_locations_reflect_evidence_files():
    delta = _delta(evidence={"files": ["src/api.py", "src/auth.py"]})
    log = build_sarif([delta])
    locs = log["runs"][0]["results"][0]["locations"]
    uris = [loc["physicalLocation"]["artifactLocation"]["uri"] for loc in locs]
    assert uris == ["src/api.py", "src/auth.py"]


def test_sarif_properties_and_fingerprints():
    upd = ProposedBaselineUpdate(kind="component", target="api", change="add entry point")
    delta = _delta(
        delta_id="fp-1",
        contradicts_assumption="A1",
        proposed_baseline_update=upd,
        low_confidence=True,
    )
    result = build_sarif([delta])["runs"][0]["results"][0]
    props = result["properties"]
    assert props["severity"] == "high"
    assert props["confidence"] == "medium"
    assert props["stride"] == [Stride.ELEVATION_OF_PRIVILEGE.value]
    assert props["contradicts_assumption"] == "A1"
    assert props["recommended_action"] == "Review the new entry point."
    assert props["affected_elements"] == ["component:api"]
    assert props["proposed_baseline_update"] == upd.to_dict()
    assert props["low_confidence"] is True
    assert result["partialFingerprints"]["deltaId"] == "fp-1"


def test_sarif_json_serializable():
    log = build_sarif([_delta(evidence={"files": ["x.py"]})])
    round_trip = json.loads(json.dumps(log))
    assert round_trip["version"] == "2.1.0"


def test_sarif_empty():
    log = build_sarif([])
    assert log["runs"][0]["results"] == []
    assert log["runs"][0]["tool"]["driver"]["rules"] == []


# --------------------------------------------------------------------------- #
# build_comment
# --------------------------------------------------------------------------- #

def test_comment_empty():
    text = build_comment([])
    assert "No threat-model deltas detected." in text


def test_comment_advisory_header():
    text = build_comment([_delta()])
    assert "advisory" in text.lower()
    assert "non-blocking" in text.lower()


def test_comment_groups_by_severity():
    deltas = [
        _delta(delta_id="h", severity=Severity.HIGH),
        _delta(delta_id="m", severity=Severity.MEDIUM, type=DeltaType.CONTROL_CHANGE),
        _delta(delta_id="l", severity=Severity.LOW, type=DeltaType.UNTRACKED_PATH),
    ]
    text = build_comment(deltas)
    assert "### High" in text
    assert "### Medium" in text
    assert "### Low" in text
    # High section appears before Medium which appears before Low.
    assert text.index("### High") < text.index("### Medium") < text.index("### Low")


def test_comment_omits_empty_sections():
    text = build_comment([_delta(severity=Severity.HIGH)])
    assert "### High" in text
    assert "### Medium" not in text
    assert "### Low" not in text


def test_comment_shows_stride_assumption_and_action():
    delta = _delta(
        stride=[Stride.SPOOFING, Stride.TAMPERING],
        contradicts_assumption="A7",
        recommended_action="Add authn to the new endpoint.",
    )
    text = build_comment([delta])
    assert Stride.SPOOFING.value in text
    assert Stride.TAMPERING.value in text
    assert "A7" in text
    assert "Add authn to the new endpoint." in text


def test_comment_low_confidence_note():
    text = build_comment([_delta(confidence=Confidence.LOW, low_confidence=True)])
    assert "low confidence" in text.lower()


def test_comment_proposed_baseline_update():
    upd = ProposedBaselineUpdate(kind="dataflow", target="df-1", change="record new flow")
    text = build_comment([_delta(proposed_baseline_update=upd)])
    assert "Proposed baseline update" in text
    assert "record new flow" in text


def test_comment_needs_review_label_hook():
    deltas = [_delta(severity=Severity.HIGH, requires_human_review=True)]
    text = build_comment(deltas)
    assert "needs human review" in text.lower()
    assert "security/needs-review" in text


def test_comment_consolidates_parallel_assumption_violations():
    # Several assumption violations on one component collapse into a single
    # root-caused block instead of N near-identical bullets.
    comp = _delta(
        delta_id="c",
        type=DeltaType.NEW_ENTRY_POINT,
        affected_elements=["comp.api"],
    )
    comp.change_signals = ["new entry point", "control change"]
    av = [
        _delta(
            delta_id=f"a{i}",
            type=DeltaType.ASSUMPTION_VIOLATION,
            affected_elements=["comp.api"],
            contradicts_assumption=aid,
            requires_human_review=True,
            description=f"Change weakens or violates assumption '{aid}': reason {i}",
        )
        for i, aid in enumerate(["asm.one", "asm.two", "asm.three"])
    ]
    text = build_comment([comp, *av])
    # One consolidated block, not three separate assumption bullets.
    assert "contradicted assumptions (3)" in text
    assert text.count("**contradicted assumptions") == 1
    assert "Root cause: new entry point on `comp.api`" in text
    # All three assumptions are still listed as consequences.
    for aid in ("asm.one", "asm.two", "asm.three"):
        assert aid in text


def test_comment_single_assumption_not_consolidated():
    # A lone assumption violation renders as a normal bullet (no block overhead).
    av = _delta(
        type=DeltaType.ASSUMPTION_VIOLATION,
        affected_elements=["comp.api"],
        contradicts_assumption="asm.solo",
        description="Change weakens or violates assumption 'asm.solo': lonely",
    )
    text = build_comment([av])
    assert "contradicted assumptions (" not in text
    assert "asm.solo" in text


def test_comment_footer_counts():
    deltas = [
        _delta(delta_id="h", severity=Severity.HIGH),
        _delta(delta_id="l", severity=Severity.LOW, type=DeltaType.UNTRACKED_PATH),
    ]
    text = build_comment(deltas)
    assert "2 delta(s)" in text


# --------------------------------------------------------------------------- #
# write_outputs
# --------------------------------------------------------------------------- #

def test_write_outputs(tmp_path):
    sarif_path = tmp_path / "out.sarif"
    comment_path = tmp_path / "comment.md"
    write_outputs([_delta()], str(sarif_path), str(comment_path))
    log = json.loads(sarif_path.read_text())
    assert log["version"] == "2.1.0"
    assert "advisory" in comment_path.read_text().lower()
