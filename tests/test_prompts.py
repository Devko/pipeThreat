"""Tests for the Stage 2/3/4 prompt builders (threat_delta.prompts)."""

from __future__ import annotations

from threat_delta import prompts
from threat_delta.models import (
    Assumption,
    ChangedFile,
    Component,
    Diff,
    FileAnnotation,
    Flags,
    Hunk,
    Sensitivity,
    Slice,
    Asset,
    TrustBoundary,
)


def _slice() -> Slice:
    return Slice(
        components=[
            Component(
                id="user_service",
                name="User Service",
                trust_zone="internal",
                handles_assets=("asset.user_pii",),
                entry_points=("grpc_internal",),
            )
        ],
        trust_boundaries=[TrustBoundary(id="dmz", name="DMZ Edge")],
        assets=[Asset(id="user_pii", name="User PII", sensitivity=Sensitivity.HIGH)],
    )


def _diff() -> Diff:
    return Diff(
        pr="PR-1",
        files=[
            ChangedFile(
                path="svc/handler.py",
                hunks=[Hunk(header="@@ -1,3 +1,9 @@ def handle()", content="+ secret body")],
            )
        ],
    )


def _annotations() -> list[FileAnnotation]:
    return [
        FileAnnotation(
            path="svc/handler.py",
            entry_points=["http_post"],
            untrusted_inputs=["request.body"],
            sinks=["db.execute"],
        )
    ]


def test_classification_prompt_has_labels_and_schema():
    p = prompts.classification_prompt(_slice(), _diff(), _annotations())
    assert "Affected threat-model elements:" in p
    assert "Changed entry points / inputs / sinks (from static analysis):" in p
    assert "Diff summary:" in p
    assert '"new_entry_point":bool' in p
    # data appears verbatim under labels
    assert "user_service" in p
    assert "User Service" in p
    assert "svc/handler.py" in p
    assert "http_post" in p
    # diff summary uses the hunk header, NOT the body
    assert "@@ -1,3 +1,9 @@ def handle()" in p
    assert "secret body" not in p


def test_format_annotations_none():
    assert prompts.format_annotations([]) == "(none)"


def test_format_assumptions_numbered():
    out = prompts.format_assumptions(
        [Assumption(id="a1", statement="Input is validated.")]
    )
    assert out == "1. a1: Input is validated."
    assert prompts.format_assumptions([]) == "(none)"


def test_stride_prompt_has_component_and_flags_and_hunk():
    flags = Flags(new_entry_point=True, asset_handling_change=True)
    comp = _slice().components[0]
    p = prompts.stride_prompt(comp, "RAW HUNK TEXT", flags)
    assert "Component: user_service" in p
    assert "zone: internal" in p
    assert "Positive change flags:" in p
    assert "new_entry_point" in p
    assert "asset_handling_change" in p
    assert "new_data_flow" not in p  # not positive
    assert "Relevant code change:" in p
    assert "RAW HUNK TEXT" in p
    assert '"stride":"Spoofing|Tampering' in p


def test_assumption_prompt_has_labels_and_verbatim_data():
    assumptions = [Assumption(id="a1", statement="TLS terminates at the gateway.")]
    p = prompts.assumption_prompt(assumptions, _diff(), _annotations())
    assert "Stated security assumptions:" in p
    assert "Changed entry points / inputs / sinks:" in p
    assert "Diff summary:" in p
    assert "a1: TLS terminates at the gateway." in p
    assert '"violations":[' in p
