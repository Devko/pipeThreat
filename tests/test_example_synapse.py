"""Regression test for the Matrix Synapse worked example.

Imports the sample's report generator and asserts the pipeline produces the
expected high-severity, human-review findings — so the example can't silently
rot as the code evolves.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from threat_delta.models import DeltaType, Severity
from threat_delta.validate import has_errors, validate_file

_SAMPLE = Path(__file__).resolve().parent.parent / "examples" / "synapse"


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "synapse_generate_report", _SAMPLE / "generate_report.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sample_baseline_validates_clean():
    assert not has_errors(validate_file(_SAMPLE / "threat-model.yaml"))


def test_sample_report_is_high_severity():
    result = _load_generator().build_result()

    assert result.pr == "17421"
    assert len(result.deltas) == 5
    # Every delta is High and needs human review.
    assert all(d.severity == Severity.HIGH for d in result.deltas)
    assert all(d.requires_human_review for d in result.deltas)

    types = {d.type for d in result.deltas}
    assert DeltaType.NEW_ENTRY_POINT in types
    assert DeltaType.ASSET_EXPOSURE in types
    assert DeltaType.ASSUMPTION_VIOLATION in types

    # The three stated assumptions are all flagged.
    contradicted = {
        d.contradicts_assumption
        for d in result.deltas
        if d.type == DeltaType.ASSUMPTION_VIOLATION
    }
    assert contradicted == {
        "asm.client_requires_token",
        "asm.admin_requires_admin",
        "asm.user_scoped_access",
    }

    # SARIF renders, stays advisory (never blocks the build).
    levels = {r["level"] for r in result.sarif["runs"][0]["results"]}
    assert "error" not in levels
