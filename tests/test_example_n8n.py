"""Regression test for the n8n worked example.

Asserts the sample produces tiered severity (High assumption violations + a
Medium component delta) and the Tampering / DenialOfService STRIDE categories.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from threat_delta.models import DeltaType, Severity, Stride
from threat_delta.validate import has_errors, validate_file

_SAMPLE = Path(__file__).resolve().parent.parent / "examples" / "n8n"


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "n8n_generate_report", _SAMPLE / "generate_report.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sample_baseline_validates_clean():
    assert not has_errors(validate_file(_SAMPLE / "threat-model.yaml"))


def test_sample_report_is_tiered():
    result = _load_generator().build_result()

    assert result.pr == "8421"
    # Three High assumption violations + one Medium collapsed component delta.
    assert len(result.deltas) == 4

    highs = [d for d in result.deltas if d.severity == Severity.HIGH]
    mediums = [d for d in result.deltas if d.severity == Severity.MEDIUM]
    assert len(highs) == 3 and len(mediums) == 1  # tiered, not all-High

    # The High deltas are the assumption violations; only they need review.
    assert all(d.type == DeltaType.ASSUMPTION_VIOLATION for d in highs)
    assert all(d.requires_human_review for d in highs)
    assert all(not d.requires_human_review for d in mediums)

    # The single Medium delta folds all of the component's change-signals.
    assert mediums[0].change_signals
    assert len(mediums[0].change_signals) > 1

    # The full STRIDE breadth, including the categories the other examples lack.
    all_stride = {s for d in result.deltas for s in d.stride}
    assert {Stride.TAMPERING, Stride.DENIAL_OF_SERVICE, Stride.SPOOFING} <= all_stride

    levels = {r["level"] for r in result.sarif["runs"][0]["results"]}
    assert "error" not in levels  # advisory
