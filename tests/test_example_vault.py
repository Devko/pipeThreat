"""Regression test for the HashiCorp Vault worked example.

Asserts the sample produces the expected high-severity findings — including the
Repudiation STRIDE category (audit-log bypass) — so the example can't silently rot.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from threat_delta.models import DeltaType, Severity, Stride
from threat_delta.validate import has_errors, validate_file

_SAMPLE = Path(__file__).resolve().parent.parent / "examples" / "vault"


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "vault_generate_report", _SAMPLE / "generate_report.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sample_baseline_validates_clean():
    assert not has_errors(validate_file(_SAMPLE / "threat-model.yaml"))


def test_sample_report_is_high_severity_with_repudiation():
    result = _load_generator().build_result()

    assert result.pr == "29101"
    assert len(result.deltas) == 6
    assert all(d.severity == Severity.HIGH for d in result.deltas)
    assert all(d.requires_human_review for d in result.deltas)

    types = {d.type for d in result.deltas}
    assert DeltaType.NEW_ENTRY_POINT in types
    assert DeltaType.TRUST_BOUNDARY_CROSSING in types
    assert DeltaType.ASSUMPTION_VIOLATION in types

    # The audit bypass should surface as Repudiation somewhere in the STRIDE set.
    all_stride = {s for d in result.deltas for s in d.stride}
    assert Stride.REPUDIATION in all_stride
    assert Stride.INFORMATION_DISCLOSURE in all_stride

    contradicted = {
        d.contradicts_assumption
        for d in result.deltas
        if d.type == DeltaType.ASSUMPTION_VIOLATION
    }
    assert contradicted == {
        "asm.all_requests_authenticated",
        "asm.acl_enforced",
        "asm.all_access_audited",
    }

    # SARIF renders and stays advisory.
    levels = {r["level"] for r in result.sarif["runs"][0]["results"]}
    assert "error" not in levels
