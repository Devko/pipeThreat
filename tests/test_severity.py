"""Tests for the deterministic severity rules (spec §7)."""

from __future__ import annotations

from threat_delta.models import Asset, Confidence, DeltaType, Sensitivity, Severity
from threat_delta.severity import (
    asset_floor,
    compute_severity,
    confidence_from_flags,
)


def _asset(sensitivity: Sensitivity) -> Asset:
    return Asset(id=f"a-{sensitivity.value}", name=sensitivity.value, sensitivity=sensitivity)


CRITICAL = _asset(Sensitivity.CRITICAL)
HIGH = _asset(Sensitivity.HIGH)
MEDIUM = _asset(Sensitivity.MEDIUM)
LOW = _asset(Sensitivity.LOW)


# --------------------------------------------------------------------------- #
# asset_floor
# --------------------------------------------------------------------------- #

def test_asset_floor_critical():
    assert asset_floor([LOW, CRITICAL]) == Severity.HIGH


def test_asset_floor_high():
    assert asset_floor([MEDIUM, HIGH]) == Severity.MEDIUM


def test_asset_floor_low_or_none():
    assert asset_floor([LOW, MEDIUM]) == Severity.LOW
    assert asset_floor([]) == Severity.LOW


# --------------------------------------------------------------------------- #
# compute_severity — each §7 row
# --------------------------------------------------------------------------- #

def test_critical_asset_forces_high():
    sev = compute_severity(delta_type=DeltaType.NEW_DATA_FLOW, affected_assets=[CRITICAL])
    assert sev == Severity.HIGH


def test_high_asset_forces_medium():
    sev = compute_severity(delta_type=DeltaType.NEW_DATA_FLOW, affected_assets=[HIGH])
    assert sev == Severity.MEDIUM


def test_assumption_violation_guarding_sensitive_is_high():
    sev = compute_severity(
        delta_type=DeltaType.ASSUMPTION_VIOLATION,
        affected_assets=[],
        assumption_guards_sensitive=True,
    )
    assert sev == Severity.HIGH


def test_assumption_violation_not_guarding_is_low():
    sev = compute_severity(
        delta_type=DeltaType.ASSUMPTION_VIOLATION,
        affected_assets=[],
        assumption_guards_sensitive=False,
    )
    assert sev == Severity.LOW


def test_trust_boundary_crossing_into_internal_is_high():
    sev = compute_severity(
        delta_type=DeltaType.TRUST_BOUNDARY_CROSSING,
        affected_assets=[],
        into_internal_zone=True,
    )
    assert sev == Severity.HIGH


def test_trust_boundary_crossing_not_internal_is_low():
    sev = compute_severity(
        delta_type=DeltaType.TRUST_BOUNDARY_CROSSING,
        affected_assets=[],
        into_internal_zone=False,
    )
    assert sev == Severity.LOW


def test_new_entry_point_internal_is_high():
    sev = compute_severity(
        delta_type=DeltaType.NEW_ENTRY_POINT,
        affected_assets=[],
        new_internal_entry_point=True,
    )
    assert sev == Severity.HIGH


def test_control_change_weakens_is_medium():
    sev = compute_severity(
        delta_type=DeltaType.CONTROL_CHANGE,
        affected_assets=[],
        weakens_control=True,
    )
    assert sev == Severity.MEDIUM


def test_control_change_no_weaken_is_low():
    sev = compute_severity(
        delta_type=DeltaType.CONTROL_CHANGE,
        affected_assets=[],
        weakens_control=False,
    )
    assert sev == Severity.LOW


def test_untracked_path_low():
    sev = compute_severity(
        delta_type=DeltaType.UNTRACKED_PATH,
        affected_assets=[],
        untracked_in_finding=False,
    )
    assert sev == Severity.LOW


def test_untracked_path_in_finding_is_medium():
    sev = compute_severity(
        delta_type=DeltaType.UNTRACKED_PATH,
        affected_assets=[],
        untracked_in_finding=True,
    )
    assert sev == Severity.MEDIUM


def test_default_is_low():
    sev = compute_severity(delta_type=DeltaType.ASSET_EXPOSURE, affected_assets=[LOW])
    assert sev == Severity.LOW


# --------------------------------------------------------------------------- #
# MAX across rows / worked example
# --------------------------------------------------------------------------- #

def test_worked_example_new_entry_point_and_assumption_violation_high():
    # new_entry_point on internal component AND assumption guarding high asset
    # -> HIGH (max across rows).
    sev = compute_severity(
        delta_type=DeltaType.NEW_ENTRY_POINT,
        affected_assets=[HIGH],
        new_internal_entry_point=True,
        assumption_guards_sensitive=True,
    )
    assert sev == Severity.HIGH


def test_max_across_rows_high_asset_plus_control_change():
    # high asset (MEDIUM floor) combined with a non-escalating type stays MEDIUM.
    sev = compute_severity(
        delta_type=DeltaType.CONTROL_CHANGE,
        affected_assets=[HIGH],
        weakens_control=False,
    )
    assert sev == Severity.MEDIUM


def test_critical_asset_wins_over_lower_rows():
    sev = compute_severity(
        delta_type=DeltaType.CONTROL_CHANGE,
        affected_assets=[CRITICAL],
        weakens_control=True,
    )
    assert sev == Severity.HIGH


# --------------------------------------------------------------------------- #
# confidence
# --------------------------------------------------------------------------- #

def test_confidence_from_flags():
    assert confidence_from_flags(True) == Confidence.LOW
    assert confidence_from_flags(False) == Confidence.MEDIUM
