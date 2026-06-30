"""Stage 6e — deterministic severity scoring (spec §7).

Severity is *not* asked of the LLM: it is computed from facts (the delta type
and the sensitivity of the assets/zones it touches) so that the same change
always scores the same way, stable across runs. Confidence, by contrast, comes
from the model; ``low_confidence`` is surfaced but never changes the severity
(spec §7).

Every branch below quotes the §7 rule it implements. All rows are evaluated and
the MOST severe matching row wins — we start at :data:`Severity.LOW` and
escalate via :meth:`Severity.escalate_to`.
"""

from __future__ import annotations

from .models import Asset, Confidence, DeltaType, Sensitivity, Severity


# --------------------------------------------------------------------------- #
# Asset floor
# --------------------------------------------------------------------------- #

def asset_floor(assets: list[Asset]) -> Severity:
    """Severity floor implied by the most sensitive affected asset (spec §7).

    * a ``critical``-sensitivity asset present -> floor HIGH
    * else a ``high``-sensitivity asset present -> floor MEDIUM
    * else -> LOW
    """
    if any(a.sensitivity == Sensitivity.CRITICAL for a in assets):
        # "Delta touches a `critical`-sensitivity asset -> at least HIGH"
        return Severity.HIGH
    if any(a.sensitivity == Sensitivity.HIGH for a in assets):
        # "Delta touches a `high`-sensitivity asset -> at least MEDIUM"
        return Severity.MEDIUM
    return Severity.LOW


# --------------------------------------------------------------------------- #
# Severity table (spec §7)
# --------------------------------------------------------------------------- #

def compute_severity(
    *,
    delta_type: DeltaType,
    affected_assets: list[Asset],
    into_internal_zone: bool = False,
    new_internal_entry_point: bool = False,
    assumption_guards_sensitive: bool = False,
    weakens_control: bool = False,
    untracked_in_finding: bool = False,
) -> Severity:
    """Compute a delta's severity from the §7 table.

    All rows are checked and the maximum (most severe) applies. Start from LOW
    and escalate; ``low_confidence`` is intentionally *not* an input here —
    confidence never alters severity (spec §7).
    """
    severity = Severity.LOW  # "else -> LOW"

    # "Delta touches a `critical`-sensitivity asset -> at least HIGH"
    # "Delta touches a `high`-sensitivity asset -> at least MEDIUM"
    # (asset_floor folds both asset rows into one floor.)
    severity = severity.escalate_to(asset_floor(affected_assets))

    # "assumption_violation on an assumption guarding a critical/high asset -> HIGH"
    if delta_type == DeltaType.ASSUMPTION_VIOLATION and assumption_guards_sensitive:
        severity = severity.escalate_to(Severity.HIGH)

    # "trust_boundary_crossing into internal zone -> HIGH"
    if delta_type == DeltaType.TRUST_BOUNDARY_CROSSING and into_internal_zone:
        severity = severity.escalate_to(Severity.HIGH)

    # "new_entry_point on an internal component -> HIGH"
    if delta_type == DeltaType.NEW_ENTRY_POINT and new_internal_entry_point:
        severity = severity.escalate_to(Severity.HIGH)

    # "control_change weakening/removing a listed control -> at least MEDIUM"
    if delta_type == DeltaType.CONTROL_CHANGE and weakens_control:
        severity = severity.escalate_to(Severity.MEDIUM)

    # "untracked_path -> LOW, but MEDIUM if the path also appears in a
    #  step 2-4 finding"
    if delta_type == DeltaType.UNTRACKED_PATH:
        severity = severity.escalate_to(
            Severity.MEDIUM if untracked_in_finding else Severity.LOW
        )

    return severity


# --------------------------------------------------------------------------- #
# Confidence
# --------------------------------------------------------------------------- #

def confidence_from_flags(low_confidence: bool) -> Confidence:
    """Map the model's ``low_confidence`` flag to a :class:`Confidence` (spec §7).

    ``low_confidence`` downgrades *nothing* (severity is independent), but it is
    surfaced: LOW when the model was unsure, else MEDIUM.
    """
    return Confidence.LOW if low_confidence else Confidence.MEDIUM
