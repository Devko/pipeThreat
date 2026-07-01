"""Stage 5 — deterministic severity scoring.

Severity is *not* asked of the LLM: it is computed from facts (the delta type
and the sensitivity of the assets/zones it touches) so that the same change
always scores the same way, stable across runs. Confidence, by contrast, comes
from the model; ``low_confidence`` is surfaced but never changes the severity.

Every branch below quotes the severity rule it implements. All rows are evaluated and
the MOST severe matching row wins — we start at :data:`Severity.LOW` and
escalate via :meth:`Severity.escalate_to`.
"""

from __future__ import annotations

from .models import Asset, Confidence, DeltaType, Sensitivity, Severity


def _most_sensitive(assets: list[Asset]) -> Asset | None:
    order = {Sensitivity.CRITICAL: 3, Sensitivity.HIGH: 2, Sensitivity.MEDIUM: 1, Sensitivity.LOW: 0}
    return max(assets, key=lambda a: order[a.sensitivity], default=None)


# --------------------------------------------------------------------------- #
# Asset floor
# --------------------------------------------------------------------------- #

def asset_floor(assets: list[Asset]) -> Severity:
    """Severity floor implied by the most sensitive affected asset.

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
# Severity table
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
    """Compute a delta's severity from the severity table.

    All rows are checked and the maximum (most severe) applies. Start from LOW
    and escalate; ``low_confidence`` is intentionally *not* an input here —
    confidence never alters severity.
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
    #  SAST/secrets/CVE finding"
    if delta_type == DeltaType.UNTRACKED_PATH:
        severity = severity.escalate_to(
            Severity.MEDIUM if untracked_in_finding else Severity.LOW
        )

    return severity


# --------------------------------------------------------------------------- #
# Confidence
# --------------------------------------------------------------------------- #

def confidence_from_flags(low_confidence: bool) -> Confidence:
    """Map the model's ``low_confidence`` flag to a :class:`Confidence`.

    ``low_confidence`` downgrades *nothing* (severity is independent), but it is
    surfaced: LOW when the model was unsure, else MEDIUM.
    """
    return Confidence.LOW if low_confidence else Confidence.MEDIUM


def confidence_from_evidence(
    *,
    low_confidence: bool,
    corroborated: bool,
    agreement: float = 1.0,
) -> Confidence:
    """Confidence from real signal, not a flat constant.

    Confidence still never alters severity. It now reflects two facts the
    pipeline actually has:

    * ``agreement`` — the fraction of self-consistency votes that produced this
      item (1.0 when voting is off); below 0.6 we are not confident.
    * ``corroborated`` — an independent static-analysis annotation or a
      SAST/secret finding touches the same file.

    LOW when the model flagged ``low_confidence`` or the vote was split; HIGH
    when an independent source corroborates a confident finding; else MEDIUM.
    """
    if low_confidence or agreement < 0.6:
        return Confidence.LOW
    if corroborated and agreement >= 0.99:
        return Confidence.HIGH
    return Confidence.MEDIUM


# --------------------------------------------------------------------------- #
# Severity rationale (why this level — auditable, deterministic)
# --------------------------------------------------------------------------- #

def severity_rationale(
    *,
    delta_type: DeltaType,
    severity: Severity,
    affected_assets: list[Asset],
    into_internal_zone: bool = False,
    new_internal_entry_point: bool = False,
    assumption_guards_sensitive: bool = False,
    weakens_control: bool = False,
    untracked_in_finding: bool = False,
) -> str:
    """One line explaining which severity rule set this severity.

    Mirrors :func:`compute_severity`; names the dominant reason so a reviewer can
    audit the level instead of taking it on faith.
    """
    asset = _most_sensitive(affected_assets)
    if (
        delta_type == DeltaType.ASSUMPTION_VIOLATION
        and assumption_guards_sensitive
        and asset is not None
    ):
        return (
            f"assumption guards `{asset.id}` "
            f"({asset.sensitivity.value}-sensitivity) → High"
        )
    if delta_type == DeltaType.TRUST_BOUNDARY_CROSSING and into_internal_zone:
        return "crosses into an internal trust zone → High"
    if delta_type == DeltaType.NEW_ENTRY_POINT and new_internal_entry_point:
        return "new entry point on an internal component → High"
    if asset is not None and asset.sensitivity in (Sensitivity.CRITICAL, Sensitivity.HIGH):
        floor = "High" if asset.sensitivity == Sensitivity.CRITICAL else "Medium"
        return (
            f"touches `{asset.id}` ({asset.sensitivity.value}-sensitivity) "
            f"→ at least {floor}"
        )
    if delta_type == DeltaType.CONTROL_CHANGE and weakens_control:
        return "weakens or removes a listed control → at least Medium"
    if delta_type == DeltaType.UNTRACKED_PATH:
        return (
            "untracked path also appears in a SAST/secret finding → Medium"
            if untracked_in_finding
            else "untracked path (baseline drift) → Low"
        )
    return f"no sensitivity-raising rule matched → {severity.value.capitalize()}"
