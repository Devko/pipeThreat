"""Deterministic referential-integrity validation of a threat-model baseline.

The baseline (threat-model.yaml) is the *context* the whole analysis depends on
(baseline-as-code precondition). Every later stage — relevance (Stage 1),
classification (Stage 2), STRIDE deltas (Stage 3), assumption checks (Stage 4) — resolves diffs
against the ids declared here, so a malformed or dangling baseline must fail CI
fast rather than silently produce wrong deltas downstream.

This module performs *no* I/O of its own (other than via
:func:`threat_delta.baseline.load_baseline`) and calls no LLM. It only checks
that the cross-references inside an already-parsed :class:`Baseline` actually
resolve, plus a few soft style/coverage warnings.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Union

from .baseline import Baseline, BaselineError, load_baseline


@dataclass(frozen=True)
class Issue:
    """A single validation finding.

    ``level`` is ``"error"`` or ``"warning"``. Errors mean the baseline is
    unusable as-is and CI should fail; warnings are advisory.
    """

    level: str
    code: str
    message: str

    def __str__(self) -> str:
        return f"[{self.level}] {self.code}: {self.message}"


# id-prefix conventions checked by ``id_convention`` (soft / warning only).
_ID_PREFIXES = {
    "component": "comp.",
    "asset": "asset.",
    "trust_boundary": "tb.",
    "data_flow": "flow.",
    "assumption": "asm.",
}


def validate_baseline(baseline: Baseline) -> list[Issue]:
    """Check referential integrity of ``baseline`` and return ordered issues.

    Lists are iterated in their declared order so the output is deterministic.
    Most findings are errors; coverage/style findings are warnings (see the
    module docstring).
    """
    issues: list[Issue] = []

    asset_ids = set(baseline.assets_by_id)
    component_ids = set(baseline.components_by_id)
    boundary_ids = set(baseline.boundaries_by_id)

    # --- duplicate ids across every element list -------------------------- #
    seen: set[str] = set()
    ordered_elements = (
        list(baseline.assets)
        + list(baseline.trust_boundaries)
        + list(baseline.components)
        + list(baseline.data_flows)
        + list(baseline.assumptions)
        + list(baseline.accepted_risks)
    )
    for element in ordered_elements:
        eid = element.id
        if eid in seen:
            issues.append(
                Issue(
                    "error",
                    "duplicate_id",
                    f"id {eid} appears more than once in the baseline",
                )
            )
        else:
            seen.add(eid)

    # --- component cross-references --------------------------------------- #
    for comp in baseline.components:
        for asset_id in tuple(comp.handles_assets):
            if asset_id not in asset_ids:
                issues.append(
                    Issue(
                        "error",
                        "dangling_asset",
                        f"component {comp.id} references unknown asset {asset_id}",
                    )
                )
        if not tuple(comp.code_paths):
            issues.append(
                Issue(
                    "warning",
                    "no_code_paths",
                    f"component {comp.id} has no code_paths and can never be "
                    f"matched by relevance (Stage 1)",
                )
            )
        if not comp.trust_zone:
            issues.append(
                Issue(
                    "warning",
                    "no_trust_zone",
                    f"component {comp.id} has no trust_zone",
                )
            )

    # --- data-flow cross-references --------------------------------------- #
    for flow in baseline.data_flows:
        if flow.from_ not in component_ids:
            issues.append(
                Issue(
                    "error",
                    "dangling_flow_endpoint",
                    f"data_flow {flow.id} 'from' references unknown component "
                    f"{flow.from_}",
                )
            )
        if flow.to not in component_ids:
            issues.append(
                Issue(
                    "error",
                    "dangling_flow_endpoint",
                    f"data_flow {flow.id} 'to' references unknown component "
                    f"{flow.to}",
                )
            )
        for boundary_id in tuple(flow.crosses):
            if boundary_id not in boundary_ids:
                issues.append(
                    Issue(
                        "error",
                        "dangling_boundary",
                        f"data_flow {flow.id} crosses unknown trust_boundary "
                        f"{boundary_id}",
                    )
                )
        for asset_id in tuple(flow.assets):
            if asset_id not in asset_ids:
                issues.append(
                    Issue(
                        "error",
                        "dangling_asset",
                        f"data_flow {flow.id} references unknown asset {asset_id}",
                    )
                )

    # --- soft id-naming convention (warnings) ----------------------------- #
    for asset in baseline.assets:
        _check_convention(issues, "asset", asset.id)
    for boundary in baseline.trust_boundaries:
        _check_convention(issues, "trust_boundary", boundary.id)
    for comp in baseline.components:
        _check_convention(issues, "component", comp.id)
    for flow in baseline.data_flows:
        _check_convention(issues, "data_flow", flow.id)
    for assumption in baseline.assumptions:
        _check_convention(issues, "assumption", assumption.id)

    # --- coverage ---------------------------------------------------------- #
    if not baseline.components:
        issues.append(
            Issue(
                "warning",
                "no_components",
                "baseline declares no components; no diff can match anything",
            )
        )

    return issues


def _check_convention(issues: list[Issue], kind: str, element_id: str) -> None:
    prefix = _ID_PREFIXES[kind]
    if not element_id.startswith(prefix):
        issues.append(
            Issue(
                "warning",
                "id_convention",
                f"{kind} id {element_id} does not start with '{prefix}'",
            )
        )


def validate_file(path: Union[str, Path]) -> list[Issue]:
    """Load + parse the baseline at ``path`` and validate it.

    A :class:`BaselineError` (missing file or malformed structure) is reported
    as a single ``parse_error`` error rather than raised, so callers get a
    uniform ``list[Issue]`` either way.
    """
    try:
        baseline = load_baseline(path)
    except BaselineError as exc:
        return [Issue("error", "parse_error", str(exc))]
    return validate_baseline(baseline)


def has_errors(issues: list[Issue]) -> bool:
    """True if any issue is an error (warnings alone do not fail CI)."""
    return any(issue.level == "error" for issue in issues)
