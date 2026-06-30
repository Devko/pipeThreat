"""Stage orchestration and delta assembly for pipeline step 6.

Wires the per-stage modules into the flow from spec §5:

    6a resolve_slice         (deterministic)
    6b classify_change       (1 LLM call)        -- gates 6c AND 6d
    6c stride_deltas         (N LLM calls)       -- per affected component
    6d assumption_check      (1 LLM call)
    6e assemble + score + emit (deterministic)

The *assembly* in 6e is the cross-cutting glue: it turns the raw stage outputs
(untracked paths from 6a, coarse flags from 6b, per-component STRIDE from 6c,
assumption violations from 6d) into the final scored :class:`Delta` objects of
spec §8, applying the deterministic §7 severity rules.

Assembly model (faithful to §6e's literal "dedupe by (type, affected_elements)"):
one delta per *(type, affected element)* rather than one consolidated delta per
component. Every positive flag and every violated assumption is represented and
independently severity-scored, so nothing is silently merged away. The
worked-example's narrative "one delta" therefore appears here as a small set of
per-(type, element) deltas covering the same change.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .assumptions import assumption_check
from .baseline import Baseline
from .classify import classify_change
from .emit import build_comment, build_sarif
from .llm import LLMClient
from .models import (
    Asset,
    Component,
    Confidence,
    Delta,
    DeltaType,
    Diff,
    FileAnnotation,
    Finding,
    Flags,
    Hunk,
    ProposedBaselineUpdate,
    Severity,
    Slice,
    Stride,
    StrideDelta,
    Violation,
)
from .relevance import resolve_slice
from .severity import compute_severity, confidence_from_flags
from .stride import stride_deltas

# Map a positive 6b flag to the delta type it produces.
_FLAG_TO_TYPE: dict[str, DeltaType] = {
    "new_entry_point": DeltaType.NEW_ENTRY_POINT,
    "new_data_flow": DeltaType.NEW_DATA_FLOW,
    "trust_boundary_crossing": DeltaType.TRUST_BOUNDARY_CROSSING,
    "asset_handling_change": DeltaType.ASSET_EXPOSURE,
    "control_change": DeltaType.CONTROL_CHANGE,
}

_BASELINE_UPDATE_KIND: dict[DeltaType, str] = {
    DeltaType.NEW_ENTRY_POINT: "component_entry_point_added",
    DeltaType.NEW_DATA_FLOW: "data_flow_added",
    DeltaType.TRUST_BOUNDARY_CROSSING: "trust_boundary_crossing_added",
    DeltaType.ASSET_EXPOSURE: "component_asset_handling_changed",
    DeltaType.CONTROL_CHANGE: "control_changed",
}

_RECOMMENDED_ACTION: dict[DeltaType, str] = {
    DeltaType.NEW_ENTRY_POINT: (
        "Confirm the new entry point is intended; add explicit authz + input "
        "validation, or route it through the gateway."
    ),
    DeltaType.NEW_DATA_FLOW: (
        "Confirm the new data flow is intended and that it crosses only the "
        "expected, controlled trust boundaries."
    ),
    DeltaType.TRUST_BOUNDARY_CROSSING: (
        "Verify the crossing is authorized and that the boundary's controls "
        "(authn/authz, validation) apply to the new path."
    ),
    DeltaType.ASSET_EXPOSURE: (
        "Confirm the asset exposure is intended; verify access controls and "
        "that sensitive data is not newly disclosed."
    ),
    DeltaType.CONTROL_CHANGE: (
        "Review the changed/removed control; restore it or document the "
        "compensating control in the baseline."
    ),
    DeltaType.UNTRACKED_PATH: (
        "Extend the threat-model baseline to cover this path (new or widened "
        "component), then re-run the analysis."
    ),
    DeltaType.ASSUMPTION_VIOLATION: (
        "Restore the assumption or, if the change is a legitimate evolution, "
        "update the baseline assumption and obtain security review."
    ),
}


@dataclass
class AnalysisResult:
    """Everything 6e produces, plus the intermediate stage outputs for debugging."""
    pr: str
    deltas: list[Delta] = field(default_factory=list)
    slice: Slice | None = None
    flags: Flags = field(default_factory=Flags)
    violations: list[Violation] = field(default_factory=list)
    stride_by_component: dict[str, list[StrideDelta]] = field(default_factory=dict)

    @property
    def sarif(self) -> dict:
        return build_sarif(self.deltas)

    @property
    def comment(self) -> str:
        return build_comment(self.deltas)

    def to_dict(self) -> dict:
        return {
            "pr": self.pr,
            "deltas": [d.to_dict() for d in self.deltas],
        }


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def analyze(
    diff: Diff,
    baseline: Baseline,
    annotations: list[FileAnnotation],
    findings: list[Finding],
    llm: LLMClient,
    *,
    pr: str | None = None,
    max_hunk_chars: int = 4000,
) -> AnalysisResult:
    """Run stages 6a–6e and return the assembled, scored result."""
    pr = pr or diff.pr or "0"

    # 6a — relevance resolution (deterministic). Bounds all downstream context.
    sl = resolve_slice(diff, baseline)
    if sl.is_empty:
        # Nothing matched and nothing untracked -> exit with no deltas (§6a).
        return AnalysisResult(pr=pr, slice=sl)

    flags = Flags()
    stride_by_component: dict[str, list[StrideDelta]] = {}
    violations: list[Violation] = []

    # 6b/6c/6d only apply when the diff touched tracked components. (A pure
    # untracked-path PR still emits its 6a untracked deltas below.)
    if sl.components:
        # 6b — coarse classification (1 LLM call). Gates 6c AND 6d (§6b).
        flags = classify_change(sl, diff, annotations, llm)
        if flags.any_positive:
            # 6c — STRIDE deltas, once per affected component (§6c).
            for comp in sl.components:
                hunks = _hunks_for_component(comp, diff, sl)
                deltas = stride_deltas(
                    comp, hunks, flags, llm, max_hunk_chars=max_hunk_chars
                )
                if deltas:
                    stride_by_component[comp.id] = deltas
            # 6d — assumption contradiction (1 LLM call), exhaustive over the
            # slice's assumptions (§6d, §11).
            violations = assumption_check(sl.assumptions, diff, annotations, llm)

    # 6e — assemble, score, dedupe (deterministic).
    deltas = _assemble_deltas(
        pr=pr,
        sl=sl,
        flags=flags,
        stride_by_component=stride_by_component,
        violations=violations,
        baseline=baseline,
        annotations=annotations,
        findings=findings,
    )

    return AnalysisResult(
        pr=pr,
        deltas=deltas,
        slice=sl,
        flags=flags,
        violations=violations,
        stride_by_component=stride_by_component,
    )


# --------------------------------------------------------------------------- #
# 6e — delta assembly (the cross-cutting glue)
# --------------------------------------------------------------------------- #

def _assemble_deltas(
    *,
    pr: str,
    sl: Slice,
    flags: Flags,
    stride_by_component: dict[str, list[StrideDelta]],
    violations: list[Violation],
    baseline: Baseline,
    annotations: list[FileAnnotation],
    findings: list[Finding],
) -> list[Delta]:
    ann_by_path = {a.path: a for a in annotations}
    finding_paths = {f.file for f in findings}
    raw: list[Delta] = []

    # --- untracked-path deltas (from 6a) ------------------------------------ #
    for path in sl.untracked_paths:
        in_finding = path in finding_paths
        raw.append(
            Delta(
                delta_id="",  # assigned after dedup/order
                pr=pr,
                type=DeltaType.UNTRACKED_PATH,
                affected_elements=[],
                severity=compute_severity(
                    delta_type=DeltaType.UNTRACKED_PATH,
                    affected_assets=[],
                    untracked_in_finding=in_finding,
                ),
                confidence=Confidence.MEDIUM,
                description=(
                    f"Changed path '{path}' is not claimed by any threat-model "
                    "component (baseline drift)."
                    + (" Also appears in a SAST/secret finding." if in_finding else "")
                ),
                recommended_action=_RECOMMENDED_ACTION[DeltaType.UNTRACKED_PATH],
                requires_human_review=True,
                evidence={"files": [path]},
                proposed_baseline_update=ProposedBaselineUpdate(
                    kind="component_added",
                    target="(new)",
                    change=f"add or extend a component to cover {path}",
                ),
            )
        )

    # --- component flag deltas (from 6b flags + 6c STRIDE) ------------------ #
    for comp in sl.components:
        comp_stride = stride_by_component.get(comp.id, [])
        comp_assets = _component_assets(comp, baseline)
        comp_paths = sl.matched_paths.get(comp.id, [])
        entry_points = _entry_points_for(comp_paths, ann_by_path)
        stride_low_conf = any(s.low_confidence for s in comp_stride)
        low_conf = flags.low_confidence or stride_low_conf

        for flag_name, dtype in _FLAG_TO_TYPE.items():
            if not getattr(flags, flag_name):
                continue
            into_internal = (
                dtype == DeltaType.TRUST_BOUNDARY_CROSSING
                and comp.trust_zone == "internal"
            )
            new_internal_ep = (
                dtype == DeltaType.NEW_ENTRY_POINT and comp.trust_zone == "internal"
            )
            severity = compute_severity(
                delta_type=dtype,
                affected_assets=comp_assets,
                into_internal_zone=into_internal,
                new_internal_entry_point=new_internal_ep,
                weakens_control=(dtype == DeltaType.CONTROL_CHANGE),
            )
            raw.append(
                Delta(
                    delta_id="",
                    pr=pr,
                    type=dtype,
                    affected_elements=[comp.id],
                    severity=severity,
                    confidence=confidence_from_flags(low_conf),
                    description=_component_description(comp, dtype, comp_stride),
                    recommended_action=_RECOMMENDED_ACTION[dtype],
                    requires_human_review=(severity == Severity.HIGH),
                    stride=_dedupe_stride(comp_stride),
                    evidence=_evidence(comp_paths, entry_points),
                    proposed_baseline_update=_baseline_update(comp, dtype, entry_points),
                    low_confidence=low_conf,
                )
            )

    # --- assumption-violation deltas (from 6d) ------------------------------ #
    changed_component_ids = [c.id for c in sl.components]
    slice_assets = _slice_assets(sl, baseline)
    guards_sensitive = any(
        a.sensitivity.value in ("critical", "high") for a in slice_assets
    )
    all_changed_paths = sorted(
        {p for paths in sl.matched_paths.values() for p in paths}
    )
    all_entry_points = _entry_points_for(all_changed_paths, ann_by_path)
    for v in violations:
        if not v.violated:
            continue
        severity = compute_severity(
            delta_type=DeltaType.ASSUMPTION_VIOLATION,
            affected_assets=slice_assets,
            assumption_guards_sensitive=guards_sensitive,
        )
        raw.append(
            Delta(
                delta_id="",
                pr=pr,
                type=DeltaType.ASSUMPTION_VIOLATION,
                affected_elements=list(changed_component_ids),
                severity=severity,
                confidence=confidence_from_flags(v.low_confidence),
                contradicts_assumption=v.assumption_id,
                description=(
                    f"Change weakens or violates assumption '{v.assumption_id}': "
                    f"{v.reason}"
                ),
                recommended_action=_RECOMMENDED_ACTION[DeltaType.ASSUMPTION_VIOLATION],
                requires_human_review=True,
                evidence=_evidence(all_changed_paths, all_entry_points),
                proposed_baseline_update=ProposedBaselineUpdate(
                    kind="assumption_revisited",
                    target=v.assumption_id,
                    change="confirm intended; update or reaffirm the assumption",
                ),
                low_confidence=v.low_confidence,
            )
        )

    # --- drop deltas referencing ids not in the baseline (§11 guard) -------- #
    valid_ids = baseline.all_ids
    raw = [
        d
        for d in raw
        if all(eid in valid_ids for eid in d.affected_elements)
        and (d.contradicts_assumption is None or d.contradicts_assumption in valid_ids)
    ]

    # --- dedupe and assign stable ids --------------------------------------- #
    return _dedupe_and_id(raw, pr)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _hunks_for_component(comp: Component, diff: Diff, sl: Slice) -> list[Hunk]:
    paths = set(sl.matched_paths.get(comp.id, []))
    hunks: list[Hunk] = []
    for f in diff.files:
        if f.path in paths:
            hunks.extend(f.hunks)
    return hunks


def _component_assets(comp: Component, baseline: Baseline) -> list[Asset]:
    return [
        baseline.assets_by_id[aid]
        for aid in comp.handles_assets
        if aid in baseline.assets_by_id
    ]


def _slice_assets(sl: Slice, baseline: Baseline) -> list[Asset]:
    # Assets already resolved on the slice are authoritative; fall back to
    # resolving via components if the slice carries none.
    if sl.assets:
        return list(sl.assets)
    seen: dict[str, Asset] = {}
    for comp in sl.components:
        for a in _component_assets(comp, baseline):
            seen.setdefault(a.id, a)
    return list(seen.values())


def _entry_points_for(
    paths: list[str], ann_by_path: dict[str, FileAnnotation]
) -> list[str]:
    out: list[str] = []
    for p in paths:
        ann = ann_by_path.get(p)
        if not ann:
            continue
        for ep in ann.entry_points:
            if ep not in out:
                out.append(ep)
    return out


def _evidence(paths: list[str], entry_points: list[str]) -> dict:
    ev: dict = {"files": list(paths)}
    if entry_points:
        ev["entry_points"] = list(entry_points)
    return ev


def _dedupe_stride(stride: list[StrideDelta]) -> list[Stride]:
    out: list[Stride] = []
    for s in stride:
        if s.stride not in out:
            out.append(s.stride)
    return out


def _component_description(
    comp: Component, dtype: DeltaType, stride: list[StrideDelta]
) -> str:
    label = {
        DeltaType.NEW_ENTRY_POINT: "New entry point",
        DeltaType.NEW_DATA_FLOW: "New data flow",
        DeltaType.TRUST_BOUNDARY_CROSSING: "Trust-boundary crossing",
        DeltaType.ASSET_EXPOSURE: "Asset-handling change",
        DeltaType.CONTROL_CHANGE: "Control change",
    }[dtype]
    base = f"{label} on {comp.name} ({comp.trust_zone} zone)."
    if stride:
        reasons = "; ".join(f"{s.stride.value}: {s.reason}" for s in stride)
        base += f" STRIDE: {reasons}"
    return base


def _baseline_update(
    comp: Component, dtype: DeltaType, entry_points: list[str]
) -> ProposedBaselineUpdate:
    kind = _BASELINE_UPDATE_KIND[dtype]
    if dtype == DeltaType.NEW_ENTRY_POINT:
        ep = entry_points[0] if entry_points else "<entry_point>"
        change = f"entry_points += {ep}"
    elif dtype == DeltaType.NEW_DATA_FLOW:
        change = f"add a data_flow involving {comp.id}"
    elif dtype == DeltaType.TRUST_BOUNDARY_CROSSING:
        change = f"document the new boundary crossing for {comp.id}"
    elif dtype == DeltaType.ASSET_EXPOSURE:
        change = f"review handles_assets for {comp.id}"
    else:  # CONTROL_CHANGE
        change = f"review controls affecting {comp.id}"
    return ProposedBaselineUpdate(kind=kind, target=comp.id, change=change)


def _dedupe_and_id(raw: list[Delta], pr: str) -> list[Delta]:
    """Dedupe by (type, affected_elements, contradicts_assumption) keeping the
    most severe, then assign stable ``td-<pr>-<n>`` ids in a deterministic order.

    The dedup key extends §6e's "(type, affected_elements)" with
    ``contradicts_assumption`` so two distinct violated assumptions on the same
    elements are not collapsed into one.
    """
    best: dict[tuple, Delta] = {}
    for d in raw:
        key = (
            d.type.value,
            tuple(sorted(d.affected_elements)),
            d.contradicts_assumption or "",
            tuple(sorted(d.evidence.get("files", []))) if d.type == DeltaType.UNTRACKED_PATH else (),
        )
        cur = best.get(key)
        if cur is None or d.severity.rank > cur.severity.rank:
            best[key] = d

    # Deterministic ordering: severity desc, then type, then elements.
    ordered = sorted(
        best.values(),
        key=lambda d: (
            -d.severity.rank,
            d.type.value,
            tuple(sorted(d.affected_elements)),
            d.contradicts_assumption or "",
        ),
    )
    for i, d in enumerate(ordered, start=1):
        d.delta_id = f"td-{pr}-{i}"
    return ordered
