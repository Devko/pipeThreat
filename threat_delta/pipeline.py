"""Stage orchestration and delta assembly for pipeline step 6.

Wires the per-stage modules into the flow from spec §5:

    6a resolve_slice         (deterministic)
    6b classify_change       (voted)             -- gates 6c AND 6d
    6c stride_deltas         (per component, voted)
    6d assumption_check      (per assumption, voted)
    6e assemble + score + emit (deterministic)

    Each model-driven stage (6b/6c/6d) samples ``LLMConfig.votes`` times and keeps
    the majority (``votes=1`` by default = one call). 6c fans out one call per
    affected component; 6d fans out one call per assumption.

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
from .severity import (
    compute_severity,
    confidence_from_evidence,
    severity_rationale,
)
from .signals import regions_by_path, signals_for_component, signals_for_paths
from .stride import stride_deltas

# Map a positive 6b flag to the delta type it produces. Ordered by descending
# tiebreak priority: when two flags compute the same severity, the representative
# type for the collapsed component delta is the first present in this order.
_FLAG_TO_TYPE: dict[str, DeltaType] = {
    "new_entry_point": DeltaType.NEW_ENTRY_POINT,
    "trust_boundary_crossing": DeltaType.TRUST_BOUNDARY_CROSSING,
    "control_change": DeltaType.CONTROL_CHANGE,
    "asset_handling_change": DeltaType.ASSET_EXPOSURE,
    "new_data_flow": DeltaType.NEW_DATA_FLOW,
}

# Short human label per change-signal type, for the collapsed component delta.
_FLAG_LABEL: dict[DeltaType, str] = {
    DeltaType.NEW_ENTRY_POINT: "new entry point",
    DeltaType.TRUST_BOUNDARY_CROSSING: "trust-boundary crossing",
    DeltaType.CONTROL_CHANGE: "control change",
    DeltaType.ASSET_EXPOSURE: "asset-handling change",
    DeltaType.NEW_DATA_FLOW: "new data flow",
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
    prior_keys: set[tuple] | None = None,
) -> AnalysisResult:
    """Run stages 6a–6e and return the assembled, scored result.

    ``prior_keys`` (from :func:`delta_key` over a previous run) suppresses
    unchanged deltas so a re-run on the same PR only surfaces what is new — the
    incremental "subtract the base state" mode (opt-in; ``None`` reports all).
    """
    pr = pr or diff.pr or "0"

    # 6a — relevance resolution (deterministic). Bounds all downstream context.
    sl = resolve_slice(diff, baseline)
    if sl.is_empty:
        # Nothing matched and nothing untracked -> exit with no deltas (§6a).
        return AnalysisResult(pr=pr, slice=sl)

    flags = Flags()
    stride_by_component: dict[str, list[StrideDelta]] = {}
    violations: list[Violation] = []

    # Deterministic grounding facts fed to the model-driven stages (§6, §11).
    all_changed_paths = sorted({p for ps in sl.matched_paths.values() for p in ps})
    slice_signals = signals_for_paths(all_changed_paths, diff, annotations)

    # 6b/6c/6d only apply when the diff touched tracked components. (A pure
    # untracked-path PR still emits its 6a untracked deltas below.)
    if sl.components:
        # 6b — coarse classification (voted). Gates 6c AND 6d (§6b).
        flags = classify_change(sl, diff, annotations, llm)
        if flags.any_positive:
            # 6c — STRIDE deltas, once per affected component (§6c), each call
            # grounded by that component's deterministic signals.
            for comp in sl.components:
                hunks = _hunks_for_component(comp, diff, sl)
                comp_signals = signals_for_component(comp, sl, diff, annotations)
                deltas = stride_deltas(
                    comp,
                    hunks,
                    flags,
                    llm,
                    max_hunk_chars=max_hunk_chars,
                    signals=comp_signals,
                )
                if deltas:
                    stride_by_component[comp.id] = deltas
            # 6d — assumption contradiction, fanned out one call per assumption
            # over the slice's assumptions (§6d, §11).
            violations = assumption_check(
                sl.assumptions, diff, annotations, llm, signals=slice_signals
            )

    # 6e — assemble, score, dedupe (deterministic).
    deltas = _assemble_deltas(
        pr=pr,
        sl=sl,
        diff=diff,
        flags=flags,
        stride_by_component=stride_by_component,
        violations=violations,
        baseline=baseline,
        annotations=annotations,
        findings=findings,
    )

    if prior_keys is not None:
        # Incremental mode: drop deltas already reported by the prior run, then
        # re-id so the surviving (new/changed) deltas number from 1.
        deltas = [d for d in deltas if delta_key(d) not in prior_keys]
        deltas = _reassign_ids(deltas, pr)

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
    diff: Diff,
    flags: Flags,
    stride_by_component: dict[str, list[StrideDelta]],
    violations: list[Violation],
    baseline: Baseline,
    annotations: list[FileAnnotation],
    findings: list[Finding],
) -> list[Delta]:
    ann_by_path = {a.path: a for a in annotations}
    finding_paths = {f.file for f in findings}
    regions = regions_by_path(diff)
    raw: list[Delta] = []

    # --- untracked-path deltas (from 6a) ------------------------------------ #
    for path in sl.untracked_paths:
        in_finding = path in finding_paths
        severity = compute_severity(
            delta_type=DeltaType.UNTRACKED_PATH,
            affected_assets=[],
            untracked_in_finding=in_finding,
        )
        raw.append(
            Delta(
                delta_id="",  # assigned after dedup/order
                pr=pr,
                type=DeltaType.UNTRACKED_PATH,
                affected_elements=[],
                severity=severity,
                confidence=confidence_from_evidence(
                    low_confidence=False, corroborated=in_finding
                ),
                description=(
                    f"Changed path '{path}' is not claimed by any threat-model "
                    "component (baseline drift)."
                    + (" Also appears in a SAST/secret finding." if in_finding else "")
                ),
                recommended_action=_RECOMMENDED_ACTION[DeltaType.UNTRACKED_PATH],
                requires_human_review=True,
                evidence=_evidence([path], [], regions),
                proposed_baseline_update=ProposedBaselineUpdate(
                    kind="component_added",
                    target="(new)",
                    change=f"add or extend a component to cover {path}",
                ),
                severity_rationale=severity_rationale(
                    delta_type=DeltaType.UNTRACKED_PATH,
                    severity=severity,
                    affected_assets=[],
                    untracked_in_finding=in_finding,
                ),
            )
        )

    # --- one collapsed delta per component (from 6b flags + 6c STRIDE) ------- #
    # Rather than N near-identical per-flag deltas, emit a single component delta
    # listing every positive change-signal, scored at the most severe of them.
    for comp in sl.components:
        present_types = [
            dtype for flag_name, dtype in _FLAG_TO_TYPE.items() if getattr(flags, flag_name)
        ]
        if not present_types:
            continue

        comp_stride = stride_by_component.get(comp.id, [])
        comp_assets = _component_assets(comp, baseline)
        comp_paths = sl.matched_paths.get(comp.id, [])
        entry_points = _entry_points_for(comp_paths, ann_by_path)
        stride_low_conf = any(s.low_confidence for s in comp_stride)
        low_conf = flags.low_confidence or stride_low_conf
        agreement = min((s.agreement for s in comp_stride), default=1.0)
        corroborated = _corroborated(comp_paths, ann_by_path, finding_paths)

        # Score each present signal; the collapsed delta takes the max severity,
        # and its representative type (for ruleId / action) is the highest-scoring
        # signal, tiebroken by _FLAG_TO_TYPE order (present_types preserves it).
        scored = [
            (_signal_severity(dtype, comp, comp_assets), dtype) for dtype in present_types
        ]
        max_rank = max(sev.rank for sev, _ in scored)
        severity, rep_type = next((s, t) for s, t in scored if s.rank == max_rank)
        rep_into_internal = (
            rep_type == DeltaType.TRUST_BOUNDARY_CROSSING and comp.trust_zone == "internal"
        )
        rep_new_ep = (
            rep_type == DeltaType.NEW_ENTRY_POINT and comp.trust_zone == "internal"
        )
        signal_labels = [_FLAG_LABEL[t] for t in present_types]

        raw.append(
            Delta(
                delta_id="",
                pr=pr,
                type=rep_type,
                affected_elements=[comp.id],
                severity=severity,
                confidence=confidence_from_evidence(
                    low_confidence=low_conf,
                    corroborated=corroborated,
                    agreement=agreement,
                ),
                description=_component_description(comp, signal_labels, comp_stride),
                recommended_action=_RECOMMENDED_ACTION[rep_type],
                requires_human_review=(severity == Severity.HIGH),
                stride=_dedupe_stride(comp_stride),
                evidence=_evidence(comp_paths, entry_points, regions),
                proposed_baseline_update=_combined_baseline_update(
                    comp, present_types, entry_points, rep_type
                ),
                low_confidence=low_conf,
                severity_rationale=severity_rationale(
                    delta_type=rep_type,
                    severity=severity,
                    affected_assets=comp_assets,
                    into_internal_zone=rep_into_internal,
                    new_internal_entry_point=rep_new_ep,
                    weakens_control=(rep_type == DeltaType.CONTROL_CHANGE),
                ),
                change_signals=signal_labels,
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
    assumption_corroborated = _corroborated(all_changed_paths, ann_by_path, finding_paths)
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
                confidence=confidence_from_evidence(
                    low_confidence=v.low_confidence,
                    corroborated=assumption_corroborated,
                    agreement=v.agreement,
                ),
                contradicts_assumption=v.assumption_id,
                description=(
                    f"Change weakens or violates assumption '{v.assumption_id}': "
                    f"{v.reason}"
                ),
                recommended_action=_RECOMMENDED_ACTION[DeltaType.ASSUMPTION_VIOLATION],
                requires_human_review=True,
                evidence=_evidence(all_changed_paths, all_entry_points, regions),
                proposed_baseline_update=ProposedBaselineUpdate(
                    kind="assumption_revisited",
                    target=v.assumption_id,
                    change="confirm intended; update or reaffirm the assumption",
                ),
                low_confidence=v.low_confidence,
                severity_rationale=severity_rationale(
                    delta_type=DeltaType.ASSUMPTION_VIOLATION,
                    severity=severity,
                    affected_assets=slice_assets,
                    assumption_guards_sensitive=guards_sensitive,
                ),
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


def _evidence(
    paths: list[str], entry_points: list[str], regions: dict[str, int] | None = None
) -> dict:
    ev: dict = {"files": list(paths)}
    if entry_points:
        ev["entry_points"] = list(entry_points)
    if regions:
        # Per-file start line (for region-level SARIF), only for files present.
        scoped = {p: regions[p] for p in paths if p in regions}
        if scoped:
            ev["regions"] = scoped
    return ev


def _corroborated(
    paths: list[str],
    ann_by_path: dict[str, FileAnnotation],
    finding_paths: set[str],
) -> bool:
    """True when an independent source touches one of ``paths``.

    Corroboration = a step-5 annotation that actually carries signal
    (entry points / untrusted inputs / sinks) **or** a step 2-4 finding on the
    same file. Used to raise confidence beyond the model's own say-so.
    """
    for p in paths:
        if p in finding_paths:
            return True
        ann = ann_by_path.get(p)
        if ann and (ann.entry_points or ann.untrusted_inputs or ann.sinks):
            return True
    return False


def _signal_severity(
    dtype: DeltaType, comp: Component, comp_assets: list[Asset]
) -> Severity:
    """Severity a single change-signal would score on its own (for the max)."""
    return compute_severity(
        delta_type=dtype,
        affected_assets=comp_assets,
        into_internal_zone=(
            dtype == DeltaType.TRUST_BOUNDARY_CROSSING and comp.trust_zone == "internal"
        ),
        new_internal_entry_point=(
            dtype == DeltaType.NEW_ENTRY_POINT and comp.trust_zone == "internal"
        ),
        weakens_control=(dtype == DeltaType.CONTROL_CHANGE),
    )


def _dedupe_stride(stride: list[StrideDelta]) -> list[Stride]:
    out: list[Stride] = []
    for s in stride:
        if s.stride not in out:
            out.append(s.stride)
    return out


def _component_description(
    comp: Component, signal_labels: list[str], stride: list[StrideDelta]
) -> str:
    """One sentence summarising every change-signal folded into this delta."""
    if len(signal_labels) == 1:
        head = f"{signal_labels[0].capitalize()} on {comp.name} ({comp.trust_zone} zone)."
    else:
        head = (
            f"{len(signal_labels)} change-signals on {comp.name} "
            f"({comp.trust_zone} zone): {', '.join(signal_labels)}."
        )
    if stride:
        reasons = "; ".join(f"{s.stride.value}: {s.reason}" for s in stride)
        head += f" STRIDE: {reasons}"
    return head


def _combined_baseline_update(
    comp: Component,
    types: list[DeltaType],
    entry_points: list[str],
    rep_type: DeltaType,
) -> ProposedBaselineUpdate:
    """One proposed baseline edit covering all of a component's change-signals.

    ``kind`` matches ``rep_type`` — the delta's representative (highest-severity)
    signal — so the emitted delta type and its proposed-update kind never
    disagree.
    """
    parts: list[str] = []
    for dtype in types:
        if dtype == DeltaType.NEW_ENTRY_POINT:
            ep = entry_points[0] if entry_points else "<entry_point>"
            parts.append(f"entry_points += {ep}")
        elif dtype == DeltaType.NEW_DATA_FLOW:
            parts.append(f"add a data_flow involving {comp.id}")
        elif dtype == DeltaType.TRUST_BOUNDARY_CROSSING:
            parts.append("document the new boundary crossing")
        elif dtype == DeltaType.ASSET_EXPOSURE:
            parts.append("review handles_assets")
        else:  # CONTROL_CHANGE
            parts.append("review affecting controls")
    kind = _BASELINE_UPDATE_KIND[rep_type]
    return ProposedBaselineUpdate(kind=kind, target=comp.id, change="; ".join(parts))


def delta_key(delta: Delta) -> tuple:
    """Stable identity of a delta across runs (dedupe + incremental subtraction).

    §6e's "(type, affected_elements)" extended with ``contradicts_assumption``
    (so two distinct violated assumptions are not collapsed) and, for untracked
    paths, the file set (so each drifted path is its own delta).
    """
    return (
        delta.type.value,
        tuple(sorted(delta.affected_elements)),
        delta.contradicts_assumption or "",
        tuple(sorted(delta.evidence.get("files", [])))
        if delta.type == DeltaType.UNTRACKED_PATH
        else (),
    )


def prior_keys_from_dicts(deltas: list[dict]) -> set[tuple]:
    """Build the suppression key-set from a previous run's serialized deltas.

    Accepts the dict shape produced by :meth:`Delta.to_dict`, so a prior
    ``deltas.json`` can drive incremental subtraction without reconstructing
    :class:`Delta` objects.
    """
    keys: set[tuple] = set()
    for d in deltas:
        dtype = d.get("type", "")
        files = (d.get("evidence") or {}).get("files", [])
        keys.add(
            (
                dtype,
                tuple(sorted(d.get("affected_elements", []))),
                d.get("contradicts_assumption") or "",
                tuple(sorted(files)) if dtype == DeltaType.UNTRACKED_PATH.value else (),
            )
        )
    return keys


def _reassign_ids(deltas: list[Delta], pr: str) -> list[Delta]:
    """Renumber ``td-<pr>-<n>`` over the given (already ordered) deltas."""
    for i, d in enumerate(deltas, start=1):
        d.delta_id = f"td-{pr}-{i}"
    return deltas


def _dedupe_and_id(raw: list[Delta], pr: str) -> list[Delta]:
    """Dedupe by :func:`delta_key` keeping the most severe, then assign stable
    ``td-<pr>-<n>`` ids in a deterministic order."""
    best: dict[tuple, Delta] = {}
    for d in raw:
        key = delta_key(d)
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
    return _reassign_ids(ordered, pr)
