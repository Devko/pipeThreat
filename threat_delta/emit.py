"""Stage 6e — output emitters: SARIF log and PR comment (spec §6e, §8, §9).

This step is *advisory / non-blocking* (spec §9): it must never fail a build.
Accordingly the SARIF ``level`` mapping never uses ``"error"`` — high/medium map
to ``"warning"`` and low maps to ``"note"``. The PR comment groups deltas by
severity and surfaces, per delta, the type, affected element(s), STRIDE
categories, the contradicted assumption (if any), and the recommended action.

These are pure functions over ``list[Delta]``; only :func:`write_outputs`
performs I/O.
"""

from __future__ import annotations

import json

from .models import Confidence, Delta, DeltaType, Severity


# Delta types that describe a component change (the "root cause" of the
# assumption violations that ride along with it).
_COMPONENT_TYPES = frozenset(
    {
        DeltaType.NEW_ENTRY_POINT,
        DeltaType.TRUST_BOUNDARY_CROSSING,
        DeltaType.CONTROL_CHANGE,
        DeltaType.ASSET_EXPOSURE,
        DeltaType.NEW_DATA_FLOW,
    }
)

_CONFIDENCE_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/"
    "schema/sarif-schema-2.1.0.json"
)


# --------------------------------------------------------------------------- #
# Level mapping (spec §9 — never block the build)
# --------------------------------------------------------------------------- #

def _sarif_level(severity: Severity) -> str:
    """Map severity to a SARIF level (spec §9: advisory — never ``"error"``).

    high -> "warning", medium -> "warning", low -> "note".
    """
    if severity == Severity.LOW:
        return "note"
    # HIGH and MEDIUM both map to "warning" so the run is never failing.
    return "warning"


# --------------------------------------------------------------------------- #
# SARIF (spec §6e, §8)
# --------------------------------------------------------------------------- #

def _rules_for(deltas: list[Delta]) -> list[dict]:
    """One unique rule per distinct ``delta.type`` (in first-seen order)."""
    rules: list[dict] = []
    seen: set[str] = set()
    for delta in deltas:
        rule_id = delta.type.value
        if rule_id in seen:
            continue
        seen.add(rule_id)
        name = "".join(part.capitalize() for part in rule_id.split("_"))
        rules.append(
            {
                "id": rule_id,
                "name": name,
                "shortDescription": {"text": rule_id.replace("_", " ")},
                "defaultConfiguration": {"level": _sarif_level(delta.severity)},
                "helpUri": (
                    "https://github.com/Devko/pipeThreat/blob/main/docs/"
                    f"deltas.md#{rule_id}"
                ),
            }
        )
    return rules


def _locations_for(delta: Delta) -> list[dict]:
    """One physicalLocation per file in ``delta.evidence['files']``.

    When the diff gave us a hunk start line (``evidence['regions']``), the
    location carries a ``region`` so the finding anchors to the changed lines in
    the PR diff rather than the whole file.
    """
    if not delta.evidence:
        return []
    files = delta.evidence.get("files", [])
    regions = delta.evidence.get("regions", {})
    locations: list[dict] = []
    for file in files:
        physical: dict = {"artifactLocation": {"uri": file}}
        if file in regions:
            physical["region"] = {"startLine": regions[file]}
        locations.append({"physicalLocation": physical})
    return locations


def _result_properties(delta: Delta) -> dict:
    """The per-result properties bag (spec §8 fields)."""
    props: dict = {
        "severity": delta.severity.value,
        "confidence": delta.confidence.value,
        "stride": [s.value for s in delta.stride],
        "contradicts_assumption": delta.contradicts_assumption,
        "requires_human_review": delta.requires_human_review,
        "affected_elements": list(delta.affected_elements),
        "recommended_action": delta.recommended_action,
    }
    if delta.severity_rationale:
        props["severity_rationale"] = delta.severity_rationale
    if delta.change_signals:
        props["change_signals"] = list(delta.change_signals)
    if delta.proposed_baseline_update is not None:
        props["proposed_baseline_update"] = delta.proposed_baseline_update.to_dict()
    if delta.low_confidence:
        props["low_confidence"] = True
    return props


def build_sarif(
    deltas: list[Delta],
    *,
    tool_name: str = "threat-model-delta",
    info_uri: str = "https://github.com/Devko/pipeThreat",
) -> dict:
    """Build a SARIF 2.1.0 log from the deltas (spec §6e, §8).

    One ``result`` per delta; ``ruleId`` is the delta type; ``level`` is the
    advisory mapping (warning/note, never error). ``tool.driver.rules`` holds one
    deduped rule per distinct type. ``partialFingerprints`` carries the
    ``delta_id`` for stable dedupe across runs.
    """
    results: list[dict] = []
    for delta in deltas:
        results.append(
            {
                "ruleId": delta.type.value,
                "level": _sarif_level(delta.severity),
                "message": {"text": delta.description},
                "locations": _locations_for(delta),
                "partialFingerprints": {"deltaId": delta.delta_id},
                "properties": _result_properties(delta),
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "informationUri": info_uri,
                        "rules": _rules_for(deltas),
                    }
                },
                "results": results,
            }
        ],
    }


# --------------------------------------------------------------------------- #
# PR comment (spec §9)
# --------------------------------------------------------------------------- #

_SEVERITY_SECTIONS = (
    (Severity.HIGH, "High"),
    (Severity.MEDIUM, "Medium"),
    (Severity.LOW, "Low"),
)

_NO_DELTAS = "No threat-model deltas detected."

_ADVISORY_HEADER = (
    "## Threat-Model Delta (advisory)\n\n"
    "_This check is advisory and **non-blocking** — it never fails the build._"
)


def _format_delta(delta: Delta) -> str:
    """Render one delta as a Markdown sub-block (spec §9 fields)."""
    elements = ", ".join(f"`{e}`" for e in delta.affected_elements) or "_(none)_"
    lines: list[str] = []
    title = f"- **{delta.type.value}** — affected: {elements}"
    if delta.requires_human_review:
        title += "  :warning: **needs human review**"
    lines.append(title)

    if delta.change_signals and len(delta.change_signals) > 1:
        lines.append(f"  - Change signals: {', '.join(delta.change_signals)}")
    stride = ", ".join(s.value for s in delta.stride)
    if stride:
        lines.append(f"  - STRIDE: {stride}")
    if delta.contradicts_assumption:
        lines.append(f"  - Contradicts assumption: `{delta.contradicts_assumption}`")

    confidence = delta.confidence.value
    if delta.low_confidence:
        confidence += " (low confidence)"
    lines.append(f"  - Confidence: {confidence}")
    if delta.severity_rationale:
        lines.append(f"  - Why {delta.severity.value}: {delta.severity_rationale}")

    if delta.description:
        lines.append(f"  - {delta.description}")
    if delta.recommended_action:
        lines.append(f"  - Recommended action: {delta.recommended_action}")
    if delta.proposed_baseline_update is not None:
        upd = delta.proposed_baseline_update
        lines.append(
            f"  - Proposed baseline update: {upd.kind} `{upd.target}` — {upd.change}"
        )
    return "\n".join(lines)


def _component_delta_index(deltas: list[Delta]) -> dict[str, Delta]:
    """Map component id -> its change delta (the root-cause anchor)."""
    index: dict[str, Delta] = {}
    for d in deltas:
        if d.type in _COMPONENT_TYPES and d.affected_elements:
            index.setdefault(d.affected_elements[0], d)
    return index


def _assumption_reason(delta: Delta) -> str:
    """The bare reason from an assumption-violation description.

    Descriptions read ``Change weakens or violates assumption 'X': <reason>``;
    strip the boilerplate prefix so the consolidated list stays scannable.
    """
    marker = "': "
    i = delta.description.find(marker)
    return delta.description[i + len(marker):] if i != -1 else delta.description


def _format_assumption_group(members: list[Delta], comp_index: dict[str, Delta]) -> str:
    """Render several assumption violations on one component as a single block.

    Turns N parallel ``assumption_violation`` deltas (which all stem from one
    change) into a single finding that names the root cause once and lists the
    contradicted assumptions as consequences — so a reviewer reads one issue, not
    five look-alikes.
    """
    affected_ids = sorted({e for d in members for e in d.affected_elements})
    elements = ", ".join(f"`{e}`" for e in affected_ids) or "_(none)_"
    title = f"- **contradicted assumptions ({len(members)})** — affected: {elements}"
    if any(d.requires_human_review for d in members):
        title += "  :warning: **needs human review**"
    lines = [title]

    # Root cause: the co-located component change, named once.
    comp = next((comp_index[e] for e in affected_ids if e in comp_index), None)
    if comp is not None:
        signal = comp.change_signals[0] if comp.change_signals else comp.type.value.replace("_", " ")
        lines.append(f"  - Root cause: {signal} on `{comp.affected_elements[0]}`")

    conf = min(members, key=lambda d: _CONFIDENCE_RANK[d.confidence]).confidence
    conf_text = conf.value + (" (low confidence)" if any(d.low_confidence for d in members) else "")
    lines.append(f"  - Confidence: {conf_text}")

    for d in members:
        reason = _assumption_reason(d)
        lines.append(f"  - `{d.contradicts_assumption}`" + (f" — {reason}" if reason else ""))
    lines.append(f"  - Recommended action: {members[0].recommended_action}")
    return "\n".join(lines)


def _format_section(group: list[Delta], comp_index: dict[str, Delta]) -> str:
    """Render one severity section, consolidating parallel assumption violations.

    Component/untracked deltas render individually first (the change that was
    made); assumption violations that share a component collapse into one
    ``contradicted assumptions`` block (the consequences of that change).
    """
    others = [d for d in group if d.type != DeltaType.ASSUMPTION_VIOLATION]
    assumptions = [d for d in group if d.type == DeltaType.ASSUMPTION_VIOLATION]

    blocks = [_format_delta(d) for d in others]

    by_component: dict[tuple, list[Delta]] = {}
    for d in assumptions:
        by_component.setdefault(tuple(sorted(d.affected_elements)), []).append(d)
    for members in by_component.values():
        if len(members) >= 2:
            blocks.append(_format_assumption_group(members, comp_index))
        else:
            blocks.append(_format_delta(members[0]))
    return "\n".join(blocks)


def build_comment(deltas: list[Delta]) -> str:
    """Render the PR comment grouping deltas by severity (spec §9).

    Within each severity band, several assumption violations that stem from one
    component change are consolidated into a single root-caused block, so a
    reviewer sees one issue with its consequences instead of a wall of
    near-identical findings.
    """
    if not deltas:
        return f"{_ADVISORY_HEADER}\n\n{_NO_DELTAS}"

    parts: list[str] = [_ADVISORY_HEADER]
    comp_index = _component_delta_index(deltas)

    for severity, label in _SEVERITY_SECTIONS:
        group = [d for d in deltas if d.severity == severity]
        if not group:
            continue
        parts.append(f"### {label} ({len(group)})")
        parts.append(_format_section(group, comp_index))

    # Footer: counts + the security/needs-review label hook (spec §9).
    counts = {
        label: sum(1 for d in deltas if d.severity == sev)
        for sev, label in _SEVERITY_SECTIONS
    }
    summary = ", ".join(f"{label}: {counts[label]}" for _, label in _SEVERITY_SECTIONS)
    footer = f"---\n**{len(deltas)} delta(s)** — {summary}."

    needs_review = any(
        d.severity == Severity.HIGH and d.requires_human_review for d in deltas
    )
    if needs_review:
        footer += (
            "\n\nA high-severity delta needs human review — apply the "
            "`security/needs-review` label."
        )
    parts.append(footer)

    return "\n\n".join(parts)


# --------------------------------------------------------------------------- #
# Convenience I/O (used by the CLI)
# --------------------------------------------------------------------------- #

def write_outputs(deltas: list[Delta], sarif_path: str, comment_path: str) -> None:
    """Write the SARIF JSON and the Markdown comment to disk (spec §6e)."""
    with open(sarif_path, "w", encoding="utf-8") as fh:
        json.dump(build_sarif(deltas), fh, indent=2)
    with open(comment_path, "w", encoding="utf-8") as fh:
        fh.write(build_comment(deltas))
