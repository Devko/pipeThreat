"""Prompt templates for the model-driven stages (Stages 2/3/4).

Pure string builders — no LLM calls, no I/O. Each renders one of the prompt
bodies by filling placeholders with a compact, *data-only* projection
of the baseline slice, the static-analysis annotations and the diff.

Prompt-injection mitigation: every value derived from a diff, an
annotation, an assumption statement or any other untrusted source is included
verbatim **as data**, under a clearly labelled section header, and is never
concatenated into the prompt as if it were an instruction. The section labels
below ("Diff summary:", "Changed entry points / inputs / sinks:", ...) are the
delimiters that separate trusted instructions from untrusted data.
"""

from __future__ import annotations

from .models import (
    Assumption,
    Component,
    Diff,
    FileAnnotation,
    Flags,
    Slice,
)


# --------------------------------------------------------------------------- #
# Section / field formatters (data-only projections)
# --------------------------------------------------------------------------- #

def _fmt_list(values) -> str:
    """Render a sequence of ids as ``[a, b]`` (``[]`` when empty)."""
    return "[" + ", ".join(str(v) for v in values) + "]"


def format_slice_refs(slice: Slice) -> str:
    """Compact id+name+ref lines for the affected threat-model elements.

    Emits one line per component, trust boundary and asset (and data flow) —
    ids, names and zone/handles/entry-point *references* only, never full
    prose — so the model sees the structure of the slice without burning the
    context budget.
    """
    lines: list[str] = []
    for c in slice.components:
        lines.append(
            f"comp.{c.id} ({c.name}) zone={c.trust_zone} "
            f"handles={_fmt_list(c.handles_assets)} "
            f"entry_points={_fmt_list(c.entry_points)}"
        )
    for b in slice.trust_boundaries:
        lines.append(f"boundary.{b.id} ({b.name})")
    for a in slice.assets:
        lines.append(f"asset.{a.id} ({a.name}) sensitivity={a.sensitivity.value}")
    for f in slice.data_flows:
        lines.append(
            f"dataflow.{f.id} ({f.from_} -> {f.to}) "
            f"crosses={_fmt_list(f.crosses)} assets={_fmt_list(f.assets)}"
        )
    return "\n".join(lines) if lines else "(none)"


def format_annotations(annotations: list[FileAnnotation]) -> str:
    """One ``path: entry_points=[...] untrusted_inputs=[...] sinks=[...]`` line
    per annotated file (static-analysis output). ``(none)`` when there are none."""
    if not annotations:
        return "(none)"
    lines = []
    for a in annotations:
        lines.append(
            f"{a.path}: entry_points={_fmt_list(a.entry_points)} "
            f"untrusted_inputs={_fmt_list(a.untrusted_inputs)} "
            f"sinks={_fmt_list(a.sinks)}"
        )
    return "\n".join(lines)


def format_diff_summary(diff: Diff) -> str:
    """Per-file path plus its hunk headers — never the full hunk bodies.

    Keeps the classification/assumption prompts short; the full hunk text is
    only ever sent to the per-component STRIDE stage (Stage 3), and even there it is
    capped (see :func:`stride.stride_deltas`).
    """
    if not diff.files:
        return "(none)"
    lines = []
    for f in diff.files:
        lines.append(f"{f.path}")
        for h in f.hunks:
            header = (h.header or "").strip()
            if header:
                lines.append(f"  {header}")
    return "\n".join(lines)


def format_assumptions(assumptions: list[Assumption]) -> str:
    """Numbered ``id: statement`` lines (Stage 4 input). ``(none)`` if empty."""
    if not assumptions:
        return "(none)"
    return "\n".join(
        f"{i}. {a.id}: {a.statement}" for i, a in enumerate(assumptions, start=1)
    )


# --------------------------------------------------------------------------- #
# Prompt bodies
# --------------------------------------------------------------------------- #

def classification_prompt(
    slice: Slice,
    diff: Diff,
    annotations: list[FileAnnotation],
) -> str:
    """Stage 2 — delta-type classification prompt body."""
    return (
        "Affected threat-model elements:\n"
        f"{format_slice_refs(slice)}\n"
        "\n"
        "Changed entry points / inputs / sinks (from static analysis):\n"
        f"{format_annotations(annotations)}\n"
        "\n"
        "Diff summary:\n"
        f"{format_diff_summary(diff)}\n"
        "\n"
        "For each category, is it plausibly introduced or changed by this diff?\n"
        'Output JSON: {"new_entry_point":bool,"new_data_flow":bool,'
        '"trust_boundary_crossing":bool,"asset_handling_change":bool,'
        '"control_change":bool}'
    )


def _positive_flag_names(flags: Flags) -> list[str]:
    names = []
    if flags.new_entry_point:
        names.append("new_entry_point")
    if flags.new_data_flow:
        names.append("new_data_flow")
    if flags.trust_boundary_crossing:
        names.append("trust_boundary_crossing")
    if flags.asset_handling_change:
        names.append("asset_handling_change")
    if flags.control_change:
        names.append("control_change")
    return names


def _signals_section(signals: list[str] | None) -> str:
    """Optional labelled data block of deterministic grounding facts (Stages 3/4)."""
    if not signals:
        return ""
    body = "\n".join(f"- {s}" for s in signals)
    return f"Deterministic signals (facts from static analysis):\n{body}\n\n"


def stride_prompt(
    component: Component,
    hunk_text: str,
    flags: Flags,
    signals: list[str] | None = None,
) -> str:
    """Stage 3 — per-component STRIDE delta prompt body."""
    return (
        f"Component: {component.id} (zone: {component.trust_zone}, "
        f"handles: {_fmt_list(component.handles_assets)}, "
        f"entry points: {_fmt_list(component.entry_points)})\n"
        f"Positive change flags: {_fmt_list(_positive_flag_names(flags))}\n"
        "\n"
        f"{_signals_section(signals)}"
        "Relevant code change:\n"
        f"{hunk_text}\n"
        "\n"
        "Which STRIDE categories does THIS change newly introduce or worsen for "
        "THIS component? Only categories the change actually affects.\n"
        'Output JSON: {"deltas":[{"stride":"Spoofing|Tampering|Repudiation|'
        'InformationDisclosure|DenialOfService|ElevationOfPrivilege",'
        '"reason":"<=20 words"}]}'
    )


def assumption_prompt(
    assumptions: list[Assumption],
    diff: Diff,
    annotations: list[FileAnnotation],
    signals: list[str] | None = None,
) -> str:
    """Stage 4 — batched assumption-violation prompt body (all assumptions at once)."""
    return (
        "Stated security assumptions:\n"
        f"{format_assumptions(assumptions)}\n"
        "\n"
        "Changed entry points / inputs / sinks:\n"
        f"{format_annotations(annotations)}\n"
        "\n"
        f"{_signals_section(signals)}"
        "Diff summary:\n"
        f"{format_diff_summary(diff)}\n"
        "\n"
        "For each assumption, does this change violate or weaken it?\n"
        'Output JSON: {"violations":[{"assumption_id":"...","violated":bool,'
        '"reason":"<=20 words"}]}  (include only violated:true entries)'
    )


def assumption_prompt_single(
    assumption: Assumption,
    diff: Diff,
    annotations: list[FileAnnotation],
    signals: list[str] | None = None,
) -> str:
    """Stage 4 — single-assumption prompt body (one bounded call per assumption).

    Fanning out one assumption per call keeps the question narrow, which a small
    local model answers far more reliably than a batched "judge this whole list"
    prompt (batching silently drops items). The assumption id is echoed back so a
    deterministic stub can key on it.
    """
    return (
        f"Stated security assumption:\n{assumption.id}: {assumption.statement}\n"
        "\n"
        "Changed entry points / inputs / sinks:\n"
        f"{format_annotations(annotations)}\n"
        "\n"
        f"{_signals_section(signals)}"
        "Diff summary:\n"
        f"{format_diff_summary(diff)}\n"
        "\n"
        f"Considering ONLY assumption '{assumption.id}', does this change violate "
        "or weaken it?\n"
        'Output JSON: {"assumption_id":"'
        f"{assumption.id}"
        '","violated":bool,"reason":"<=20 words"}'
    )
