"""Stage 6a — deterministic relevance resolution.

Given a parsed :class:`~threat_delta.models.Diff` and the loaded
:class:`~threat_delta.baseline.Baseline`, resolve the changed paths to the
*slice* of baseline elements they affect (spec §6a). This slice bounds all
context handed to the later (LLM-driven) stages, so it must be deterministic:
elements are emitted in the baseline's declared order with no reliance on set
iteration order.
"""

from __future__ import annotations

import re

from .baseline import Baseline
from .models import (
    Asset,
    Assumption,
    Component,
    DataFlow,
    Diff,
    Slice,
    TrustBoundary,
)


# --------------------------------------------------------------------------- #
# Glob matching
# --------------------------------------------------------------------------- #

def _glob_to_regex(pattern: str) -> str:
    """Translate a path glob into a regex.

    Supports ``**`` (spanning directory separators), and ``*``/``?`` within a
    single path segment. ``**/`` and a trailing ``/**`` are handled so they may
    match zero path components.
    """
    i = 0
    n = len(pattern)
    out: list[str] = ["^"]
    while i < n:
        c = pattern[i]
        if c == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                # `**` — consume it, and an optional following slash.
                j = i + 2
                if j < n and pattern[j] == "/":
                    # `**/` matches any number of leading dirs (incl. none).
                    out.append("(?:.*/)?")
                    i = j + 1
                else:
                    # bare `**` or trailing `**` — match anything.
                    out.append(".*")
                    i = j
            else:
                # single `*` — match within a segment (no separator).
                out.append("[^/]*")
                i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    out.append("$")
    return "".join(out)


def path_matches(path: str, pattern: str) -> bool:
    """Return ``True`` if ``path`` matches glob ``pattern`` (``**``-aware)."""
    return re.match(_glob_to_regex(pattern), path) is not None


# --------------------------------------------------------------------------- #
# Slice resolution (6a)
# --------------------------------------------------------------------------- #

def resolve_slice(diff: Diff, baseline: Baseline) -> Slice:
    """Resolve a diff to the affected baseline slice (spec §6a).

    Each changed path is matched against every component's ``code_paths`` globs.
    Matched components pull in the data-flows that reference them, the trust
    boundaries those flows cross, and the assets the components handle. All
    assumptions are always included (they are checked exhaustively in 6d).
    Unmatched paths are recorded as ``untracked_paths``.
    """
    affected_components: set[str] = set()
    matched_paths: dict[str, list[str]] = {}
    untracked: list[str] = []

    for path in diff.paths:
        hit = False
        for component in baseline.components:
            if any(path_matches(path, pat) for pat in component.code_paths):
                hit = True
                affected_components.add(component.id)
                matched_paths.setdefault(component.id, [])
                if path not in matched_paths[component.id]:
                    matched_paths[component.id].append(path)
        if not hit and path not in untracked:
            untracked.append(path)

    # Components — emit in declared order.
    components: list[Component] = [
        c for c in baseline.components if c.id in affected_components
    ]

    # Data flows referencing any affected component (from_ or to).
    affected_flow_ids: set[str] = set()
    data_flows: list[DataFlow] = []
    for flow in baseline.data_flows:
        if flow.from_ in affected_components or flow.to in affected_components:
            affected_flow_ids.add(flow.id)
            data_flows.append(flow)

    # Trust boundaries crossed by the matched data flows.
    crossed_boundary_ids: set[str] = set()
    for flow in data_flows:
        crossed_boundary_ids.update(flow.crosses)
    trust_boundaries: list[TrustBoundary] = [
        b for b in baseline.trust_boundaries if b.id in crossed_boundary_ids
    ]

    # Assets handled by the affected components (resolved via id map).
    handled_asset_ids: set[str] = set()
    for component in components:
        handled_asset_ids.update(component.handles_assets)
    assets: list[Asset] = [
        a for a in baseline.assets if a.id in handled_asset_ids
    ]

    # All assumptions, in declared order (spec: always included in full).
    assumptions: list[Assumption] = list(baseline.assumptions)

    return Slice(
        components=components,
        trust_boundaries=trust_boundaries,
        data_flows=data_flows,
        assets=assets,
        assumptions=assumptions,
        untracked_paths=untracked,
        matched_paths=matched_paths,
    )
