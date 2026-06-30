"""Baseline-coverage report — how completely a baseline's component
``code_paths`` cover a repository's source files (spec §6a / §10).

This is a deterministic, no-LLM measurement of *baseline completeness*: it
answers "which source files does the threat-model baseline already account for,
and which fall through the cracks?". Closing those gaps deliberately (by adding
``code_paths`` to components) is preferable to discovering them only as
``untracked_path`` drift on individual PRs (spec §10).

Glob matching is reused from :func:`threat_delta.relevance.path_matches`; this
module never reimplements it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Union

from .baseline import Baseline
from .relevance import path_matches


# Directory names pruned during a source-tree walk by default.
DEFAULT_IGNORE_DIRS: frozenset[str] = frozenset({
    ".git",
    ".github",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".pytest_cache",
    ".idea",
    ".vscode",
    ".eggs",
})

# Cap for the number of uncovered paths listed by ``format_report``.
_UNCOVERED_LISTING_CAP = 50


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #

@dataclass
class CoverageReport:
    """Result of :func:`compute_coverage` (spec §6a / §10)."""

    # component_id -> matched source paths (sorted, deduplicated)
    covered: dict[str, list[str]] = field(default_factory=dict)
    # source paths matched by NO component (sorted)
    uncovered: list[str] = field(default_factory=list)
    # component ids whose code_paths matched zero files (sorted)
    empty_components: list[str] = field(default_factory=list)
    # number of distinct input paths
    total_paths: int = 0

    @property
    def covered_count(self) -> int:
        """Distinct source paths matched by at least one component.

        A path is counted once even if it matches several components.
        """
        covered_paths: set[str] = set()
        for paths in self.covered.values():
            covered_paths.update(paths)
        return len(covered_paths)

    @property
    def coverage_ratio(self) -> float:
        """Fraction of input paths covered (0.0 when there are no paths)."""
        if self.total_paths == 0:
            return 0.0
        return self.covered_count / self.total_paths

    def to_dict(self) -> dict:
        return {
            "covered": {cid: list(paths) for cid, paths in self.covered.items()},
            "uncovered": list(self.uncovered),
            "empty_components": list(self.empty_components),
            "total_paths": self.total_paths,
            "covered_count": self.covered_count,
            "coverage_ratio": self.coverage_ratio,
        }


# --------------------------------------------------------------------------- #
# Coverage computation
# --------------------------------------------------------------------------- #

def compute_coverage(baseline: Baseline, paths: list[str]) -> CoverageReport:
    """Report how completely ``baseline`` covers ``paths`` (spec §6a / §10).

    Each distinct path is tested against every component's ``code_paths`` globs
    via :func:`threat_delta.relevance.path_matches`. A path is *covered* if it
    matches at least one component (and is recorded under each matching
    component). Paths matching no component become ``uncovered``. Components that
    match no path at all become ``empty_components``. All lists are deduplicated
    and sorted; ``total_paths`` counts distinct input paths.
    """
    distinct_paths = sorted(set(paths))

    covered: dict[str, list[str]] = {}
    uncovered: list[str] = []

    for path in distinct_paths:
        matched_any = False
        for component in baseline.components:
            if any(path_matches(path, pat) for pat in component.code_paths):
                matched_any = True
                covered.setdefault(component.id, []).append(path)
        if not matched_any:
            uncovered.append(path)

    # Per-component path lists are already sorted (distinct_paths is sorted and
    # iterated in order), but sort defensively to honour the contract.
    for cid in covered:
        covered[cid] = sorted(set(covered[cid]))

    empty_components = sorted(
        c.id for c in baseline.components if c.id not in covered
    )

    return CoverageReport(
        covered=covered,
        uncovered=sorted(uncovered),
        empty_components=empty_components,
        total_paths=len(distinct_paths),
    )


# --------------------------------------------------------------------------- #
# Source discovery
# --------------------------------------------------------------------------- #

def collect_source_paths(
    root: Union[str, Path],
    *,
    ignore: Optional[Iterable[str]] = None,
    extensions: Optional[Iterable[str]] = None,
) -> list[str]:
    """Walk ``root`` and return repo-relative POSIX source paths, sorted.

    Pruned directory names default to :data:`DEFAULT_IGNORE_DIRS` (plus any
    ``*.egg-info`` directory and any hidden directory whose name starts with
    ``.``). When ``extensions`` is given (e.g. ``{".py", ".js"}``) only files
    with those suffixes are returned; otherwise every file is included. Returned
    paths are relative to ``root`` with forward slashes regardless of OS.
    """
    root_path = Path(root)
    ignore_dirs = set(ignore) if ignore is not None else set(DEFAULT_IGNORE_DIRS)
    exts = set(extensions) if extensions is not None else None

    results: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        # Prune ignored / hidden / *.egg-info directories in-place.
        dirnames[:] = [
            d for d in dirnames
            if d not in ignore_dirs
            and not d.startswith(".")
            and not d.endswith(".egg-info")
        ]
        for name in filenames:
            if exts is not None and Path(name).suffix not in exts:
                continue
            abs_path = Path(dirpath) / name
            rel = abs_path.relative_to(root_path)
            results.append(rel.as_posix())

    return sorted(results)


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def format_report(report: CoverageReport, *, show_paths: bool = False) -> str:
    """Render a concise text summary of a :class:`CoverageReport`."""
    pct = report.coverage_ratio * 100
    lines = [
        f"Total source files:   {report.total_paths}",
        f"Covered files:        {report.covered_count}",
        f"Coverage:             {pct:.1f}%",
        f"Uncovered files:      {len(report.uncovered)}",
    ]
    if report.empty_components:
        lines.append("Empty components:     " + ", ".join(report.empty_components))
    else:
        lines.append("Empty components:     (none)")

    if show_paths and report.uncovered:
        lines.append("Uncovered paths:")
        shown = report.uncovered[:_UNCOVERED_LISTING_CAP]
        for path in shown:
            lines.append(f"  - {path}")
        remaining = len(report.uncovered) - len(shown)
        if remaining > 0:
            lines.append(f"  ... and {remaining} more")

    return "\n".join(lines)
