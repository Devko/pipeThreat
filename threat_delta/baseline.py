"""Load and index the human-authored threat-model baseline (threat-model.yaml).

The baseline is the *context* for the whole step (spec §3). It is loaded once,
validated, and exposed as a :class:`Baseline` with id->element lookup maps so the
deterministic relevance stage (6a) can resolve a diff to the elements it affects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Union

import yaml

from .models import (
    AcceptedRisk,
    Asset,
    Assumption,
    Component,
    DataFlow,
    Sensitivity,
    System,
    TrustBoundary,
)


class BaselineError(ValueError):
    """Raised when threat-model.yaml is missing required structure."""


@dataclass
class Baseline:
    system: System
    assets: list[Asset] = field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    data_flows: list[DataFlow] = field(default_factory=list)
    assumptions: list[Assumption] = field(default_factory=list)
    accepted_risks: list[AcceptedRisk] = field(default_factory=list)

    # id -> element lookup maps, built in __post_init__
    assets_by_id: dict[str, Asset] = field(default_factory=dict, repr=False)
    boundaries_by_id: dict[str, TrustBoundary] = field(default_factory=dict, repr=False)
    components_by_id: dict[str, Component] = field(default_factory=dict, repr=False)
    flows_by_id: dict[str, DataFlow] = field(default_factory=dict, repr=False)
    assumptions_by_id: dict[str, Assumption] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self.assets_by_id = {a.id: a for a in self.assets}
        self.boundaries_by_id = {b.id: b for b in self.trust_boundaries}
        self.components_by_id = {c.id: c for c in self.components}
        self.flows_by_id = {f.id: f for f in self.data_flows}
        self.assumptions_by_id = {a.id: a for a in self.assumptions}

    @property
    def all_ids(self) -> set[str]:
        """Every element id in the baseline — used to drop deltas that reference
        ids which do not exist (hallucination guard, spec §11)."""
        return (
            set(self.assets_by_id)
            | set(self.boundaries_by_id)
            | set(self.components_by_id)
            | set(self.flows_by_id)
            | set(self.assumptions_by_id)
        )


def _require(mapping: dict, key: str, ctx: str) -> object:
    if key not in mapping:
        raise BaselineError(f"{ctx}: missing required key '{key}'")
    return mapping[key]


def _as_tuple(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value)
    return (str(value),)


def parse_baseline(data: dict) -> Baseline:
    """Build a :class:`Baseline` from already-parsed YAML/JSON data."""
    if not isinstance(data, dict):
        raise BaselineError("baseline root must be a mapping")

    sys_raw = _require(data, "system", "baseline")
    if not isinstance(sys_raw, dict):
        raise BaselineError("baseline.system must be a mapping")
    system = System(
        name=str(_require(sys_raw, "name", "system")),
        version=str(sys_raw.get("version", "")),
        description=str(sys_raw.get("description", "")),
    )

    assets = []
    for a in data.get("assets", []) or []:
        sens_raw = str(_require(a, "sensitivity", f"asset {a.get('id')}")).lower()
        try:
            sensitivity = Sensitivity(sens_raw)
        except ValueError:
            raise BaselineError(
                f"asset {a.get('id')}: invalid sensitivity '{sens_raw}'"
            )
        assets.append(
            Asset(
                id=str(_require(a, "id", "asset")),
                name=str(a.get("name", a.get("id"))),
                sensitivity=sensitivity,
            )
        )

    boundaries = [
        TrustBoundary(
            id=str(_require(b, "id", "trust_boundary")),
            name=str(b.get("name", b.get("id"))),
            description=str(b.get("description", "")),
            controls=_as_tuple(b.get("controls")),
        )
        for b in data.get("trust_boundaries", []) or []
    ]

    components = [
        Component(
            id=str(_require(c, "id", "component")),
            name=str(c.get("name", c.get("id"))),
            trust_zone=str(c.get("trust_zone", "")),
            code_paths=_as_tuple(c.get("code_paths")),
            handles_assets=_as_tuple(c.get("handles_assets")),
            entry_points=_as_tuple(c.get("entry_points")),
        )
        for c in data.get("components", []) or []
    ]

    flows = [
        DataFlow(
            id=str(_require(f, "id", "data_flow")),
            from_=str(_require(f, "from", "data_flow")),
            to=str(_require(f, "to", "data_flow")),
            crosses=_as_tuple(f.get("crosses")),
            assets=_as_tuple(f.get("assets")),
        )
        for f in data.get("data_flows", []) or []
    ]

    assumptions = [
        Assumption(
            id=str(_require(a, "id", "assumption")),
            statement=str(_require(a, "statement", "assumption")),
        )
        for a in data.get("assumptions", []) or []
    ]

    accepted_risks = [
        AcceptedRisk(
            id=str(_require(r, "id", "accepted_risk")),
            statement=str(_require(r, "statement", "accepted_risk")),
        )
        for r in data.get("accepted_risks", []) or []
    ]

    return Baseline(
        system=system,
        assets=assets,
        trust_boundaries=boundaries,
        components=components,
        data_flows=flows,
        assumptions=assumptions,
        accepted_risks=accepted_risks,
    )


def load_baseline(path: Union[str, Path]) -> Baseline:
    """Load and parse threat-model.yaml from disk."""
    p = Path(path)
    if not p.exists():
        raise BaselineError(f"baseline file not found: {p}")
    with p.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return parse_baseline(data or {})
