"""LLM-assisted scaffold mode — a one-time, offline, human-reviewed draft.

Authoring the *initial* baseline is the one place the spec sanctions LLM help
(spec §3 bootstrapping note): producing the very first ``threat-model.yaml`` is
a bootstrap step, done offline, whose output a human reviews and edits before it
becomes authoritative. This module keeps that help **bounded**, matching the
tool's philosophy:

* Deterministic code (reused from :mod:`threat_delta.scaffold`) discovers the
  components and their ``code_paths`` from the directory layout — no guessing.
* The LLM only fills a few narrow *judgment* fields per component (trust zone,
  the human-readable asset names it handles, its entry points), and is shown a
  *small bounded sample* of that component's source — never the whole repo.
* **Code, not the LLM, owns id generation and referential integrity.** Asset ids
  are derived deterministically from proposed names and components reference only
  ids the code itself minted, so the result always parses
  (:func:`threat_delta.baseline.parse_baseline`) and validates clean
  (:func:`threat_delta.validate.validate_baseline` yields no errors — no dangling
  asset refs).

The rendered file is banner-marked as a DRAFT requiring human review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

import yaml

from .coverage import collect_source_paths
from .llm import SYSTEM_PREAMBLE, LLMClient
from .relevance import path_matches
from .scaffold import (
    ScaffoldComponent,
    _placeholder_assumptions,
    _placeholder_components,
    discover_components,
)

# Allowed trust zones the LLM may pick from; anything else falls back.
_ALLOWED_TRUST_ZONES: frozenset[str] = frozenset(
    {"internet", "dmz", "internal", "data"}
)
_DEFAULT_TRUST_ZONE = "internal"

# Bounds on the context sample handed to the LLM per component.
_MAX_FILES = 5
_MAX_LINES_PER_FILE = 40


# --------------------------------------------------------------------------- #
# Bounded per-component context
# --------------------------------------------------------------------------- #

def _component_context(
    root: Union[str, Path],
    component: ScaffoldComponent,
    *,
    max_chars: int = 2000,
) -> str:
    """Gather a small, bounded source sample for one ``component``.

    Walks ``root`` once (via :func:`threat_delta.coverage.collect_source_paths`),
    keeps the repo-relative POSIX paths matching any of the component's
    ``code_paths`` globs (via :func:`threat_delta.relevance.path_matches`), reads
    just the first ~40 lines of up to ~5 of those files, concatenates them, and
    hard-truncates to ``max_chars`` with a ``... [truncated]`` marker. Never reads
    the whole repo.
    """
    root_path = Path(root)
    all_paths = collect_source_paths(root_path)
    matched = [
        p
        for p in all_paths
        if any(path_matches(p, pat) for pat in component.code_paths)
    ]
    matched = matched[:_MAX_FILES]

    chunks: list[str] = []
    for rel in matched:
        try:
            text = (root_path / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        head = "\n".join(text.splitlines()[:_MAX_LINES_PER_FILE])
        chunks.append(f"# file: {rel}\n{head}")

    sample = "\n\n".join(chunks)
    if len(sample) > max_chars:
        sample = sample[:max_chars].rstrip() + "\n... [truncated]"
    return sample


# --------------------------------------------------------------------------- #
# Per-component proposal (the only LLM call)
# --------------------------------------------------------------------------- #

@dataclass
class ComponentProposal:
    """The narrow judgment fields the LLM proposes for one component."""

    trust_zone: str
    handles_assets: list[str] = field(default_factory=list)  # ASSET NAMES (free text)
    entry_points: list[str] = field(default_factory=list)
    low_confidence: bool = False


def _coerce_str_list(value) -> list[str]:
    """Coerce arbitrary JSON into a list of non-empty stripped strings."""
    if value is None:
        return []
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        return []
    out: list[str] = []
    for item in items:
        if item is None:
            continue
        text = str(item).strip()
        if text:
            out.append(text)
    return out


def propose_component(
    root: Union[str, Path],
    component: ScaffoldComponent,
    llm: LLMClient,
    *,
    max_chars: int = 2000,
) -> ComponentProposal:
    """Ask the LLM for one component's trust zone, assets and entry points.

    Exactly **one** ``llm.complete_json`` call (stage ``"classify"``) over a
    bounded context. The response is parsed defensively: ``trust_zone`` falls
    back to ``"internal"`` if outside the allowed set; ``handles_assets`` and
    ``entry_points`` default to ``[]`` and are coerced to lists of stripped
    strings; ``low_confidence`` is honoured if present.
    """
    sample = _component_context(root, component, max_chars=max_chars)
    prompt = (
        "Classify ONE software component for an initial threat model.\n"
        f"Component id: {component.id}\n"
        f"Component name: {component.name}\n"
        "Source code sample (bounded, may be truncated):\n"
        "-----\n"
        f"{sample}\n"
        "-----\n"
        "Answer ONLY with a JSON object of this exact shape:\n"
        '{"trust_zone": one of ["internet","dmz","internal","data"], '
        '"handles_assets": ["<human-readable asset name>", ...], '
        '"entry_points": ["http_public"|"grpc_internal"|"cli"|"queue"|...]}\n'
        "handles_assets are human-readable names of data/assets this component "
        "touches (e.g. \"Session token\", \"User PII\"). entry_points are how it "
        "is invoked. If unsure, use an empty list and set \"low_confidence\": true."
    )

    data = llm.complete_json(prompt, system=SYSTEM_PREAMBLE, stage="classify")
    if not isinstance(data, dict):
        data = {}

    zone_raw = str(data.get("trust_zone", "")).strip().lower()
    trust_zone = zone_raw if zone_raw in _ALLOWED_TRUST_ZONES else _DEFAULT_TRUST_ZONE

    return ComponentProposal(
        trust_zone=trust_zone,
        handles_assets=_coerce_str_list(data.get("handles_assets")),
        entry_points=_coerce_str_list(data.get("entry_points")),
        low_confidence=bool(data.get("low_confidence", False)),
    )


# --------------------------------------------------------------------------- #
# Deterministic model assembly (code owns ids + referential integrity)
# --------------------------------------------------------------------------- #

def _slug(name: str) -> str:
    """``"Session token"`` -> ``"session_token"`` (lowercase, non-alnum -> ``_``)."""
    lowered = name.lower()
    collapsed = re.sub(r"[^a-z0-9]+", "_", lowered)
    return collapsed.strip("_")


def build_model(
    root: Union[str, Path],
    components: list[ScaffoldComponent],
    proposals: dict[str, ComponentProposal],
    *,
    system_name: str,
    version: str = "0.1.0",
) -> dict:
    """Deterministically assemble a baseline dict from components + proposals.

    ``proposals`` maps a :class:`ScaffoldComponent` id to its
    :class:`ComponentProposal`. Asset ids are minted here from proposed asset
    *names* (``"asset." + slug(name)``) and components reference only those minted
    ids, so every cross-reference resolves — the output validates with no dangling
    asset errors regardless of what the LLM produced. ``sensitivity`` defaults to
    a safe-high ``"high"`` that a human downgrades. If no assets were proposed,
    one ``asset.example`` placeholder is emitted.
    """
    # Build a stable name -> id slug map over all proposed asset names, in the
    # order components are listed (then names within a component), deduped by id.
    name_to_id: dict[str, str] = {}
    assets: list[dict] = []
    seen_ids: set[str] = set()

    for comp in components:
        proposal = proposals.get(comp.id)
        if proposal is None:
            continue
        for asset_name in proposal.handles_assets:
            asset_id = "asset." + _slug(asset_name)
            # Remember the resolution for THIS exact name (first id wins).
            name_to_id.setdefault(asset_name, asset_id)
            if asset_id in seen_ids:
                continue
            seen_ids.add(asset_id)
            assets.append(
                {
                    "id": asset_id,
                    "name": asset_name,
                    "sensitivity": "high",
                }
            )

    if not assets:
        assets.append(
            {"id": "asset.example", "name": "Example asset", "sensitivity": "high"}
        )

    # Components — resolve proposed asset NAMES to the ids we just minted.
    out_components: list[dict] = []
    for comp in components:
        proposal = proposals.get(comp.id)
        if proposal is None:
            proposal = ComponentProposal(trust_zone=_DEFAULT_TRUST_ZONE)
        handles_ids: list[str] = []
        for asset_name in proposal.handles_assets:
            asset_id = name_to_id.get(asset_name)
            if asset_id is not None and asset_id not in handles_ids:
                handles_ids.append(asset_id)
        out_components.append(
            {
                "id": comp.id,
                "name": comp.name,
                "trust_zone": proposal.trust_zone,
                "code_paths": list(comp.code_paths),
                "handles_assets": handles_ids,
                "entry_points": list(proposal.entry_points),
            }
        )

    # Trust boundaries — placeholders needing human judgment (controls empty).
    trust_boundaries = [
        {
            "id": "tb.internet_edge",
            "name": "Internet edge",
            "description": "Boundary between the public internet and the system.",
            "controls": [],
        },
        {
            "id": "tb.internal",
            "name": "Internal boundary",
            "description": "Boundary between internal components and data stores.",
            "controls": [],
        },
    ]

    assumptions = [
        {"id": asm_id, "statement": statement}
        for asm_id, statement in _placeholder_assumptions()
    ]

    return {
        "system": {
            "name": system_name,
            "version": version,
            "description": "TODO: one-line description of what this system does.",
        },
        "assets": assets,
        "trust_boundaries": trust_boundaries,
        "components": out_components,
        "data_flows": [],
        "assumptions": assumptions,
        "accepted_risks": [],
    }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

_LLM_BANNER = """\
# ============================================================================
# DRAFT — LLM-PROPOSED, HUMAN REVIEW REQUIRED.
#
# This baseline was bootstrapped with LLM assistance (spec §3 bootstrapping
# note): a ONE-TIME, OFFLINE draft. Component code_paths were discovered
# deterministically by code; the trust_zone / handles_assets / entry_points
# fields were *proposed* by a local model over a small code sample and are NOT
# yet authoritative. Asset ids and all cross-references were generated by code,
# so this file parses and validates clean — but the security judgments are
# guesses.
#
# review: downgrade asset sensitivity from the safe-high default where wrong.
# review: confirm each trust_zone and fill trust_boundary controls.
# review: wire data_flows and prune anything that does not apply.
# ============================================================================
"""


def render_llm_baseline(model: dict) -> str:
    """Render the baseline ``model`` dict to YAML *text* with a DRAFT banner.

    The body is produced with :func:`yaml.safe_dump` (block style, keys in the
    given order) and the human-review banner plus ``# review:`` hints are
    prepended as comments. Guaranteed to round-trip through
    :func:`yaml.safe_load` and :func:`threat_delta.baseline.parse_baseline`.
    """
    body = yaml.safe_dump(model, sort_keys=False, default_flow_style=False)
    return _LLM_BANNER + "\n" + body


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def init_baseline_llm(
    root: Union[str, Path],
    llm: LLMClient,
    *,
    out: Optional[Union[str, Path]] = None,
    system_name: Optional[str] = None,
    version: str = "0.1.0",
    max_chars: int = 2000,
) -> str:
    """Bootstrap an LLM-assisted baseline draft for the repo at ``root``.

    Components (and their ``code_paths``) are discovered deterministically; one
    bounded LLM call per component fills the judgment fields; the model is then
    assembled and rendered by code. If ``out`` is given, a
    :class:`FileExistsError` is raised when it already exists (never clobber a
    committed baseline); otherwise parent dirs are created and the text written.
    Returns the rendered YAML text regardless.
    """
    root_path = Path(root)

    components = discover_components(root_path)
    if not components:
        components = _placeholder_components()

    if system_name is None:
        system_name = root_path.resolve().name or "system"

    proposals: dict[str, ComponentProposal] = {}
    for comp in components:
        proposals[comp.id] = propose_component(
            root_path, comp, llm, max_chars=max_chars
        )

    model = build_model(
        root_path,
        components,
        proposals,
        system_name=system_name,
        version=version,
    )
    text = render_llm_baseline(model)

    if out is not None:
        out_path = Path(out)
        if out_path.exists():
            raise FileExistsError(
                f"refusing to overwrite existing baseline: {out_path}"
            )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")

    return text
