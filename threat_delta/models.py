"""Shared data models for the Threat-Model Delta step (pipeline step 6).

These dataclasses are the contract between every stage:

    resolve_slice (6a)  -> Slice
    classify_change (6b) -> Flags
    stride_deltas (6c)   -> list[StrideDelta]
    assumption_check (6d)-> list[Violation]
    score_and_emit (6e)  -> (sarif, comment) built from list[Delta]

Nothing here performs I/O or calls an LLM; these are plain value objects so the
deterministic and the model-driven stages can be developed and tested in
isolation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #

class Sensitivity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2}[self.value]

    def escalate_to(self, floor: "Severity") -> "Severity":
        """Return whichever of ``self``/``floor`` is more severe."""
        return self if self.rank >= floor.rank else floor


class Stride(str, Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "InformationDisclosure"
    DENIAL_OF_SERVICE = "DenialOfService"
    ELEVATION_OF_PRIVILEGE = "ElevationOfPrivilege"


class DeltaType(str, Enum):
    TRUST_BOUNDARY_CROSSING = "trust_boundary_crossing"
    NEW_ENTRY_POINT = "new_entry_point"
    NEW_DATA_FLOW = "new_data_flow"
    ASSET_EXPOSURE = "asset_exposure"
    ASSUMPTION_VIOLATION = "assumption_violation"
    CONTROL_CHANGE = "control_change"
    UNTRACKED_PATH = "untracked_path"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# --------------------------------------------------------------------------- #
# Baseline elements (parsed from threat-model.yaml — see baseline.py)
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class System:
    name: str
    version: str = ""
    description: str = ""


@dataclass(frozen=True)
class Asset:
    id: str
    name: str
    sensitivity: Sensitivity


@dataclass(frozen=True)
class TrustBoundary:
    id: str
    name: str
    description: str = ""
    controls: tuple[str, ...] = ()


@dataclass(frozen=True)
class Component:
    id: str
    name: str
    trust_zone: str
    code_paths: tuple[str, ...] = ()
    handles_assets: tuple[str, ...] = ()
    entry_points: tuple[str, ...] = ()


@dataclass(frozen=True)
class DataFlow:
    id: str
    from_: str
    to: str
    crosses: tuple[str, ...] = ()
    assets: tuple[str, ...] = ()


@dataclass(frozen=True)
class Assumption:
    id: str
    statement: str


@dataclass(frozen=True)
class AcceptedRisk:
    id: str
    statement: str


# --------------------------------------------------------------------------- #
# Inputs (diff / annotations / findings)
# --------------------------------------------------------------------------- #

@dataclass
class Hunk:
    """A single contiguous change region within a file."""
    header: str = ""
    content: str = ""


@dataclass
class ChangedFile:
    path: str
    hunks: list[Hunk] = field(default_factory=list)
    touched_functions: list[str] = field(default_factory=list)

    @property
    def patch_text(self) -> str:
        return "\n".join(h.content for h in self.hunks if h.content)


@dataclass
class Diff:
    """Output of step 1 (scope): the changed files for this PR."""
    files: list[ChangedFile] = field(default_factory=list)
    pr: str = ""

    @property
    def paths(self) -> list[str]:
        return [f.path for f in self.files]


@dataclass
class FileAnnotation:
    """Output of step 5: static-analysis annotations for one file."""
    path: str
    entry_points: list[str] = field(default_factory=list)
    untrusted_inputs: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """Output of steps 2-4 (SAST / secrets / CVE) — optional correlation input."""
    id: str
    file: str
    severity: str = ""
    message: str = ""


# --------------------------------------------------------------------------- #
# Stage outputs
# --------------------------------------------------------------------------- #

@dataclass
class Slice:
    """6a output — the relevant baseline slice that bounds all LLM context."""
    components: list[Component] = field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = field(default_factory=list)
    data_flows: list[DataFlow] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    assumptions: list[Assumption] = field(default_factory=list)
    untracked_paths: list[str] = field(default_factory=list)
    # component id -> the changed paths that matched it
    matched_paths: dict[str, list[str]] = field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        return not self.components and not self.untracked_paths


@dataclass
class Flags:
    """6b output — which delta-types are plausibly in play."""
    new_entry_point: bool = False
    new_data_flow: bool = False
    trust_boundary_crossing: bool = False
    asset_handling_change: bool = False
    control_change: bool = False
    low_confidence: bool = False

    @property
    def any_positive(self) -> bool:
        return any([
            self.new_entry_point,
            self.new_data_flow,
            self.trust_boundary_crossing,
            self.asset_handling_change,
            self.control_change,
        ])


@dataclass
class StrideDelta:
    """6c output item — one STRIDE category newly introduced/worsened."""
    stride: Stride
    reason: str
    low_confidence: bool = False
    # Fraction of self-consistency votes that surfaced this category (1.0 when
    # voting is off). Feeds the confidence rule.
    agreement: float = 1.0


@dataclass
class Violation:
    """6d output item — one assumption the change violates/weakens."""
    assumption_id: str
    violated: bool
    reason: str
    low_confidence: bool = False
    # Fraction of self-consistency votes that judged this assumption violated.
    agreement: float = 1.0


@dataclass
class ProposedBaselineUpdate:
    kind: str
    target: str
    change: str

    def to_dict(self) -> dict:
        return {"kind": self.kind, "target": self.target, "change": self.change}


@dataclass
class Delta:
    """Final per-delta output object (see spec §8)."""
    delta_id: str
    pr: str
    type: DeltaType
    affected_elements: list[str]
    severity: Severity
    confidence: Confidence
    description: str
    recommended_action: str
    requires_human_review: bool = False
    stride: list[Stride] = field(default_factory=list)
    contradicts_assumption: Optional[str] = None
    evidence: dict = field(default_factory=dict)
    proposed_baseline_update: Optional[ProposedBaselineUpdate] = None
    low_confidence: bool = False
    # One-line, deterministic explanation of *why* this severity (which asset
    # sensitivity / trust zone / rule drove it) — see severity.severity_rationale.
    severity_rationale: str = ""
    # Human labels for the change-signals folded into a collapsed component delta
    # (e.g. ["new entry point", "trust-boundary crossing"]). Empty for the
    # single-signal delta types (untracked_path, assumption_violation).
    change_signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {
            "delta_id": self.delta_id,
            "pr": self.pr,
            "type": self.type.value,
            "affected_elements": list(self.affected_elements),
            "stride": [s.value for s in self.stride],
            "contradicts_assumption": self.contradicts_assumption,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "evidence": self.evidence,
            "description": self.description,
            "recommended_action": self.recommended_action,
            "requires_human_review": self.requires_human_review,
        }
        if self.severity_rationale:
            d["severity_rationale"] = self.severity_rationale
        if self.change_signals:
            d["change_signals"] = list(self.change_signals)
        if self.proposed_baseline_update is not None:
            d["proposed_baseline_update"] = self.proposed_baseline_update.to_dict()
        if self.low_confidence:
            d["low_confidence"] = True
        return d
