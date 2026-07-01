"""Threat-Model Delta analysis (advisory, non-blocking).

Evaluates a PR as a *delta* against a human-authored threat-model baseline:
deterministic code does breadth (relevance, severity, gating); a small local LLM
answers narrow classification questions over tiny inputs.
"""

from .models import (
    Asset,
    Assumption,
    ChangedFile,
    Component,
    Confidence,
    DataFlow,
    Delta,
    DeltaType,
    Diff,
    FileAnnotation,
    Finding,
    Flags,
    Hunk,
    ProposedBaselineUpdate,
    Sensitivity,
    Severity,
    Slice,
    Stride,
    StrideDelta,
    System,
    TrustBoundary,
    Violation,
)
from .baseline import Baseline, BaselineError, load_baseline, parse_baseline
from .llm import LLMClient, LLMConfig, LLMError, ScriptedLLMClient, SYSTEM_PREAMBLE
from .pipeline import AnalysisResult, analyze
from .step import needs_human_review, run_step
from .scaffold import ScaffoldComponent, discover_components, init_baseline, render_baseline
from .validate import Issue, has_errors, validate_baseline, validate_file
from .coverage import CoverageReport, collect_source_paths, compute_coverage, format_report
from .transports import OllamaClient, OpenAICompatibleClient, build_client
from .scaffold_llm import ComponentProposal, init_baseline_llm, propose_component

__version__ = "0.1.0"

__all__ = [
    # models
    "Asset", "Assumption", "ChangedFile", "Component", "Confidence",
    "DataFlow", "Delta", "DeltaType", "Diff", "FileAnnotation", "Finding",
    "Flags", "Hunk", "ProposedBaselineUpdate", "Sensitivity", "Severity",
    "Slice", "Stride", "StrideDelta", "System", "TrustBoundary", "Violation",
    # baseline
    "Baseline", "BaselineError", "load_baseline", "parse_baseline",
    # llm
    "LLMClient", "LLMConfig", "LLMError", "ScriptedLLMClient", "SYSTEM_PREAMBLE",
    # pipeline
    "AnalysisResult", "analyze",
    # standalone step entry point
    "run_step", "needs_human_review",
    # baseline bootstrapping / maintenance tooling
    "ScaffoldComponent", "discover_components", "init_baseline", "render_baseline",
    "Issue", "has_errors", "validate_baseline", "validate_file",
    "CoverageReport", "collect_source_paths", "compute_coverage", "format_report",
    # LLM transports + LLM-assisted scaffolding
    "build_client", "OpenAICompatibleClient", "OllamaClient",
    "init_baseline_llm", "propose_component", "ComponentProposal",
    "__version__",
]
