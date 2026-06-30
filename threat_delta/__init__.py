"""Threat-Model Delta — pipeline step 6 (advisory, non-blocking).

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
    "__version__",
]
