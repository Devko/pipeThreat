"""Standalone pipeline entry point for step 6 (Threat-Model Delta).

A larger CI pipeline orchestrates many steps; this module exposes step 6 as a
*single callable* — :func:`run_step` — that an orchestrator can drop in without
knowing anything about the internal stages (6a–6e).

It accepts either filesystem paths *or* already-constructed objects for every
input, loads whatever is given as a path, runs the full analysis, and returns an
:class:`~threat_delta.pipeline.AnalysisResult` that exposes ``.deltas``,
``.sarif`` and ``.comment``. The step is advisory: it returns results and never
raises on "findings exist"; gating is the caller's choice (see
``AnalysisResult`` / :func:`needs_human_review`).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Union

import json

from .baseline import Baseline, load_baseline
from .diff import load_annotations, load_diff, load_findings
from .llm import LLMClient, ScriptedLLMClient
from .models import Delta, Diff, FileAnnotation, Finding, Severity
from .pipeline import AnalysisResult, analyze, prior_keys_from_dicts

BaselineInput = Union[str, Path, Baseline]
DiffInput = Union[str, Path, Diff]
AnnotationsInput = Union[str, Path, list[FileAnnotation], None]
FindingsInput = Union[str, Path, list[Finding], None]
PriorInput = Union[str, Path, AnalysisResult, list, dict, None]


def run_step(
    *,
    baseline: BaselineInput,
    diff: DiffInput,
    annotations: AnnotationsInput = None,
    findings: FindingsInput = None,
    pr: str = "",
    llm: Optional[LLMClient] = None,
    max_hunk_chars: int = 4000,
    prior: PriorInput = None,
) -> AnalysisResult:
    """Run the Threat-Model Delta step as one standalone pipeline function.

    Every input may be a path (``str``/``Path``) or an in-memory object:

    * ``baseline`` — path to ``threat-model.yaml`` or a :class:`Baseline`.
    * ``diff`` — path to a unified/structured diff or a :class:`Diff`.
    * ``annotations`` — step-5 annotations path / list / ``None``.
    * ``findings`` — step 2-4 findings path / list / ``None``.
    * ``llm`` — an :class:`LLMClient`; defaults to the conservative offline stub
      (reports nothing rather than hallucinating) so the step is runnable with no
      model server wired up.

    Returns an :class:`AnalysisResult`; read ``.deltas``, ``.sarif`` and
    ``.comment`` from it. Never blocks — gating is left to the caller.
    """
    bl = baseline if isinstance(baseline, Baseline) else load_baseline(baseline)
    df = diff if isinstance(diff, Diff) else load_diff(diff)
    anns = _resolve_annotations(annotations)
    finds = _resolve_findings(findings)
    client = llm if llm is not None else ScriptedLLMClient(default={})

    return analyze(
        df,
        bl,
        anns,
        finds,
        client,
        pr=pr or df.pr,
        max_hunk_chars=max_hunk_chars,
        prior_keys=_resolve_prior(prior),
    )


def needs_human_review(result: AnalysisResult) -> list[Delta]:
    """High-severity deltas that require human review (spec §9 gate input).

    The standalone step never decides the build outcome itself; an orchestrator
    that wants the optional required-review hook can call this and act on a
    non-empty list (e.g. set the ``security/needs-review`` label).
    """
    return [
        d
        for d in result.deltas
        if d.severity == Severity.HIGH and d.requires_human_review
    ]


def _resolve_annotations(annotations: AnnotationsInput) -> list[FileAnnotation]:
    if annotations is None:
        return []
    if isinstance(annotations, (str, Path)):
        return load_annotations(annotations)
    return list(annotations)


def _resolve_findings(findings: FindingsInput) -> list[Finding]:
    if findings is None:
        return []
    if isinstance(findings, (str, Path)):
        return load_findings(findings)
    return list(findings)


def _resolve_prior(prior: PriorInput) -> Optional[set]:
    """Resolve the optional prior-run input into a suppression key-set.

    ``None`` -> ``None`` (report every delta). A path/list/dict/AnalysisResult is
    reduced to the set of :func:`~threat_delta.pipeline.delta_key` tuples already
    reported, so a re-run only surfaces what is new (incremental subtraction).
    """
    if prior is None:
        return None
    if isinstance(prior, AnalysisResult):
        return prior_keys_from_dicts([d.to_dict() for d in prior.deltas])
    if isinstance(prior, (str, Path)):
        data = json.loads(Path(prior).read_text(encoding="utf-8"))
    else:
        data = prior
    deltas = data.get("deltas", []) if isinstance(data, dict) else list(data)
    return prior_keys_from_dicts(deltas)
