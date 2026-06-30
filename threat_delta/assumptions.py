"""Stage 6d — security-assumption violation check (pipeline step 6).

Asks the model whether the change violates or weakens any of the threat model's
*stated* security assumptions. Only assumptions present in the slice are sent, so
the model reasons over a small, fixed set.

Two guards (spec §11): the model is told to return only ``violated:true``
entries, but we re-filter on the returned ``violated`` flag anyway, and we drop
any ``assumption_id`` that does not match an assumption we actually supplied (a
hallucinated id must never reach scoring).
"""

from __future__ import annotations

from . import prompts
from .llm import LLMClient
from .models import Assumption, Diff, FileAnnotation, Violation


_MAX_REASON_CHARS = 200


def _coerce_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1"}
    return bool(value)


def assumption_check(
    assumptions: list[Assumption],
    diff: Diff,
    annotations: list[FileAnnotation],
    llm: LLMClient,
) -> list[Violation]:
    """6d — assumptions this change violates/weakens.

    Returns ``[]`` without calling the model when there are no assumptions.
    Otherwise runs one JSON completion and keeps only entries that are both
    ``violated`` truthy and reference a known ``assumption_id``. A top-level
    ``"low_confidence": true`` propagates to every produced violation.
    """
    if not assumptions:
        return []

    known_ids = {a.id for a in assumptions}
    prompt = prompts.assumption_prompt(assumptions, diff, annotations)
    result = llm.complete_json(prompt, stage="assumptions")

    low_confidence = _coerce_bool(result.get("low_confidence", False))
    raw_violations = result.get("violations", [])
    if not isinstance(raw_violations, list):
        return []

    violations: list[Violation] = []
    for item in raw_violations:
        if not isinstance(item, dict):
            continue
        if not _coerce_bool(item.get("violated", False)):
            continue
        assumption_id = item.get("assumption_id")
        if assumption_id not in known_ids:
            # Hallucination guard: unknown assumption id -> drop.
            continue
        reason = str(item.get("reason", "")).strip()[:_MAX_REASON_CHARS]
        violations.append(
            Violation(
                assumption_id=assumption_id,
                violated=True,
                reason=reason,
                low_confidence=low_confidence,
            )
        )
    return violations
