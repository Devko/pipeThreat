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
    *,
    signals: list[str] | None = None,
) -> list[Violation]:
    """6d — assumptions this change violates/weakens, one bounded call each.

    Returns ``[]`` without calling the model when there are no assumptions.
    Otherwise **fans out one call per assumption** (a narrow yes/no question a
    small model answers far more reliably than a batched list), each voted
    ``config.votes`` times. An assumption is reported violated when a majority of
    its samples say so; the vote ``agreement`` is recorded. Unknown
    ``assumption_id`` values are dropped (hallucination guard, spec §11).
    """
    if not assumptions:
        return []

    violations: list[Violation] = []
    for assumption in assumptions:
        prompt = prompts.assumption_prompt_single(
            assumption, diff, annotations, signals=signals
        )
        samples = llm.complete_json_samples(
            prompt, stage="assumptions", prefer_keys=("violated", "assumption_id")
        )
        n = len(samples)
        majority = n // 2 + 1

        votes_violated = 0
        reason = ""
        any_low_conf = False
        for result in samples:
            if not isinstance(result, dict):
                continue
            # Defend against a stub/model that echoes a different id.
            rid = result.get("assumption_id", assumption.id)
            if rid not in (assumption.id, None):
                continue
            any_low_conf = any_low_conf or _coerce_bool(result.get("low_confidence", False))
            if _coerce_bool(result.get("violated", False)):
                votes_violated += 1
                if not reason:
                    reason = str(result.get("reason", "")).strip()[:_MAX_REASON_CHARS]

        if votes_violated < majority:
            continue
        agreement = votes_violated / n
        violations.append(
            Violation(
                assumption_id=assumption.id,
                violated=True,
                reason=reason,
                low_confidence=any_low_conf or agreement < 1.0,
                agreement=agreement,
            )
        )
    return violations
