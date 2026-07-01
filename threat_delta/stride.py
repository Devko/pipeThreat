"""Stage 3 — per-component STRIDE delta analysis.

For a single affected component this asks the model which STRIDE categories the
change *newly introduces or worsens* for that component. It runs only when Stage 2
produced at least one positive flag, and it sends the actual code change — but
capped: the concatenated hunk text is deterministically truncated to
``max_hunk_chars`` before the prompt is built (a "summarize the hunk
deterministically first" budget cap), so an oversized PR cannot blow the
context window of a small model.

The parser is a hallucination guard: any returned ``stride`` string
that is not a valid :class:`Stride` value is dropped rather than coerced.
"""

from __future__ import annotations

import re

from . import prompts
from .llm import LLMClient
from .models import Component, Flags, Hunk, Stride, StrideDelta


# Cap on a single delta's reason — the prompt asks for <=20 words; this is a
# hard character backstop so a rambling model cannot bloat the output.
_MAX_REASON_CHARS = 200


def _norm(text: str) -> str:
    """Lowercase and strip everything but letters (for tolerant matching)."""
    return re.sub(r"[^a-z]", "", text.lower())


# Canonical enum values, keyed by their normalized spelling.
_STRIDE_BY_NORM = {_norm(s.value): s for s in Stride}

# Common formatting variants / synonyms a model may emit instead of the exact
# enum spelling (e.g. "Information Disclosure", "Elevation of Privileges", "DoS").
_STRIDE_ALIASES = {
    "disclosure": Stride.INFORMATION_DISCLOSURE,
    "infodisclosure": Stride.INFORMATION_DISCLOSURE,
    "dos": Stride.DENIAL_OF_SERVICE,
    "elevationofprivileges": Stride.ELEVATION_OF_PRIVILEGE,
    "privilegeescalation": Stride.ELEVATION_OF_PRIVILEGE,
    "eop": Stride.ELEVATION_OF_PRIVILEGE,
}

# Single-letter STRIDE codes.
_STRIDE_LETTERS = {
    "s": Stride.SPOOFING,
    "t": Stride.TAMPERING,
    "r": Stride.REPUDIATION,
    "i": Stride.INFORMATION_DISCLOSURE,
    "d": Stride.DENIAL_OF_SERVICE,
    "e": Stride.ELEVATION_OF_PRIVILEGE,
}


def coerce_stride(raw) -> Stride | None:
    """Map a model-supplied STRIDE label to a :class:`Stride`, tolerantly.

    Accepts the exact enum spelling plus common variants: spacing/casing/
    punctuation differences ("Information Disclosure", "information_disclosure"),
    synonyms ("DoS", "privilege escalation"), and single-letter codes ("I").
    Returns ``None`` for anything unrecognized (the hallucination guard).
    """
    if raw is None:
        return None
    norm = _norm(str(raw))
    if not norm:
        return None
    if norm in _STRIDE_BY_NORM:
        return _STRIDE_BY_NORM[norm]
    if norm in _STRIDE_ALIASES:
        return _STRIDE_ALIASES[norm]
    if len(norm) == 1 and norm in _STRIDE_LETTERS:
        return _STRIDE_LETTERS[norm]
    return None

_TRUNCATION_MARKER = "\n... [truncated]"


def _concat_hunks(hunks: list[Hunk], max_hunk_chars: int) -> str:
    """Join hunk contents and deterministically truncate to ``max_hunk_chars``.

    Truncation takes the first ``max_hunk_chars`` characters and appends a
    visible marker so the model (and tests) can see the body was cut.
    """
    text = "\n".join(h.content for h in hunks if h.content)
    if len(text) > max_hunk_chars:
        text = text[:max_hunk_chars] + _TRUNCATION_MARKER
    return text


def _parse_sample(result: dict) -> tuple[list[tuple[Stride, str]], bool]:
    """Parse one sample into ``[(stride, reason), ...]`` plus its low-conf flag."""
    low_confidence = bool(result.get("low_confidence", False))
    raw_deltas = result.get("deltas", [])
    if not isinstance(raw_deltas, list):
        return [], low_confidence
    out: list[tuple[Stride, str]] = []
    for item in raw_deltas:
        if not isinstance(item, dict):
            continue
        stride = coerce_stride(item.get("stride"))
        if stride is None:
            # Hallucination guard: unrecognized STRIDE label -> drop the entry.
            continue
        reason = str(item.get("reason", "")).strip()[:_MAX_REASON_CHARS]
        out.append((stride, reason))
    return out, low_confidence


def stride_deltas(
    component: Component,
    hunks: list[Hunk],
    flags: Flags,
    llm: LLMClient,
    *,
    max_hunk_chars: int = 4000,
    signals: list[str] | None = None,
) -> list[StrideDelta]:
    """Stage 3 — STRIDE deltas this change introduces/worsens for ``component``.

    Returns ``[]`` immediately when no flag is positive (nothing for Stage 3 to do).
    Otherwise builds the per-component prompt (with a capped hunk body and the
    deterministic ``signals`` block), runs ``config.votes`` samples and keeps a
    STRIDE category when a **majority** of samples surfaced it. Each kept delta
    records the vote ``agreement`` (1.0 when voting is off); entries whose
    ``stride`` is not a valid :class:`Stride` value are dropped (hallucination
    guard).
    """
    if not flags.any_positive:
        return []

    hunk_text = _concat_hunks(hunks, max_hunk_chars)
    prompt = prompts.stride_prompt(component, hunk_text, flags, signals=signals)
    samples = llm.complete_json_samples(prompt, stage="stride", prefer_keys=("deltas",))

    n = len(samples)
    majority = n // 2 + 1
    # Tally votes per STRIDE category, preserving first-seen order; keep the
    # first non-empty reason seen for each.
    counts: dict[Stride, int] = {}
    reasons: dict[Stride, str] = {}
    order: list[Stride] = []
    any_low_conf = False
    for result in samples:
        parsed, low_conf = _parse_sample(result)
        any_low_conf = any_low_conf or low_conf
        seen_in_sample: set[Stride] = set()
        for stride, reason in parsed:
            if stride not in counts:
                counts[stride] = 0
                order.append(stride)
            if stride not in seen_in_sample:
                counts[stride] += 1
                seen_in_sample.add(stride)
            if reason and not reasons.get(stride):
                reasons[stride] = reason

    deltas: list[StrideDelta] = []
    for stride in order:
        if counts[stride] < majority:
            continue  # not enough agreement across votes
        agreement = counts[stride] / n
        deltas.append(
            StrideDelta(
                stride=stride,
                reason=reasons.get(stride, ""),
                low_confidence=any_low_conf or agreement < 1.0,
                agreement=agreement,
            )
        )
    return deltas
