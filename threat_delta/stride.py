"""Stage 6c — per-component STRIDE delta analysis (pipeline step 6).

For a single affected component this asks the model which STRIDE categories the
change *newly introduces or worsens* for that component. It runs only when 6b
produced at least one positive flag, and it sends the actual code change — but
capped: the concatenated hunk text is deterministically truncated to
``max_hunk_chars`` before the prompt is built (the spec's "summarize the hunk
deterministically first" budget cap, §2/§11), so an oversized PR cannot blow the
context window of a 4B model.

The parser is a hallucination guard (spec §11): any returned ``stride`` string
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


def stride_deltas(
    component: Component,
    hunks: list[Hunk],
    flags: Flags,
    llm: LLMClient,
    *,
    max_hunk_chars: int = 4000,
) -> list[StrideDelta]:
    """6c — STRIDE deltas this change introduces/worsens for ``component``.

    Returns ``[]`` immediately when no flag is positive (nothing for 6c to do).
    Otherwise builds the per-component prompt with a capped hunk body, runs one
    JSON completion, and parses the ``{"deltas": [...]}`` list into
    :class:`StrideDelta` objects. Entries whose ``stride`` is not a valid
    :class:`Stride` value are skipped. A top-level ``"low_confidence": true``
    propagates to every produced delta.
    """
    if not flags.any_positive:
        return []

    hunk_text = _concat_hunks(hunks, max_hunk_chars)
    prompt = prompts.stride_prompt(component, hunk_text, flags)
    result = llm.complete_json(prompt, stage="stride", prefer_keys=("deltas",))

    low_confidence = bool(result.get("low_confidence", False))
    raw_deltas = result.get("deltas", [])
    if not isinstance(raw_deltas, list):
        return []

    deltas: list[StrideDelta] = []
    for item in raw_deltas:
        if not isinstance(item, dict):
            continue
        stride = coerce_stride(item.get("stride"))
        if stride is None:
            # Hallucination guard: unrecognized STRIDE label -> drop the entry.
            continue
        reason = str(item.get("reason", "")).strip()[:_MAX_REASON_CHARS]
        deltas.append(
            StrideDelta(
                stride=stride,
                reason=reason,
                low_confidence=low_confidence,
            )
        )
    return deltas
