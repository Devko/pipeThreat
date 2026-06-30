"""Stage 6b — delta-type classification (pipeline step 6).

Asks the model a single, narrow question: of the five coarse delta categories
(new entry point, new data flow, trust-boundary crossing, asset-handling change,
control change), which are *plausibly* introduced or changed by this diff? The
boolean answers gate the more expensive per-component STRIDE stage (6c): if no
flag is positive there is nothing for 6c to reason about.

This module only maps the model's JSON into a :class:`Flags` value object; it is
defensive about missing keys and non-boolean truthy/falsey values because a small
local model will not always emit a clean schema (spec §11).
"""

from __future__ import annotations

from . import prompts
from .llm import LLMClient
from .models import Diff, FileAnnotation, Flags, Slice


_FLAG_KEYS = (
    "new_entry_point",
    "new_data_flow",
    "trust_boundary_crossing",
    "asset_handling_change",
    "control_change",
)


def _coerce_bool(value) -> bool:
    """Coerce a model-returned value to bool.

    Accepts JSON booleans, but also tolerates the strings ``"true"``/``"false"``
    (and ``"yes"``/``"no"``/``"1"``/``"0"``) a 4B sometimes emits instead.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1"}
    return bool(value)


def classify_change(
    slice: Slice,
    diff: Diff,
    annotations: list[FileAnnotation],
    llm: LLMClient,
) -> Flags:
    """6b — classify which coarse delta-types are plausibly in play.

    Builds the classification prompt, runs one JSON completion and maps the
    result into :class:`Flags`. Missing keys default to ``False``; a top-level
    ``"low_confidence": true`` propagates to :attr:`Flags.low_confidence`.
    """
    prompt = prompts.classification_prompt(slice, diff, annotations)
    result = llm.complete_json(prompt, stage="classify")

    flags = Flags()
    for key in _FLAG_KEYS:
        if key in result:
            setattr(flags, key, _coerce_bool(result[key]))
    flags.low_confidence = _coerce_bool(result.get("low_confidence", False))
    return flags
