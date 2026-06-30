"""LLM client contract for the model-driven stages (6b/6c/6d).

The spec targets a local ~4B model on a CPU-only runner (Gemma 4 E4B class) with
temperature=0 and a *capped* reasoning budget (spec §2, §11). The pipeline only
ever needs one capability: send a system preamble + one narrow user prompt, get
back a single JSON object. That is the whole interface.

Concrete transports (llama.cpp server, Ollama, etc.) implement
:class:`LLMClient`. Tests and dry-runs use :class:`ScriptedLLMClient`, which
returns canned JSON keyed by a tag in the prompt — so every deterministic stage
can be exercised without a model.

Robust JSON extraction lives here (``parse_json_object``) because a 4B will
occasionally wrap output in prose or fences despite instructions; the call sites
should not each reinvent that.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


# Shared system preamble for all LLM calls (spec §6).
SYSTEM_PREAMBLE = (
    "You are a security analysis function in a CI pipeline. You receive a small, "
    "pre-filtered context and answer ONE narrow question. Output ONLY valid JSON "
    "matching the requested schema, with no prose, no markdown, no code fences. "
    "If the context is insufficient to decide, set the field to false/null and add "
    'a "low_confidence": true field. Do not infer beyond the provided context.'
)


class LLMError(RuntimeError):
    """Raised when the model call fails or returns unusable output."""


# Default per-stage reasoning budgets (spec §2: reasoning ON but *bounded* for
# each narrow analysis call). Classification is a cheap gate so it gets the least;
# the assumption check is the highest-signal, most bounded judgment so it gets a
# little more. An uncapped 4B rambles and burns CPU wall-clock.
DEFAULT_STAGE_BUDGETS = {
    "classify": 128,     # 6b — coarse yes/no flags
    "stride": 256,       # 6c — STRIDE deltas over one hunk
    "assumptions": 384,  # 6d — exhaustive assumption contradiction check
}


@dataclass
class LLMConfig:
    model: str = "gemma4:e4b"
    temperature: float = 0.0
    max_tokens: int = 512
    # Reasoning/thinking ON for the analysis calls, but capped (spec §2/§11).
    reasoning: bool = True
    # Fallback cap used when a stage has no explicit per-stage budget.
    reasoning_budget_tokens: int = 256
    # Per-stage overrides (see DEFAULT_STAGE_BUDGETS).
    stage_reasoning_budgets: dict = field(
        default_factory=lambda: dict(DEFAULT_STAGE_BUDGETS)
    )
    timeout_s: float = 120.0

    def budget_for(self, stage: str | None) -> int:
        """Reasoning-token budget for ``stage`` (0 when reasoning is disabled)."""
        if not self.reasoning:
            return 0
        if stage and stage in self.stage_reasoning_budgets:
            return self.stage_reasoning_budgets[stage]
        return self.reasoning_budget_tokens


class LLMClient(ABC):
    """Minimal contract: one JSON-returning completion per narrow question."""

    def __init__(self, config: LLMConfig | None = None) -> None:
        self.config = config or LLMConfig()

    @abstractmethod
    def _raw_complete(self, system: str, prompt: str, *, stage: str | None = None) -> str:
        """Return the model's raw text for ``system`` + ``prompt``.

        ``stage`` (one of ``"classify"``/``"stride"``/``"assumptions"``) lets a
        transport pick the per-stage reasoning budget via
        :meth:`LLMConfig.budget_for`.
        """

    def complete_json(
        self, prompt: str, *, system: str = SYSTEM_PREAMBLE, stage: str | None = None
    ) -> dict:
        """Run one call and return the parsed JSON object.

        ``stage`` selects the per-stage reasoning budget. Raises
        :class:`LLMError` if no JSON object can be recovered.
        """
        raw = self._raw_complete(system, prompt, stage=stage)
        return parse_json_object(raw)


def parse_json_object(text: str) -> dict:
    """Best-effort recovery of a single JSON object from model output.

    Tolerates surrounding prose and ```json fences even though the preamble
    forbids them — a small local model will not always comply.
    """
    if text is None:
        raise LLMError("model returned no text")
    stripped = text.strip()

    # Fast path: clean JSON.
    try:
        obj = json.loads(stripped)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass

    # Strip code fences if present.
    fence = re.search(r"```(?:json)?\s*(.*?)```", stripped, re.DOTALL)
    if fence:
        try:
            obj = json.loads(fence.group(1).strip())
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

    # Last resort: the first balanced {...} span.
    span = _first_balanced_object(stripped)
    if span is not None:
        try:
            obj = json.loads(span)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

    raise LLMError(f"could not parse JSON object from model output: {text!r:.200}")


def _first_balanced_object(text: str) -> str | None:
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


class ScriptedLLMClient(LLMClient):
    """Deterministic test/dry-run client.

    ``responses`` maps a substring *tag* (expected to appear in the prompt) to the
    dict that should be returned. The first matching tag wins; if nothing matches,
    ``default`` is returned. This lets tests script 6b/6c/6d independently.
    """

    def __init__(
        self,
        responses: dict[str, dict] | None = None,
        default: dict | None = None,
        config: LLMConfig | None = None,
    ) -> None:
        super().__init__(config)
        self.responses = responses or {}
        self.default = default if default is not None else {}
        self.calls: list[str] = []
        self.stages: list[str | None] = []

    def _raw_complete(self, system: str, prompt: str, *, stage: str | None = None) -> str:
        self.calls.append(prompt)
        self.stages.append(stage)
        for tag, payload in self.responses.items():
            if tag in prompt:
                return json.dumps(payload)
        return json.dumps(self.default)
