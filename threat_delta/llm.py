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
    model: str = "gemma4:e2b"
    temperature: float = 0.0
    # Room for a thinking model (e.g. gemma4:e2b) to reason *and* still emit the
    # JSON answer; a tighter cap can leave `content` empty after the thinking.
    max_tokens: int = 1536
    # Reasoning/thinking ON for the analysis calls, but capped (spec §2/§11).
    reasoning: bool = True
    # Fallback cap used when a stage has no explicit per-stage budget.
    reasoning_budget_tokens: int = 256
    # Per-stage overrides (see DEFAULT_STAGE_BUDGETS).
    stage_reasoning_budgets: dict = field(
        default_factory=lambda: dict(DEFAULT_STAGE_BUDGETS)
    )
    # Generous default: a ~4B model on a cold CPU runner can take minutes for the
    # first inference (model load + generation).
    timeout_s: float = 300.0

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
        self,
        prompt: str,
        *,
        system: str = SYSTEM_PREAMBLE,
        stage: str | None = None,
        prefer_keys: tuple[str, ...] = (),
    ) -> dict:
        """Run one call and return the parsed JSON object.

        ``stage`` selects the per-stage reasoning budget. ``prefer_keys`` helps
        recover the right object from a thinking model's chain-of-thought (the
        answer object usually contains one of these keys and comes last). Raises
        :class:`LLMError` if no JSON object can be recovered.
        """
        raw = self._raw_complete(system, prompt, stage=stage)
        return parse_json_object(raw, prefer_keys=prefer_keys)


def parse_json_object(text: str, *, prefer_keys: tuple[str, ...] = ()) -> dict:
    """Best-effort recovery of a single JSON object from model output.

    Tolerates surrounding prose and ```json fences even though the preamble
    forbids them — a small local model will not always comply. For *thinking*
    models the answer is buried in chain-of-thought, so when the whole string
    isn't clean JSON we scan every balanced ``{...}`` span and prefer the LAST
    one (the conclusion comes last); ``prefer_keys`` further biases toward the
    object that actually carries the expected answer key.
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

    # Scan every balanced {...} span; collect the ones that parse to a dict.
    candidates: list[dict] = []
    for span in _balanced_objects(stripped):
        try:
            obj = json.loads(span)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            candidates.append(obj)

    if candidates:
        if prefer_keys:
            for obj in reversed(candidates):
                if any(k in obj for k in prefer_keys):
                    return obj
        # No keyed match (or none requested): the final object wins.
        return candidates[-1]

    raise LLMError(f"could not parse JSON object from model output: {text!r:.200}")


def _balanced_objects(text: str):
    """Yield each top-level balanced ``{...}`` span in ``text``, in order."""
    i = 0
    n = len(text)
    while i < n:
        if text[i] != "{":
            i += 1
            continue
        depth = 0
        in_str = False
        escape = False
        j = i
        while j < n:
            ch = text[j]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
                j += 1
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    yield text[i : j + 1]
                    break
            j += 1
        i = j + 1


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
