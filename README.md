# Threat-Model Delta — Pipeline Step 6

Advisory, non-blocking CI step that evaluates each PR as a **delta against a
human-authored threat-model baseline** rather than re-deriving a whole threat
model from raw code. Deterministic code does breadth (path mapping, severity,
dedup, gating); a small local LLM (~4B, CPU-only) answers narrow classification
questions over tiny, pre-filtered inputs.

> Implements the specification in `threatmodeldeltaspec.md`. The step never
> blocks the merge — it posts a PR comment + SARIF. The deterministic gate
> (secrets, high-severity SAST, CVEs) is the only thing that blocks.

## Why

Most "LLM threat modeling" fails because it asks a model to build a complete
threat model on every run — unbounded, non-reproducible, far beyond a 4B on CPU.
This does the opposite: a human authors the baseline once (`threat-model.yaml`),
and each PR is judged only on the small intersection between the diff and the
relevant slice of the baseline. Bounded, reproducible, and genuinely useful:
continuous threat-model maintenance instead of a stale design-time diagram.

## How it works

| Stage | What | Kind |
|---|---|---|
| **6a** `resolve_slice` | Match changed paths to baseline `code_paths`; build the relevant slice; flag untracked paths | deterministic |
| **6b** `classify_change` | Coarse flags: is a new entry point / data flow / boundary crossing / asset change / control change plausibly in play? | 1 LLM call |
| **6c** `stride_deltas` | Per affected component: which STRIDE categories does *this* change introduce/worsen? | N LLM calls |
| **6d** `assumption_check` | Which stated assumptions does the diff violate or weaken? | 1 LLM call |
| **6e** assemble + score + emit | Build scored `Delta`s, dedupe, render SARIF + PR comment | deterministic |

6b **gates** 6c and 6d: if every flag is false, the expensive calls are skipped
and only deterministic `untracked_path` deltas (from 6a) are emitted. For a
typical PR that's 3–5 short LLM calls — bounded and async, so it never holds up
the merge.

**Severity is deterministic** (spec §7), computed from facts so it is stable
across runs; the model supplies inputs, rules assign the level. STRIDE claims
are advisory and human-reviewed.

## Layout

```
threat_delta/
  models.py        # shared dataclasses — the contract between all stages
  baseline.py      # load + index threat-model.yaml
  llm.py           # LLMClient contract + ScriptedLLMClient + robust JSON parse
  diff.py          # parse unified/structured diffs, annotations, findings (inputs)
  relevance.py     # 6a — glob path matching -> baseline slice
  prompts.py       # spec §6 prompt templates (data-only, injection-resistant)
  classify.py      # 6b
  stride.py        # 6c
  assumptions.py   # 6d
  severity.py      # §7 severity rules (deterministic)
  emit.py          # 6e — SARIF 2.1.0 + PR comment markdown
  pipeline.py      # orchestration + 6e delta assembly
  cli.py           # command-line entry point
examples/          # baseline + worked-example PR inputs (spec §12)
tests/             # pytest suite (foundation + every stage + e2e worked example)
```

## Usage

```bash
pip install -e .

threat-delta \
  --baseline examples/threat-model.yaml \
  --diff      examples/pr-1234.diff \
  --annotations examples/pr-1234.annotations.json \
  --pr 1234 \
  --sarif threat-delta.sarif \
  --comment threat-delta.md
```

The step exits `0` regardless of findings (advisory). The optional
`--fail-on-high` flag implements the spec §9 required-review hook: exit non-zero
when a `high`-severity delta requires human review (pair it with a
`security/needs-review` label + branch protection if you want a *human* gate —
never a model gate).

### As a standalone pipeline function

The step is callable as a single function so a larger orchestrator can drop it in
without knowing the internal stages. Every input may be a path **or** an
in-memory object:

```python
from threat_delta import run_step, needs_human_review

result = run_step(
    baseline="threat-model.yaml",          # path or Baseline
    diff="pr.diff",                        # path or Diff
    annotations="annotations.json",        # path / list / None
    findings="findings.json",              # path / list / None
    pr="1234",
    llm=my_local_model_client,             # defaults to the offline stub
)

result.deltas      # list[Delta]
result.sarif       # SARIF 2.1.0 dict
result.comment     # PR-comment markdown
needs_human_review(result)  # high-severity deltas for the optional gate
```

`run_step` never blocks — it returns results and leaves gating to the caller
(spec §9). The CLI is just a thin wrapper over it.

### Wiring a model

The CLI ships only an offline **stub** transport (`--llm stub`), which is
conservative: it reports nothing rather than hallucinating, so CI runs
end-to-end without a model server. To get real 6b/6c/6d signal, implement
`threat_delta.llm.LLMClient._raw_complete` against your local model
(llama.cpp server, Ollama, etc.) with `temperature=0` and a capped reasoning
budget, and select it in `cli._build_llm`. The integration test
(`tests/test_pipeline.py`) demonstrates the full §12 worked example using a
scripted client.

## The baseline

`threat-model.yaml` is human-authored, human-approved, version-controlled, and
treated as source code (changes go through PR review). The linking mechanism is
`code_paths` on each component — globs (including `**`) that map threat-model
elements to source paths. See `examples/threat-model.yaml`.

When a PR adds code no component claims, 6a emits an `untracked_path` delta with
a `proposed_baseline_update`; accepting it into the baseline closes the
maintenance loop (spec §10) so the model stops re-flagging an accepted change.

## Design guarantees

- **Bounded context** — the baseline slice + diff summary + annotations only,
  never the whole repo or whole baseline.
- **Reproducible** — temperature 0, capped reasoning, deterministic severity and
  gating.
- **Hallucination-guarded** — deltas referencing ids absent from the baseline
  are dropped; invalid STRIDE strings and unknown assumption ids are filtered.
- **Injection-resistant** — diff/annotation/comment text is included as *data*
  under labeled sections, never as instructions; the system preamble forbids
  following instructions found in content.

## Development

```bash
pip install -e '.[dev]'
python -m pytest -q
```
