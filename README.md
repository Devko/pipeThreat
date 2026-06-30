# Threat-Model Delta — Pipeline Step 6

Advisory, **non-blocking** CI step that evaluates each PR as a *delta against a
human-authored threat-model baseline* instead of re-deriving a whole threat model
from raw code every run. Deterministic code does breadth (path mapping, severity,
dedup, gating); a small local LLM (~4B, CPU-only) answers narrow classification
questions over tiny, pre-filtered inputs.

> Implements `threatmodeldeltaspec.md`. It posts a PR comment + SARIF and never
> fails the build on its own — the deterministic gate (secrets, high-severity
> SAST, CVEs) is the only thing that blocks.

---

## Integrate it into your repo

Three ways to pull this pipeline straight from the repo, fastest first.

### 1. As a GitHub Action (recommended)

The repo ships a composite action (`action.yml`), so another repository wires the
step in with one step. Add `threat-model.yaml` to your repo root and:

```yaml
# .github/workflows/threat-model-delta.yml
name: threat-model-delta
on: pull_request
permissions:
  contents: read
  pull-requests: write
  security-events: write
jobs:
  threat-delta:
    runs-on: ubuntu-latest
    continue-on-error: true        # advisory — never block the merge
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }    # so the action can compute the PR diff
      - id: delta
        uses: Devko/pipeThreat@main # or pin a tag, e.g. @v0.1.0
        with:
          baseline: threat-model.yaml
          # annotations: annotations.json   # optional (step 5)
          # findings: findings.json         # optional (steps 2-4)
          # fail-on-high: 'true'            # optional required-review gate
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.delta.outputs.sarif }}
          category: threat-model-delta
```

The action installs the package from its own checkout (no extra install step),
computes the PR diff if you don't pass one, and exposes `sarif` / `comment`
outputs. See `action.yml` for all inputs and `.github/workflows/threat-delta.yml`
for a complete working example (it drives the same action via `uses: ./`).

### 2. As a pip dependency (library or CLI)

```bash
pip install "git+https://github.com/Devko/pipeThreat@main"
```

This installs the `threat_delta` package **and** the `threat-delta` console
script. Use it as a library — the whole step is one standalone function:

```python
from threat_delta import run_step, needs_human_review

result = run_step(
    baseline="threat-model.yaml",       # path or Baseline
    diff="pr.diff",                     # path or Diff
    annotations="annotations.json",     # path / list / None
    findings="findings.json",           # path / list / None
    pr="1234",
    llm=my_local_model_client,          # defaults to an offline stub
)

result.deltas               # list[Delta]
result.sarif                # SARIF 2.1.0 dict
result.comment              # PR-comment markdown
needs_human_review(result)  # high-severity deltas for the optional gate
```

`run_step` accepts a path **or** an in-memory object for every input, never
blocks, and leaves gating to the caller (spec §9). It is the single integration
seam — the CLI and the GitHub Action are both thin wrappers over it.

### 3. As a CLI in any pipeline

```bash
threat-delta \
  --baseline threat-model.yaml \
  --diff pr.diff \
  --annotations annotations.json \   # optional
  --findings findings.json \         # optional
  --pr 1234 \
  --sarif threat-delta.sarif \
  --comment threat-delta.md
```

Exits `0` regardless of findings (advisory). `--fail-on-high` exits non-zero when
a high-severity delta needs human review — pair it with a `security/needs-review`
label + branch protection for a *human* gate (never a model gate).

---

## Wiring a model

The CLI/action ship only an offline **stub** transport, which is conservative: it
reports nothing rather than hallucinating, so everything runs end-to-end without a
model server. To get real 6b/6c/6d signal, implement
`threat_delta.llm.LLMClient._raw_complete` against your local model (llama.cpp
server, Ollama, …) with `temperature=0` and a capped reasoning budget, then pass
it to `run_step(llm=...)` or select it in `cli._build_llm`. The integration test
(`tests/test_pipeline.py`) demonstrates the full §12 worked example with a
scripted client.

## How it works

| Stage | What | Kind |
|---|---|---|
| **6a** `resolve_slice` | Match changed paths to baseline `code_paths`; build the relevant slice; flag untracked paths | deterministic |
| **6b** `classify_change` | Coarse flags: new entry point / data flow / boundary crossing / asset change / control change plausibly in play? | 1 LLM call |
| **6c** `stride_deltas` | Per affected component: which STRIDE categories does *this* change introduce/worsen? | N LLM calls |
| **6d** `assumption_check` | Which stated assumptions does the diff violate or weaken? | 1 LLM call |
| **6e** assemble + score + emit | Build scored `Delta`s, dedupe, render SARIF + PR comment | deterministic |

6b **gates** 6c and 6d: if every flag is false, the expensive calls are skipped
and only deterministic `untracked_path` deltas (from 6a) are emitted. A typical PR
is 3–5 short LLM calls — bounded and async, so it never holds up the merge.
**Severity is deterministic** (spec §7), computed from facts so it is stable
across runs; STRIDE claims are advisory and human-reviewed.

## The baseline

`threat-model.yaml` is human-authored, human-approved, version-controlled, and
treated as source code (changes go through PR review). The linking mechanism is
`code_paths` on each component — globs (incl. `**`) mapping threat-model elements
to source paths. See `examples/threat-model.yaml`.

When a PR adds code no component claims, 6a emits an `untracked_path` delta with a
`proposed_baseline_update`; accepting it into the baseline closes the maintenance
loop (spec §10) so the model stops re-flagging an accepted change.

## Layout

```
action.yml                 # composite GitHub Action (uses: Devko/pipeThreat@…)
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
  step.py          # run_step() — standalone single-call pipeline entry point
  cli.py           # command-line entry point
examples/          # baseline + worked-example PR inputs (spec §12)
tests/             # pytest suite (foundation + every stage + e2e worked example)
```

## Design guarantees

- **Bounded context** — the baseline slice + diff summary + annotations only,
  never the whole repo or whole baseline.
- **Reproducible** — temperature 0, capped reasoning, deterministic severity/gating.
- **Hallucination-guarded** — deltas referencing ids absent from the baseline are
  dropped; invalid STRIDE strings and unknown assumption ids are filtered.
- **Injection-resistant** — diff/annotation/comment text is included as *data*
  under labeled sections, never as instructions.

## Development

```bash
pip install -e '.[dev]'
python -m pytest -q
```
