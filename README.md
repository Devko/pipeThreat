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

## Wiring a model (Gemma)

Three transports ship in `threat_delta.transports` (stdlib only, no extra deps):

| `--llm` | Client | Default endpoint / model |
|---|---|---|
| `stub` (default) | offline, reports nothing rather than hallucinating | — |
| `ollama` | `OllamaClient` | Ollama's native `/api/chat`, `gemma4:e2b` |
| `openai` | `OpenAICompatibleClient` | any OpenAI-compatible `/chat/completions` (llama.cpp server, vLLM, LM Studio) |

**Recommended: `gemma4:e2b` with reasoning on.** Reasoning is **on by default**
(`--no-think` to disable). A measured comparison on a CPU `ubuntu-latest` runner,
analysing the Synapse worked example (see below):

| model + mode | STRIDE coverage | assumption checks | analyze time |
|---|---|---|---|
| `gemma4:e4b`, reasoning off | InformationDisclosure | — | ~3 min |
| `gemma4:e4b`, reasoning on | (lost in chain-of-thought) | 2 | ~13 min |
| **`gemma4:e2b`, reasoning on** | **InfoDisclosure + ElevationOfPrivilege** | **2** | **~4 min** |

The smaller "effective-2B" model (7.2 GB) thinks fast enough on CPU that bounded
reasoning is affordable — giving the richest STRIDE *and* the assumption-check
signal, quickly. `e4b` is heavier (9.6 GB) and best run with `--no-think`.

```bash
# Recommended: local gemma4:e2b via Ollama, reasoning on (the default):
threat-delta analyze --baseline threat-model.yaml --diff pr.diff --llm ollama
```

Or from Python:

```python
from threat_delta import run_step, build_client
result = run_step(baseline="threat-model.yaml", diff="pr.diff",
                  llm=build_client("ollama"))  # gemma4:e2b
```

> Ollama-specific note: `OllamaClient` calls Ollama's **native `/api/chat`**
> endpoint, because the OpenAI `/v1` shim silently ignores the `think` flag (so a
> thinking model never actually stops thinking). The native endpoint honors it.

### Running Gemma in CI

By default the GitHub Action runs the `stub` (deterministic only) — it does **not**
provision a model, so out of the box CI emits only `untracked_path` deltas. To get
real 6b/6c/6d signal, switch the action to provision a local Gemma on the runner:

```yaml
- uses: Devko/pipeThreat@main
  with:
    baseline: threat-model.yaml
    llm: ollama
    llm-model: gemma4:e2b   # ~7.2GB; the default
```

The action installs Ollama, pulls the model (~4 min; not cached — a multi-GB model
is too large for GitHub's 10 GB cache), serves it, and points the step at it. It
runs on the standard CPU-only `ubuntu-latest` runner — slow per call (tens of
seconds), but the step makes only 3–5 calls per PR and is async/non-blocking,
exactly the spec's runtime target ("CPU-only CI runner, local ~4B"). For fast
repeated runs, use a self-hosted runner with the model pre-pulled, or point
`--llm openai` at an existing endpoint.

**Reasoning is on but capped** (spec §2/§11): `temperature=0` and a *per-stage*
reasoning budget — 6b classify `128`, 6c STRIDE `256`, 6d assumptions `384`
tokens (`LLMConfig.stage_reasoning_budgets`; `temperature`/`max_tokens` are always
hard caps). `--no-think` (or `LLMConfig(reasoning=False)`) disables thinking for a
larger/slower model. The integration test (`tests/test_pipeline.py`) demonstrates
the full §12 worked example with a scripted client.

### LLM-assisted baseline drafting

`threat-delta init --llm ollama` drafts the *initial* baseline with the model
instead of just a deterministic skeleton — a spec §3 one-time, offline,
human-reviewed bootstrap. It stays bounded and on-philosophy: deterministic code
discovers the components and `code_paths`; the model only fills the narrow
judgment fields (`trust_zone`, handled assets, entry points) per component over a
*small per-component code sample* — never the whole repo. Code (not the model)
mints asset ids and resolves references, so the draft always passes `validate`.
The output is labelled `DRAFT — HUMAN REVIEW REQUIRED`; review and commit it as
source.

## Worked example (Matrix Synapse)

[`examples/synapse/`](examples/synapse/) runs the whole step end-to-end against a
real, recognizable project. A PR adds a client endpoint that exports **any user's**
account data by `user_id` with no auth check; the step returns **5 High-severity
deltas** — STRIDE (InformationDisclosure / ElevationOfPrivilege / Spoofing) plus
three contradicted assumptions — each needing human review. See the generated
[`report/threat-delta.md`](examples/synapse/report/threat-delta.md) and
[`report/threat-delta.sarif`](examples/synapse/report/threat-delta.sarif), and
`examples/synapse/README.md` for the walk-through. Regenerate with
`python examples/synapse/generate_report.py`.

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

### Getting the *initial* baseline

Authoring the first baseline is deliberately **not** the delta step's job (spec §1
out of scope, §3 precondition). Three deterministic helpers make bootstrapping and
upkeep easy — none of them call an LLM:

```bash
# 1. Scaffold a starter threat-model.yaml from the repo's directory layout.
#    Review it, fill in the TODOs (trust zones, assets, assumptions), commit it.
threat-delta init . --out threat-model.yaml

# 2. Validate it as source — referential integrity, in CI on every change.
threat-delta validate --baseline threat-model.yaml

# 3. Measure completeness — which source paths no component covers yet.
threat-delta coverage --baseline threat-model.yaml . --ext .py --show-paths
```

Recommended path: scaffold a skeleton with `init`, or commit a minimal baseline
(`system` + `assets` + `assumptions`) and let the step's own `untracked_path`
deltas tell you, PR by PR, which components to add ("bootstrap-by-drift"). Either
way, `validate` it in CI and use `coverage` to close gaps deliberately. The
baseline can also be drafted with a one-time, offline, *human-reviewed* LLM pass —
the expensive whole-repo analysis we refuse to run per-PR is fine as a one-shot.

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
  transports.py    # real LLM clients (Ollama / OpenAI-compatible), stdlib-only
  scaffold.py      # `init` — scaffold a starter baseline from the repo layout
  scaffold_llm.py  # `init --llm` — LLM-assisted baseline draft (bounded)
  validate.py      # `validate` — baseline referential-integrity checks
  coverage.py      # `coverage` — source paths no component covers
  cli.py           # command-line entry point (analyze/init/validate/coverage)
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
