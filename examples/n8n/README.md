# Worked example — n8n (TypeScript / Node)

An end-to-end run of the Threat-Model Delta step against a real TypeScript project,
[n8n](https://github.com/n8n-io/n8n). The third worked example (with the Python
[Synapse](../synapse/) and Go [Vault](../vault/) ones) — a different language again,
and the one that exercises **Tampering** and **DenialOfService** STRIDE categories
and **tiered severity** (High + Medium in one report).

> **Note.** This baseline is a small *illustrative* model: its components and
> `code_paths` mirror n8n's monorepo layout, but it is not an authoritative threat
> model for the project. The committed report is generated with a **scripted model**
> (deterministic and reproducible without a model server), representing what a small
> local model returns for this diff. Everything else — relevance, the deterministic
> §7 severity, dedup, and SARIF/comment rendering — is the real pipeline. Run it
> live with `--llm ollama` (see below).

## The PR

`pr-public-trigger.diff` adds `POST /webhook-public/:workflowId` in
`packages/cli/src/webhooks/PublicTriggerHandler.ts`. It looks up a workflow by id
and **executes it synchronously with the request body as trigger data** — with
**no authentication, no signature check, and no rate limit**.

## How the step reasons about it

- **6a (relevance):** `packages/cli/src/webhooks/**` → `comp.webhooks` (zone `edge`,
  handles `asset.workflow_data` — high). Pulls in all assumptions.
- **6b (classify):** `new_entry_point`, `trust_boundary_crossing`, `control_change`.
- **6c (STRIDE for `comp.webhooks`):** `Spoofing` (no caller authentication),
  `Tampering` (attacker-controlled body drives execution), `DenialOfService`
  (unauthenticated, unbounded synchronous runs) and `ElevationOfPrivilege` (runs
  workflows that use stored credentials).
- **6d (assumptions):** violates `asm.webhooks_authenticated`,
  `asm.no_unauthenticated_execution` and `asm.public_endpoints_rate_limited`.
- **6e (score):** **tiered, deterministically** — the assumption violations guard a
  high-sensitivity asset, so they are **High** (needs human review); the
  flag-derived component deltas land at **Medium**. Six deltas total.

This tiering is the point of deterministic severity: the model supplies the same
facts either way, and §7 rules — not the model — decide what blocks a reviewer's
attention.

## Files

| File | What |
|---|---|
| `threat-model.yaml` | Baseline: 3 assets, 3 trust boundaries, 5 components, 3 assumptions. Passes `validate`. |
| `pr-public-trigger.diff` | The PR under review. |
| `pr-public-trigger.annotations.json` | Step-5 static-analysis annotations. |
| `generate_report.py` | Runs the pipeline with the scripted model and writes `report/`. |
| `report/threat-delta.md` · `.sarif` · `deltas.json` | The generated outputs. |

## Reproduce it

```bash
# Scripted model (offline, deterministic — what this repo ships):
python examples/n8n/generate_report.py

# Or live against a local model via Ollama:
threat-delta analyze \
  --baseline examples/n8n/threat-model.yaml \
  --diff examples/n8n/pr-public-trigger.diff \
  --annotations examples/n8n/pr-public-trigger.annotations.json \
  --pr 8421 --llm ollama --llm-model gemma4:e2b \
  --sarif examples/n8n/report/threat-delta.sarif \
  --comment examples/n8n/report/threat-delta.md
```

See [`report/threat-delta.md`](report/threat-delta.md) for the rendered output.
