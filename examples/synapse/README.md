# Worked example — Matrix Synapse

A complete, end-to-end run of the Threat-Model Delta step against a real,
recognizable open-source project ([Matrix Synapse](https://github.com/element-hq/synapse)),
showing the inputs and the generated report.

> **Note.** This baseline is a small *illustrative* model: its components and
> `code_paths` mirror Synapse's real package layout, but it is not an authoritative
> threat model for the project. The committed report is generated with a **scripted
> model** (so it's deterministic and reproducible without a model server),
> representing what a small local model returns for this diff. Everything else —
> relevance, the deterministic §7 severity, dedup, and SARIF/comment rendering — is
> the real pipeline. Run it live with `--llm ollama` (see below).

## The files

| File | What |
|---|---|
| `threat-model.yaml` | The baseline: 5 assets, 3 trust boundaries, 7 components, 5 assumptions. Passes `threat-delta validate`. |
| `pr-account-export.diff` | The PR under review (see below). |
| `pr-account-export.annotations.json` | Step-5 static-analysis annotations for the changed file. |
| `generate_report.py` | Runs the pipeline with the scripted model and writes `report/`. |
| `report/threat-delta.md` | The generated PR comment. |
| `report/threat-delta.sarif` | The generated SARIF 2.1.0 log. |
| `report/deltas.json` | The raw deltas. |

## The PR

`pr-account-export.diff` adds a new client-server endpoint
`GET /_matrix/client/v3/account_export?user_id=…` in
`synapse/rest/client/account_export.py`. It reads the **target user id straight
from the query string** and returns that user's profile, account data and recent
room events — with **no access-token check, no admin check, and no binding of the
caller to the requested user**.

A plain linter might note "missing auth". The delta step explains *why it matters
at the system level*.

## How the step reasons about it

- **6a (relevance):** `synapse/rest/client/**` → `comp.client_api` (zone `edge`,
  handles `access_token` (critical), `message_content`, `account_data`). Pulls in
  all assumptions.
- **6b (classify):** `new_entry_point: true`, `asset_handling_change: true`.
- **6c (STRIDE for `comp.client_api`):** `InformationDisclosure` (returns any
  user's data without authorization), `ElevationOfPrivilege` (non-admin reads
  arbitrary users' data), `Spoofing` (`user_id` not bound to the caller).
- **6d (assumptions):** violates `asm.client_requires_token` (no token check),
  `asm.admin_requires_admin` (returns others' data without admin) and
  `asm.user_scoped_access` (arbitrary `user_id`).
- **6e (score):** severity is **High** deterministically — the component handles a
  `critical` asset and the change violates assumptions guarding sensitive assets.
  Five deltas, all `requires_human_review: true`, each with a
  `proposed_baseline_update`.

## Reproduce it

```bash
# Scripted model (offline, deterministic — what this repo ships):
python examples/synapse/generate_report.py

# Or live against a local Gemma via Ollama:
threat-delta analyze \
  --baseline examples/synapse/threat-model.yaml \
  --diff examples/synapse/pr-account-export.diff \
  --annotations examples/synapse/pr-account-export.annotations.json \
  --pr 17421 --llm ollama --llm-model gemma4:e2b \
  --sarif examples/synapse/report/threat-delta.sarif \
  --comment examples/synapse/report/threat-delta.md
```

See [`report/threat-delta.md`](report/threat-delta.md) for the rendered output.
