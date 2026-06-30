# Worked example — HashiCorp Vault (Go)

An end-to-end run of the Threat-Model Delta step against a real Go project,
[HashiCorp Vault](https://github.com/hashicorp/vault). It's a second worked example
(alongside the Python [Synapse](../synapse/) one) to show that `code_paths` and the
whole pipeline are language-agnostic — and to surface a different STRIDE mix.

> **Note.** This baseline is a small *illustrative* model: its components and
> `code_paths` mirror Vault's real package layout, but it is not an authoritative
> threat model for the project. The committed report is generated with a **scripted
> model** (deterministic and reproducible without a model server), representing
> what a small local model returns for this diff. Everything else — relevance, the
> deterministic §7 severity, dedup, and SARIF/comment rendering — is the real
> pipeline. Run it live with `--llm ollama` (see below).

## The PR

`pr-debug-inspect.diff` adds a new HTTP endpoint
`GET /v1/sys/internal/inspect?path=…` in `http/sys_inspect.go` that returns the
**raw stored value** at any path, reading **straight from the storage barrier** —
with **no token required, no ACL policy check, and no audit-log entry**.

A linter sees a new handler. The delta step sees that it punches through three of
Vault's core security boundaries at once.

## How the step reasons about it

- **6a (relevance):** `http/**` → `comp.http_api` (zone `edge`, handles
  `asset.tokens` — critical). Pulls in all assumptions.
- **6b (classify):** `new_entry_point`, `trust_boundary_crossing`, `control_change`.
- **6c (STRIDE for `comp.http_api`):** `InformationDisclosure` (returns decrypted
  secrets), `ElevationOfPrivilege` (reads any path with no ACL check), and
  **`Repudiation`** (the access leaves no audit trail).
- **6d (assumptions):** violates `asm.all_requests_authenticated` (no token),
  `asm.acl_enforced` (no policy check) and `asm.all_access_audited` (no audit entry).
- **6e (score):** **High** deterministically — `comp.http_api` handles a `critical`
  asset and the change violates assumptions guarding sensitive assets. Six deltas,
  all `requires_human_review: true`.

## Files

| File | What |
|---|---|
| `threat-model.yaml` | Baseline: 5 assets, 4 trust boundaries, 6 components, 4 assumptions. Passes `validate`. |
| `pr-debug-inspect.diff` | The PR under review. |
| `pr-debug-inspect.annotations.json` | Step-5 static-analysis annotations. |
| `generate_report.py` | Runs the pipeline with the scripted model and writes `report/`. |
| `report/threat-delta.md` · `.sarif` · `deltas.json` | The generated outputs. |

## Reproduce it

```bash
# Scripted model (offline, deterministic — what this repo ships):
python examples/vault/generate_report.py

# Or live against a local model via Ollama:
threat-delta analyze \
  --baseline examples/vault/threat-model.yaml \
  --diff examples/vault/pr-debug-inspect.diff \
  --annotations examples/vault/pr-debug-inspect.annotations.json \
  --pr 29101 --llm ollama --llm-model gemma4:e2b \
  --sarif examples/vault/report/threat-delta.sarif \
  --comment examples/vault/report/threat-delta.md
```

See [`report/threat-delta.md`](report/threat-delta.md) for the rendered output.
