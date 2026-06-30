## Threat-Model Delta (advisory)

_This check is advisory and **non-blocking** — it never fails the build._

### High (3)

- **assumption_violation** — affected: `comp.webhooks`  :warning: **needs human review**
  - Contradicts assumption: `asm.no_unauthenticated_execution`
  - Confidence: high
  - Why high: assumption guards `asset.workflow_data` (high-sensitivity) → High
  - Change weakens or violates assumption 'asm.no_unauthenticated_execution': an anonymous request triggers workflow execution
  - Recommended action: Restore the assumption or, if the change is a legitimate evolution, update the baseline assumption and obtain security review.
  - Proposed baseline update: assumption_revisited `asm.no_unauthenticated_execution` — confirm intended; update or reaffirm the assumption
- **assumption_violation** — affected: `comp.webhooks`  :warning: **needs human review**
  - Contradicts assumption: `asm.public_endpoints_rate_limited`
  - Confidence: high
  - Why high: assumption guards `asset.workflow_data` (high-sensitivity) → High
  - Change weakens or violates assumption 'asm.public_endpoints_rate_limited': the public endpoint applies no rate limit
  - Recommended action: Restore the assumption or, if the change is a legitimate evolution, update the baseline assumption and obtain security review.
  - Proposed baseline update: assumption_revisited `asm.public_endpoints_rate_limited` — confirm intended; update or reaffirm the assumption
- **assumption_violation** — affected: `comp.webhooks`  :warning: **needs human review**
  - Contradicts assumption: `asm.webhooks_authenticated`
  - Confidence: high
  - Why high: assumption guards `asset.workflow_data` (high-sensitivity) → High
  - Change weakens or violates assumption 'asm.webhooks_authenticated': endpoint verifies no token or signature
  - Recommended action: Restore the assumption or, if the change is a legitimate evolution, update the baseline assumption and obtain security review.
  - Proposed baseline update: assumption_revisited `asm.webhooks_authenticated` — confirm intended; update or reaffirm the assumption

### Medium (1)

- **new_entry_point** — affected: `comp.webhooks`
  - Change signals: new entry point, trust-boundary crossing, control change
  - STRIDE: Spoofing, Tampering, DenialOfService, ElevationOfPrivilege
  - Confidence: high
  - Why medium: touches `asset.workflow_data` (high-sensitivity) → at least Medium
  - 3 change-signals on Webhook receiver (edge zone): new entry point, trust-boundary crossing, control change. STRIDE: Spoofing: no authentication or signature check — any caller can trigger a workflow; Tampering: attacker-controlled request body is passed straight in as workflow trigger data; DenialOfService: unauthenticated synchronous execution with no rate limit; ElevationOfPrivilege: triggers workflows that run with stored credentials
  - Recommended action: Confirm the new entry point is intended; add explicit authz + input validation, or route it through the gateway.
  - Proposed baseline update: component_entry_point_added `comp.webhooks` — entry_points += http_webhook; document the new boundary crossing; review affecting controls

---
**4 delta(s)** — High: 3, Medium: 1, Low: 0.

A high-severity delta needs human review — apply the `security/needs-review` label.
