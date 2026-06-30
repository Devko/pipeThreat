## Threat-Model Delta (advisory)

_This check is advisory and **non-blocking** — it never fails the build._

### High (3)

- **assumption_violation** — affected: `comp.webhooks`  :warning: **needs human review**
  - Contradicts assumption: `asm.no_unauthenticated_execution`
  - Confidence: medium
  - Change weakens or violates assumption 'asm.no_unauthenticated_execution': an anonymous request triggers workflow execution
  - Recommended action: Restore the assumption or, if the change is a legitimate evolution, update the baseline assumption and obtain security review.
  - Proposed baseline update: assumption_revisited `asm.no_unauthenticated_execution` — confirm intended; update or reaffirm the assumption
- **assumption_violation** — affected: `comp.webhooks`  :warning: **needs human review**
  - Contradicts assumption: `asm.public_endpoints_rate_limited`
  - Confidence: medium
  - Change weakens or violates assumption 'asm.public_endpoints_rate_limited': the public endpoint applies no rate limit
  - Recommended action: Restore the assumption or, if the change is a legitimate evolution, update the baseline assumption and obtain security review.
  - Proposed baseline update: assumption_revisited `asm.public_endpoints_rate_limited` — confirm intended; update or reaffirm the assumption
- **assumption_violation** — affected: `comp.webhooks`  :warning: **needs human review**
  - Contradicts assumption: `asm.webhooks_authenticated`
  - Confidence: medium
  - Change weakens or violates assumption 'asm.webhooks_authenticated': endpoint verifies no token or signature
  - Recommended action: Restore the assumption or, if the change is a legitimate evolution, update the baseline assumption and obtain security review.
  - Proposed baseline update: assumption_revisited `asm.webhooks_authenticated` — confirm intended; update or reaffirm the assumption

### Medium (3)

- **control_change** — affected: `comp.webhooks`
  - STRIDE: Spoofing, Tampering, DenialOfService, ElevationOfPrivilege
  - Confidence: medium
  - Control change on Webhook receiver (edge zone). STRIDE: Spoofing: no authentication or signature check — any caller can trigger a workflow; Tampering: attacker-controlled request body is passed straight in as workflow trigger data; DenialOfService: unauthenticated synchronous execution with no rate limit; ElevationOfPrivilege: triggers workflows that run with stored credentials
  - Recommended action: Review the changed/removed control; restore it or document the compensating control in the baseline.
  - Proposed baseline update: control_changed `comp.webhooks` — review controls affecting comp.webhooks
- **new_entry_point** — affected: `comp.webhooks`
  - STRIDE: Spoofing, Tampering, DenialOfService, ElevationOfPrivilege
  - Confidence: medium
  - New entry point on Webhook receiver (edge zone). STRIDE: Spoofing: no authentication or signature check — any caller can trigger a workflow; Tampering: attacker-controlled request body is passed straight in as workflow trigger data; DenialOfService: unauthenticated synchronous execution with no rate limit; ElevationOfPrivilege: triggers workflows that run with stored credentials
  - Recommended action: Confirm the new entry point is intended; add explicit authz + input validation, or route it through the gateway.
  - Proposed baseline update: component_entry_point_added `comp.webhooks` — entry_points += http_webhook
- **trust_boundary_crossing** — affected: `comp.webhooks`
  - STRIDE: Spoofing, Tampering, DenialOfService, ElevationOfPrivilege
  - Confidence: medium
  - Trust-boundary crossing on Webhook receiver (edge zone). STRIDE: Spoofing: no authentication or signature check — any caller can trigger a workflow; Tampering: attacker-controlled request body is passed straight in as workflow trigger data; DenialOfService: unauthenticated synchronous execution with no rate limit; ElevationOfPrivilege: triggers workflows that run with stored credentials
  - Recommended action: Verify the crossing is authorized and that the boundary's controls (authn/authz, validation) apply to the new path.
  - Proposed baseline update: trust_boundary_crossing_added `comp.webhooks` — document the new boundary crossing for comp.webhooks

---
**6 delta(s)** — High: 3, Medium: 3, Low: 0.

A high-severity delta needs human review — apply the `security/needs-review` label.
