## Threat-Model Delta (advisory)

_This check is advisory and **non-blocking** — it never fails the build._

### High (4)

- **assumption_violation** — affected: `comp.http_api`  :warning: **needs human review**
  - Contradicts assumption: `asm.acl_enforced`
  - Confidence: high
  - Why high: assumption guards `asset.tokens` (critical-sensitivity) → High
  - Change weakens or violates assumption 'asm.acl_enforced': reads storage directly with no ACL policy evaluation
  - Recommended action: Restore the assumption or, if the change is a legitimate evolution, update the baseline assumption and obtain security review.
  - Proposed baseline update: assumption_revisited `asm.acl_enforced` — confirm intended; update or reaffirm the assumption
- **assumption_violation** — affected: `comp.http_api`  :warning: **needs human review**
  - Contradicts assumption: `asm.all_access_audited`
  - Confidence: high
  - Why high: assumption guards `asset.tokens` (critical-sensitivity) → High
  - Change weakens or violates assumption 'asm.all_access_audited': returns secret data without writing an audit entry
  - Recommended action: Restore the assumption or, if the change is a legitimate evolution, update the baseline assumption and obtain security review.
  - Proposed baseline update: assumption_revisited `asm.all_access_audited` — confirm intended; update or reaffirm the assumption
- **assumption_violation** — affected: `comp.http_api`  :warning: **needs human review**
  - Contradicts assumption: `asm.all_requests_authenticated`
  - Confidence: high
  - Why high: assumption guards `asset.tokens` (critical-sensitivity) → High
  - Change weakens or violates assumption 'asm.all_requests_authenticated': new endpoint requires no token
  - Recommended action: Restore the assumption or, if the change is a legitimate evolution, update the baseline assumption and obtain security review.
  - Proposed baseline update: assumption_revisited `asm.all_requests_authenticated` — confirm intended; update or reaffirm the assumption
- **new_entry_point** — affected: `comp.http_api`  :warning: **needs human review**
  - Change signals: new entry point, trust-boundary crossing, control change
  - STRIDE: InformationDisclosure, ElevationOfPrivilege, Repudiation
  - Confidence: high
  - Why high: touches `asset.tokens` (critical-sensitivity) → at least High
  - 3 change-signals on HTTP API (edge zone): new entry point, trust-boundary crossing, control change. STRIDE: InformationDisclosure: returns raw decrypted secrets read straight from the storage barrier; ElevationOfPrivilege: reads any storage path with no token and no ACL policy check; Repudiation: secret access is not written to the audit log
  - Recommended action: Confirm the new entry point is intended; add explicit authz + input validation, or route it through the gateway.
  - Proposed baseline update: component_entry_point_added `comp.http_api` — entry_points += http_api; document the new boundary crossing; review affecting controls

---
**4 delta(s)** — High: 4, Medium: 0, Low: 0.

A high-severity delta needs human review — apply the `security/needs-review` label.
