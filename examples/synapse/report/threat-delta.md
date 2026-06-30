## Threat-Model Delta (advisory)

_This check is advisory and **non-blocking** — it never fails the build._

### High (4)

- **assumption_violation** — affected: `comp.client_api`  :warning: **needs human review**
  - Contradicts assumption: `asm.admin_requires_admin`
  - Confidence: high
  - Why high: assumption guards `asset.access_token` (critical-sensitivity) → High
  - Change weakens or violates assumption 'asm.admin_requires_admin': returns another user's data without a server-admin token
  - Recommended action: Restore the assumption or, if the change is a legitimate evolution, update the baseline assumption and obtain security review.
  - Proposed baseline update: assumption_revisited `asm.admin_requires_admin` — confirm intended; update or reaffirm the assumption
- **assumption_violation** — affected: `comp.client_api`  :warning: **needs human review**
  - Contradicts assumption: `asm.client_requires_token`
  - Confidence: high
  - Why high: assumption guards `asset.access_token` (critical-sensitivity) → High
  - Change weakens or violates assumption 'asm.client_requires_token': new client endpoint mounted with no access-token check
  - Recommended action: Restore the assumption or, if the change is a legitimate evolution, update the baseline assumption and obtain security review.
  - Proposed baseline update: assumption_revisited `asm.client_requires_token` — confirm intended; update or reaffirm the assumption
- **assumption_violation** — affected: `comp.client_api`  :warning: **needs human review**
  - Contradicts assumption: `asm.user_scoped_access`
  - Confidence: high
  - Why high: assumption guards `asset.access_token` (critical-sensitivity) → High
  - Change weakens or violates assumption 'asm.user_scoped_access': reads an arbitrary user_id instead of the authenticated user
  - Recommended action: Restore the assumption or, if the change is a legitimate evolution, update the baseline assumption and obtain security review.
  - Proposed baseline update: assumption_revisited `asm.user_scoped_access` — confirm intended; update or reaffirm the assumption
- **new_entry_point** — affected: `comp.client_api`  :warning: **needs human review**
  - Change signals: new entry point, asset-handling change
  - STRIDE: InformationDisclosure, ElevationOfPrivilege, Spoofing
  - Confidence: high
  - Why high: touches `asset.access_token` (critical-sensitivity) → at least High
  - 2 change-signals on Client-Server REST API (edge zone): new entry point, asset-handling change. STRIDE: InformationDisclosure: returns any user's account data and messages without authorization; ElevationOfPrivilege: non-admin caller reads arbitrary users' data by id; Spoofing: user_id read from query string, not bound to an authenticated caller
  - Recommended action: Confirm the new entry point is intended; add explicit authz + input validation, or route it through the gateway.
  - Proposed baseline update: component_entry_point_added `comp.client_api` — entry_points += http_client_api; review handles_assets

---
**4 delta(s)** — High: 4, Medium: 0, Low: 0.

A high-severity delta needs human review — apply the `security/needs-review` label.
