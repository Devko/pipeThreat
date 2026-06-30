## Threat-Model Delta (advisory)

_This check is advisory and **non-blocking** — it never fails the build._

### High (5)

- **asset_exposure** — affected: `comp.client_api`  :warning: **needs human review**
  - STRIDE: InformationDisclosure, ElevationOfPrivilege, Spoofing
  - Confidence: medium
  - Asset-handling change on Client-Server REST API (edge zone). STRIDE: InformationDisclosure: returns any user's account data and messages without authorization; ElevationOfPrivilege: non-admin caller reads arbitrary users' data by id; Spoofing: user_id read from query string, not bound to an authenticated caller
  - Recommended action: Confirm the asset exposure is intended; verify access controls and that sensitive data is not newly disclosed.
  - Proposed baseline update: component_asset_handling_changed `comp.client_api` — review handles_assets for comp.client_api
- **assumption_violation** — affected: `comp.client_api`  :warning: **needs human review**
  - Contradicts assumption: `asm.admin_requires_admin`
  - Confidence: medium
  - Change weakens or violates assumption 'asm.admin_requires_admin': returns another user's data without a server-admin token
  - Recommended action: Restore the assumption or, if the change is a legitimate evolution, update the baseline assumption and obtain security review.
  - Proposed baseline update: assumption_revisited `asm.admin_requires_admin` — confirm intended; update or reaffirm the assumption
- **assumption_violation** — affected: `comp.client_api`  :warning: **needs human review**
  - Contradicts assumption: `asm.client_requires_token`
  - Confidence: medium
  - Change weakens or violates assumption 'asm.client_requires_token': new client endpoint mounted with no access-token check
  - Recommended action: Restore the assumption or, if the change is a legitimate evolution, update the baseline assumption and obtain security review.
  - Proposed baseline update: assumption_revisited `asm.client_requires_token` — confirm intended; update or reaffirm the assumption
- **assumption_violation** — affected: `comp.client_api`  :warning: **needs human review**
  - Contradicts assumption: `asm.user_scoped_access`
  - Confidence: medium
  - Change weakens or violates assumption 'asm.user_scoped_access': reads an arbitrary user_id instead of the authenticated user
  - Recommended action: Restore the assumption or, if the change is a legitimate evolution, update the baseline assumption and obtain security review.
  - Proposed baseline update: assumption_revisited `asm.user_scoped_access` — confirm intended; update or reaffirm the assumption
- **new_entry_point** — affected: `comp.client_api`  :warning: **needs human review**
  - STRIDE: InformationDisclosure, ElevationOfPrivilege, Spoofing
  - Confidence: medium
  - New entry point on Client-Server REST API (edge zone). STRIDE: InformationDisclosure: returns any user's account data and messages without authorization; ElevationOfPrivilege: non-admin caller reads arbitrary users' data by id; Spoofing: user_id read from query string, not bound to an authenticated caller
  - Recommended action: Confirm the new entry point is intended; add explicit authz + input validation, or route it through the gateway.
  - Proposed baseline update: component_entry_point_added `comp.client_api` — entry_points += http_client_api

---
**5 delta(s)** — High: 5, Medium: 0, Low: 0.

A high-severity delta needs human review — apply the `security/needs-review` label.
