## Threat-Model Delta (advisory)

_This check is advisory and **non-blocking** — it never fails the build._

### High (6)

- **assumption_violation** — affected: `comp.http_api`  :warning: **needs human review**
  - Contradicts assumption: `asm.acl_enforced`
  - Confidence: medium
  - Change weakens or violates assumption 'asm.acl_enforced': reads storage directly with no ACL policy evaluation
  - Recommended action: Restore the assumption or, if the change is a legitimate evolution, update the baseline assumption and obtain security review.
  - Proposed baseline update: assumption_revisited `asm.acl_enforced` — confirm intended; update or reaffirm the assumption
- **assumption_violation** — affected: `comp.http_api`  :warning: **needs human review**
  - Contradicts assumption: `asm.all_access_audited`
  - Confidence: medium
  - Change weakens or violates assumption 'asm.all_access_audited': returns secret data without writing an audit entry
  - Recommended action: Restore the assumption or, if the change is a legitimate evolution, update the baseline assumption and obtain security review.
  - Proposed baseline update: assumption_revisited `asm.all_access_audited` — confirm intended; update or reaffirm the assumption
- **assumption_violation** — affected: `comp.http_api`  :warning: **needs human review**
  - Contradicts assumption: `asm.all_requests_authenticated`
  - Confidence: medium
  - Change weakens or violates assumption 'asm.all_requests_authenticated': new endpoint requires no token
  - Recommended action: Restore the assumption or, if the change is a legitimate evolution, update the baseline assumption and obtain security review.
  - Proposed baseline update: assumption_revisited `asm.all_requests_authenticated` — confirm intended; update or reaffirm the assumption
- **control_change** — affected: `comp.http_api`  :warning: **needs human review**
  - STRIDE: InformationDisclosure, ElevationOfPrivilege, Repudiation
  - Confidence: medium
  - Control change on HTTP API (edge zone). STRIDE: InformationDisclosure: returns raw decrypted secrets read straight from the storage barrier; ElevationOfPrivilege: reads any storage path with no token and no ACL policy check; Repudiation: secret access is not written to the audit log
  - Recommended action: Review the changed/removed control; restore it or document the compensating control in the baseline.
  - Proposed baseline update: control_changed `comp.http_api` — review controls affecting comp.http_api
- **new_entry_point** — affected: `comp.http_api`  :warning: **needs human review**
  - STRIDE: InformationDisclosure, ElevationOfPrivilege, Repudiation
  - Confidence: medium
  - New entry point on HTTP API (edge zone). STRIDE: InformationDisclosure: returns raw decrypted secrets read straight from the storage barrier; ElevationOfPrivilege: reads any storage path with no token and no ACL policy check; Repudiation: secret access is not written to the audit log
  - Recommended action: Confirm the new entry point is intended; add explicit authz + input validation, or route it through the gateway.
  - Proposed baseline update: component_entry_point_added `comp.http_api` — entry_points += http_api
- **trust_boundary_crossing** — affected: `comp.http_api`  :warning: **needs human review**
  - STRIDE: InformationDisclosure, ElevationOfPrivilege, Repudiation
  - Confidence: medium
  - Trust-boundary crossing on HTTP API (edge zone). STRIDE: InformationDisclosure: returns raw decrypted secrets read straight from the storage barrier; ElevationOfPrivilege: reads any storage path with no token and no ACL policy check; Repudiation: secret access is not written to the audit log
  - Recommended action: Verify the crossing is authorized and that the boundary's controls (authn/authz, validation) apply to the new path.
  - Proposed baseline update: trust_boundary_crossing_added `comp.http_api` — document the new boundary crossing for comp.http_api

---
**6 delta(s)** — High: 6, Medium: 0, Low: 0.

A high-severity delta needs human review — apply the `security/needs-review` label.
