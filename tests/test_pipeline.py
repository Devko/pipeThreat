"""End-to-end integration tests for the orchestration + 6e assembly.

The centrepiece reproduces the spec §12 worked example: a new public HTTP route
added to the (internal) User Service. With a scripted model returning the §12
flags, STRIDE and violations, the pipeline must produce a HIGH-severity,
human-review delta set that crosses a trust boundary into an internal component
and contradicts the stated assumptions.
"""

from __future__ import annotations

import json

import pytest

from threat_delta.baseline import parse_baseline
from threat_delta.diff import parse_unified_diff
from threat_delta.llm import ScriptedLLMClient
from threat_delta.models import (
    DeltaType,
    FileAnnotation,
    Finding,
    Severity,
)
from threat_delta.pipeline import analyze


BASELINE_DATA = {
    "system": {"name": "payments-api", "version": "2025.11"},
    "assets": [
        {"id": "asset.cardholder_pan", "name": "Cardholder PAN", "sensitivity": "critical"},
        {"id": "asset.user_pii", "name": "User PII", "sensitivity": "high"},
        {"id": "asset.session_token", "name": "Session token", "sensitivity": "high"},
    ],
    "trust_boundaries": [
        {"id": "tb.internet_edge", "name": "Internet to Edge", "controls": ["waf"]},
        {"id": "tb.dmz_internal", "name": "DMZ to Internal", "controls": ["mtls"]},
    ],
    "components": [
        {"id": "comp.api_gateway", "name": "API Gateway", "trust_zone": "dmz",
         "code_paths": ["src/gateway/**"], "handles_assets": ["asset.session_token"],
         "entry_points": ["http_public"]},
        {"id": "comp.tokenizer", "name": "Tokenizer Service", "trust_zone": "internal",
         "code_paths": ["src/tokenizer/**"], "handles_assets": ["asset.cardholder_pan"],
         "entry_points": ["grpc_internal"]},
        {"id": "comp.user_service", "name": "User Service", "trust_zone": "internal",
         "code_paths": ["src/users/**"], "handles_assets": ["asset.user_pii"],
         "entry_points": ["grpc_internal"]},
    ],
    "data_flows": [
        {"id": "flow.tokenize", "from": "comp.api_gateway", "to": "comp.tokenizer",
         "crosses": ["tb.dmz_internal"], "assets": ["asset.cardholder_pan"]},
    ],
    "assumptions": [
        {"id": "asm.edge_validation", "statement": "All external input validated at gateway."},
        {"id": "asm.no_direct_internal_ingress", "statement": "Internal services not reachable from internet."},
        {"id": "asm.pan_never_logged", "statement": "PAN never logged in plaintext."},
    ],
}

WORKED_EXAMPLE_DIFF = """diff --git a/src/users/admin_handler.py b/src/users/admin_handler.py
new file mode 100644
--- /dev/null
+++ b/src/users/admin_handler.py
@@ -0,0 +1,5 @@
+class AdminHandler(BaseHTTPRequestHandler):
+    def do_GET(self):
+        user_id = self.path.rsplit("/", 1)[-1]
+        profile = get_user_profile(user_id)
+        self.wfile.write(profile.to_json().encode())
"""


@pytest.fixture
def baseline():
    return parse_baseline(BASELINE_DATA)


def _worked_example_llm():
    # Scripted to the §12 outputs: classification flags, user_service STRIDE,
    # and the two assumption violations.
    return ScriptedLLMClient(
        responses={
            # 6b classification — keyed on a label present in that prompt only.
            "is it plausibly introduced": {
                "new_entry_point": True,
                "trust_boundary_crossing": True,
                "asset_handling_change": True,
                "new_data_flow": False,
                "control_change": False,
            },
            # 6c STRIDE — keyed on the component id present in the stride prompt.
            "comp.user_service (zone": {
                "deltas": [
                    {"stride": "InformationDisclosure", "reason": "returns full PII without authz"},
                    {"stride": "ElevationOfPrivilege", "reason": "internal data reachable by external caller"},
                    {"stride": "Spoofing", "reason": "no caller authentication on new route"},
                ]
            },
            # 6d assumptions — keyed on a label present in that prompt only.
            "does this change violate or weaken it": {
                "violations": [
                    {"assumption_id": "asm.no_direct_internal_ingress", "violated": True,
                     "reason": "internal service now has a public entry point"},
                    {"assumption_id": "asm.edge_validation", "violated": True,
                     "reason": "input no longer guaranteed to transit gateway validation"},
                ]
            },
        },
        default={},
    )


def test_worked_example_high_severity(baseline):
    diff = parse_unified_diff(WORKED_EXAMPLE_DIFF, pr="1234")
    annotations = [
        FileAnnotation(
            path="src/users/admin_handler.py",
            entry_points=["http_public"],
            untrusted_inputs=["self.path"],
            sinks=["get_user_profile"],
        )
    ]
    result = analyze(diff, baseline, annotations, [], _worked_example_llm(), pr="1234")

    assert result.deltas, "expected deltas for the worked example"
    # At least one HIGH delta requiring human review.
    high = [d for d in result.deltas if d.severity == Severity.HIGH]
    assert high, "worked example must yield a HIGH-severity delta"
    assert all(d.delta_id.startswith("td-1234-") for d in result.deltas)

    types = {d.type for d in result.deltas}
    # New entry point on an internal component -> HIGH (§7).
    assert DeltaType.NEW_ENTRY_POINT in types
    # Assumption violations surfaced and tied to known assumptions.
    av = [d for d in result.deltas if d.type == DeltaType.ASSUMPTION_VIOLATION]
    assert {d.contradicts_assumption for d in av} == {
        "asm.no_direct_internal_ingress",
        "asm.edge_validation",
    }
    for d in av:
        assert d.severity == Severity.HIGH  # guards high-sensitivity asset

    # new_entry_point delta carries STRIDE from 6c and a baseline-update proposal.
    nep = next(d for d in result.deltas if d.type == DeltaType.NEW_ENTRY_POINT)
    assert nep.stride, "STRIDE should be attached to the entry-point delta"
    assert nep.requires_human_review
    assert nep.proposed_baseline_update.target == "comp.user_service"
    assert "http_public" in nep.proposed_baseline_update.change
    assert "http_public" in nep.evidence.get("entry_points", [])

    # SARIF + comment render and are advisory (no error level).
    sarif = result.sarif
    assert sarif["version"] == "2.1.0"
    json.dumps(sarif)  # serializable
    levels = {r["level"] for r in sarif["runs"][0]["results"]}
    assert "error" not in levels
    assert "High" in result.comment


def test_untracked_path_emits_low_delta(baseline):
    diff = parse_unified_diff(
        "diff --git a/docs/readme.md b/docs/readme.md\n"
        "--- a/docs/readme.md\n+++ b/docs/readme.md\n"
        "@@ -1 +1 @@\n-old\n+new\n",
        pr="77",
    )
    # Stub model: nothing positive. Only the 6a untracked-path delta should appear.
    result = analyze(diff, baseline, [], [], ScriptedLLMClient(default={}), pr="77")
    assert len(result.deltas) == 1
    d = result.deltas[0]
    assert d.type == DeltaType.UNTRACKED_PATH
    assert d.severity == Severity.LOW
    assert d.requires_human_review
    assert d.evidence["files"] == ["docs/readme.md"]


def test_untracked_path_bumped_to_medium_when_in_finding(baseline):
    diff = parse_unified_diff(
        "diff --git a/docs/x.md b/docs/x.md\n--- a/docs/x.md\n+++ b/docs/x.md\n"
        "@@ -1 +1 @@\n-a\n+b\n",
        pr="9",
    )
    findings = [Finding(id="SAST-1", file="docs/x.md", severity="medium", message="x")]
    result = analyze(diff, baseline, [], findings, ScriptedLLMClient(default={}), pr="9")
    assert result.deltas[0].severity == Severity.MEDIUM


def test_no_match_no_untracked_exits_empty(baseline):
    # A diff that touches a tracked component but the stub flags nothing and there
    # are no untracked paths -> no deltas.
    diff = parse_unified_diff(
        "diff --git a/src/users/util.py b/src/users/util.py\n"
        "--- a/src/users/util.py\n+++ b/src/users/util.py\n"
        "@@ -1 +1 @@\n-a\n+b\n",
        pr="5",
    )
    result = analyze(diff, baseline, [], [], ScriptedLLMClient(default={}), pr="5")
    assert result.deltas == []


def test_flags_gate_skips_6c_6d(baseline):
    # When 6b returns all-false, 6c/6d must not call the model (spec §6b gate).
    diff = parse_unified_diff(
        "diff --git a/src/users/util.py b/src/users/util.py\n"
        "--- a/src/users/util.py\n+++ b/src/users/util.py\n"
        "@@ -1 +1 @@\n-a\n+b\n",
        pr="5",
    )
    llm = ScriptedLLMClient(default={})  # 6b -> all false
    analyze(diff, baseline, [], [], llm, pr="5")
    # Exactly one call (6b). 6c and 6d skipped.
    assert len(llm.calls) == 1
