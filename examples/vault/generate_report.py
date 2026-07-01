#!/usr/bin/env python3
"""Generate the worked-example Threat-Model Delta report for the Vault sample.

Runs the real pipeline (`threat_delta.run_step`) over the sample baseline, diff
and annotations in this directory, and writes the SARIF + PR-comment report into
``report/``.

The three model calls (Stages 2/3/4) are driven by a **scripted model** so the report
is deterministic and reproducible without a model server (the same technique the
tests use). Everything else (relevance, severity, dedup, SARIF/comment rendering)
is the real pipeline. Run it live instead with:

    threat-delta analyze \
        --baseline examples/vault/threat-model.yaml \
        --diff examples/vault/pr-debug-inspect.diff \
        --annotations examples/vault/pr-debug-inspect.annotations.json \
        --pr 29101 --llm ollama --llm-model gemma4:e2b \
        --sarif report/threat-delta.sarif --comment report/threat-delta.md
"""

from __future__ import annotations

import json
from pathlib import Path

from threat_delta import AnalysisResult, ScriptedLLMClient, run_step

HERE = Path(__file__).resolve().parent
PR = "29101"

# What a small local model is expected to return for this PR, keyed by a unique
# substring of each stage's prompt (Stage 2 / Stage 3-for-http_api / Stage 4).
SCRIPTED_MODEL = ScriptedLLMClient(
    responses={
        # Stage 2 — classification gate.
        "is it plausibly introduced or changed by this diff?": {
            "new_entry_point": True,
            "trust_boundary_crossing": True,
            "control_change": True,
            "asset_handling_change": False,
            "new_data_flow": False,
        },
        # Stage 3 — STRIDE deltas for the affected component (comp.http_api).
        "comp.http_api (zone": {
            "deltas": [
                {
                    "stride": "InformationDisclosure",
                    "reason": "returns raw decrypted secrets read straight from the storage barrier",
                },
                {
                    "stride": "ElevationOfPrivilege",
                    "reason": "reads any storage path with no token and no ACL policy check",
                },
                {
                    "stride": "Repudiation",
                    "reason": "secret access is not written to the audit log",
                },
            ]
        },
        # Stage 4 — assumption contradictions, fanned out one call per assumption and
        # keyed on the assumption id echoed in each single-assumption prompt.
        "asm.all_requests_authenticated": {
            "assumption_id": "asm.all_requests_authenticated",
            "violated": True,
            "reason": "new endpoint requires no token",
        },
        "asm.acl_enforced": {
            "assumption_id": "asm.acl_enforced",
            "violated": True,
            "reason": "reads storage directly with no ACL policy evaluation",
        },
        "asm.all_access_audited": {
            "assumption_id": "asm.all_access_audited",
            "violated": True,
            "reason": "returns secret data without writing an audit entry",
        },
    },
    default={},
)


def build_result() -> AnalysisResult:
    """Run the pipeline over the sample inputs and return the result."""
    return run_step(
        baseline=HERE / "threat-model.yaml",
        diff=HERE / "pr-debug-inspect.diff",
        annotations=HERE / "pr-debug-inspect.annotations.json",
        pr=PR,
        llm=SCRIPTED_MODEL,
    )


def main() -> None:
    result = build_result()
    out = HERE / "report"
    out.mkdir(exist_ok=True)
    (out / "threat-delta.sarif").write_text(
        json.dumps(result.sarif, indent=2) + "\n", encoding="utf-8"
    )
    (out / "threat-delta.md").write_text(result.comment + "\n", encoding="utf-8")
    (out / "deltas.json").write_text(
        json.dumps(result.to_dict(), indent=2) + "\n", encoding="utf-8"
    )
    print(result.comment)
    print(f"\nWrote report to {out}/ ({len(result.deltas)} deltas)")


if __name__ == "__main__":
    main()
