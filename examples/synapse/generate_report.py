#!/usr/bin/env python3
"""Generate the worked-example Threat-Model Delta report for the Synapse sample.

Runs the real pipeline (`threat_delta.run_step`) over the sample baseline, diff
and annotations in this directory, and writes the SARIF + PR-comment report into
``report/``.

There is no Gemma server in this demo environment, so the three model calls
(6b/6c/6d) are driven by a **scripted stand-in** that returns what a Gemma-class
model is expected to produce for this diff — the same technique the integration
tests use. Everything else (relevance, severity, dedup, SARIF/comment rendering)
is the real, deterministic pipeline. Run it live instead with:

    threat-delta analyze \
        --baseline examples/synapse/threat-model.yaml \
        --diff examples/synapse/pr-account-export.diff \
        --annotations examples/synapse/pr-account-export.annotations.json \
        --pr 17421 --llm ollama --llm-model gemma4:e2b \
        --sarif report/threat-delta.sarif --comment report/threat-delta.md
"""

from __future__ import annotations

import json
from pathlib import Path

from threat_delta import AnalysisResult, ScriptedLLMClient, run_step

HERE = Path(__file__).resolve().parent
PR = "17421"

# What a Gemma-class model is expected to return for this PR, keyed by a unique
# substring of each stage's prompt (6b / 6c-for-client_api / 6d).
SCRIPTED_MODEL = ScriptedLLMClient(
    responses={
        # 6b — classification gate.
        "is it plausibly introduced or changed by this diff?": {
            "new_entry_point": True,
            "asset_handling_change": True,
            "trust_boundary_crossing": False,
            "new_data_flow": False,
            "control_change": False,
        },
        # 6c — STRIDE deltas for the affected component (comp.client_api).
        "comp.client_api (zone": {
            "deltas": [
                {
                    "stride": "InformationDisclosure",
                    "reason": "returns any user's account data and messages without authorization",
                },
                {
                    "stride": "ElevationOfPrivilege",
                    "reason": "non-admin caller reads arbitrary users' data by id",
                },
                {
                    "stride": "Spoofing",
                    "reason": "user_id read from query string, not bound to an authenticated caller",
                },
            ]
        },
        # 6d — assumption contradictions.
        "does this change violate or weaken it?": {
            "violations": [
                {
                    "assumption_id": "asm.client_requires_token",
                    "violated": True,
                    "reason": "new client endpoint mounted with no access-token check",
                },
                {
                    "assumption_id": "asm.admin_requires_admin",
                    "violated": True,
                    "reason": "returns another user's data without a server-admin token",
                },
                {
                    "assumption_id": "asm.user_scoped_access",
                    "violated": True,
                    "reason": "reads an arbitrary user_id instead of the authenticated user",
                },
            ]
        },
    },
    default={},
)


def build_result() -> AnalysisResult:
    """Run the pipeline over the sample inputs and return the result."""
    return run_step(
        baseline=HERE / "threat-model.yaml",
        diff=HERE / "pr-account-export.diff",
        annotations=HERE / "pr-account-export.annotations.json",
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
