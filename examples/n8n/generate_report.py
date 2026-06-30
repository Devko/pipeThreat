#!/usr/bin/env python3
"""Generate the worked-example Threat-Model Delta report for the n8n sample.

Runs the real pipeline (`threat_delta.run_step`) over the sample baseline, diff
and annotations in this directory, and writes the SARIF + PR-comment report into
``report/``.

The three model calls (6b/6c/6d) are driven by a **scripted model** so the report
is deterministic and reproducible without a model server (the same technique the
tests use). Everything else (relevance, severity, dedup, SARIF/comment rendering)
is the real pipeline. Run it live instead with:

    threat-delta analyze \
        --baseline examples/n8n/threat-model.yaml \
        --diff examples/n8n/pr-public-trigger.diff \
        --annotations examples/n8n/pr-public-trigger.annotations.json \
        --pr 8421 --llm ollama --llm-model gemma4:e2b \
        --sarif report/threat-delta.sarif --comment report/threat-delta.md
"""

from __future__ import annotations

import json
from pathlib import Path

from threat_delta import AnalysisResult, ScriptedLLMClient, run_step

HERE = Path(__file__).resolve().parent
PR = "8421"

# What a small local model is expected to return for this PR, keyed by a unique
# substring of each stage's prompt (6b / 6c-for-webhooks / 6d).
SCRIPTED_MODEL = ScriptedLLMClient(
    responses={
        # 6b — classification gate.
        "is it plausibly introduced or changed by this diff?": {
            "new_entry_point": True,
            "trust_boundary_crossing": True,
            "control_change": True,
            "asset_handling_change": False,
            "new_data_flow": False,
        },
        # 6c — STRIDE deltas for the affected component (comp.webhooks).
        "comp.webhooks (zone": {
            "deltas": [
                {
                    "stride": "Spoofing",
                    "reason": "no authentication or signature check — any caller can trigger a workflow",
                },
                {
                    "stride": "Tampering",
                    "reason": "attacker-controlled request body is passed straight in as workflow trigger data",
                },
                {
                    "stride": "DenialOfService",
                    "reason": "unauthenticated synchronous execution with no rate limit",
                },
                {
                    "stride": "ElevationOfPrivilege",
                    "reason": "triggers workflows that run with stored credentials",
                },
            ]
        },
        # 6d — assumption contradictions, fanned out one call per assumption and
        # keyed on the assumption id echoed in each single-assumption prompt.
        "asm.webhooks_authenticated": {
            "assumption_id": "asm.webhooks_authenticated",
            "violated": True,
            "reason": "endpoint verifies no token or signature",
        },
        "asm.no_unauthenticated_execution": {
            "assumption_id": "asm.no_unauthenticated_execution",
            "violated": True,
            "reason": "an anonymous request triggers workflow execution",
        },
        "asm.public_endpoints_rate_limited": {
            "assumption_id": "asm.public_endpoints_rate_limited",
            "violated": True,
            "reason": "the public endpoint applies no rate limit",
        },
    },
    default={},
)


def build_result() -> AnalysisResult:
    """Run the pipeline over the sample inputs and return the result."""
    return run_step(
        baseline=HERE / "threat-model.yaml",
        diff=HERE / "pr-public-trigger.diff",
        annotations=HERE / "pr-public-trigger.annotations.json",
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
