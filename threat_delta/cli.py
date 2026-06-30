"""Command-line entry point for the Threat-Model Delta step.

Wires real inputs into :func:`threat_delta.pipeline.analyze` and writes the
SARIF + PR comment outputs. The step is advisory/non-blocking (spec §9): it
exits 0 regardless of findings unless ``--fail-on-high`` is explicitly set for
an environment that wants the optional required-review hook.

Example:

    threat-delta \\
        --baseline examples/threat-model.yaml \\
        --diff examples/pr-1234.diff \\
        --annotations examples/pr-1234.annotations.json \\
        --pr 1234 \\
        --sarif out.sarif --comment out.md

By default a deterministic offline stub model is used (no network), so the CLI
runs end-to-end in CI without a model server. Point ``--llm`` at a real
transport when one is wired up.
"""

from __future__ import annotations

import argparse
import json
import sys

from .baseline import load_baseline
from .diff import load_annotations, load_diff, load_findings
from .llm import LLMClient, LLMConfig, ScriptedLLMClient
from .pipeline import analyze


def _build_llm(kind: str) -> LLMClient:
    """Return an LLM client. Only the offline stub ships by default.

    A real local-model transport (llama.cpp / Ollama) implements
    :class:`~threat_delta.llm.LLMClient` and can be selected here; until one is
    configured, ``stub`` keeps the CLI runnable end-to-end and conservative
    (it reports nothing rather than hallucinating).
    """
    if kind == "stub":
        # Conservative default: every flag false, no violations. Produces only
        # deterministic 6a untracked-path deltas. Replace with a real client to
        # get 6b/6c/6d signal.
        return ScriptedLLMClient(default={}, config=LLMConfig())
    raise SystemExit(f"unknown --llm transport '{kind}' (only 'stub' is built in)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="threat-delta",
        description="Pipeline step 6 — threat-model delta analysis (advisory).",
    )
    p.add_argument("--baseline", required=True, help="path to threat-model.yaml")
    p.add_argument("--diff", required=True, help="unified diff or structured .json")
    p.add_argument("--annotations", help="step-5 annotations JSON (optional)")
    p.add_argument("--findings", help="step 2-4 findings JSON (optional)")
    p.add_argument("--pr", default="", help="PR number/identifier")
    p.add_argument("--sarif", help="write SARIF 2.1.0 log to this path")
    p.add_argument("--comment", help="write the PR comment markdown to this path")
    p.add_argument(
        "--json", dest="json_out", help="write the raw deltas JSON to this path"
    )
    p.add_argument("--llm", default="stub", help="LLM transport (default: stub)")
    p.add_argument(
        "--max-hunk-chars",
        type=int,
        default=4000,
        help="per-component hunk budget for 6c (default: 4000)",
    )
    p.add_argument(
        "--fail-on-high",
        action="store_true",
        help=(
            "exit non-zero if any high-severity delta requires human review "
            "(optional required-review hook, spec §9; off by default)"
        ),
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    baseline = load_baseline(args.baseline)
    diff = load_diff(args.diff)
    annotations = load_annotations(args.annotations)
    findings = load_findings(args.findings)
    llm = _build_llm(args.llm)

    pr = args.pr or diff.pr or "0"
    result = analyze(
        diff,
        baseline,
        annotations,
        findings,
        llm,
        pr=pr,
        max_hunk_chars=args.max_hunk_chars,
    )

    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as fh:
            json.dump(result.sarif, fh, indent=2)
    if args.comment:
        with open(args.comment, "w", encoding="utf-8") as fh:
            fh.write(result.comment)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(result.to_dict(), fh, indent=2)

    # Always print the human-readable comment to stdout for log visibility.
    print(result.comment)

    needs_review = [
        d
        for d in result.deltas
        if d.severity.value == "high" and d.requires_human_review
    ]
    if args.fail_on_high and needs_review:
        print(
            f"\n::error::{len(needs_review)} high-severity delta(s) require human "
            "review (security/needs-review).",
            file=sys.stderr,
        )
        return 1

    # Advisory/non-blocking by default (spec §9).
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
