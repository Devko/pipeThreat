"""Command-line entry point for the Threat-Model Delta tooling.

Subcommands:

    analyze    run the step on a PR diff (the default; spec §5/§9)
    init       scaffold a starter threat-model.yaml from the repo layout (§3)
    validate   check baseline referential integrity (baseline-as-code, §3)
    coverage   report which source paths no component claims (§6a/§10)

``analyze`` is the default: invoking ``threat-delta --baseline ... --diff ...``
with no subcommand still works, so existing callers (the GitHub Action) are
unaffected.

By default ``analyze`` uses a deterministic offline stub model (no network), so
the CLI runs end-to-end in CI without a model server. Point ``--llm`` at a real
transport when one is wired up.
"""

from __future__ import annotations

import argparse
import json
import sys

from .coverage import collect_source_paths, compute_coverage, format_report
from .llm import LLMClient, LLMConfig, ScriptedLLMClient
from .scaffold import init_baseline
from .step import needs_human_review, run_step
from .validate import has_errors, validate_file


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


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="threat-delta",
        description="Threat-model delta analysis and baseline tooling (pipeline step 6).",
    )
    sub = p.add_subparsers(dest="command")

    # analyze (default) --------------------------------------------------- #
    a = sub.add_parser("analyze", help="run the delta step on a PR diff (advisory)")
    _add_analyze_args(a)

    # init ---------------------------------------------------------------- #
    i = sub.add_parser("init", help="scaffold a starter threat-model.yaml")
    i.add_argument("root", nargs="?", default=".", help="repo root to scan (default: .)")
    i.add_argument("--out", help="write the skeleton here (default: stdout)")
    i.add_argument("--system-name", help="system name (default: repo dir name)")
    i.add_argument("--version", default="0.1.0", help="system version (default: 0.1.0)")

    # validate ------------------------------------------------------------ #
    v = sub.add_parser("validate", help="check baseline referential integrity")
    v.add_argument("--baseline", required=True, help="path to threat-model.yaml")
    v.add_argument(
        "--strict",
        action="store_true",
        help="exit non-zero on warnings too (default: only errors fail)",
    )

    # coverage ------------------------------------------------------------ #
    c = sub.add_parser("coverage", help="report source paths no component covers")
    c.add_argument("--baseline", required=True, help="path to threat-model.yaml")
    c.add_argument("root", nargs="?", default=".", help="repo root to scan (default: .)")
    c.add_argument(
        "--ext",
        action="append",
        help="restrict to these file extensions (repeatable, e.g. --ext .py)",
    )
    c.add_argument("--show-paths", action="store_true", help="list uncovered paths")
    c.add_argument(
        "--fail-under",
        type=float,
        default=None,
        help="exit non-zero if coverage ratio is below this (0.0-1.0)",
    )

    return p


def _add_analyze_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--baseline", required=True, help="path to threat-model.yaml")
    p.add_argument("--diff", required=True, help="unified diff or structured .json")
    p.add_argument("--annotations", help="step-5 annotations JSON (optional)")
    p.add_argument("--findings", help="step 2-4 findings JSON (optional)")
    p.add_argument("--pr", default="", help="PR number/identifier")
    p.add_argument("--sarif", help="write SARIF 2.1.0 log to this path")
    p.add_argument("--comment", help="write the PR comment markdown to this path")
    p.add_argument("--json", dest="json_out", help="write the raw deltas JSON to this path")
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


# --------------------------------------------------------------------------- #
# Subcommand handlers
# --------------------------------------------------------------------------- #

def _cmd_analyze(args: argparse.Namespace) -> int:
    # The CLI is a thin wrapper over the standalone pipeline entry point.
    result = run_step(
        baseline=args.baseline,
        diff=args.diff,
        annotations=args.annotations,
        findings=args.findings,
        pr=args.pr,
        llm=_build_llm(args.llm),
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

    review = needs_human_review(result)
    if args.fail_on_high and review:
        print(
            f"\n::error::{len(review)} high-severity delta(s) require human "
            "review (security/needs-review).",
            file=sys.stderr,
        )
        return 1

    # Advisory/non-blocking by default (spec §9).
    return 0


def _cmd_init(args: argparse.Namespace) -> int:
    try:
        text = init_baseline(
            args.root,
            out=args.out,
            system_name=args.system_name,
            version=args.version,
        )
    except FileExistsError as e:
        print(f"error: {e} (refusing to overwrite a committed baseline)", file=sys.stderr)
        return 1
    if args.out:
        print(f"Wrote baseline skeleton to {args.out}", file=sys.stderr)
        print("Review and edit it, then commit it as source (spec §3).", file=sys.stderr)
    else:
        print(text)
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    issues = validate_file(args.baseline)
    for issue in issues:
        print(str(issue))
    errors = has_errors(issues)
    warnings = any(i.level == "warning" for i in issues)
    if not issues:
        print(f"OK: {args.baseline} is valid.")
    if errors:
        return 1
    if args.strict and warnings:
        return 1
    return 0


def _cmd_coverage(args: argparse.Namespace) -> int:
    paths = collect_source_paths(args.root, extensions=args.ext)
    report = compute_coverage(_load_baseline(args.baseline), paths)
    print(format_report(report, show_paths=args.show_paths))
    if args.fail_under is not None and report.coverage_ratio < args.fail_under:
        print(
            f"\n::error::coverage {report.coverage_ratio:.0%} is below the "
            f"--fail-under threshold of {args.fail_under:.0%}.",
            file=sys.stderr,
        )
        return 1
    return 0


def _load_baseline(path: str):
    from .baseline import load_baseline

    return load_baseline(path)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

_HANDLERS = {
    "analyze": _cmd_analyze,
    "init": _cmd_init,
    "validate": _cmd_validate,
    "coverage": _cmd_coverage,
}


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    # Default to `analyze` when no subcommand is given (back-compat with the
    # `threat-delta --baseline ... --diff ...` form used by the GitHub Action).
    if raw and raw[0] not in _HANDLERS and raw[0] not in ("-h", "--help"):
        raw = ["analyze", *raw]

    args = build_parser().parse_args(raw)
    if args.command is None:
        build_parser().print_help()
        return 0
    return _HANDLERS[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
