"""Tests for the standalone pipeline entry point (run_step)."""

from __future__ import annotations

import json

from threat_delta import needs_human_review, run_step
from threat_delta.baseline import parse_baseline
from threat_delta.diff import parse_unified_diff
from threat_delta.llm import ScriptedLLMClient
from threat_delta.models import FileAnnotation, Severity

from tests.test_pipeline import BASELINE_DATA, WORKED_EXAMPLE_DIFF, _worked_example_llm


UNTRACKED_DIFF = (
    "diff --git a/docs/readme.md b/docs/readme.md\n"
    "--- a/docs/readme.md\n+++ b/docs/readme.md\n@@ -1 +1 @@\n-a\n+b\n"
)


def test_run_step_accepts_paths(tmp_path):
    bl = tmp_path / "threat-model.yaml"
    import yaml

    bl.write_text(yaml.safe_dump(BASELINE_DATA), encoding="utf-8")
    df = tmp_path / "pr.diff"
    df.write_text(UNTRACKED_DIFF, encoding="utf-8")

    # All inputs as paths; an explicit stub LLM. Only the 6a untracked delta
    # appears (6a is deterministic and never calls the model).
    result = run_step(baseline=str(bl), diff=str(df), pr="42", llm=ScriptedLLMClient(default={}))
    assert len(result.deltas) == 1
    assert result.deltas[0].type.value == "untracked_path"
    assert result.pr == "42"
    json.dumps(result.sarif)  # serializable
    assert "advisory" in result.comment.lower()


def test_run_step_accepts_objects_worked_example():
    # All inputs as in-memory objects, with the scripted §12 model.
    baseline = parse_baseline(BASELINE_DATA)
    diff = parse_unified_diff(WORKED_EXAMPLE_DIFF, pr="1234")
    annotations = [
        FileAnnotation(path="src/users/admin_handler.py", entry_points=["http_public"])
    ]
    result = run_step(
        baseline=baseline,
        diff=diff,
        annotations=annotations,
        findings=[],
        llm=_worked_example_llm(),
    )
    assert result.pr == "1234"
    review = needs_human_review(result)
    assert review, "worked example must surface a high-severity human-review delta"
    assert all(d.severity == Severity.HIGH for d in review)


def test_run_step_stub_is_conservative():
    # No annotations, no findings, explicit stub LLM -> no false positives on
    # tracked code.
    baseline = parse_baseline(BASELINE_DATA)
    diff = parse_unified_diff(
        "diff --git a/src/users/u.py b/src/users/u.py\n"
        "--- a/src/users/u.py\n+++ b/src/users/u.py\n@@ -1 +1 @@\n-a\n+b\n",
        pr="1",
    )
    result = run_step(baseline=baseline, diff=diff, llm=ScriptedLLMClient(default={}))
    assert result.deltas == []
    assert needs_human_review(result) == []


def test_run_step_requires_an_llm():
    # No silent stub default: omitting llm must error rather than fabricate an
    # empty "no deltas" result that hides the fact no model ran.
    import pytest

    from threat_delta.llm import LLMError

    baseline = parse_baseline(BASELINE_DATA)
    diff = parse_unified_diff(
        "diff --git a/src/users/u.py b/src/users/u.py\n"
        "--- a/src/users/u.py\n+++ b/src/users/u.py\n@@ -1 +1 @@\n-a\n+b\n",
        pr="1",
    )
    with pytest.raises(LLMError):
        run_step(baseline=baseline, diff=diff)
