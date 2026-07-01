"""Tests for threat_delta.coverage (baseline-coverage report)."""

from __future__ import annotations

from threat_delta.baseline import parse_baseline
from threat_delta.coverage import (
    CoverageReport,
    collect_source_paths,
    compute_coverage,
    format_report,
)


def _baseline():
    return parse_baseline({
        "system": {"name": "demo"},
        "components": [
            {"id": "comp.gateway", "code_paths": ["src/gateway/**"]},
            {"id": "comp.users", "code_paths": ["src/users/**"]},
            {"id": "comp.unused", "code_paths": ["src/nope/**"]},
        ],
    })


def test_compute_coverage():
    baseline = _baseline()
    paths = [
        "src/gateway/app.py",
        "src/users/h.py",
        "src/users/store.py",
        "docs/readme.md",
        "README.md",
    ]
    report = compute_coverage(baseline, paths)

    assert report.covered["comp.gateway"] == ["src/gateway/app.py"]
    assert report.covered["comp.users"] == ["src/users/h.py", "src/users/store.py"]
    assert report.uncovered == ["README.md", "docs/readme.md"]
    assert report.empty_components == ["comp.unused"]
    assert report.total_paths == 5
    assert report.covered_count == 3
    assert report.coverage_ratio == 0.6


def test_coverage_ratio_zero_when_no_paths():
    report = CoverageReport()
    assert report.coverage_ratio == 0.0
    assert report.to_dict()["coverage_ratio"] == 0.0


def test_compute_coverage_dedupes_input_paths():
    baseline = _baseline()
    report = compute_coverage(
        baseline, ["src/gateway/app.py", "src/gateway/app.py"]
    )
    assert report.total_paths == 1
    assert report.covered["comp.gateway"] == ["src/gateway/app.py"]


def test_collect_source_paths(tmp_path):
    (tmp_path / "src" / "users").mkdir(parents=True)
    (tmp_path / "src" / "users" / "h.py").write_text("x = 1\n")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "x.md").write_text("doc\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "cfg").write_text("cfg\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "m.js").write_text("// js\n")

    paths = collect_source_paths(tmp_path)
    assert paths == ["docs/x.md", "src/users/h.py"]

    only_py = collect_source_paths(tmp_path, extensions={".py"})
    assert only_py == ["src/users/h.py"]


def test_format_report_mentions_percentage_and_empty_component():
    baseline = _baseline()
    report = compute_coverage(
        baseline,
        ["src/gateway/app.py", "docs/readme.md"],
    )
    text = format_report(report)
    assert "50.0%" in text
    assert "comp.unused" in text
    assert "comp.users" in text  # also empty for this path set


def test_format_report_show_paths_lists_uncovered():
    baseline = _baseline()
    report = compute_coverage(baseline, ["README.md", "docs/readme.md"])
    text = format_report(report, show_paths=True)
    assert "README.md" in text
    assert "docs/readme.md" in text
