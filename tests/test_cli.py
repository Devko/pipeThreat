"""Tests for the CLI subcommand dispatch (analyze / init / validate / coverage)."""

from __future__ import annotations

import json

import yaml

from threat_delta.cli import main

from tests.test_pipeline import BASELINE_DATA


def _write_baseline(tmp_path):
    p = tmp_path / "threat-model.yaml"
    p.write_text(yaml.safe_dump(BASELINE_DATA), encoding="utf-8")
    return p


def test_analyze_backcompat_no_subcommand(tmp_path, capsys):
    # `threat-delta --baseline ... --diff ...` (no subcommand) still routes to
    # analyze — the form the GitHub Action uses.
    bl = _write_baseline(tmp_path)
    diff = tmp_path / "pr.diff"
    diff.write_text(
        "diff --git a/docs/x.md b/docs/x.md\n--- a/docs/x.md\n+++ b/docs/x.md\n"
        "@@ -1 +1 @@\n-a\n+b\n",
        encoding="utf-8",
    )
    sarif = tmp_path / "out.sarif"
    rc = main(["--baseline", str(bl), "--diff", str(diff), "--pr", "1", "--sarif", str(sarif)])
    assert rc == 0
    doc = json.loads(sarif.read_text())
    assert doc["version"] == "2.1.0"
    assert "advisory" in capsys.readouterr().out.lower()


def test_analyze_explicit_subcommand(tmp_path):
    bl = _write_baseline(tmp_path)
    diff = tmp_path / "pr.diff"
    diff.write_text(
        "diff --git a/src/users/u.py b/src/users/u.py\n"
        "--- a/src/users/u.py\n+++ b/src/users/u.py\n@@ -1 +1 @@\n-a\n+b\n",
        encoding="utf-8",
    )
    assert main(["analyze", "--baseline", str(bl), "--diff", str(diff)]) == 0


def test_validate_ok_and_error(tmp_path, capsys):
    bl = _write_baseline(tmp_path)
    assert main(["validate", "--baseline", str(bl)]) == 0
    capsys.readouterr()

    # Dangling asset reference -> validate exits non-zero.
    bad = dict(BASELINE_DATA)
    bad = json.loads(json.dumps(BASELINE_DATA))  # deep copy
    bad["components"][2]["handles_assets"] = ["asset.does_not_exist"]
    bad_path = tmp_path / "bad.yaml"
    bad_path.write_text(yaml.safe_dump(bad), encoding="utf-8")
    assert main(["validate", "--baseline", str(bad_path)]) == 1
    assert "dangling_asset" in capsys.readouterr().out


def test_init_then_validate_roundtrip(tmp_path):
    # Build a fake repo with a src/ layout, scaffold, then validate the output.
    (tmp_path / "src" / "gateway").mkdir(parents=True)
    (tmp_path / "src" / "users").mkdir(parents=True)
    (tmp_path / "src" / "gateway" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src" / "users" / "__init__.py").write_text("", encoding="utf-8")
    out = tmp_path / "threat-model.yaml"
    assert main(["init", str(tmp_path), "--out", str(out)]) == 0
    assert out.exists()
    # The scaffold must be a valid baseline.
    assert main(["validate", "--baseline", str(out)]) == 0
    # Refuses to clobber an existing baseline.
    assert main(["init", str(tmp_path), "--out", str(out)]) == 1


def test_coverage_fail_under(tmp_path, capsys):
    bl = _write_baseline(tmp_path)
    # No source files match the payments-api baseline under this empty tree's
    # docs dir -> 0% coverage -> --fail-under trips.
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "x.md").write_text("x", encoding="utf-8")
    rc = main(["coverage", "--baseline", str(bl), str(tmp_path), "--fail-under", "0.5"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "Coverage:" in out
