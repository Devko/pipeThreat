"""Tests for threat_delta.validate (baseline referential-integrity, spec §3)."""

from __future__ import annotations

import textwrap

import pytest

from threat_delta.baseline import parse_baseline
from threat_delta.validate import (
    Issue,
    has_errors,
    validate_baseline,
    validate_file,
)


def _clean_dict() -> dict:
    """Spec example baseline: clean, no referential errors."""
    return {
        "system": {"name": "Example"},
        "assets": [
            {"id": "asset.user_pii", "name": "User PII", "sensitivity": "high"},
        ],
        "trust_boundaries": [
            {"id": "tb.dmz_internal", "name": "DMZ/Internal"},
        ],
        "components": [
            {
                "id": "comp.user_service",
                "name": "User Service",
                "trust_zone": "internal",
                "code_paths": ["src/user_service/**"],
                "handles_assets": ["asset.user_pii"],
            },
            {
                "id": "comp.api_gateway",
                "name": "API Gateway",
                "trust_zone": "dmz",
                "code_paths": ["src/gateway/**"],
            },
            {
                "id": "comp.tokenizer",
                "name": "Tokenizer",
                "trust_zone": "internal",
                "code_paths": ["src/tokenizer/**"],
            },
        ],
        "data_flows": [
            {
                "id": "flow.login",
                "from": "comp.api_gateway",
                "to": "comp.tokenizer",
                "crosses": ["tb.dmz_internal"],
                "assets": ["asset.user_pii"],
            },
        ],
    }


def _codes(issues: list[Issue]) -> list[str]:
    return [i.code for i in issues]


# --------------------------------------------------------------------------- #
# Clean baseline
# --------------------------------------------------------------------------- #

def test_clean_baseline_has_no_errors():
    baseline = parse_baseline(_clean_dict())
    issues = validate_baseline(baseline)
    assert not has_errors(issues)
    # The spec example is also warning-free.
    assert issues == []


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

def test_dangling_asset_in_component():
    data = _clean_dict()
    data["components"][0]["handles_assets"] = ["asset.does_not_exist"]
    issues = validate_baseline(parse_baseline(data))
    assert "dangling_asset" in _codes(issues)
    assert has_errors(issues)


def test_dangling_flow_endpoint_unknown_to():
    data = _clean_dict()
    data["data_flows"][0]["to"] = "comp.ghost"
    issues = validate_baseline(parse_baseline(data))
    assert "dangling_flow_endpoint" in _codes(issues)
    assert has_errors(issues)


def test_dangling_boundary():
    data = _clean_dict()
    data["data_flows"][0]["crosses"] = ["tb.nope"]
    issues = validate_baseline(parse_baseline(data))
    assert "dangling_boundary" in _codes(issues)
    assert has_errors(issues)


def test_duplicate_id_across_components():
    data = _clean_dict()
    data["components"].append(
        {
            "id": "comp.user_service",  # duplicate of first component
            "name": "Dup",
            "trust_zone": "internal",
            "code_paths": ["src/dup/**"],
        }
    )
    issues = validate_baseline(parse_baseline(data))
    assert "duplicate_id" in _codes(issues)
    assert has_errors(issues)


# --------------------------------------------------------------------------- #
# Warnings
# --------------------------------------------------------------------------- #

def test_empty_code_paths_is_warning_only():
    data = {
        "system": {"name": "Example"},
        "components": [
            {"id": "comp.lonely", "trust_zone": "internal", "code_paths": []},
        ],
    }
    issues = validate_baseline(parse_baseline(data))
    assert "no_code_paths" in _codes(issues)
    assert not has_errors(issues)


def test_no_trust_zone_warning():
    data = {
        "system": {"name": "Example"},
        "components": [
            {"id": "comp.x", "trust_zone": "", "code_paths": ["src/**"]},
        ],
    }
    issues = validate_baseline(parse_baseline(data))
    assert "no_trust_zone" in _codes(issues)
    assert not has_errors(issues)


def test_id_convention_warning():
    data = {
        "system": {"name": "Example"},
        "components": [
            {"id": "weird_id", "trust_zone": "internal", "code_paths": ["src/**"]},
        ],
    }
    issues = validate_baseline(parse_baseline(data))
    assert "id_convention" in _codes(issues)
    assert not has_errors(issues)


def test_no_components_warning():
    data = {"system": {"name": "Example"}}
    issues = validate_baseline(parse_baseline(data))
    assert "no_components" in _codes(issues)
    assert not has_errors(issues)


# --------------------------------------------------------------------------- #
# validate_file
# --------------------------------------------------------------------------- #

def test_validate_file_parse_error(tmp_path):
    bad = tmp_path / "threat-model.yaml"
    bad.write_text(
        textwrap.dedent(
            """\
            assets:
              - id: asset.x
                sensitivity: high
            """
        ),
        encoding="utf-8",
    )
    issues = validate_file(bad)
    assert _codes(issues) == ["parse_error"]
    assert has_errors(issues)


def test_validate_file_clean(tmp_path):
    import yaml

    good = tmp_path / "threat-model.yaml"
    good.write_text(yaml.safe_dump(_clean_dict()), encoding="utf-8")
    issues = validate_file(good)
    assert not has_errors(issues)


# --------------------------------------------------------------------------- #
# has_errors / Issue
# --------------------------------------------------------------------------- #

def test_has_errors_truth_table():
    assert has_errors([Issue("error", "x", "m")]) is True
    assert has_errors([Issue("warning", "x", "m")]) is False
    assert has_errors([]) is False
    assert has_errors([Issue("warning", "a", "m"), Issue("error", "b", "m")]) is True


def test_issue_str():
    s = str(Issue("error", "dangling_asset", "component comp.x references unknown asset asset.y"))
    assert s == "[error] dangling_asset: component comp.x references unknown asset asset.y"
