"""Tests for Stage 1 — deterministic relevance resolution."""

from __future__ import annotations

import pytest

from threat_delta.baseline import parse_baseline
from threat_delta.diff import parse_unified_diff
from threat_delta.models import ChangedFile, Diff
from threat_delta.relevance import path_matches, resolve_slice


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

BASELINE_DATA = {
    "system": {"name": "payments-api", "version": "1.0"},
    "assets": [
        {"id": "asset.user_pii", "name": "User PII", "sensitivity": "high"},
        {"id": "asset.card_token", "name": "Card Token", "sensitivity": "critical"},
        {"id": "asset.audit_log", "name": "Audit Log", "sensitivity": "medium"},
    ],
    "trust_boundaries": [
        {
            "id": "tb.dmz_internal",
            "name": "DMZ / Internal",
            "controls": ["mTLS"],
        },
    ],
    "components": [
        {
            "id": "comp.api_gateway",
            "name": "API Gateway",
            "trust_zone": "dmz",
            "code_paths": ["src/gateway/**"],
            "handles_assets": ["asset.user_pii"],
            "entry_points": ["POST /pay"],
        },
        {
            "id": "comp.tokenizer",
            "name": "Tokenizer",
            "trust_zone": "internal",
            "code_paths": ["src/tokenizer/**"],
            "handles_assets": ["asset.card_token"],
        },
        {
            "id": "comp.user_service",
            "name": "User Service",
            "trust_zone": "internal",
            "code_paths": ["src/users/**"],
            "handles_assets": ["asset.user_pii"],
        },
    ],
    "data_flows": [
        {
            "id": "flow.tokenize",
            "from": "comp.api_gateway",
            "to": "comp.tokenizer",
            "crosses": ["tb.dmz_internal"],
            "assets": ["asset.card_token"],
        },
    ],
    "assumptions": [
        {"id": "asm.tls", "statement": "All external traffic is TLS-terminated."},
        {"id": "asm.authn", "statement": "Gateway authenticates every request."},
        {"id": "asm.tokenized", "statement": "Card data is tokenized before storage."},
    ],
}


@pytest.fixture
def baseline():
    return parse_baseline(BASELINE_DATA)


# --------------------------------------------------------------------------- #
# path_matches
# --------------------------------------------------------------------------- #

def test_path_matches_double_star_suffix():
    assert path_matches("src/users/admin_handler.py", "src/users/**") is True


def test_path_matches_non_matching_component():
    assert path_matches("src/gateway/app.py", "src/users/**") is False


def test_path_matches_double_star_middle():
    assert path_matches("src/a/b.py", "src/**/b.py") is True


def test_path_matches_single_star_extension():
    assert path_matches("a.py", "*.py") is True


def test_path_matches_single_star_no_separator():
    # `*` must not cross directory separators.
    assert path_matches("src/app.py", "*.py") is False


def test_path_matches_question_mark():
    assert path_matches("a.py", "?.py") is True
    assert path_matches("ab.py", "?.py") is False


def test_path_matches_double_star_zero_dirs():
    # `**/` may match zero directories.
    assert path_matches("b.py", "**/b.py") is True
    assert path_matches("src/x/b.py", "**/b.py") is True


def test_path_matches_bare_double_star():
    assert path_matches("anything/at/all.py", "**") is True


# --------------------------------------------------------------------------- #
# resolve_slice
# --------------------------------------------------------------------------- #

def test_resolve_slice_user_service(baseline):
    diff = Diff(files=[ChangedFile(path="src/users/admin_handler.py")])
    sl = resolve_slice(diff, baseline)

    assert [c.id for c in sl.components] == ["comp.user_service"]
    assert [a.id for a in sl.assets] == ["asset.user_pii"]
    # All assumptions are always included.
    assert [a.id for a in sl.assumptions] == ["asm.tls", "asm.authn", "asm.tokenized"]
    assert sl.untracked_paths == []
    assert sl.matched_paths == {"comp.user_service": ["src/users/admin_handler.py"]}
    # user_service is not part of flow.tokenize, so no flows/boundaries.
    assert sl.data_flows == []
    assert sl.trust_boundaries == []
    assert sl.is_empty is False


def test_resolve_slice_gateway_pulls_flow_and_boundary(baseline):
    diff = Diff(files=[ChangedFile(path="src/gateway/app.py")])
    sl = resolve_slice(diff, baseline)

    assert [c.id for c in sl.components] == ["comp.api_gateway"]
    # flow.tokenize references comp.api_gateway (from_).
    assert [f.id for f in sl.data_flows] == ["flow.tokenize"]
    # which crosses tb.dmz_internal.
    assert [b.id for b in sl.trust_boundaries] == ["tb.dmz_internal"]
    assert [a.id for a in sl.assets] == ["asset.user_pii"]


def test_resolve_slice_untracked_path(baseline):
    diff = Diff(files=[ChangedFile(path="docs/readme.md")])
    sl = resolve_slice(diff, baseline)

    assert sl.components == []
    assert sl.untracked_paths == ["docs/readme.md"]
    # Assumptions still always included.
    assert len(sl.assumptions) == 3
    assert sl.is_empty is False


def test_resolve_slice_empty_diff(baseline):
    sl = resolve_slice(Diff(), baseline)
    assert sl.components == []
    assert sl.untracked_paths == []
    assert sl.is_empty is True


def test_resolve_slice_multiple_components(baseline):
    diff = Diff(
        files=[
            ChangedFile(path="src/gateway/app.py"),
            ChangedFile(path="src/tokenizer/core.py"),
            ChangedFile(path="docs/x.md"),
        ]
    )
    sl = resolve_slice(diff, baseline)

    # Declared order preserved.
    assert [c.id for c in sl.components] == ["comp.api_gateway", "comp.tokenizer"]
    assert [f.id for f in sl.data_flows] == ["flow.tokenize"]
    assert [b.id for b in sl.trust_boundaries] == ["tb.dmz_internal"]
    # Union of handled assets, in baseline order.
    assert [a.id for a in sl.assets] == ["asset.user_pii", "asset.card_token"]
    assert sl.untracked_paths == ["docs/x.md"]


def test_resolve_slice_determinism(baseline):
    diff = Diff(
        files=[
            ChangedFile(path="src/tokenizer/core.py"),
            ChangedFile(path="src/gateway/app.py"),
        ]
    )
    first = resolve_slice(diff, baseline)
    second = resolve_slice(diff, baseline)
    assert [c.id for c in first.components] == [c.id for c in second.components]
    # Order follows baseline declaration regardless of diff order.
    assert [c.id for c in first.components] == ["comp.api_gateway", "comp.tokenizer"]


def test_resolve_slice_from_unified_diff(baseline):
    text = (
        "diff --git a/src/users/admin_handler.py b/src/users/admin_handler.py\n"
        "--- a/src/users/admin_handler.py\n"
        "+++ b/src/users/admin_handler.py\n"
        "@@ -1,3 +1,4 @@\n"
        " def handler():\n"
        "+    grant_admin()\n"
        "     return\n"
    )
    diff = parse_unified_diff(text)
    sl = resolve_slice(diff, baseline)
    assert [c.id for c in sl.components] == ["comp.user_service"]
