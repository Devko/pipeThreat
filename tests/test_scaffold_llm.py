"""Tests for the LLM-assisted scaffold mode.

The key guarantee: code owns id generation and referential integrity, so the
bootstrapped draft always parses and validates with NO errors (no dangling asset
references) regardless of what the scripted model proposes.
"""

from __future__ import annotations

import pytest
import yaml

from threat_delta.baseline import parse_baseline
from threat_delta.llm import ScriptedLLMClient
from threat_delta.scaffold import discover_components
from threat_delta.scaffold_llm import init_baseline_llm
from threat_delta.validate import has_errors, validate_baseline


def _make_repo(tmp_path):
    gateway = tmp_path / "src" / "gateway"
    users = tmp_path / "src" / "users"
    gateway.mkdir(parents=True)
    users.mkdir(parents=True)
    (gateway / "app.py").write_text(
        "def handle_request(req):\n"
        "    # public HTTP handler\n"
        "    token = req.headers.get('Authorization')\n"
        "    return 200, token\n",
        encoding="utf-8",
    )
    (users / "store.py").write_text(
        "class UserStore:\n"
        "    def get(self, user_id):\n"
        "        return self._db.fetch(user_id)\n",
        encoding="utf-8",
    )
    return tmp_path


def _client():
    # Keyed on the component id that appears in each prompt.
    return ScriptedLLMClient(
        responses={
            "comp.gateway": {
                "trust_zone": "dmz",
                "handles_assets": ["Session token"],
                "entry_points": ["http_public"],
            },
            "comp.users": {
                "trust_zone": "internal",
                "handles_assets": ["User PII"],
                "entry_points": ["grpc_internal"],
            },
        }
    )


def test_validates_clean_no_dangling_refs(tmp_path):
    root = _make_repo(tmp_path)
    text = init_baseline_llm(root, _client(), system_name="demo")

    # Parses through both yaml.safe_load and parse_baseline.
    data = yaml.safe_load(text)
    baseline = parse_baseline(data)

    issues = validate_baseline(baseline)
    assert has_errors(issues) is False, [str(i) for i in issues]


def test_assets_and_handles_assets_wired(tmp_path):
    root = _make_repo(tmp_path)
    text = init_baseline_llm(root, _client(), system_name="demo")
    baseline = parse_baseline(yaml.safe_load(text))

    # Assets exist for both proposed names, with generated ids.
    asset_names = {a.name for a in baseline.assets}
    assert "Session token" in asset_names
    assert "User PII" in asset_names

    by_name = {a.name: a.id for a in baseline.assets}
    session_id = by_name["Session token"]
    pii_id = by_name["User PII"]
    assert session_id == "asset.session_token"
    assert pii_id == "asset.user_pii"

    comps = {c.id: c for c in baseline.components}
    assert session_id in comps["comp.gateway"].handles_assets
    assert pii_id in comps["comp.users"].handles_assets


def test_trust_zone_propagates(tmp_path):
    root = _make_repo(tmp_path)
    text = init_baseline_llm(root, _client(), system_name="demo")
    baseline = parse_baseline(yaml.safe_load(text))
    comps = {c.id: c for c in baseline.components}
    assert comps["comp.gateway"].trust_zone == "dmz"
    assert comps["comp.users"].trust_zone == "internal"


def test_bounded_one_call_per_component(tmp_path):
    root = _make_repo(tmp_path)
    llm = _client()
    init_baseline_llm(root, llm, system_name="demo")
    n_components = len(discover_components(root))
    assert n_components == 2
    assert len(llm.calls) == n_components
    assert all(stage == "classify" for stage in llm.stages)


def test_refuses_to_clobber_existing_out(tmp_path):
    root = _make_repo(tmp_path)
    out = tmp_path / "threat-model.yaml"
    out.write_text("existing\n", encoding="utf-8")
    with pytest.raises(FileExistsError):
        init_baseline_llm(root, _client(), out=out, system_name="demo")
    # untouched
    assert out.read_text(encoding="utf-8") == "existing\n"


def test_writes_when_out_absent(tmp_path):
    root = _make_repo(tmp_path)
    out = tmp_path / "nested" / "threat-model.yaml"
    text = init_baseline_llm(root, _client(), out=out, system_name="demo")
    assert out.exists()
    assert out.read_text(encoding="utf-8") == text
