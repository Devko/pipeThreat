"""Tests for the deterministic baseline scaffolder (scaffold.py)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from threat_delta.baseline import parse_baseline
from threat_delta.scaffold import (
    ScaffoldComponent,
    discover_components,
    init_baseline,
    render_baseline,
)


def _write(path: Path, text: str = "x") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_discover_src_layout(tmp_path: Path) -> None:
    for comp in ("gateway", "users", "tokenizer"):
        _write(tmp_path / "src" / comp / "__init__.py")
    # Noise that must be ignored.
    _write(tmp_path / "docs" / "x")
    _write(tmp_path / "tests" / "x")
    _write(tmp_path / ".git" / "x")

    comps = discover_components(tmp_path)

    assert [c.id for c in comps] == ["comp.gateway", "comp.tokenizer", "comp.users"]
    by_id = {c.id: c for c in comps}
    assert by_id["comp.gateway"].code_paths == ["src/gateway/**"]
    assert by_id["comp.tokenizer"].code_paths == ["src/tokenizer/**"]
    assert by_id["comp.users"].code_paths == ["src/users/**"]
    assert by_id["comp.users"].name == "Users"


def test_discover_no_src_layout(tmp_path: Path) -> None:
    _write(tmp_path / "api" / "__init__.py")
    _write(tmp_path / "lib" / "__init__.py")
    _write(tmp_path / "node_modules" / "pkg" / "index.js")

    comps = discover_components(tmp_path)

    assert [c.id for c in comps] == ["comp.api", "comp.lib"]
    by_id = {c.id: c for c in comps}
    assert by_id["comp.api"].code_paths == ["api/**"]
    assert by_id["comp.lib"].code_paths == ["lib/**"]


def test_discover_empty(tmp_path: Path) -> None:
    assert discover_components(tmp_path) == []


def _three_components() -> list[ScaffoldComponent]:
    return [
        ScaffoldComponent("comp.gateway", "Gateway", ["src/gateway/**"]),
        ScaffoldComponent("comp.tokenizer", "Tokenizer", ["src/tokenizer/**"]),
        ScaffoldComponent("comp.users", "Users", ["src/users/**"]),
    ]


def test_render_parses_both_ways() -> None:
    text = render_baseline("payments-api", _three_components())

    data = yaml.safe_load(text)
    assert isinstance(data, dict)

    baseline = parse_baseline(data)
    assert baseline.system.name == "payments-api"
    assert {c.id for c in baseline.components} == {
        "comp.gateway",
        "comp.tokenizer",
        "comp.users",
    }
    # Placeholders required by the parser must be present and valid.
    assert baseline.assets and baseline.assets[0].id == "asset.example"
    assert baseline.assumptions
    assert all(a.statement for a in baseline.assumptions)


def test_render_empty_components_uses_placeholder() -> None:
    text = render_baseline("svc", [])
    baseline = parse_baseline(yaml.safe_load(text))
    assert [c.id for c in baseline.components] == ["comp.example"]
    assert baseline.components[0].code_paths == ("src/**",)


def test_init_baseline_writes_and_roundtrips(tmp_path: Path) -> None:
    for comp in ("gateway", "users", "tokenizer"):
        _write(tmp_path / "src" / comp / "__init__.py")

    out = tmp_path / "out" / "threat-model.yaml"
    text = init_baseline(tmp_path, out=out)

    assert out.exists()
    assert out.read_text(encoding="utf-8") == text

    baseline = parse_baseline(yaml.safe_load(out.read_text(encoding="utf-8")))
    assert {c.id for c in baseline.components} == {
        "comp.gateway",
        "comp.tokenizer",
        "comp.users",
    }
    # system_name defaults to the basename of root.
    assert baseline.system.name == tmp_path.resolve().name


def test_init_baseline_refuses_to_clobber(tmp_path: Path) -> None:
    out = tmp_path / "threat-model.yaml"
    _write(out, "system:\n  name: existing\n")
    with pytest.raises(FileExistsError):
        init_baseline(tmp_path, out=out)
