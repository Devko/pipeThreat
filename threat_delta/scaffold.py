"""Scaffold a starter ``threat-model.yaml`` from a repository's layout.

The whole analysis presumes a *human-authored* baseline: the threat model
is the context every downstream stage reasons against, so it must be written and
approved by a person and committed alongside the code. That is a hard
precondition — there is nothing to compute a delta *against* until it exists.

This module supports "bootstrap-by-drift" for the maintenance loop:
when a repo has no baseline yet, we deterministically derive a *skeleton* from
the directory layout — no LLM, no guessing about security properties — that a
human then reviews, fills in, and commits. The generated file is intentionally
littered with ``# TODO:`` guidance so it is obvious it is a draft, not an
authoritative model.

Everything here is pure and deterministic: same tree in, same YAML out.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Union

# Directories that are never interesting as "components" of a system: tooling,
# dependency caches, build artefacts, docs and tests. Hidden dirs (".*") are
# also ignored (handled separately so we don't have to enumerate them).
DEFAULT_IGNORE: frozenset[str] = frozenset(
    {
        ".git",
        ".github",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        "docs",
        "tests",
        "test",
        ".pytest_cache",
        ".idea",
        ".vscode",
        "examples",
        ".eggs",
    }
)


@dataclass(frozen=True)
class ScaffoldComponent:
    """A component guessed from the directory layout (pre-human-review)."""

    id: str
    name: str
    code_paths: list[str] = field(default_factory=list)


def _is_ignored(name: str, ignore: frozenset[str]) -> bool:
    """A directory is ignored if hidden, explicitly listed, or an egg-info."""
    if name.startswith("."):
        return True
    if name in ignore:
        return True
    if name.endswith(".egg-info"):
        return True
    return False


def _dirname_to_name(dirname: str) -> str:
    """``user_service`` -> ``User Service`` (title-cased, ``_`` -> space)."""
    return dirname.replace("_", " ").title()


def _immediate_dirs(parent: Path) -> list[str]:
    """Sorted names of immediate sub-directories of ``parent``."""
    return sorted(p.name for p in parent.iterdir() if p.is_dir())


def discover_components(
    root: Union[str, Path],
    *,
    src_dirs: Optional[Iterable[str]] = None,  # reserved; see note below
    ignore: Optional[Iterable[str]] = None,
) -> list[ScaffoldComponent]:
    """Guess the system's components from ``root``'s directory layout.

    Heuristic, deterministic (results sorted by ``id``):

    * If a ``src/`` directory exists under ``root``, each immediate sub-directory
      of ``src/`` becomes a component
      (``id=comp.<dirname>``, ``code_paths=["src/<dirname>/**"]``).
    * Otherwise, each immediate top-level directory of ``root`` that is not
      ignored becomes a component
      (``id=comp.<dirname>``, ``code_paths=["<dirname>/**"]``).

    ``ignore`` defaults to :data:`DEFAULT_IGNORE` (plus anything ending in
    ``.egg-info`` and any hidden directory). If nothing is discovered, returns
    ``[]`` — the caller still renders a skeleton with a placeholder component.

    ``src_dirs`` is accepted for forward-compatibility (callers that want to
    point at non-``src`` source roots) but is not required by the current
    heuristic; it is intentionally unused here to keep behaviour deterministic.
    """
    root_path = Path(root)
    ignore_set = DEFAULT_IGNORE if ignore is None else frozenset(ignore)

    if not root_path.is_dir():
        return []

    src = root_path / "src"
    components: list[ScaffoldComponent] = []

    if src.is_dir():
        for dirname in _immediate_dirs(src):
            if _is_ignored(dirname, ignore_set):
                continue
            components.append(
                ScaffoldComponent(
                    id=f"comp.{dirname}",
                    name=_dirname_to_name(dirname),
                    code_paths=[f"src/{dirname}/**"],
                )
            )
    else:
        for dirname in _immediate_dirs(root_path):
            if _is_ignored(dirname, ignore_set):
                continue
            components.append(
                ScaffoldComponent(
                    id=f"comp.{dirname}",
                    name=_dirname_to_name(dirname),
                    code_paths=[f"{dirname}/**"],
                )
            )

    components.sort(key=lambda c: c.id)
    return components


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

_BANNER = """\
# ============================================================================
# GENERATED THREAT-MODEL SKELETON — NOT YET AUTHORITATIVE.
#
# This file was scaffolded automatically from the repository's directory layout
# (deterministic, no LLM). The whole Threat-Model Delta analysis presumes a
# *human-authored*, *human-approved* baseline: nothing below is a real
# security assertion yet.
#
# Before committing:
#   1. Review every component, asset, trust boundary and assumption.
#   2. Replace each `# TODO:` with a real, deliberate value.
#   3. Wire `handles_assets` / `entry_points` / `data_flows` so diffs resolve.
#   4. Delete anything that does not apply.
#
# `code_paths` is the linking mechanism: it maps elements to source paths so a
# diff can resolve to the elements it affects.
# ============================================================================
"""


def _yaml_quote(value: str) -> str:
    """Double-quote a scalar and escape what YAML needs escaped."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def render_baseline(
    system_name: str,
    components: list[ScaffoldComponent],
    *,
    version: str = "0.1.0",
) -> str:
    """Render a baseline skeleton as YAML *text* (with comments and TODOs).

    The text is hand-built (not ``yaml.dump``) so it can carry explanatory ``#``
    comments and ``# TODO:`` guidance. It is guaranteed to parse with both
    :func:`yaml.safe_load` and :func:`threat_delta.baseline.parse_baseline`:
    every structured value required by the parser (component ``id``, asset
    ``id`` + ``sensitivity``, assumption ``id`` + ``statement``) is a real
    placeholder, with the "fill me in" intent expressed only in comments.
    """
    lines: list[str] = []
    lines.append(_BANNER.rstrip("\n"))
    lines.append("")

    # ---- system ----------------------------------------------------------- #
    lines.append("system:")
    lines.append(f"  name: {_yaml_quote(system_name)}")
    lines.append(f"  version: {_yaml_quote(version)}")
    lines.append(
        "  description: "
        + _yaml_quote("TODO: one-line description of what this system does.")
    )
    lines.append("")

    # ---- assets ----------------------------------------------------------- #
    lines.append("# TODO: enumerate the data/assets worth protecting and their")
    lines.append("# sensitivity (one of: critical, high, medium, low).")
    lines.append("assets:")
    lines.append("  - id: asset.example")
    lines.append("    name: Example asset")
    lines.append("    sensitivity: high  # TODO: critical | high | medium | low")
    lines.append("")

    # ---- trust_boundaries ------------------------------------------------- #
    lines.append("# TODO: list the trust boundaries and the controls that guard")
    lines.append("# each crossing (e.g. authn, tls, input_validation).")
    lines.append("trust_boundaries:")
    lines.append("  - id: tb.example")
    lines.append("    name: Example boundary")
    lines.append(
        "    description: "
        + _yaml_quote("TODO: who/what is on each side of this boundary.")
    )
    lines.append("    controls: []  # TODO: e.g. [authn, tls, input_validation]")
    lines.append("")

    # ---- components ------------------------------------------------------- #
    lines.append("# One block per component discovered from the layout. Set a real")
    lines.append("# trust_zone, then wire handles_assets / entry_points.")
    lines.append("components:")
    rendered = components if components else _placeholder_components()
    for comp in rendered:
        lines.append(f"  - id: {comp.id}")
        lines.append(f"    name: {_yaml_quote(comp.name)}")
        lines.append(
            '    trust_zone: "internal"  # TODO: real zone, e.g. dmz | internal | external'
        )
        paths = ", ".join(_yaml_quote(p) for p in comp.code_paths)
        lines.append(f"    code_paths: [{paths}]")
        lines.append("    handles_assets: []  # TODO: asset ids this component touches")
        lines.append("    entry_points: []    # TODO: e.g. http_public, grpc_internal")
    lines.append("")

    # ---- assumptions ------------------------------------------------------ #
    lines.append("# Security assumptions a change might violate. Edit these to match")
    lines.append("# how the system is actually built and operated.")
    lines.append("assumptions:")
    for asm_id, statement in _placeholder_assumptions():
        lines.append(f"  - id: {asm_id}")
        lines.append(f"    statement: {_yaml_quote(statement)}")
    lines.append("")

    # ---- accepted_risks --------------------------------------------------- #
    lines.append("# TODO: risks you have consciously accepted (id + statement).")
    lines.append("accepted_risks: []")
    lines.append("")

    return "\n".join(lines)


def _placeholder_components() -> list[ScaffoldComponent]:
    """Single fallback component when discovery found nothing."""
    return [
        ScaffoldComponent(
            id="comp.example",
            name="Example component",
            code_paths=["src/**"],
        )
    ]


def _placeholder_assumptions() -> list[tuple[str, str]]:
    """Common starter assumptions (id, statement) — all flagged as TODO."""
    return [
        (
            "asm.input_validation",
            "TODO: all externally originated input is validated before reaching "
            "internal logic.",
        ),
        (
            "asm.authn_required",
            "TODO: privileged operations require an authenticated and authorized "
            "caller.",
        ),
        (
            "asm.secrets_not_logged",
            "TODO: secrets and sensitive data are never written to logs in "
            "plaintext.",
        ),
    ]


def init_baseline(
    root: Union[str, Path],
    *,
    out: Optional[Union[str, Path]] = None,
    system_name: Optional[str] = None,
    version: str = "0.1.0",
) -> str:
    """Discover components under ``root`` and render a baseline skeleton.

    ``system_name`` defaults to the basename of the absolute path of ``root``.
    If ``out`` is given, the rendered text is written there (parent directories
    created as needed) and a :class:`FileExistsError` is raised if ``out``
    already exists — we never clobber a committed baseline. Returns the rendered
    YAML text regardless of whether it was written.
    """
    root_path = Path(root)
    components = discover_components(root_path)

    if system_name is None:
        system_name = root_path.resolve().name or "system"

    text = render_baseline(system_name, components, version=version)

    if out is not None:
        out_path = Path(out)
        if out_path.exists():
            raise FileExistsError(
                f"refusing to overwrite existing baseline: {out_path}"
            )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")

    return text
