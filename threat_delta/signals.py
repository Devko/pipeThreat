"""Deterministic change-signals — grounding facts for the model-driven stages.

The model-driven stages (6c/6d) work better when they are handed *facts the
pipeline already knows deterministically* rather than asked to imagine a threat
from a raw hunk. This module derives a small, bounded set of such facts — from
the static-analysis annotations (step 5) and a keyword scan of the **added**
diff lines only — and the prompt builders inject them as a labelled data block.

This keeps the project's thesis intact: deterministic code does the breadth
(what entry points/sinks/controls the diff touches), and the LLM does the narrow
judgment (does that constitute a STRIDE delta / assumption violation). Nothing
here calls a model; everything is reproducible.

The scan is intentionally conservative — a handful of well-understood security
keywords — so a signal means "this token literally appears in the added code",
never an inference. Signals are phrased as neutral observations, not
instructions, and are passed as data (spec §11, prompt-injection mitigation).
"""

from __future__ import annotations

import re

from .models import ChangedFile, Component, Diff, FileAnnotation, Slice


# Keyword groups: a signal fires when any of the terms appears on an *added*
# line. Kept small and auditable on purpose.
_AUTH_TERMS = (
    "auth", "authenticate", "authorization", "authorize", "permission",
    "token", "apikey", "api_key", "credential", "login", "session", "acl",
)
_RATELIMIT_TERMS = ("rate limit", "ratelimit", "rate_limit", "throttle", "quota")
_PUBLIC_TERMS = ("public", "unauthenticated", "anonymous", "webhook")
_VALIDATION_TERMS = ("validate", "validation", "sanitize", "sanitise", "escape", "schema")
_AUDIT_TERMS = ("audit", "logger", "logging", "journal")


def _added_lines(file: ChangedFile) -> list[str]:
    """Body of every added (``+``) line in the file's hunks, sans the ``+``.

    Hunk-header lines (``+++`` and ``@@``) are excluded so only real additions
    are scanned.
    """
    out: list[str] = []
    for hunk in file.hunks:
        for line in hunk.content.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                out.append(line[1:])
    return out


def _contains(haystack: str, terms) -> bool:
    """Whole-token match of any ``term`` in ``haystack`` (already lowercased).

    Uses alnum boundaries rather than raw substring so a keyword only fires as a
    word: ``public`` does not match ``publickey``, ``acl`` does not match
    ``oracle``, ``logger`` does not match ``blogger``. This keeps the scan the
    "conservative, a signal means the token literally appears" guarantee the
    module docstring promises.
    """
    for term in terms:
        if re.search(r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])", haystack):
            return True
    return False


def hunk_start_line(header: str) -> int | None:
    """Parse the new-file start line from a unified-diff hunk header.

    ``@@ -12,3 +40,8 @@`` -> ``40``. Returns ``None`` when the header is not a
    standard hunk header (e.g. structured-JSON diffs that carry no ``@@`` line).
    """
    match = re.search(r"\+(\d+)", header or "")
    return int(match.group(1)) if match else None


def regions_by_path(diff: Diff) -> dict[str, int]:
    """Map each changed file to the start line of its first hunk (for SARIF).

    Deterministic; files whose hunks carry no parseable header are omitted.
    """
    regions: dict[str, int] = {}
    for file in diff.files:
        for hunk in file.hunks:
            line = hunk_start_line(hunk.header)
            if line is not None:
                regions[file.path] = line
                break
    return regions


def signals_for_paths(
    paths: list[str],
    diff: Diff,
    annotations: list[FileAnnotation],
) -> list[str]:
    """Deterministic grounding facts for the given changed ``paths``.

    Combines step-5 annotations (entry points / untrusted inputs / sinks) with a
    keyword scan of the added lines. Returns short, de-duplicated, neutral
    observation strings — or ``[]`` when nothing notable is found.
    """
    path_set = set(paths)
    ann_by_path = {a.path: a for a in annotations}
    files = [f for f in diff.files if f.path in path_set]

    added = "\n".join(line for f in files for line in _added_lines(f)).lower()

    # From static analysis (authoritative, structural).
    entry_points: list[str] = []
    untrusted = False
    sinks: list[str] = []
    for p in paths:
        ann = ann_by_path.get(p)
        if not ann:
            continue
        entry_points.extend(ann.entry_points)
        untrusted = untrusted or bool(ann.untrusted_inputs)
        sinks.extend(ann.sinks)

    signals: list[str] = []
    if entry_points:
        uniq = ", ".join(dict.fromkeys(entry_points))
        signals.append(f"adds/changes entry point(s): {uniq}")
    if untrusted and sinks:
        uniq = ", ".join(dict.fromkeys(sinks))
        signals.append(f"untrusted input reaches sink(s): {uniq}")
    elif untrusted:
        signals.append("handles untrusted/attacker-controlled input")

    # From the added code (keyword observations).
    if added:
        touches_auth = _contains(added, _AUTH_TERMS)
        if _contains(added, _PUBLIC_TERMS) and not touches_auth:
            signals.append("added code exposes a public/unauthenticated path")
        if not _contains(added, _RATELIMIT_TERMS) and (entry_points or _contains(added, _PUBLIC_TERMS)):
            signals.append("no rate-limit/throttle present on the new path")
        if not _contains(added, _VALIDATION_TERMS) and (untrusted or sinks):
            signals.append("no explicit input validation on the changed path")
        if not _contains(added, _AUDIT_TERMS) and sinks:
            signals.append("the sensitive operation is not written to an audit log")

    # De-duplicate while preserving order.
    return list(dict.fromkeys(signals))


def signals_for_component(
    component: Component,
    slice: Slice,
    diff: Diff,
    annotations: list[FileAnnotation],
) -> list[str]:
    """Deterministic grounding facts scoped to one component's changed paths."""
    paths = slice.matched_paths.get(component.id, [])
    return signals_for_paths(paths, diff, annotations)


def format_signals(signals: list[str]) -> str:
    """Render signals as a compact, labelled, data-only block for a prompt."""
    if not signals:
        return "(none detected)"
    return "\n".join(f"- {s}" for s in signals)
