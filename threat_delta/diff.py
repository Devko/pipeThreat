"""Input loaders for the Threat-Model Delta step (pipeline step 6).

This module parses the *pipeline inputs* — the PR diff (step 1 / scope), the
static-analysis annotations (step 5) and the SAST/secrets/CVE findings
(steps 2-4) — into the plain value objects declared in :mod:`threat_delta.models`.

It performs only I/O and parsing; no relevance resolution (that is stage 6a in
:mod:`threat_delta.relevance`) and no LLM calls.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Union

from .models import ChangedFile, Diff, FileAnnotation, Finding, Hunk

PathLike = Union[str, Path]


# --------------------------------------------------------------------------- #
# Unified-diff parsing
# --------------------------------------------------------------------------- #

def _strip_prefix(path: str) -> str:
    """Strip a leading ``a/`` or ``b/`` git diff prefix."""
    path = path.strip()
    if path.startswith(("a/", "b/")):
        return path[2:]
    return path


def parse_unified_diff(text: str, pr: str = "") -> Diff:
    """Parse standard unified (``git diff``) text into a :class:`Diff`.

    Tolerant of new files (``--- /dev/null``), deletions, renames and files
    with no hunks.
    """
    diff = Diff(pr=pr)
    lines = text.splitlines()

    current: Optional[ChangedFile] = None
    current_hunk: Optional[Hunk] = None
    # paths gathered from the most recent `diff --git` header, used as a
    # fallback when no +++/--- lines are present (e.g. pure renames).
    git_old: Optional[str] = None
    git_new: Optional[str] = None
    saw_file_header = False  # +++/--- already established the path for `current`

    def flush_hunk() -> None:
        nonlocal current_hunk
        if current is not None and current_hunk is not None:
            current.hunks.append(current_hunk)
        current_hunk = None

    def start_file(path: str) -> ChangedFile:
        nonlocal current, current_hunk
        flush_hunk()
        cf = ChangedFile(path=path)
        diff.files.append(cf)
        current = cf
        current_hunk = None
        return cf

    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]

        if line.startswith("diff --git "):
            flush_hunk()
            # `diff --git a/old b/new`
            parts = line[len("diff --git "):].split(" ")
            git_old = _strip_prefix(parts[0]) if len(parts) >= 1 else None
            git_new = _strip_prefix(parts[1]) if len(parts) >= 2 else None
            # Create the file now using the header path; +++/--- may refine it.
            path = git_new or git_old or ""
            start_file(path)
            saw_file_header = False
            i += 1
            continue

        if line.startswith("--- "):
            old = line[4:].strip()
            # Begin a new file if there is no `diff --git` driving this section.
            if current is None or saw_file_header or current_hunk is not None:
                start_file("")
            # Look ahead for the matching +++ line.
            new = None
            if i + 1 < n and lines[i + 1].startswith("+++ "):
                new = lines[i + 1][4:].strip()
            if new is not None and new != "/dev/null":
                path = _strip_prefix(new)
            elif old != "/dev/null":
                path = _strip_prefix(old)
            else:
                path = git_new or git_old or ""
            if current is None:
                start_file(path)
            else:
                current.path = path
            saw_file_header = True
            if new is not None:
                i += 2
            else:
                i += 1
            continue

        if line.startswith("+++ "):
            # Standalone +++ without a preceding --- on this iteration.
            new = line[4:].strip()
            if current is None:
                start_file("")
            if new != "/dev/null":
                current.path = _strip_prefix(new)
            saw_file_header = True
            i += 1
            continue

        if line.startswith("@@"):
            flush_hunk()
            if current is None:
                # A hunk with no file header — synthesise one.
                start_file(git_new or git_old or "")
            current_hunk = Hunk(header=line, content=line)
            i += 1
            continue

        # Body of a hunk (context / + / - / "\ No newline...").
        if current_hunk is not None:
            current_hunk.content += "\n" + line
            i += 1
            continue

        # Otherwise: metadata line (index, rename from/to, mode, etc.) — ignore,
        # but honour rename targets so the path is the new name.
        if line.startswith("rename to "):
            if current is not None:
                current.path = _strip_prefix(line[len("rename to "):])
        i += 1

    flush_hunk()
    return diff


# --------------------------------------------------------------------------- #
# Structured-JSON diff
# --------------------------------------------------------------------------- #

def _diff_from_json(data: dict) -> Diff:
    files: list[ChangedFile] = []
    for f in data.get("files", []) or []:
        hunks = [
            Hunk(header=str(h.get("header", "")), content=str(h.get("content", "")))
            for h in (f.get("hunks", []) or [])
        ]
        files.append(
            ChangedFile(
                path=str(f.get("path", "")),
                hunks=hunks,
                touched_functions=[str(x) for x in (f.get("touched_functions", []) or [])],
            )
        )
    return Diff(files=files, pr=str(data.get("pr", "")))


def load_diff(path: PathLike) -> Diff:
    """Load a :class:`Diff` from disk.

    ``.json`` files are parsed as the structured shape
    ``{"pr": .., "files": [{"path":.., "hunks":[..], "touched_functions":[..]}]}``;
    anything else is treated as unified-diff text.

    Raises :class:`FileNotFoundError` if the (required) diff file is missing.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"diff file not found: {p}")
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() == ".json":
        data = json.loads(text)
        return _diff_from_json(data)
    return parse_unified_diff(text)


# --------------------------------------------------------------------------- #
# Annotations (step 5)
# --------------------------------------------------------------------------- #

def _annotation_from(path: str, raw: dict) -> FileAnnotation:
    return FileAnnotation(
        path=path,
        entry_points=[str(x) for x in (raw.get("entry_points", []) or [])],
        untrusted_inputs=[str(x) for x in (raw.get("untrusted_inputs", []) or [])],
        sinks=[str(x) for x in (raw.get("sinks", []) or [])],
    )


def load_annotations(path: Optional[PathLike]) -> list[FileAnnotation]:
    """Load step-5 file annotations.

    Accepts either a JSON list of ``{path, entry_points, ...}`` objects or an
    object mapping ``path -> {entry_points, ...}``. Optional input: returns
    ``[]`` when ``path`` is ``None`` or the file does not exist.
    """
    if path is None:
        return []
    p = Path(path)
    if not p.exists():
        return []
    data = json.loads(p.read_text(encoding="utf-8"))

    annotations: list[FileAnnotation] = []
    if isinstance(data, list):
        for item in data:
            annotations.append(_annotation_from(str(item.get("path", "")), item))
    elif isinstance(data, dict):
        for file_path, raw in data.items():
            annotations.append(_annotation_from(str(file_path), raw or {}))
    return annotations


# --------------------------------------------------------------------------- #
# Findings (steps 2-4)
# --------------------------------------------------------------------------- #

def load_findings(path: Optional[PathLike]) -> list[Finding]:
    """Load SAST/secrets/CVE findings. Optional input: ``[]`` when ``path`` is
    ``None`` or the file does not exist."""
    if path is None:
        return []
    p = Path(path)
    if not p.exists():
        return []
    data = json.loads(p.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for item in data or []:
        findings.append(
            Finding(
                id=str(item.get("id", "")),
                file=str(item.get("file", "")),
                severity=str(item.get("severity", "")),
                message=str(item.get("message", "")),
            )
        )
    return findings
