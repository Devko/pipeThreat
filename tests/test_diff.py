"""Tests for the input loaders (diff / annotations / findings)."""

from __future__ import annotations

import json

import pytest

from threat_delta.diff import (
    load_annotations,
    load_diff,
    load_findings,
    parse_unified_diff,
)


# --------------------------------------------------------------------------- #
# parse_unified_diff
# --------------------------------------------------------------------------- #

SAMPLE_DIFF = """diff --git a/src/users/admin_handler.py b/src/users/admin_handler.py
index 1234567..89abcde 100644
--- a/src/users/admin_handler.py
+++ b/src/users/admin_handler.py
@@ -1,3 +1,4 @@
 def handler():
+    grant_admin()
     return
@@ -10,2 +11,3 @@
 def other():
+    log()
     pass
"""


def test_parse_unified_diff_single_file_two_hunks():
    diff = parse_unified_diff(SAMPLE_DIFF, pr="PR-7")
    assert diff.pr == "PR-7"
    assert diff.paths == ["src/users/admin_handler.py"]
    cf = diff.files[0]
    assert len(cf.hunks) == 2
    assert cf.hunks[0].header == "@@ -1,3 +1,4 @@"
    assert "grant_admin()" in cf.hunks[0].content
    assert cf.hunks[0].content.startswith("@@ -1,3 +1,4 @@")
    assert "log()" in cf.hunks[1].content


def test_parse_unified_diff_multiple_files():
    text = (
        "diff --git a/src/gateway/app.py b/src/gateway/app.py\n"
        "--- a/src/gateway/app.py\n"
        "+++ b/src/gateway/app.py\n"
        "@@ -1 +1,2 @@\n"
        " x\n"
        "+y\n"
        "diff --git a/src/tokenizer/core.py b/src/tokenizer/core.py\n"
        "--- a/src/tokenizer/core.py\n"
        "+++ b/src/tokenizer/core.py\n"
        "@@ -1 +1,2 @@\n"
        " a\n"
        "+b\n"
    )
    diff = parse_unified_diff(text)
    assert diff.paths == ["src/gateway/app.py", "src/tokenizer/core.py"]
    assert all(len(f.hunks) == 1 for f in diff.files)


def test_parse_unified_diff_new_file():
    text = (
        "diff --git a/src/new_mod.py b/src/new_mod.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/src/new_mod.py\n"
        "@@ -0,0 +1,2 @@\n"
        "+import os\n"
        "+x = 1\n"
    )
    diff = parse_unified_diff(text)
    assert diff.paths == ["src/new_mod.py"]
    assert len(diff.files[0].hunks) == 1


def test_parse_unified_diff_deleted_file():
    text = (
        "diff --git a/src/old_mod.py b/src/old_mod.py\n"
        "deleted file mode 100644\n"
        "--- a/src/old_mod.py\n"
        "+++ /dev/null\n"
        "@@ -1,2 +0,0 @@\n"
        "-import os\n"
        "-x = 1\n"
    )
    diff = parse_unified_diff(text)
    # Deletion uses the old path.
    assert diff.paths == ["src/old_mod.py"]


def test_parse_unified_diff_rename_no_hunks():
    text = (
        "diff --git a/src/a.py b/src/b.py\n"
        "similarity index 100%\n"
        "rename from src/a.py\n"
        "rename to src/b.py\n"
    )
    diff = parse_unified_diff(text)
    assert diff.paths == ["src/b.py"]
    assert diff.files[0].hunks == []


def test_parse_unified_diff_no_git_header():
    # Plain unified diff without `diff --git`.
    text = (
        "--- a/foo.py\n"
        "+++ b/foo.py\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n"
    )
    diff = parse_unified_diff(text)
    assert diff.paths == ["foo.py"]
    assert len(diff.files[0].hunks) == 1


def test_parse_unified_diff_empty():
    diff = parse_unified_diff("")
    assert diff.files == []


# --------------------------------------------------------------------------- #
# load_diff
# --------------------------------------------------------------------------- #

def test_load_diff_unified_text(tmp_path):
    p = tmp_path / "change.diff"
    p.write_text(SAMPLE_DIFF, encoding="utf-8")
    diff = load_diff(p)
    assert diff.paths == ["src/users/admin_handler.py"]


def test_load_diff_json(tmp_path):
    p = tmp_path / "change.json"
    payload = {
        "pr": "PR-9",
        "files": [
            {
                "path": "src/users/x.py",
                "hunks": [{"header": "@@ -1 +1 @@", "content": "@@ -1 +1 @@\n+z"}],
                "touched_functions": ["x.handler"],
            }
        ],
    }
    p.write_text(json.dumps(payload), encoding="utf-8")
    diff = load_diff(p)
    assert diff.pr == "PR-9"
    assert diff.paths == ["src/users/x.py"]
    assert diff.files[0].hunks[0].header == "@@ -1 +1 @@"
    assert diff.files[0].touched_functions == ["x.handler"]


def test_load_diff_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_diff(tmp_path / "nope.diff")


def test_load_diff_accepts_str_path(tmp_path):
    p = tmp_path / "change.diff"
    p.write_text(SAMPLE_DIFF, encoding="utf-8")
    diff = load_diff(str(p))
    assert diff.paths == ["src/users/admin_handler.py"]


# --------------------------------------------------------------------------- #
# load_annotations
# --------------------------------------------------------------------------- #

def test_load_annotations_list(tmp_path):
    p = tmp_path / "ann.json"
    p.write_text(
        json.dumps(
            [
                {
                    "path": "src/users/x.py",
                    "entry_points": ["POST /admin"],
                    "untrusted_inputs": ["request.body"],
                    "sinks": ["db.exec"],
                }
            ]
        ),
        encoding="utf-8",
    )
    anns = load_annotations(p)
    assert len(anns) == 1
    assert anns[0].path == "src/users/x.py"
    assert anns[0].entry_points == ["POST /admin"]
    assert anns[0].untrusted_inputs == ["request.body"]
    assert anns[0].sinks == ["db.exec"]


def test_load_annotations_mapping(tmp_path):
    p = tmp_path / "ann.json"
    p.write_text(
        json.dumps({"src/users/x.py": {"entry_points": ["POST /admin"]}}),
        encoding="utf-8",
    )
    anns = load_annotations(p)
    assert len(anns) == 1
    assert anns[0].path == "src/users/x.py"
    assert anns[0].entry_points == ["POST /admin"]
    # Missing lists default to [].
    assert anns[0].sinks == []
    assert anns[0].untrusted_inputs == []


def test_load_annotations_none():
    assert load_annotations(None) == []


def test_load_annotations_missing_file(tmp_path):
    assert load_annotations(tmp_path / "missing.json") == []


# --------------------------------------------------------------------------- #
# load_findings
# --------------------------------------------------------------------------- #

def test_load_findings(tmp_path):
    p = tmp_path / "find.json"
    p.write_text(
        json.dumps(
            [
                {"id": "F1", "file": "src/users/x.py", "severity": "high", "message": "sqli"},
                {"id": "F2", "file": "src/gateway/app.py"},
            ]
        ),
        encoding="utf-8",
    )
    findings = load_findings(p)
    assert len(findings) == 2
    assert findings[0].id == "F1"
    assert findings[0].severity == "high"
    assert findings[0].message == "sqli"
    # Defaults.
    assert findings[1].severity == ""
    assert findings[1].message == ""


def test_load_findings_none():
    assert load_findings(None) == []


def test_load_findings_missing_file(tmp_path):
    assert load_findings(tmp_path / "missing.json") == []
