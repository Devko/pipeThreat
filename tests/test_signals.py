"""Tests for the deterministic change-signals module (grounding facts)."""

from __future__ import annotations

from threat_delta.models import ChangedFile, Diff, FileAnnotation, Hunk
from threat_delta.signals import (
    hunk_start_line,
    regions_by_path,
    signals_for_paths,
)


def _diff(content: str, path: str = "api.py", header: str = "@@ -0,0 +1,4 @@") -> Diff:
    return Diff(files=[ChangedFile(path=path, hunks=[Hunk(header=header, content=content)])])


def test_hunk_start_line_parses_new_file_offset():
    assert hunk_start_line("@@ -12,3 +40,8 @@ def f():") == 40
    assert hunk_start_line("@@ -1 +1 @@") == 1
    assert hunk_start_line("not a hunk header") is None


def test_regions_by_path_uses_first_hunk():
    diff = Diff(
        files=[
            ChangedFile(
                path="a.py",
                hunks=[Hunk(header="@@ -0,0 +5,2 @@"), Hunk(header="@@ -0,0 +99,2 @@")],
            )
        ]
    )
    assert regions_by_path(diff) == {"a.py": 5}


def test_signals_from_annotations_entry_points_and_sinks():
    diff = _diff("+def handler(req):\n+    return read(req.path)")
    ann = [FileAnnotation(path="api.py", entry_points=["http_public"],
                          untrusted_inputs=["req.path"], sinks=["read"])]
    signals = signals_for_paths(["api.py"], diff, ann)
    joined = " | ".join(signals)
    assert "http_public" in joined
    assert "untrusted input reaches sink" in joined


def test_signals_flag_missing_auth_and_rate_limit():
    # Added code exposes a public path with no auth/rate-limit/validation tokens.
    diff = _diff("+@app.post('/webhook/public')\n+def run(body):\n+    execute(body)")
    ann = [FileAnnotation(path="api.py", entry_points=["http_webhook"], sinks=["execute"])]
    signals = signals_for_paths(["api.py"], diff, ann)
    joined = " | ".join(signals)
    assert "public/unauthenticated" in joined
    assert "rate-limit" in joined


def test_signals_suppressed_when_auth_present():
    diff = _diff("+def run(body):\n+    require_auth(body.token)\n+    rate_limit()\n+    validate(body)")
    ann = [FileAnnotation(path="api.py", sinks=["execute"], untrusted_inputs=["body"])]
    signals = signals_for_paths(["api.py"], diff, ann)
    joined = " | ".join(signals)
    assert "public/unauthenticated" not in joined
    assert "no rate-limit" not in joined


def test_no_signals_for_unrelated_change():
    diff = _diff("+# just a comment\n+x = 1", path="util.py")
    assert signals_for_paths(["util.py"], diff, []) == []


def test_keyword_scan_is_whole_token_not_substring():
    # Regression: a literal '*' (multiplication/pointer) or words like 'oracle'
    # / 'catalog.' must NOT be read as auth/public/audit signals.
    from threat_delta.signals import _AUDIT_TERMS, _AUTH_TERMS, _PUBLIC_TERMS, _contains

    assert not _contains("area := w * h", _PUBLIC_TERMS)  # '*' is not "public"
    assert not _contains("p := *ptr", _PUBLIC_TERMS)
    assert not _contains("connect to oracle", _AUTH_TERMS)  # 'acl' not in 'oracle'
    assert not _contains("catalog.load()", _AUDIT_TERMS)    # 'log' not a term; no false audit
    # Real tokens still match on a word boundary.
    assert _contains("require_auth(token)", _AUTH_TERMS)
    assert _contains("post('/webhook-public/:id')", _PUBLIC_TERMS)
    assert _contains("logger.info(x)", _AUDIT_TERMS)


def test_math_pointer_change_has_no_public_signal():
    diff = _diff("+area := w * h\n+p := *ptr", path="m.go")
    ann = [FileAnnotation(path="m.go", entry_points=["calc"])]
    signals = signals_for_paths(["m.go"], diff, ann)
    assert not any("public" in s for s in signals)
