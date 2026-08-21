"""A reviewer must see the change, and must never be shown a partial one silently."""

from __future__ import annotations

from solvan.application.patch_diff import MAX_LINES, diff_view, parse_unified_diff

_DIFF = """diff --git a/src/payments.py b/src/payments.py
index 1111111..2222222 100644
--- a/src/payments.py
+++ b/src/payments.py
@@ -82,7 +82,9 @@ def charge(request):
     connection = pool.acquire()
     try:
         return _write(connection, request)
-    except PaymentError:
-        raise
+    except PaymentError:
+        raise
+    finally:
+        pool.release(connection)
"""


def test_parses_files_line_numbers_and_counts() -> None:
    parsed = parse_unified_diff(_DIFF)
    assert len(parsed.files) == 1
    changed = parsed.files[0]
    assert changed.path == "src/payments.py"
    assert (parsed.added, parsed.removed) == (4, 2)

    added = [line for line in changed.lines if line.kind == "add"]
    removed = [line for line in changed.lines if line.kind == "remove"]
    # An added line has a new-file number and no old-file number, so the reader
    # can locate it in the file that will exist after the change.
    assert all(line.new_line is not None and line.old_line is None for line in added)
    assert all(line.old_line is not None and line.new_line is None for line in removed)
    assert added[-1].text.strip() == "pool.release(connection)"

    context = [line for line in changed.lines if line.kind == "context"]
    assert context[0].old_line == 82 and context[0].new_line == 82


def test_an_oversized_patch_says_so_instead_of_showing_a_silent_sample() -> None:
    body = "\n".join(f"+line {index}" for index in range(MAX_LINES + 50))
    parsed = parse_unified_diff(f"+++ b/big.py\n@@ -1,1 +1,1 @@\n{body}\n")
    assert parsed.truncated is True
    assert "Truncated" in parsed.note


def test_unparsable_content_yields_no_reviewable_change() -> None:
    parsed = parse_unified_diff("this is not a diff at all")
    assert parsed.files == ()
    assert "No reviewable change" in parsed.note


def test_diff_text_is_never_interpreted_as_markup() -> None:
    hostile = '+++ b/x.py\n@@ -1,1 +1,1 @@\n+<script>alert("x")</script>\n'
    view = diff_view(hostile)
    files = view["files"]
    assert isinstance(files, list)
    line = files[0]["lines"][-1]
    # It survives verbatim as text; escaping is the renderer's job and React
    # escapes by default. What matters here is that we neither strip nor
    # execute it, so the reviewer sees exactly what is in the artifact.
    assert line["text"] == '<script>alert("x")</script>'
