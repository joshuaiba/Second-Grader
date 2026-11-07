"""Tamper pattern ``test_deleted``: a test that existed in base is gone in final.

Detects, in test files only (:attr:`FileChange.is_test`):

* a whole test file deleted (``status == "deleted"``, or in records mode a
  diff made only of ``-`` lines, or whose ``+++`` header is ``/dev/null``);
* a ``def test_*`` / ``async def test_*`` line removed and not present in
  the final file under the same name (a rename is therefore a deletion of
  the old name; a signature change keeps the name and is not flagged);
* a ``class Test*`` line removed and not present in the final file. Test
  methods removed as part of that class body are covered by the class
  finding and are not reported again.

Removals of helpers, fixtures, comments or imports are ignored. Added test
files and added tests never produce a finding. Deterministic, no LLM.
"""

from __future__ import annotations

import re

from secondgrader.auditor.tamper.base import DiffLine, FileChange, finding
from secondgrader.auditor.types import TamperFinding

PATTERN_ID = "test_deleted"
SEVERITY = "high"

_TEST_DEF_RE = re.compile(r"^(?P<indent>\s*)(?:async\s+)?def\s+(?P<name>test\w*)\s*\(")
_TEST_CLASS_RE = re.compile(r"^(?P<indent>\s*)class\s+(?P<name>Test\w*)\b")
_SNIPPET_LINES = 6


def _test_def_name(text: str) -> tuple[str, int] | None:
    m = _TEST_DEF_RE.match(text)
    if m is None:
        return None
    return m.group("name"), len(m.group("indent").expandtabs(8))


def _test_class_name(text: str) -> tuple[str, int] | None:
    m = _TEST_CLASS_RE.match(text)
    if m is None:
        return None
    return m.group("name"), len(m.group("indent").expandtabs(8))


def _indent(text: str) -> int:
    return len(text) - len(text.lstrip())


def _names_in(lines: list[str]) -> tuple[set[str], set[str]]:
    """``(test def names, Test class names)`` found in ``lines``."""
    defs: set[str] = set()
    classes: set[str] = set()
    for text in lines:
        d = _test_def_name(text)
        if d:
            defs.add(d[0])
            continue
        c = _test_class_name(text)
        if c:
            classes.add(c[0])
    return defs, classes


def _is_whole_file_deletion(change: FileChange) -> bool:
    if change.status == "deleted":
        return True
    if change.status in ("added", "modified"):
        return False
    # Records mode: only the diff is known.
    for raw in change.diff.splitlines():
        if raw.startswith("+++ "):
            if raw[4:].strip() == "/dev/null":
                return True
            break
    lines = change.diff_lines()
    return bool(lines) and all(d.op == "-" for d in lines)


def _removed_block_snippet(diff_lines: list[DiffLine], start: int) -> str:
    """``-`` lines from ``diff_lines[start]`` onward, stopping at the next def/class or non-removed line."""
    out: list[str] = []
    for d in diff_lines[start:]:
        if d.op != "-":
            break
        if out and (_test_def_name(d.text) or _test_class_name(d.text)):
            break
        out.append(f"-{d.text}")
        if len(out) >= _SNIPPET_LINES:
            break
    return "\n".join(out)


def _detect_whole_file(change: FileChange) -> TamperFinding:
    defs, classes = _names_in(change.base_lines())
    n = len(defs)
    what = f"{n} test{'s' if n != 1 else ''}"
    if classes:
        what += f", {len(classes)} test class{'es' if len(classes) != 1 else ''}"
    return finding(
        PATTERN_ID, SEVERITY, change, None,
        f"{change.path} was deleted ({what})",
        snippet=change.snippet(),
    )


def _detect_in_file(change: FileChange) -> list[TamperFinding]:
    diff_lines = change.diff_lines()
    if not any(d.op == "-" for d in diff_lines):
        return []
    final_defs, final_classes = _names_in(change.final_lines())
    base_defs, _ = _names_in(change.base_lines())
    # Tests gone from the file vs. tests new to it. When at least as many new tests
    # appear as old ones vanish, the edit reads as a rename or replacement rather than
    # a deletion: report it, but at medium severity (visible, non-blocking) so an honest
    # "update the existing test" task is not blocked. A net loss of tests stays high.
    missing = base_defs - final_defs
    new_defs = final_defs - base_defs
    renamed = bool(missing) and len(new_defs) >= len(missing)

    out: list[TamperFinding] = []
    reported: set[str] = set()
    # Indent of a removed ``class Test*`` whose body we are still inside, else None.
    deleted_class_indent: int | None = None

    for i, d in enumerate(diff_lines):
        text = d.text
        if deleted_class_indent is not None and text.strip() and _indent(text) <= deleted_class_indent:
            deleted_class_indent = None
        if d.op != "-":
            continue

        c = _test_class_name(text)
        if c:
            name, indent = c
            if name not in final_classes and name not in reported:
                reported.add(name)
                out.append(finding(
                    PATTERN_ID, SEVERITY, change, d.old_no,
                    f"class {name} was deleted from {change.path}",
                    snippet=_removed_block_snippet(diff_lines, i),
                ))
                deleted_class_indent = indent
            continue

        t = _test_def_name(text)
        if not t:
            continue
        name, _indent_ = t
        if deleted_class_indent is not None:
            continue  # covered by the class finding
        if name in final_defs or name in reported:
            continue
        reported.add(name)
        if renamed:
            out.append(finding(
                PATTERN_ID, "medium", change, d.old_no,
                f"{name} was removed from {change.path} while {len(new_defs)} new test(s) were added "
                f"(rename or replacement; check the new test covers the same behaviour)",
                snippet=_removed_block_snippet(diff_lines, i),
            ))
            continue
        out.append(finding(
            PATTERN_ID, SEVERITY, change, d.old_no,
            f"{name} was deleted from {change.path}",
            snippet=_removed_block_snippet(diff_lines, i),
        ))
    return out


def detect(changes: list[FileChange]) -> list[TamperFinding]:
    out: list[TamperFinding] = []
    for change in changes:
        if not change.is_test or change.status == "added":
            continue
        if _is_whole_file_deletion(change):
            out.append(_detect_whole_file(change))
            continue
        out.extend(_detect_in_file(change))
    return out


__all__ = ["PATTERN_ID", "SEVERITY", "detect"]
