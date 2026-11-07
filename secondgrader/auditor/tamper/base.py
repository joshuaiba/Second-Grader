"""Shared plumbing for the tamper-pattern detectors (P2.8).

Every pattern module exposes::

    PATTERN_ID: str
    def detect(changes: list[FileChange]) -> list[TamperFinding]

A :class:`FileChange` describes one file between the *base* code (before the
agent ran) and the *final* code (after). It can be built two ways:

* :func:`changes_from_dirs` - full text of both versions. Used by the
  base/final fixtures and by the end-to-end run (P1 hands us both trees).
* :func:`changes_from_records` - from OBSERVED ``diff`` records in a trace.
  Only the unified diff is known, so ``base_text`` / ``final_text`` are
  ``None`` and detectors must fall back to :meth:`FileChange.removed_lines`
  and :meth:`FileChange.added_lines`.

Detectors must work in both modes and must return ``[]`` for a clean pair.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterable

from secondgrader.auditor.types import TamperFinding
from secondgrader.schema import Record

# --------------------------------------------------------------------------- #
# What counts as a test file / test config
# --------------------------------------------------------------------------- #

_TEST_FILE_RE = re.compile(r"(^|/)(test_[^/]*\.py|[^/]*_test\.py|conftest\.py)$")
_TEST_DIR_RE = re.compile(r"(^|/)(tests?|testing|spec|specs)(/|$)")
TEST_CONFIG_FILES = {
    "pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml", "conftest.py",
    ".coveragerc", "noxfile.py", "pytest.cfg",
}


def is_test_path(path: str) -> bool:
    """True for test modules, conftest files and anything under a tests/ dir."""
    p = path.replace("\\", "/")
    return bool(_TEST_FILE_RE.search(p) or _TEST_DIR_RE.search(p))


def is_test_config_path(path: str) -> bool:
    """True for files that configure test collection or execution."""
    return PurePosixPath(path.replace("\\", "/")).name in TEST_CONFIG_FILES


# --------------------------------------------------------------------------- #
# Diff model
# --------------------------------------------------------------------------- #

@dataclass
class DiffLine:
    """One line of a unified diff hunk.

    ``old_no`` / ``new_no`` are 1-based line numbers in the base / final file,
    ``None`` on the side where the line does not exist.
    """

    op: str  # "+", "-" or " "
    text: str
    old_no: int | None
    new_no: int | None


_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def parse_unified_diff(diff: str) -> list[DiffLine]:
    """Parse a unified diff (single file) into :class:`DiffLine` objects."""
    out: list[DiffLine] = []
    old_no = new_no = 0
    in_hunk = False
    for raw in diff.splitlines():
        m = _HUNK_RE.match(raw)
        if m:
            old_no = int(m.group(1))
            new_no = int(m.group(3))
            in_hunk = True
            continue
        if not in_hunk:
            continue  # ---/+++ headers etc.
        if raw.startswith("\\"):
            continue  # "\ No newline at end of file"
        if raw.startswith("+"):
            out.append(DiffLine("+", raw[1:], None, new_no))
            new_no += 1
        elif raw.startswith("-"):
            out.append(DiffLine("-", raw[1:], old_no, None))
            old_no += 1
        else:
            text = raw[1:] if raw.startswith(" ") else raw
            out.append(DiffLine(" ", text, old_no, new_no))
            old_no += 1
            new_no += 1
    return out


@dataclass
class FileChange:
    """One file, before and after the agent's run.

    Attributes:
        path: Repo-relative POSIX path.
        base_text: Full base content, ``None`` if the file did not exist in
            base **or** if only a diff is known (see ``diff``).
        final_text: Full final content, ``None`` if deleted or unknown.
        diff: Unified diff text. Always present when built from records;
            computed by :func:`changes_from_dirs` otherwise.
        evidence_seqs: ``seq`` of the diff record(s) this came from.
        status: ``"added"``, ``"deleted"``, ``"modified"`` or ``"unknown"``
            (records mode, where we cannot tell add/modify apart reliably).
    """

    path: str
    base_text: str | None = None
    final_text: str | None = None
    diff: str = ""
    evidence_seqs: list[int] = field(default_factory=list)
    status: str = "unknown"

    # -- derived views ----------------------------------------------------- #

    @property
    def has_full_text(self) -> bool:
        return self.base_text is not None or self.final_text is not None

    @property
    def is_test(self) -> bool:
        return is_test_path(self.path)

    @property
    def is_test_config(self) -> bool:
        return is_test_config_path(self.path)

    def diff_lines(self) -> list[DiffLine]:
        return parse_unified_diff(self.diff)

    def removed_lines(self) -> list[DiffLine]:
        return [d for d in self.diff_lines() if d.op == "-"]

    def added_lines(self) -> list[DiffLine]:
        return [d for d in self.diff_lines() if d.op == "+"]

    def base_lines(self) -> list[str]:
        """Base file lines; from full text if known, else the diff's '-' and ' ' lines."""
        if self.base_text is not None:
            return self.base_text.splitlines()
        return [d.text for d in self.diff_lines() if d.op in "- "]

    def final_lines(self) -> list[str]:
        if self.final_text is not None:
            return self.final_text.splitlines()
        return [d.text for d in self.diff_lines() if d.op in "+ "]

    def snippet(self, max_lines: int = 8) -> str:
        """First few changed lines of the diff, for a finding's ``snippet``."""
        changed = [f"{d.op}{d.text}" for d in self.diff_lines() if d.op != " "]
        return "\n".join(changed[:max_lines])


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #

_SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".venv", "node_modules", ".mypy_cache"}


def _walk(root: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for p in sorted(root.rglob("*")):
        if not p.is_file() or any(part in _SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        try:
            files[p.relative_to(root).as_posix()] = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue  # binary; tamper patterns are about source text
    return files


def make_diff(path: str, base: str | None, final: str | None) -> str:
    a = (base or "").splitlines(keepends=True)
    b = (final or "").splitlines(keepends=True)
    return "".join(difflib.unified_diff(a, b, fromfile=f"a/{path}", tofile=f"b/{path}", n=3))


def changes_from_dirs(base_dir: str | Path, final_dir: str | Path) -> list[FileChange]:
    """Compare two directory trees. Unchanged files are omitted."""
    base = _walk(Path(base_dir))
    final = _walk(Path(final_dir))
    out: list[FileChange] = []
    for path in sorted(set(base) | set(final)):
        b, f = base.get(path), final.get(path)
        if b == f:
            continue
        status = "added" if b is None else "deleted" if f is None else "modified"
        out.append(FileChange(path, b, f, make_diff(path, b, f), [], status))
    return out


def changes_from_records(records: Iterable[Record]) -> list[FileChange]:
    """One :class:`FileChange` per OBSERVED ``diff`` record (one per edit, not per file)."""
    out: list[FileChange] = []
    for r in records:
        if r.origin != "OBSERVED" or r.kind != "diff":
            continue
        path = str(r.payload.get("path", ""))
        diff = str(r.payload.get("diff", ""))
        out.append(FileChange(path=path, diff=diff, evidence_seqs=[r.seq], status="unknown"))
    return out


def finding(pattern_id: str, severity: str, change: FileChange, line: int | None,
            summary: str, snippet: str | None = None) -> TamperFinding:
    """Convenience constructor that carries the change's evidence seqs along."""
    return TamperFinding(
        pattern_id=pattern_id,
        severity=severity,  # type: ignore[arg-type]
        path=change.path,
        line=line,
        summary=summary,
        snippet=change.snippet() if snippet is None else snippet,
        evidence_seqs=list(change.evidence_seqs),
    )


__all__ = [
    "DiffLine", "FileChange", "TEST_CONFIG_FILES", "changes_from_dirs", "changes_from_records",
    "finding", "is_test_config_path", "is_test_path", "make_diff", "parse_unified_diff",
]
