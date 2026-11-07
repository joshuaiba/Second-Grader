"""Tamper-pattern detectors (P2.8). One module per pattern; this package aggregates them.

Each pattern module defines ``PATTERN_ID`` and ``detect(changes) -> list[TamperFinding]``.
Add a module to :data:`PATTERN_MODULES` when it lands. Missing modules are
skipped so the package imports while patterns are still being written.
"""

from __future__ import annotations

import importlib
from typing import Iterable

from secondgrader.auditor.tamper.base import (
    FileChange,
    changes_from_dirs,
    changes_from_records,
)
from secondgrader.auditor.types import TamperFinding
from secondgrader.schema import Record

PATTERN_MODULES: tuple[str, ...] = (
    "test_deleted",
    "assert_weakened",
    "skip_added",
    "special_cased",
    "config_tamper",
    "swallowed_failures",
    "expected_value_edited",
)


def _load_patterns():
    mods = []
    for name in PATTERN_MODULES:
        try:
            mods.append(importlib.import_module(f"secondgrader.auditor.tamper.{name}"))
        except ModuleNotFoundError as exc:
            if exc.name and exc.name.endswith(name):
                continue  # not written yet
            raise
    return mods


def detect_all(changes: Iterable[FileChange]) -> list[TamperFinding]:
    """Run every available pattern over the changes. Deterministic order."""
    changes = list(changes)
    out: list[TamperFinding] = []
    for mod in _load_patterns():
        out.extend(mod.detect(changes))
    out.sort(key=lambda f: (f.path, f.line if f.line is not None else -1, f.pattern_id))
    return out


def detect_in_dirs(base_dir, final_dir) -> list[TamperFinding]:
    return detect_all(changes_from_dirs(base_dir, final_dir))


def detect_in_records(records: Iterable[Record]) -> list[TamperFinding]:
    return detect_all(changes_from_records(records))


__all__ = ["PATTERN_MODULES", "detect_all", "detect_in_dirs", "detect_in_records"]
