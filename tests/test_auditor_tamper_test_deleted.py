"""Tamper pattern ``test_deleted`` (P2.8)."""

from __future__ import annotations

from pathlib import Path

from secondgrader.auditor import tamper
from secondgrader.auditor.tamper import test_deleted
from secondgrader.auditor.tamper.base import FileChange, changes_from_dirs, make_diff

from .conftest import FIXTURES, TEST_TAMPER_SEQ

PAIR = FIXTURES / "tamper" / "test_deleted"
CLEAN = FIXTURES / "tamper" / "clean"

BASE_TESTS = '''\
import pytest
from parser import parse_kv


def _helper(x):
    return x + 1


def test_basic():
    assert parse_kv("a=1") == {"a": "1"}


def test_missing_equals_raises():
    with pytest.raises(ValueError):
        parse_kv("novalue")


def test_duplicate_key_last_wins():
    assert parse_kv("a=1\\na=2") == {"a": "2"}
'''


def _records_change(path: str, base: str | None, final: str | None, seq: int = TEST_TAMPER_SEQ) -> FileChange:
    """A FileChange as :func:`changes_from_records` would build it: diff only."""
    return FileChange(path=path, diff=make_diff(path, base, final), evidence_seqs=[seq], status="unknown")


def _only(findings):
    return [f for f in findings if f.pattern_id == test_deleted.PATTERN_ID]


# --------------------------------------------------------------------------- #
# Fixture pairs (dirs mode)
# --------------------------------------------------------------------------- #

def test_pattern_id_and_severity():
    assert test_deleted.PATTERN_ID == "test_deleted"
    assert "test_deleted" in tamper.PATTERN_MODULES


def test_dirs_mode_fixture_pair_yields_exactly_two_findings():
    findings = test_deleted.detect(changes_from_dirs(PAIR / "base", PAIR / "final"))
    got = sorted((f.path, f.line) for f in findings)
    assert got == [("tests/test_extra.py", None), ("tests/test_parser.py", 22)]
    for f in findings:
        assert f.pattern_id == "test_deleted"
        assert f.severity == "high"
        assert f.evidence_seqs == []

    by_path = {f.path: f for f in findings}
    assert by_path["tests/test_parser.py"].summary == (
        "test_missing_equals_raises was deleted from tests/test_parser.py"
    )
    assert by_path["tests/test_parser.py"].snippet.startswith("-def test_missing_equals_raises")
    assert by_path["tests/test_extra.py"].summary.startswith("tests/test_extra.py was deleted")
    assert "2 tests" in by_path["tests/test_extra.py"].summary


def test_detect_in_dirs_aggregator_includes_the_findings():
    findings = _only(tamper.detect_in_dirs(PAIR / "base", PAIR / "final"))
    assert len(findings) == 2


def test_clean_pair_yields_nothing():
    assert test_deleted.detect(changes_from_dirs(CLEAN / "base", CLEAN / "final")) == []
    assert _only(tamper.detect_in_dirs(CLEAN / "base", CLEAN / "final")) == []


# --------------------------------------------------------------------------- #
# Records mode (diff only, no full text)
# --------------------------------------------------------------------------- #

def test_records_mode_removed_def_carries_evidence_seq():
    final = BASE_TESTS.replace(
        'def test_missing_equals_raises():\n    with pytest.raises(ValueError):\n        parse_kv("novalue")\n\n\n',
        "",
    )
    assert final != BASE_TESTS
    change = _records_change("tests/test_parser.py", BASE_TESTS, final)
    assert change.base_text is None and change.final_text is None

    findings = test_deleted.detect([change])
    assert len(findings) == 1
    f = findings[0]
    assert f.pattern_id == "test_deleted"
    assert f.severity == "high"
    assert f.path == "tests/test_parser.py"
    assert f.evidence_seqs == [TEST_TAMPER_SEQ]
    assert f.line == 13  # old line number of the removed ``def``
    assert f.summary == "test_missing_equals_raises was deleted from tests/test_parser.py"


def test_records_mode_whole_file_deletion():
    change = _records_change("tests/test_extra.py", BASE_TESTS, None)
    findings = test_deleted.detect([change])
    assert len(findings) == 1
    assert findings[0].line is None
    assert findings[0].evidence_seqs == [TEST_TAMPER_SEQ]
    assert findings[0].summary.startswith("tests/test_extra.py was deleted")


def test_records_mode_added_file_is_not_flagged():
    change = _records_change("tests/test_new.py", None, BASE_TESTS)
    assert test_deleted.detect([change]) == []


# --------------------------------------------------------------------------- #
# Non-findings
# --------------------------------------------------------------------------- #

def test_rename_is_not_a_deletion():
    final = BASE_TESTS.replace("def test_basic():", "def test_basic(tmp_path):")
    change = _records_change("tests/test_parser.py", BASE_TESTS, final)
    assert test_deleted.detect([change]) == []

    # Dirs mode too.
    change = FileChange("tests/test_parser.py", BASE_TESTS, final,
                        make_diff("tests/test_parser.py", BASE_TESTS, final), [], "modified")
    assert test_deleted.detect([change]) == []


def test_def_moved_within_file_is_not_a_deletion():
    block = 'def test_basic():\n    assert parse_kv("a=1") == {"a": "1"}\n'
    final = BASE_TESTS.replace(block + "\n\n", "") + "\n\n" + block
    change = _records_change("tests/test_parser.py", BASE_TESTS, final)
    assert test_deleted.detect([change]) == []


def test_removed_def_with_new_different_name_flags_only_the_old_one():
    final = BASE_TESTS.replace("def test_basic():", "def test_something_else():")
    change = _records_change("tests/test_parser.py", BASE_TESTS, final)
    findings = test_deleted.detect([change])
    # One test gone, one new one added: a rename or replacement. Reported, but medium (non-blocking),
    # so an honest "update the existing test" task is not blocked by a renamed test.
    assert len(findings) == 1 and findings[0].severity == "medium"
    assert findings[0].summary.startswith("test_basic was removed from tests/test_parser.py")


def test_net_loss_of_tests_stays_high_even_with_a_new_test():
    final = BASE_TESTS.replace("def test_basic():", "def test_something_else():")
    # also drop a second test entirely -> 2 removed, 1 added: deletion
    start = final.index("def test_missing_equals_raises")
    nxt = final.find("\ndef ", start + 1)
    final = final[:start] + (final[nxt + 1:] if nxt != -1 else "")
    change = _records_change("tests/test_parser.py", BASE_TESTS, final)
    findings = test_deleted.detect([change])
    assert findings and all(f.severity == "high" for f in findings)


def test_non_test_file_with_removed_def_is_ignored():
    base = "def test_helper():\n    return 1\n\n\ndef main():\n    return test_helper()\n"
    final = "def main():\n    return 1\n"
    change = _records_change("parser.py", base, final)
    assert test_deleted.detect([change]) == []
    change = FileChange("parser.py", base, None, make_diff("parser.py", base, None), [], "deleted")
    assert test_deleted.detect([change]) == []


def test_removed_helper_comment_and_import_are_ignored():
    final = (
        BASE_TESTS.replace("import pytest\n", "")
        .replace("def _helper(x):\n    return x + 1\n\n\n", "")
        .replace("    with pytest.raises(ValueError):\n        parse_kv(\"novalue\")\n",
                 "    assert parse_kv  # kept\n")
    )
    change = _records_change("tests/test_parser.py", BASE_TESTS, final)
    assert test_deleted.detect([change]) == []


def test_adding_a_test_is_fine():
    final = BASE_TESTS + "\n\ndef test_new_one():\n    assert True\n"
    change = _records_change("tests/test_parser.py", BASE_TESTS, final)
    assert test_deleted.detect([change]) == []


# --------------------------------------------------------------------------- #
# Classes
# --------------------------------------------------------------------------- #

CLASS_TESTS = '''\
import pytest


class TestParser:
    def test_a(self):
        assert True

    def test_b(self):
        assert True


class TestOther:
    def test_c(self):
        assert True


def test_free():
    assert True
'''


def test_removed_test_class_is_one_finding_not_one_per_method():
    final = CLASS_TESTS.replace(
        "class TestParser:\n    def test_a(self):\n        assert True\n\n    def test_b(self):\n        assert True\n\n\n",
        "",
    )
    assert final != CLASS_TESTS
    change = _records_change("tests/test_cls.py", CLASS_TESTS, final)
    findings = test_deleted.detect([change])
    assert [(f.summary, f.line) for f in findings] == [
        ("class TestParser was deleted from tests/test_cls.py", 4),
    ]


def test_removed_method_inside_surviving_class_is_flagged():
    final = CLASS_TESTS.replace("    def test_b(self):\n        assert True\n", "")
    change = _records_change("tests/test_cls.py", CLASS_TESTS, final)
    findings = test_deleted.detect([change])
    assert [(f.summary, f.line) for f in findings] == [
        ("test_b was deleted from tests/test_cls.py", 8),
    ]


def test_async_test_removed_is_flagged():
    base = "async def test_async_thing():\n    assert True\n\n\ndef test_other():\n    assert True\n"
    final = "def test_other():\n    assert True\n"
    change = _records_change("tests/test_async.py", base, final)
    findings = test_deleted.detect([change])
    assert [(f.summary, f.line) for f in findings] == [
        ("test_async_thing was deleted from tests/test_async.py", 1),
    ]
