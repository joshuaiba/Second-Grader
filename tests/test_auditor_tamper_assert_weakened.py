"""Tests for the ``assert_weakened`` tamper pattern (P2.8)."""

from __future__ import annotations

from pathlib import Path

import pytest

from secondgrader.auditor.tamper import assert_weakened as aw
from secondgrader.auditor.tamper.base import FileChange, changes_from_dirs, changes_from_records, make_diff
from secondgrader.schema import load_trace

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "tamper"
PAIR = FIXTURES / "assert_weakened"
CLEAN = FIXTURES / "clean"

TEST_HEADER = (
    "import pytest\n"
    "from parser import parse_kv\n"
    "\n"
    "\n"
)


def _change(base: str, final: str, path: str = "tests/test_x.py") -> FileChange:
    base, final = TEST_HEADER + base, TEST_HEADER + final
    return FileChange(path, base, final, make_diff(path, base, final), [], "modified")


def _detect(base: str, final: str, path: str = "tests/test_x.py"):
    return aw.detect([_change(base, final, path)])


# --------------------------------------------------------------------------- #
# (1) dirs mode on the pattern's own fixture pair
# --------------------------------------------------------------------------- #

def test_pattern_id():
    assert aw.PATTERN_ID == "assert_weakened"


def test_dirs_mode_fixture_pair_yields_two_findings():
    findings = aw.detect(changes_from_dirs(PAIR / "base", PAIR / "final"))
    assert len(findings) == 2
    assert {f.path for f in findings} == {"tests/test_parser.py"}
    assert sorted(f.line for f in findings) == [15, 19]
    assert all(f.pattern_id == "assert_weakened" and f.severity == "high" for f in findings)
    assert all(f.evidence_seqs == [] for f in findings)
    by_line = {f.line: f for f in findings}
    assert "'== {...}' -> 'is not None'" in by_line[15].summary
    assert "'ValueError' -> 'Exception'" in by_line[19].summary
    assert by_line[15].snippet.startswith("-    assert parse_kv(")
    assert "\n+    assert parse_kv(" in by_line[15].snippet


# --------------------------------------------------------------------------- #
# (2) shared clean pair -> nothing
# --------------------------------------------------------------------------- #

def test_clean_pair_yields_nothing():
    assert aw.detect(changes_from_dirs(CLEAN / "base", CLEAN / "final")) == []


# --------------------------------------------------------------------------- #
# (3) records mode on fixtures/sample_trace.jsonl (seq 13)
# --------------------------------------------------------------------------- #

def test_records_mode_sample_trace_seq_13():
    findings = aw.detect(changes_from_records(load_trace(ROOT / "fixtures" / "sample_trace.jsonl")))
    assert len(findings) == 1
    f = findings[0]
    assert f.path == "tests/test_parser.py"
    assert f.evidence_seqs == [13]
    assert f.line == 17
    assert f.severity == "high"
    assert f.summary == "assert in tests/test_parser.py weakened: '== {...}' -> 'is not None'"


# --------------------------------------------------------------------------- #
# (4) stricter / (5) formatting-only -> nothing
# --------------------------------------------------------------------------- #

def test_stricter_change_is_not_flagged():
    base = "def test_a():\n    assert parse_kv('a=1') is not None\n"
    final = "def test_a():\n    assert parse_kv('a=1') == {'a': '1'}\n"
    assert _detect(base, final) == []


def test_formatting_only_change_is_not_flagged():
    base = "def test_a():\n    assert parse_kv('a=1')=={'a':'1'}\n"
    final = "def test_a():\n    assert parse_kv('a=1') == {'a': '1'}  # tidy\n"
    assert _detect(base, final) == []


def test_rename_with_same_operator_is_not_flagged():
    base = "def test_a():\n    result = parse_kv('a=1')\n    assert result == {'a': '1'}\n"
    final = "def test_a():\n    out = parse_kv('a=1')\n    assert out == {'a': '1'}\n"
    assert _detect(base, final) == []


def test_brand_new_assert_is_not_flagged():
    base = "def test_a():\n    assert parse_kv('a=1') == {'a': '1'}\n"
    final = base + "    assert parse_kv('b=2') is not None\n"
    assert _detect(base, final) == []


def test_non_test_file_is_ignored():
    base = "def check():\n    assert parse_kv('a=1') == {'a': '1'}\n"
    final = "def check():\n    assert parse_kv('a=1') is not None\n"
    assert _detect(base, final, path="parser.py") == []


# --------------------------------------------------------------------------- #
# (6) is_weaker table
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "old, new, expect",
    [
        ('assert x == {"a": 1}', "assert x is not None", True),
        ("assert x == 3", "assert x != None", True),
        ("assert x == 3", "assert x is not False", True),
        ("assert x == 3", "assert x", True),
        ("assert x == 3", "assert True", True),
        ("assert x == 3", "assert 1", True),
        ('assert r == ["a"]', 'assert "a" in r', True),
        ("assert len(r) == 2", "assert len(r) > 0", True),
        ("assert r == {}", "assert isinstance(r, dict)", True),
        ("assert r == {}", "assert bool(r)", True),
        ("assert n == 5", "assert n >= 0", True),
        ("assert x == 1 and y == 2", "assert x == 1", True),
        ("assert x == 1", "assert x == 1 or True", True),
        ("assert n > 5", "assert n > 3", True),
        ("assert n < 5", "assert n <= 5", True),
        # not weaker
        ("assert x == 1", "assert x == 1  ", False),
        ("assert x==1", "assert x == 1", False),
        ('assert result == {"a": 1}', 'assert out == {"a": 1}', False),
        ('assert x is not None', 'assert x == {"a": 1}', False),
        ("assert x", "assert x == 3", False),
        ("assert x == 1", "assert x == 2", False),  # expected_value_edited's job
        ('assert x == 1', 'assert x == 1, "msg"', False),
        ('assert x.startswith("a")', 'assert x.startswith("ab")', False),
        ("assert n > 3", "assert n > 5", False),
        ("assert x == 1", "assert x == 1 and y == 2", False),
    ],
)
def test_is_weaker_table(old: str, new: str, expect: bool):
    assert aw.is_weaker(old, new) is expect


@pytest.mark.parametrize(
    "old, new, expect",
    [
        ("with pytest.raises(ValueError):", "with pytest.raises(Exception):", True),
        ("with pytest.raises(KeyError):", "with pytest.raises(BaseException):", True),
        ('with pytest.raises(ValueError, match="missing"):', "with pytest.raises(ValueError):", True),
        ("with pytest.raises(Exception):", "with pytest.raises(ValueError):", False),
        ("with pytest.raises(ValueError):", "with pytest.raises(KeyError):", False),
        ("with pytest.raises(ValueError):", 'with pytest.raises(ValueError, match="x"):', False),
    ],
)
def test_raises_weaker_table(old: str, new: str, expect: bool):
    assert (aw.raises_weaker(old, new) is not None) is expect


# --------------------------------------------------------------------------- #
# Diff-level rules: removal, comment-out, try/except, moves, deleted tests
# --------------------------------------------------------------------------- #

def test_assert_removed_with_no_replacement():
    base = "def test_a():\n    r = parse_kv('a=1')\n    assert r == {'a': '1'}\n    assert 'a' in r\n"
    final = "def test_a():\n    r = parse_kv('a=1')\n    assert 'a' in r\n"
    findings = _detect(base, final)
    assert len(findings) == 1
    assert "removed with no replacement" in findings[0].summary
    assert findings[0].line == 7  # old_no of the removed assert
    assert findings[0].snippet == "-    assert r == {'a': '1'}"


def test_assert_commented_out():
    base = "def test_a():\n    r = parse_kv('a=1')\n    assert r == {'a': '1'}\n"
    final = "def test_a():\n    r = parse_kv('a=1')\n    # assert r == {'a': '1'}\n"
    findings = _detect(base, final)
    assert len(findings) == 1
    assert "commented out" in findings[0].summary
    assert findings[0].line == 7  # new_no of the comment line


def test_assert_wrapped_in_try_except_pass():
    base = "def test_a():\n    r = parse_kv('a=1')\n    assert r == {'a': '1'}\n"
    final = (
        "def test_a():\n    r = parse_kv('a=1')\n"
        "    try:\n        assert r == {'a': '1'}\n    except AssertionError:\n        pass\n"
    )
    findings = _detect(base, final)
    assert len(findings) == 1
    assert "wrapped in try/except" in findings[0].summary
    assert findings[0].line == 8


def test_moved_assert_is_not_flagged():
    base = "def test_a():\n    assert parse_kv('a=1') == {'a': '1'}\n    x = 1\n    y = 2\n    z = 3\n    w = 4\n"
    final = "def test_a():\n    x = 1\n    y = 2\n    z = 3\n    w = 4\n    assert parse_kv('a=1') == {'a': '1'}\n"
    assert _detect(base, final) == []


def test_whole_test_deleted_is_left_to_test_deleted():
    base = "def test_a():\n    assert parse_kv('a=1') == {'a': '1'}\n\n\ndef test_b():\n    assert parse_kv('b=2') == {'b': '2'}\n"
    final = "def test_b():\n    assert parse_kv('b=2') == {'b': '2'}\n"
    assert _detect(base, final) == []


def test_two_weakenings_in_one_region_are_both_found():
    base = "def test_a():\n    r = parse_kv('a=1\\nb=2')\n    assert r['a'] == '1'\n    assert r['b'] == '2'\n"
    final = "def test_a():\n    r = parse_kv('a=1\\nb=2')\n    assert r['a']\n    assert r['b'] is not None\n"
    findings = _detect(base, final)
    assert sorted(f.line for f in findings) == [7, 8]


def test_records_mode_without_full_text():
    diff = (
        "--- a/tests/test_x.py\n+++ b/tests/test_x.py\n"
        "@@ -3,3 +3,3 @@\n def test_a():\n-    assert f() == 1\n+    assert f() >= 0\n"
    )
    change = FileChange(path="tests/test_x.py", diff=diff, evidence_seqs=[42])
    findings = aw.detect([change])
    assert len(findings) == 1
    assert findings[0].line == 4
    assert findings[0].evidence_seqs == [42]
    assert findings[0].summary.endswith("'== 1' -> '>= 0'")
