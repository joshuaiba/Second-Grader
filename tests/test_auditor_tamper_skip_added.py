"""Tamper pattern ``skip_added`` (P2.8)."""

from __future__ import annotations

import pytest

from secondgrader.auditor.tamper import base
from secondgrader.auditor.tamper import skip_added
from secondgrader.auditor.types import TamperFinding

from .conftest import FIXTURES

TAMPER = FIXTURES / "tamper"
PAIR = TAMPER / "skip_added"
CLEAN = TAMPER / "clean"

TEST_PATH = "tests/test_x.py"


def _records_change(base_src: str, final_src: str, path: str = TEST_PATH,
                    seq: int = 21) -> base.FileChange:
    """A diff-only FileChange, the shape :func:`base.changes_from_records` builds."""
    return base.FileChange(path=path, diff=base.make_diff(path, base_src, final_src),
                           evidence_seqs=[seq], status="unknown")


def _dirs_change(base_src: str, final_src: str, path: str = TEST_PATH) -> base.FileChange:
    return base.FileChange(path, base_src, final_src, base.make_diff(path, base_src, final_src),
                           [], "modified")


# --------------------------------------------------------------------------- #
# 1. fixture pair, dirs mode
# --------------------------------------------------------------------------- #

def test_pattern_id():
    assert skip_added.PATTERN_ID == "skip_added"


def test_dirs_mode_on_fixture_pair_yields_two_findings():
    findings = skip_added.detect(base.changes_from_dirs(PAIR / "base", PAIR / "final"))
    assert all(isinstance(f, TamperFinding) for f in findings)
    assert [(f.path, f.line, f.severity) for f in findings] == [
        ("tests/test_parser.py", 14, "high"),
        ("tests/test_parser.py", 20, "high"),
    ]
    assert all(f.pattern_id == "skip_added" for f in findings)
    assert all(f.evidence_seqs == [] for f in findings)
    assert "@pytest.mark.skip" in findings[0].summary
    assert "pytest.skip" in findings[1].summary
    assert findings[0].snippet.startswith("+")


# --------------------------------------------------------------------------- #
# 2. clean pair
# --------------------------------------------------------------------------- #

def test_clean_pair_yields_nothing():
    assert skip_added.detect(base.changes_from_dirs(CLEAN / "base", CLEAN / "final")) == []


# --------------------------------------------------------------------------- #
# 3. records mode: diff only, evidence seq carried
# --------------------------------------------------------------------------- #

BASE_SRC = """import pytest


def test_a():
    assert 1 == 1


def test_b():
    assert 2 == 2
"""


def test_records_mode_carries_evidence_seq():
    final = BASE_SRC.replace("def test_b():", '@pytest.mark.skip(reason="later")\ndef test_b():')
    change = _records_change(BASE_SRC, final)
    assert change.base_text is None and change.final_text is None
    findings = skip_added.detect([change])
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence_seqs == [21]
    assert f.path == TEST_PATH
    assert f.line == 8  # new_no of the inserted decorator line
    assert f.severity == "high"


def test_records_mode_skip_call_inside_body():
    final = BASE_SRC.replace("def test_b():\n", 'def test_b():\n    pytest.skip("todo")\n')
    findings = skip_added.detect([_records_change(BASE_SRC, final)])
    assert [f.line for f in findings] == [9]


# --------------------------------------------------------------------------- #
# 4. a marker that merely moved
# --------------------------------------------------------------------------- #

MOVED_BASE = """import pytest


@pytest.mark.skip(reason="flaky")
def test_a():
    assert 1 == 1


def test_b():
    assert 2 == 2
"""

MOVED_FINAL = """import pytest


def test_b():
    assert 2 == 2


@pytest.mark.skip(reason="flaky")
def test_a():
    assert 1 == 1
"""


def test_moved_marker_is_not_flagged_in_either_mode():
    assert skip_added.detect([_records_change(MOVED_BASE, MOVED_FINAL)]) == []
    assert skip_added.detect([_dirs_change(MOVED_BASE, MOVED_FINAL)]) == []


def test_moved_marker_plus_a_genuinely_new_one_flags_only_the_new_one():
    final = MOVED_FINAL.replace("def test_b():", "@pytest.mark.skip\ndef test_b():")
    findings = skip_added.detect([_records_change(MOVED_BASE, final)])
    assert len(findings) == 1
    assert findings[0].line == 4


# --------------------------------------------------------------------------- #
# 5. non-skip markers are ignored
# --------------------------------------------------------------------------- #

def test_slow_marker_is_not_flagged():
    final = BASE_SRC.replace("def test_b():", "@pytest.mark.slow\ndef test_b():")
    assert skip_added.detect([_records_change(BASE_SRC, final)]) == []
    assert skip_added.detect([_dirs_change(BASE_SRC, final)]) == []


def test_skip_in_non_test_file_is_ignored():
    final = BASE_SRC.replace("def test_b():", "@pytest.mark.skip\ndef test_b():")
    assert skip_added.detect([_records_change(BASE_SRC, final, path="parser.py")]) == []


def test_skip_in_comment_or_string_is_ignored():
    final = BASE_SRC.replace(
        "    assert 2 == 2",
        '    # TODO: pytest.skip("x") once fixed\n    assert "pytest.mark.skip" != 2',
    )
    assert skip_added.detect([_records_change(BASE_SRC, final)]) == []


# --------------------------------------------------------------------------- #
# 6. rename to _test_x
# --------------------------------------------------------------------------- #

def test_rename_to_underscore_test_is_one_finding():
    final = BASE_SRC.replace("def test_b():", "def _test_b():")
    findings = skip_added.detect([_records_change(BASE_SRC, final)])
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high"
    assert f.summary == "test_b renamed to _test_b (no longer collected)"
    assert f.line == 8
    assert f.evidence_seqs == [21]


@pytest.mark.parametrize("new_name", ["xtest_b", "disabled_test_b", "__test_b"])
def test_other_disabling_prefixes_are_renames(new_name):
    final = BASE_SRC.replace("def test_b():", f"def {new_name}():")
    findings = skip_added.detect([_dirs_change(BASE_SRC, final)])
    assert [f.summary for f in findings] == [f"test_b renamed to {new_name} (no longer collected)"]


def test_plain_rename_between_test_names_is_not_flagged():
    final = BASE_SRC.replace("def test_b():", "def test_b_renamed():")
    assert skip_added.detect([_dirs_change(BASE_SRC, final)]) == []


# --------------------------------------------------------------------------- #
# 7. line table through the exposed helper
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("@pytest.mark.skip", True),
        ('@pytest.mark.skip(reason="flaky")', True),
        ("@pytest.mark.skipif(sys.platform == 'win32', reason='posix only')", True),
        ("@pytest.mark.xfail(strict=True)", True),
        ("@unittest.skip('nope')", True),
        ("@unittest.skipIf(True, 'x')", True),
        ("@unittest.skipUnless(False, 'x')", True),
        ("@skip('bare')", True),
        ("@skipif(True)", True),
        ("@xfail", True),
        ('    pytest.skip("todo")', True),
        ("    pytest.xfail('known bad')", True),
        ("    np = pytest.importorskip('numpy')", True),
        ("        self.skipTest('no db')", True),
        ("    raise unittest.SkipTest('x')", True),
        ("    raise SkipTest", True),
        ("    if True: return", True),
        ("pytestmark = pytest.mark.skip(reason='all')", True),
        ("    item.add_marker(pytest.mark.skip(reason='ci'))", True),
        # not skips
        ("@pytest.mark.slow", False),
        ("@pytest.mark.parametrize('x', [1, 2])", False),
        ("@pytest.mark.skippy", False),
        ("    # pytest.skip('x') was here", False),
        ('    assert "pytest.skip" in out', False),
        ("    skipped = compute()", False),
        ("    return value", False),
        ("def test_skip_logic():", False),
        ("    if cond: return", False),
        ("", False),
    ],
)
def test_is_skip_line_table(line, expected):
    assert skip_added.is_skip_line(line) is expected


# --------------------------------------------------------------------------- #
# extra: early return, xfail on new vs existing test, conftest
# --------------------------------------------------------------------------- #

def test_early_return_as_first_statement_is_flagged():
    final = BASE_SRC.replace("def test_b():\n", "def test_b():\n    return\n")
    findings = skip_added.detect([_dirs_change(BASE_SRC, final)])
    assert [(f.line, f.severity) for f in findings] == [(9, "high")]
    assert "early return" in findings[0].summary


def test_return_after_other_statements_is_not_flagged():
    final = BASE_SRC.replace("    assert 2 == 2\n", "    assert 2 == 2\n    return\n")
    assert skip_added.detect([_dirs_change(BASE_SRC, final)]) == []


def test_xfail_on_new_test_is_fine_in_dirs_mode_but_medium_in_records_mode():
    final = BASE_SRC + "\n\n@pytest.mark.xfail(strict=True)\ndef test_c():\n    assert 0\n"
    assert skip_added.detect([_dirs_change(BASE_SRC, final)]) == []
    findings = skip_added.detect([_records_change(BASE_SRC, final)])
    assert [f.severity for f in findings] == ["medium"]
    assert "may be new" in findings[0].summary


def test_xfail_on_existing_test_is_high():
    final = BASE_SRC.replace("def test_b():", "@pytest.mark.xfail\ndef test_b():")
    for change in (_dirs_change(BASE_SRC, final), _records_change(BASE_SRC, final)):
        findings = skip_added.detect([change])
        assert [(f.line, f.severity) for f in findings] == [(8, "high")]
        assert "pre-existing test test_b" in findings[0].summary


def test_conftest_collection_hook_adding_skip_is_medium():
    conftest_base = "import pytest\n\n\ndef pytest_collection_modifyitems(items):\n    pass\n"
    conftest_final = conftest_base.replace(
        "    pass\n",
        "    for item in items:\n        item.add_marker(pytest.mark.skip(reason='ci'))\n",
    )
    findings = skip_added.detect([_records_change(conftest_base, conftest_final, path="conftest.py")])
    assert [(f.line, f.severity) for f in findings] == [(6, "medium")]
    assert "conftest.py" in findings[0].summary


def test_detect_all_includes_this_pattern():
    from secondgrader.auditor import tamper

    found = tamper.detect_in_dirs(PAIR / "base", PAIR / "final")
    ours = [f for f in found if f.pattern_id == "skip_added"]
    assert [f.line for f in ours] == [14, 20]
