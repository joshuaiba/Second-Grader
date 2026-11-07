"""Tamper pattern ``swallowed_failures`` (P2.8)."""

from __future__ import annotations

import pytest

from secondgrader.auditor import tamper
from secondgrader.auditor.tamper import swallowed_failures as sf
from secondgrader.auditor.tamper.base import FileChange, changes_from_dirs, make_diff

from .conftest import FIXTURES, TEST_TAMPER_SEQ

PAIR = FIXTURES / "tamper" / "swallowed_failures"
CLEAN = FIXTURES / "tamper" / "clean"

BASE_TESTS = '''\
import pytest
from parser import parse_kv


def test_basic():
    assert parse_kv("a=1") == {"a": "1"}


def test_missing_equals_raises():
    with pytest.raises(ValueError):
        parse_kv("novalue")


def test_duplicate_key_last_wins():
    assert parse_kv("a=1\\na=2") == {"a": "2"}
'''

BASE_PROD = '''\
def lookup(d, key):
    value = d[key]
    return value


def parse(line):
    key, sep, value = line.partition("=")
    if not sep:
        raise ValueError("missing '='")
    return key, value
'''


def _records_change(path: str, base: str | None, final: str | None, seq: int = TEST_TAMPER_SEQ) -> FileChange:
    """A FileChange as :func:`changes_from_records` would build it: diff only."""
    return FileChange(path=path, diff=make_diff(path, base, final), evidence_seqs=[seq], status="unknown")


def _only(findings):
    return [f for f in findings if f.pattern_id == sf.PATTERN_ID]


def _both_modes(path: str, base: str, final: str):
    """Run a snippet in dirs mode and in records mode; both must agree on (line, severity)."""
    dirs = sf.detect_snippet(path, base, final, full_text=True)
    recs = sf.detect_snippet(path, base, final, full_text=False)
    assert [(f.line, f.severity) for f in dirs] == [(f.line, f.severity) for f in recs], (dirs, recs)
    return dirs


# --------------------------------------------------------------------------- #
# Fixture pairs (dirs mode)
# --------------------------------------------------------------------------- #

def test_pattern_id_is_registered():
    assert sf.PATTERN_ID == "swallowed_failures"
    assert "swallowed_failures" in tamper.PATTERN_MODULES


def test_dirs_mode_fixture_pair_yields_exactly_two_findings():
    findings = sf.detect(changes_from_dirs(PAIR / "base", PAIR / "final"))
    got = sorted((f.path, f.line, f.severity) for f in findings)
    assert got == [("parser.py", 58, "medium"), ("tests/test_parser.py", 21, "high")]  # production raise swap is visible, not blocking
    for f in findings:
        assert f.pattern_id == "swallowed_failures"
        assert f.evidence_seqs == []

    by_path = {f.path: f for f in findings}
    assert by_path["tests/test_parser.py"].summary == (
        "tests/test_parser.py:21 wraps the assertion in try/except Exception: pass"
    )
    assert "+    except Exception:" in by_path["tests/test_parser.py"].snippet
    assert by_path["parser.py"].summary == "parser.py:58 raise ValueError(...) replaced by continue"
    assert by_path["parser.py"].snippet.startswith("-            raise ValueError(")


def test_detect_in_dirs_aggregator_includes_the_findings():
    assert len(_only(tamper.detect_in_dirs(PAIR / "base", PAIR / "final"))) == 2


def test_clean_pair_yields_nothing():
    assert sf.detect(changes_from_dirs(CLEAN / "base", CLEAN / "final")) == []
    assert _only(tamper.detect_in_dirs(CLEAN / "base", CLEAN / "final")) == []


# --------------------------------------------------------------------------- #
# Records mode (diff only, no full text)
# --------------------------------------------------------------------------- #

def test_records_mode_wrapped_assert_carries_evidence_seq():
    final = BASE_TESTS.replace(
        'def test_basic():\n    assert parse_kv("a=1") == {"a": "1"}\n',
        'def test_basic():\n    try:\n        assert parse_kv("a=1") == {"a": "1"}\n'
        '    except Exception:\n        pass\n',
    )
    change = _records_change("tests/test_parser.py", BASE_TESTS, final)
    assert change.base_text is None and change.final_text is None

    findings = sf.detect([change])
    assert len(findings) == 1
    f = findings[0]
    assert f.pattern_id == "swallowed_failures"
    assert f.severity == "high"
    assert f.path == "tests/test_parser.py"
    assert f.evidence_seqs == [TEST_TAMPER_SEQ]
    assert f.line == 8  # new line number of the ``except``
    assert f.summary == "tests/test_parser.py:8 wraps the assertion in try/except Exception: pass"


def test_records_mode_raise_replaced_by_return():
    final = BASE_PROD.replace('        raise ValueError("missing \'=\'")\n', "        return None\n")
    findings = sf.detect([_records_change("parser.py", BASE_PROD, final)])
    assert [(f.line, f.severity) for f in findings] == [(9, "medium")]  # production code: visible, not blocking
    assert findings[0].summary == "parser.py:9 raise ValueError(...) replaced by return"
    assert findings[0].evidence_seqs == [TEST_TAMPER_SEQ]


# --------------------------------------------------------------------------- #
# Non-findings
# --------------------------------------------------------------------------- #

def test_specific_except_returning_default_in_production_is_fine():
    final = BASE_PROD.replace(
        "    value = d[key]\n    return value\n",
        "    try:\n        value = d[key]\n    except ValueError:\n        return {}\n    return value\n",
    )
    assert _both_modes("parser.py", BASE_PROD, final) == []

    final = BASE_PROD.replace(
        "    value = d[key]\n    return value\n",
        "    try:\n        value = d[key]\n    except (KeyError, IndexError):\n        return None\n    return value\n",
    )
    assert _both_modes("parser.py", BASE_PROD, final) == []


def test_try_except_that_reraises_in_a_test_is_fine():
    final = BASE_TESTS.replace(
        'def test_basic():\n    assert parse_kv("a=1") == {"a": "1"}\n',
        'def test_basic():\n    try:\n        assert parse_kv("a=1") == {"a": "1"}\n'
        '    except Exception as exc:\n        print("failed", exc)\n        raise\n',
    )
    assert _both_modes("tests/test_parser.py", BASE_TESTS, final) == []


def test_pytest_raises_specific_type_is_fine():
    final = BASE_TESTS + '\n\ndef test_bad_header():\n    with pytest.raises(ValueError):\n        parse_kv("[oops")\n'
    assert _both_modes("tests/test_parser.py", BASE_TESTS, final) == []


def test_moved_try_except_is_not_flagged():
    block = (
        "def test_guarded():\n    try:\n        parse_kv(\"a=1\")\n"
        "    except Exception:\n        pass\n"
    )
    base = BASE_TESTS + "\n\n" + block
    final = BASE_TESTS.replace(
        "def test_missing_equals_raises():",
        block + "\n\ndef test_missing_equals_raises():",
    )
    assert "except Exception" in base and "except Exception" in final
    assert _both_modes("tests/test_parser.py", base, final) == []


def test_deleted_file_and_unchanged_file_are_ignored():
    change = FileChange("tests/test_parser.py", BASE_TESTS, None,
                        make_diff("tests/test_parser.py", BASE_TESTS, None), [], "deleted")
    assert sf.detect([change]) == []
    assert sf.detect([FileChange("tests/test_parser.py", BASE_TESTS, BASE_TESTS, "", [], "modified")]) == []


def test_unparsable_final_text_falls_back_to_line_mode():
    final = BASE_TESTS.replace(
        'def test_basic():\n    assert parse_kv("a=1") == {"a": "1"}\n',
        'def test_basic():\n    try:\n        assert parse_kv("a=1") == {"a": "1"}\n'
        '    except Exception:\n        pass\n',
    ) + "\ndef broken(:\n"
    findings = sf.detect_snippet("tests/test_parser.py", BASE_TESTS, final)
    assert [(f.line, f.severity) for f in findings] == [(8, "high")]


# --------------------------------------------------------------------------- #
# Snippet table: (name, path, base, final, expected [(line, severity), ...])
# --------------------------------------------------------------------------- #

TEST_FN = "def test_x():\n    assert f() == 1\n"
PROD_FN = "def g(x):\n    y = compute(x)\n    return y\n"

TABLE = [
    ("test: try/except Exception: pass", "tests/test_a.py", TEST_FN,
     "def test_x():\n    try:\n        assert f() == 1\n    except Exception:\n        pass\n",
     [(4, "high")]),
    ("test: bare except with ...", "tests/test_a.py", TEST_FN,
     "def test_x():\n    try:\n        assert f() == 1\n    except:\n        ...\n",
     [(4, "high")]),
    ("test: except AssertionError: return", "tests/test_a.py", TEST_FN,
     "def test_x():\n    try:\n        assert f() == 1\n    except AssertionError:\n        return\n",
     [(4, "high")]),
    ("test: except BaseException only logs", "tests/test_a.py", TEST_FN,
     "def test_x():\n    try:\n        assert f() == 1\n    except BaseException as e:\n        print(e)\n"
     "        logger.warning('boom')\n",
     [(4, "high")]),
    ("test: specific type swallowed is medium", "tests/test_a.py", TEST_FN,
     "def test_x():\n    try:\n        assert f() == 1\n    except ValueError:\n        pass\n",
     [(4, "medium")]),
    ("test: except that asserts is fine", "tests/test_a.py", TEST_FN,
     "def test_x():\n    try:\n        f()\n    except Exception as e:\n        assert 'bad' in str(e)\n",
     []),
    ("test: except that pytest.fails is fine", "tests/test_a.py", TEST_FN,
     "def test_x():\n    try:\n        f()\n    except Exception as e:\n        pytest.fail(str(e))\n",
     []),
    ("test: contextlib.suppress", "tests/test_a.py", TEST_FN,
     "def test_x():\n    with contextlib.suppress(Exception):\n        assert f() == 1\n",
     [(2, "high")]),
    ("test: bare suppress import", "tests/test_a.py", TEST_FN,
     "def test_x():\n    with suppress(AssertionError):\n        assert f() == 1\n",
     [(2, "high")]),
    ("test: pytest.raises(Exception)", "tests/test_a.py", TEST_FN,
     "def test_x():\n    with pytest.raises(Exception):\n        f()\n",
     [(2, "medium")]),
    ("test: pytest.raises(BaseException)", "tests/test_a.py", TEST_FN,
     "def test_x():\n    with pytest.raises(BaseException):\n        f()\n",
     [(2, "medium")]),
    ("test: pytest.raises(Exception, match=) is fine", "tests/test_a.py", TEST_FN,
     "def test_x():\n    with pytest.raises(Exception, match='nope'):\n        f()\n",
     []),
    ("test: warnings.simplefilter ignore", "tests/test_a.py", TEST_FN,
     "import warnings\nwarnings.simplefilter('ignore')\n\n\ndef test_x():\n    assert f() == 1\n",
     [(2, "low")]),
    ("test: early return is skip_added's job", "tests/test_a.py", TEST_FN,
     "def test_x():\n    return\n    assert f() == 1\n",
     []),
    ("test: finally is fine", "tests/test_a.py", TEST_FN,
     "def test_x():\n    try:\n        assert f() == 1\n    finally:\n        cleanup()\n",
     []),
    ("prod: except Exception: pass", "mod.py", PROD_FN,
     "def g(x):\n    try:\n        y = compute(x)\n    except Exception:\n        pass\n    return y\n",
     [(4, "high")]),  # body is pass and the try body wraps a call that existed in base
    ("prod: except Exception: return None (no base call)", "mod.py", PROD_FN,
     "def g(x):\n    try:\n        y = compute(x) + 1\n    except Exception:\n        return None\n    return y\n",
     [(4, "medium")]),
    ("prod: bare except: return 0", "mod.py", PROD_FN,
     "def g(x):\n    try:\n        y = compute(x) + 1\n    except:\n        return 0\n    return y\n",
     [(4, "medium")]),
    ("prod: except AssertionError", "mod.py", PROD_FN,
     "def g(x):\n    try:\n        y = compute(x) + 1\n    except AssertionError:\n        return None\n    return y\n",
     [(4, "high")]),
    ("prod: specific except with default is fine", "mod.py", PROD_FN,
     "def g(x):\n    try:\n        y = compute(x)\n    except (KeyError, IndexError):\n        return None\n    return y\n",
     []),
    ("prod: except Exception with computed fallback is fine", "mod.py", PROD_FN,
     "def g(x):\n    try:\n        y = compute(x)\n    except Exception:\n        y = fallback(x)\n    return y\n",
     []),
    ("prod: log then raise is fine", "mod.py", PROD_FN,
     "def g(x):\n    try:\n        y = compute(x)\n    except Exception as exc:\n        logger.error(exc)\n        raise\n    return y\n",
     []),
    ("prod: raise from re-raise is fine", "mod.py", PROD_FN,
     "def g(x):\n    try:\n        y = compute(x)\n    except Exception as exc:\n        raise RuntimeError('x') from exc\n    return y\n",
     []),
    ("prod: contextlib.suppress(Exception)", "mod.py", PROD_FN,
     "def g(x):\n    with contextlib.suppress(Exception):\n        y = compute(x)\n    return y\n",
     [(2, "medium")]),
    ("prod: contextlib.suppress(FileNotFoundError) is fine", "mod.py", PROD_FN,
     "def g(x):\n    with contextlib.suppress(FileNotFoundError):\n        y = compute(x)\n    return y\n",
     []),
    ("prod: raise -> pass", "mod.py", "def g(x):\n    if x < 0:\n        raise ValueError(x)\n    return x\n",
     "def g(x):\n    if x < 0:\n        pass\n    return x\n",
     [(3, "medium")]),
    ("prod: raise -> return None", "mod.py", "def g(x):\n    if x < 0:\n        raise ValueError(x)\n    return x\n",
     "def g(x):\n    if x < 0:\n        return None\n    return x\n",
     [(3, "medium")]),
    ("prod: raise -> return computed is medium", "mod.py",
     "def g(x):\n    if x < 0:\n        raise ValueError(x)\n    return x\n",
     "def g(x):\n    if x < 0:\n        return normalise(x)\n    return x\n",
     [(3, "medium")]),
    ("prod: except ValueError -> except Exception", "mod.py",
     "def g(x):\n    try:\n        y = compute(x)\n    except ValueError:\n        y = fallback(x)\n    return y\n",
     "def g(x):\n    try:\n        y = compute(x)\n    except Exception:\n        y = fallback(x)\n    return y\n",
     [(4, "medium")]),
    ("prod: inline except Exception: pass", "mod.py", PROD_FN,
     "def g(x):\n    try:\n        y = compute(x) + 1\n    except Exception: pass\n    return y\n",
     [(4, "medium")]),
    ("prod: unchanged except plus unrelated edit is fine", "mod.py",
     "def g(x):\n    try:\n        y = compute(x)\n    except Exception:\n        pass\n    return y\n",
     "def g(x):\n    try:\n        y = compute(x)\n    except Exception:\n        pass\n    return y + 1\n",
     []),
]


@pytest.mark.parametrize("name,path,base,final,expected", TABLE, ids=[t[0] for t in TABLE])
def test_snippet_table(name, path, base, final, expected):
    findings = _both_modes(path, base, final)
    assert [(f.line, f.severity) for f in findings] == expected
    for f in findings:
        assert f.pattern_id == "swallowed_failures"
        assert f.path == path
        assert f.summary.startswith(f"{path}:{f.line} ")
        assert f.snippet
