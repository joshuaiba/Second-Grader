"""Tamper pattern ``config_tamper``: test-configuration tampering (P2.8)."""

from __future__ import annotations

import pytest

from secondgrader.auditor.tamper import base
from secondgrader.auditor.tamper import config_tamper as ct
from secondgrader.auditor.tamper.base import FileChange, changes_from_dirs
from tests.conftest import FIXTURES

PAIR = FIXTURES / "tamper" / "config_tamper"
CLEAN = FIXTURES / "tamper" / "clean"

DEMO_INI = "[pytest]\ntestpaths = tests\nmarkers =\n    slow: slow end-to-end check\n"


def _summaries(findings):
    return [f.summary for f in findings]


# --------------------------------------------------------------------------- #
# Fixture pairs
# --------------------------------------------------------------------------- #

def test_dirs_mode_on_tampered_pair():
    findings = ct.detect(changes_from_dirs(PAIR / "base", PAIR / "final"))
    assert len(findings) == 3
    assert all(f.pattern_id == "config_tamper" and f.severity == "high" for f in findings)
    assert all(f.evidence_seqs == [] for f in findings)

    ini = [f for f in findings if f.path == "pytest.ini"]
    assert len(ini) == 2  # one finding per offending addopts option
    assert all(f.line == 3 for f in ini)
    assert any('-m "not slow"' in f.summary for f in ini)
    assert any("--ignore=tests/test_parser.py" in f.summary for f in ini)
    assert all("addopts" in f.snippet for f in ini)

    (conf,) = [f for f in findings if f.path == "tests/conftest.py"]
    assert conf.line == 4
    assert "pytest_collection_modifyitems" in conf.summary
    # The add_marker(skip) line inside the hook body is covered by the hook finding.
    assert not any("skip applied" in s for s in _summaries(findings))


def test_clean_pair_is_quiet():
    assert ct.detect(changes_from_dirs(CLEAN / "base", CLEAN / "final")) == []


def test_clean_pair_with_unchanged_pytest_ini_is_quiet(tmp_path):
    import shutil

    for side in ("base", "final"):
        shutil.copytree(CLEAN / side, tmp_path / side)
        (tmp_path / side / "pytest.ini").write_text(DEMO_INI)
    assert ct.detect(changes_from_dirs(tmp_path / "base", tmp_path / "final")) == []


def test_records_mode_carries_evidence_seqs():
    final = (PAIR / "final" / "pytest.ini").read_text()
    change = FileChange(path="pytest.ini", diff=base.make_diff("pytest.ini", DEMO_INI, final),
                        evidence_seqs=[30], status="unknown")
    findings = ct.detect([change])
    assert len(findings) == 2
    assert all(f.evidence_seqs == [30] for f in findings)
    assert all(f.line == 3 for f in findings)


def test_records_mode_conftest_without_full_text():
    final = (PAIR / "final" / "tests" / "conftest.py").read_text()
    change = FileChange(path="tests/conftest.py", diff=base.make_diff("tests/conftest.py", "", final),
                        evidence_seqs=[41])
    findings = ct.detect([change])
    assert len(findings) == 1
    assert findings[0].evidence_seqs == [41]
    assert findings[0].line == 4


# --------------------------------------------------------------------------- #
# pytest ini rules
# --------------------------------------------------------------------------- #

def test_benign_addopts_not_flagged():
    assert ct.detect_added("pytest.ini", "addopts = -q -ra", DEMO_INI) == []
    assert ct.detect_added(
        "pytest.ini", "addopts = --tb=short --strict-markers -p no:cacheprovider --timeout=60 -x",
        DEMO_INI) == []


def test_markers_addition_not_flagged():
    added = "    integration: needs the network\n"
    assert ct.detect_added("pytest.ini", added, DEMO_INI) == []
    assert ct.detect_added("pytest.ini", "filterwarnings =\n    error::DeprecationWarning", DEMO_INI) == []


def test_testpaths_narrowed():
    before = "[pytest]\ntestpaths = tests integration\n"
    after = "[pytest]\ntestpaths = tests\n"
    findings = ct.detect_text("pytest.ini", before, after)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high" and f.line == 2
    assert "testpaths narrowed" in f.summary and "'integration'" in f.summary


def test_testpaths_widened_not_flagged():
    assert ct.detect_text("pytest.ini", "[pytest]\ntestpaths = tests\n",
                          "[pytest]\ntestpaths = tests integration\n") == []
    assert ct.detect_added("pytest.ini", "testpaths = tests", "[pytest]\n") == []


def test_testpaths_multiline_entry_removed_uses_old_line():
    before = "[pytest]\ntestpaths =\n    tests\n    integration\n"
    after = "[pytest]\ntestpaths =\n    tests\n"
    (f,) = ct.detect_text("pytest.ini", before, after)
    assert f.line == 4  # the removed ``integration`` line in base
    assert "-    integration" in f.snippet


def test_addopts_already_narrow_in_base_not_rereported():
    before = "[pytest]\naddopts = -k smoke\n"
    after = "[pytest]\naddopts = -k smoke -q\n"
    assert ct.detect_text("pytest.ini", before, after) == []
    after2 = "[pytest]\naddopts = -k smoke --ignore=tests/test_io.py\n"
    (f,) = ct.detect_text("pytest.ini", before, after2)
    assert "--ignore=tests/test_io.py" in f.summary


def test_pyproject_ini_options_addopts():
    before = "[tool.pytest.ini_options]\ntestpaths = [\"tests\"]\n"
    after = before + 'addopts = "-k smoke"\n'
    findings = ct.detect_text("pyproject.toml", before, after)
    assert len(findings) == 1
    assert findings[0].line == 3 and findings[0].severity == "high"
    assert "-k smoke" in findings[0].summary


def test_pyproject_array_addopts_and_testpaths():
    before = '[tool.pytest.ini_options]\ntestpaths = ["tests", "integration"]\naddopts = ["-ra"]\n'
    after = ('[tool.pytest.ini_options]\ntestpaths = [\n    "tests",\n]\n'
             'addopts = [\n    "-ra",\n    "-p", "no:python",\n]\n')
    s = _summaries(ct.detect_text("pyproject.toml", before, after))
    assert any("testpaths narrowed" in x for x in s)
    assert any("-p no:python" in x for x in s)
    assert len(s) == 2


def test_python_files_pattern_change():
    (f,) = ct.detect_added("pytest.ini", "python_files = check_*.py", DEMO_INI)
    assert f.severity == "high" and "python_files" in f.summary
    assert ct.detect_added("pytest.ini", "python_files = test_*.py check_*.py", DEMO_INI) == []
    (g,) = ct.detect_added("pytest.ini", "python_functions = check_", DEMO_INI)
    assert "python_functions" in g.summary
    assert ct.detect_added("pytest.ini", "python_classes = Test Check", DEMO_INI) == []


def test_norecursedirs_gaining_tests():
    (f,) = ct.detect_added("pytest.ini", "norecursedirs = .git build tests", DEMO_INI)
    assert f.severity == "high" and "'tests'" in f.summary
    assert ct.detect_added("pytest.ini", "norecursedirs = .git build dist", DEMO_INI) == []


def test_setup_cfg_tool_pytest_section():
    before = "[metadata]\nname = x\n\n[tool:pytest]\ntestpaths = tests\n"
    after = before + "addopts = --deselect tests/test_parser.py::test_basic\n"
    (f,) = ct.detect_text("setup.cfg", before, after)
    assert f.line == 6 and "--deselect" in f.summary


def test_records_mode_infers_section_from_key():
    # Hunk without the [tool:pytest] header: the key alone identifies it.
    diff = ("--- a/setup.cfg\n+++ b/setup.cfg\n@@ -10,2 +10,3 @@\n"
            " testpaths = tests\n+addopts = --lf\n markers = x\n")
    (f,) = ct.detect([FileChange(path="setup.cfg", diff=diff, evidence_seqs=[7])])
    assert f.line == 11 and "--lf" in f.summary and f.evidence_seqs == [7]


# --------------------------------------------------------------------------- #
# conftest.py rules
# --------------------------------------------------------------------------- #

def test_newly_added_conftest_with_autouse_swallow_is_high():
    text = ("import pytest\n\n\n@pytest.fixture(autouse=True)\ndef _guard():\n"
            "    try:\n        yield\n    except Exception:\n        pass\n")
    (f,) = ct.detect_text("conftest.py", None, text)
    assert f.severity == "high" and "swallows exceptions" in f.summary and f.line == 8


def test_modified_conftest_autouse_swallow_is_medium():
    before = "import pytest\n\n\n@pytest.fixture(autouse=True)\ndef _guard():\n    yield\n"
    after = ("import pytest\n\n\n@pytest.fixture(autouse=True)\ndef _guard():\n"
             "    try:\n        yield\n    except Exception:\n        pass\n")
    (f,) = ct.detect_text("conftest.py", before, after)
    assert f.severity == "medium"


def test_conftest_benign_fixture_not_flagged():
    added = "\n\n@pytest.fixture\ndef sample():\n    return {'a': 1}\n"
    assert ct.detect_added("tests/conftest.py", added, "import pytest\n") == []
    # skipif marker *definitions* are fine; only applying skips is flagged.
    assert ct.detect_added("tests/conftest.py",
                           "slow = pytest.mark.skipif(not RUN_SLOW, reason='slow')\n",
                           "import pytest\n") == []


# --------------------------------------------------------------------------- #
# tox / Makefile / package.json / workflows / coverage
# --------------------------------------------------------------------------- #

def test_tox_commands_and_ignore_errors():
    before = "[tox]\nenvlist = py311\n\n[testenv]\ncommands = pytest\n"
    after = "[tox]\nenvlist = py311\n\n[testenv]\ncommands = pytest -k smoke\nignore_errors = True\n"
    s = _summaries(ct.detect_text("tox.ini", before, after))
    assert len(s) == 2
    assert any("-k smoke" in x for x in s) and any("ignore_errors" in x for x in s)
    after2 = "[tox]\nenvlist = py311\n\n[testenv]\ncommands = echo ok\n"
    s2 = _summaries(ct.detect_text("tox.ini", before, after2))
    assert any("no-op" in x for x in s2) and any("no longer runs" in x for x in s2)


def test_makefile_test_target_gaining_or_true():
    before = "test:\n\tpytest\n\nlint:\n\truff check .\n"
    after = "test:\n\tpytest || true\n\nlint:\n\truff check .\n"
    (f,) = ct.detect_text("Makefile", before, after)
    assert f.severity == "high" and f.line == 2 and "|| true" in f.summary
    after2 = "test:\n\t@echo tests ok\n\nlint:\n\truff check .\n"
    (g,) = ct.detect_text("Makefile", before, after2)
    assert "no longer runs a test runner" in g.summary
    # Same change in a non-test target is not our business.
    assert ct.detect_text("Makefile", "clean:\n\trm -rf build\n", "clean:\n\trm -rf build || true\n") == []


def test_package_json_test_script():
    before = '{\n  "scripts": {\n    "test": "jest"\n  }\n}\n'
    for new in ('"test": "echo no tests"', '"test": "jest || true"', '"test": "jest -t smoke"'):
        after = before.replace('"test": "jest"', new)
        findings = ct.detect_text("package.json", before, after)
        assert len(findings) == 1 and findings[0].severity == "high", new
    assert ct.detect_text("package.json", before, before.replace('"jest"', '"jest --ci"')) == []


def test_workflow_test_step_is_medium():
    before = "steps:\n  - run: pytest\n"
    after = "steps:\n  - run: pytest || true\n    continue-on-error: true\n"
    findings = ct.detect_text(".github/workflows/ci.yml", before, after)
    assert len(findings) == 2 and all(f.severity == "medium" for f in findings)


def test_coveragerc_fail_under_lowered_is_low():
    (f,) = ct.detect_text(".coveragerc", "[report]\nfail_under = 90\n", "[report]\nfail_under = 10\n")
    assert f.severity == "low"
    assert ct.detect_text(".coveragerc", "[report]\nfail_under = 50\n", "[report]\nfail_under = 90\n") == []


def test_non_config_files_ignored():
    assert ct.detect_text("tests/test_x.py", "x = 1\n", "x = 1\naddopts = -k smoke\n") == []


def test_deleted_config_file_ignored():
    assert ct.detect_text("pytest.ini", DEMO_INI, None) == []


# --------------------------------------------------------------------------- #
# Table through the exposed helper
# --------------------------------------------------------------------------- #

TABLE = [
    ("pytest.ini", "addopts = -k smoke", True),
    ("pytest.ini", 'addopts = -m "not slow"', True),
    ("pytest.ini", "addopts = --ignore=tests/test_io.py", True),
    ("pytest.ini", "addopts = --ignore-glob=tests/test_*.py", True),
    ("pytest.ini", "addopts = --deselect tests/test_parser.py::test_basic", True),
    ("pytest.ini", "addopts = -p no:python", True),
    ("pytest.ini", "addopts = --co", True),
    ("pytest.ini", "addopts = --continue-on-collection-errors", True),
    ("pytest.ini", "addopts = -o testpaths=nothing", True),
    ("pytest.ini", "addopts = -p no:cacheprovider", False),
    ("pytest.ini", "addopts = -q -ra --tb=short --strict-markers", False),
    ("pytest.ini", "addopts = --maxfail=1 -x --disable-warnings --runxfail --no-cov", False),
    ("pytest.ini", "python_files = check_*.py", True),
    ("pytest.ini", "python_files = test_*.py *_test.py", False),
    ("pytest.ini", "norecursedirs = tests", True),
    ("pytest.ini", "norecursedirs = .git .tox build", False),
    ("pytest.ini", "markers =\n    slow: slow", False),
    ("pytest.ini", "# just a comment", False),
    ("pytest.ini", "testpaths = tests", False),
    ("pyproject.toml", '[tool.pytest.ini_options]\naddopts = "-k smoke"', True),
    ("pyproject.toml", '[tool.pytest.ini_options]\naddopts = "-ra -q"', False),
    ("pyproject.toml", '[tool.pytest.ini_options]\ncollect_ignore = ["tests/test_io.py"]', True),
    ("pyproject.toml", '[tool.black]\nline-length = 100', False),
    ("setup.cfg", "[tool:pytest]\naddopts = --lf", True),
    ("tox.ini", "[testenv]\nignore_outcome = True", True),
    ("tox.ini", "[testenv]\ncommands = -pytest", True),
    ("tox.ini", "[testenv]\ncommands = pytest {posargs}", False),
    ("tests/conftest.py", "def pytest_ignore_collect(collection_path, config):\n    return True", True),
    ("tests/conftest.py", "def pytest_runtest_makereport(item, call):\n    pass", True),
    ("tests/conftest.py", "collect_ignore = ['test_parser.py']", True),
    ("tests/conftest.py", "import sys\nsys.exit(0)", True),
    ("tests/conftest.py", "import _pytest\n_pytest.runner.call_and_report = lambda *a, **k: None", True),
    ("tests/conftest.py", "import pytest\npytest.skip('nope', allow_module_level=True)", True),
    ("tests/conftest.py", "import pytest\n\n@pytest.fixture\ndef db():\n    return object()", False),
    ("Makefile", "test:\n\t-pytest", True),
    ("Makefile", "test:\n\tpytest -k smoke", True),
    ("Makefile", "test:\n\tpytest -q", False),
    ("package.json", '{"scripts": {"test": "exit 0"}}', True),
    ("package.json", '{"scripts": {"test": "vitest run"}}', False),
    (".github/workflows/ci.yml", "      - run: pytest -k smoke", True),
    (".github/workflows/ci.yml", "      - run: pytest -q", False),
    ("noxfile.py", "session.run('pytest', success_codes=[0, 1])", True),
    (".coveragerc", "[report]\nfail_under = 10", False),  # only a *lowering* counts
]


@pytest.mark.parametrize("path,added,expect", TABLE, ids=[f"{p}:{a[:30]!r}" for p, a, _ in TABLE])
def test_table(path, added, expect):
    findings = ct.detect_added(path, added)
    assert bool(findings) is expect, _summaries(findings)
    for f in findings:
        assert f.pattern_id == "config_tamper"
        assert f.path == path
        assert f.line is not None
        assert f.severity in ("high", "medium", "low")
