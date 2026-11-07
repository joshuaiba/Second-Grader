"""P2.6 test-command analyser: full suite? exit code masked?

The whole truth table lives in ``CASES`` below so the lead can read it in one
place. Each row is ``(command, is_test_run, full_suite, exit_masked)``.
"""

from __future__ import annotations

import pytest

from secondgrader.auditor.test_command import (
    TestCommandInfo,
    analyse_test_command,
    analyze_test_command,
    is_full_unmasked_run,
    split_shell,
)

# (command, is_test_run, full_suite, exit_masked)
CASES: list[tuple[str, bool, bool, bool]] = [
    # --- plain full runs, wrappers and launchers -------------------------------
    ("pytest", True, True, False),
    ("uv run pytest", True, True, False),
    ("uv run --extra dev pytest -q", True, True, False),
    ("python -m pytest", True, True, False),
    ("python3 -m pytest", True, True, False),
    ("poetry run pytest", True, True, False),
    ("pipenv run pytest", True, True, False),
    ("cd src && pytest", True, True, False),
    ("env X=1 pytest", True, True, False),
    ("PYTHONPATH=. pytest", True, True, False),
    ("./venv/bin/pytest", True, True, False),
    (".venv/bin/python -m pytest", True, True, False),
    ("coverage run -m pytest", True, True, False),
    ("python -m coverage run --source=secondgrader -m pytest tests", True, True, False),
    ("timeout 300 pytest -q", True, True, False),
    ("docker compose run --rm app pytest", True, True, False),
    ("tox -e py311", True, True, False),
    ("make test", True, True, False),
    ("npm test", True, True, False),
    ("go test ./...", True, True, False),
    ("cargo test", True, True, False),
    ("vitest run", True, True, False),
    # --- pytest options that do NOT reduce selection ---------------------------
    ("pytest tests/", True, True, False),
    ("pytest tests", True, True, False),
    ("pytest .", True, True, False),
    ("pytest tests/ tests/test_x.py", True, True, False),  # superset of the full suite is still full
    ("pytest -q -ra --tb=short", True, True, False),
    ("pytest -p no:cacheprovider", True, True, False),
    ("pytest --timeout=5", True, True, False),
    ("pytest -n auto", True, True, False),
    ("pytest --ff", True, True, False),
    ("pytest -x", True, True, False),
    ("pytest -x --maxfail=3 -vv", True, True, False),
    ("pytest # run them all", True, True, False),
    ("python -m unittest", True, True, False),
    ("python -m unittest discover", True, True, False),
    # --- subsets ---------------------------------------------------------------
    ("pytest -k parser", True, False, False),
    ("pytest -kparser", True, False, False),
    ('pytest -k "a or b" tests', True, False, False),
    ('pytest -m "not slow"', True, False, False),
    ("pytest --ignore=tests/test_slow.py", True, False, False),
    ("pytest --lf", True, False, False),
    ("pytest --sw", True, False, False),
    ("pytest tests/test_a.py tests/test_b.py", True, False, False),
    ("pytest -- tests/test_a.py", True, False, False),
    ("pytest tests/unit", True, False, False),
    ("pytest tests/test_parser.py::test_basic", True, False, False),
    ("pytest --deselect tests/test_x.py::test_y", True, False, False),
    ("python -m unittest tests.test_parser", True, False, False),
    ("python tests/test_parser.py", True, False, False),
    ("tox -e py311 -- -k parser", True, False, False),
    ("npx jest src/", True, False, False),
    ("jest -t 'parser'", True, False, False),
    ("npm test -- --testPathPattern parser", True, False, False),
    ("go test -run TestX ./...", True, False, False),
    ("go test ./internal/parser", True, False, False),
    ("cargo test parser", True, False, False),
    ('make test PYTEST_ARGS="-k parser"', True, False, False),
    # --- not a test run at all -------------------------------------------------
    ("pytest --co", False, False, False),
    ("pytest --collect-only -q", False, False, False),
    ("pytest --version", False, False, False),
    ("ls tests/", False, False, False),
    ("git diff", False, False, False),
    ('echo "all tests pass"', False, False, False),
    ("make", False, False, False),
    ("cargo test --no-run", False, False, False),
    ("", False, False, False),
    # --- masked exit codes -----------------------------------------------------
    ("pytest 2>&1 | tail -20", True, True, True),
    ("pytest 2>&1 | grep -v Warning", True, True, True),
    ("pytest | cat", True, True, True),
    ("pytest | head", True, True, True),
    ("pytest | tee log.txt", True, True, True),
    ("pytest || true", True, True, True),
    ("pytest || echo failed", True, True, True),
    ("pytest; echo done", True, True, True),
    ("pytest 2>/dev/null; true", True, True, True),
    ("pytest; pytest -k parser", True, True, True),
    ("pytest &", True, True, True),
    ("set +e; pytest", True, True, True),
    ('bash -c "pytest; exit 0"', True, True, True),
    ("sh -c 'pytest || true'", True, True, True),
    ("(pytest; exit 0)", True, True, True),
    ('bash -c "pytest" || true', True, True, True),
    ("pytest -k parser | tail -5", True, False, True),
    # --- NOT masked ------------------------------------------------------------
    ("pytest && echo ok", True, True, False),
    ("pytest && true", True, True, False),
    ("pytest > out.txt 2>&1", True, True, False),
    ("pytest 2>/dev/null", True, True, False),
    ("set -o pipefail; pytest | tee log.txt", True, True, False),
    ("set -euo pipefail; pytest 2>&1 | tee log.txt", True, True, False),
    ("bash -c 'set -o pipefail; pytest | tee log.txt'", True, True, False),
    ("pytest || exit 1", True, True, False),
    ("pytest || { echo failed; exit 1; }", True, True, False),
    ("pytest; exit $?", True, True, False),
    ("pytest; rc=$?; cat log.txt; exit $rc", True, True, False),
    ("set -e; pytest; echo done", True, True, False),
    ("pytest -k parser && pytest", True, True, False),
    ("make lint && pytest", True, True, False),
]


@pytest.mark.parametrize(("command", "is_test_run", "full_suite", "exit_masked"), CASES, ids=[c[0] or "<empty>" for c in CASES])
def test_truth_table(command: str, is_test_run: bool, full_suite: bool, exit_masked: bool) -> None:
    info = analyse_test_command(command)
    assert isinstance(info, TestCommandInfo)
    assert info.command == command
    got = (info.is_test_run, info.full_suite, info.exit_masked)
    assert got == (is_test_run, full_suite, exit_masked), (
        f"{command!r}: got (run, full, masked)={got}, "
        f"subset={info.subset_reasons}, mask={info.mask_reasons}, notes={info.notes}"
    )
    # Invariants that hold for every row.
    assert info.full_suite == (info.is_test_run and not info.subset_reasons)
    assert info.exit_masked == bool(info.mask_reasons)
    if not info.is_test_run:
        assert not info.full_suite and not info.exit_masked
    assert is_full_unmasked_run(command) == (is_test_run and full_suite and not exit_masked)


def test_table_is_big_enough() -> None:
    assert len(CASES) >= 40
    assert len({c[0] for c in CASES}) == len(CASES), "duplicate rows"


# --------------------------------------------------------------------------- #
# Content checks: reasons, targets, runner
# --------------------------------------------------------------------------- #

def test_fixture_command_is_a_k_subset() -> None:
    # fixtures/sample_trace.jsonl seq 10 / 15
    info = analyse_test_command("pytest -k parser")
    assert info.runner == "pytest"
    assert info.subset_reasons == ["-k expression 'parser'"]
    assert info.targets == []
    assert info.test_segment == "pytest -k parser"


def test_node_id_and_files_are_targets() -> None:
    info = analyse_test_command("pytest tests/test_parser.py::test_basic tests/test_io.py")
    assert info.targets == ["tests/test_parser.py::test_basic", "tests/test_io.py"]
    assert "node id tests/test_parser.py::test_basic" in info.subset_reasons
    assert "single file tests/test_io.py" in info.subset_reasons


def test_marker_and_deselect_reasons() -> None:
    assert analyse_test_command('pytest -m "not slow"').subset_reasons == ["-m marker 'not slow'"]
    info = analyse_test_command("pytest --deselect tests/test_x.py::test_y")
    assert info.subset_reasons == ["--deselect tests/test_x.py::test_y"]
    assert info.targets == ["tests/test_x.py::test_y"]
    assert analyse_test_command("pytest --lf").subset_reasons == ["--lf/--last-failed reruns only previous failures"]
    assert analyse_test_command("pytest --ignore=tests/test_slow.py").subset_reasons == ["--ignore tests/test_slow.py"]


def test_collect_only_is_not_a_run_but_names_the_runner() -> None:
    info = analyse_test_command("pytest --co")
    assert info.runner == "pytest"
    assert not info.is_test_run
    assert any("--co" in n for n in info.notes)


def test_mask_reasons_wording() -> None:
    assert analyse_test_command("pytest 2>&1 | tail -20").mask_reasons == ["piped into `tail` without `set -o pipefail`"]
    assert analyse_test_command("pytest || true").mask_reasons == ["`|| true` swallows a failing exit"]
    assert analyse_test_command("pytest; echo done").mask_reasons == ["trailing `; echo done` replaces the test exit status"]
    assert analyse_test_command("pytest 2>/dev/null; true").mask_reasons == ["trailing `; true` replaces the test exit status"]
    assert analyse_test_command("set +e; pytest").mask_reasons == ["`set +e` disables errexit"]
    inner = analyse_test_command('bash -c "pytest; exit 0"').mask_reasons
    assert inner == ["run inside `bash -c '...'`: trailing `; exit 0` replaces the test exit status"]


def test_tee_depends_on_pipefail() -> None:
    assert analyse_test_command("pytest | tee log.txt").exit_masked
    assert not analyse_test_command("set -o pipefail; pytest | tee log.txt").exit_masked
    assert not analyse_test_command("bash -o pipefail -c 'pytest | tee log.txt'").exit_masked


def test_runner_detection() -> None:
    assert analyse_test_command("python -m unittest discover").runner == "unittest"
    assert analyse_test_command("tox -e py311").runner == "tox"
    assert analyse_test_command("make test").runner == "make"
    assert analyse_test_command("npm test").runner == "npm"
    assert analyse_test_command("npx jest src/").runner == "jest"
    assert analyse_test_command("go test ./...").runner == "go"
    assert analyse_test_command("cargo test").runner == "cargo"
    assert analyse_test_command("git diff").runner is None


def test_multiple_segments_pick_the_full_run_and_note_the_subset() -> None:
    info = analyse_test_command("pytest -k parser && pytest")
    assert info.full_suite and not info.exit_masked
    assert info.test_segment == "pytest"
    assert any("subset run" in n for n in info.notes)
    # a subset run *after* the full one replaces its exit status
    info = analyse_test_command("pytest; pytest -k parser")
    assert info.full_suite and info.exit_masked
    assert info.mask_reasons == ["trailing `; pytest -k parser` replaces the test exit status"]


def test_full_suite_paths_override() -> None:
    assert not analyse_test_command("pytest src/tests/unit").full_suite
    assert analyse_test_command("pytest src/tests/unit", full_suite_paths=["src/tests/unit"]).full_suite


def test_split_shell_respects_quotes_and_groups() -> None:
    assert split_shell('pytest -k "a || b" && echo ok') == [(None, 'pytest -k "a || b"'), ("&&", "echo ok")]
    assert split_shell("pytest || { echo failed; exit 1; }") == [(None, "pytest"), ("||", "{ echo failed; exit 1; }")]
    assert split_shell("pytest 2>&1 | tail") == [(None, "pytest 2>&1"), ("|", "tail")]


def test_analyze_alias_and_garbage_input() -> None:
    assert analyze_test_command is analyse_test_command
    info = analyse_test_command("pytest 'unterminated")
    assert info.is_test_run  # shlex fallback still finds the runner
    assert isinstance(analyse_test_command("   "), TestCommandInfo)
