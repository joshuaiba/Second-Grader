"""Test-command analyser (P2.6).

Answers two of the auditor's "did it really run the tests?" questions from the
raw shell string recorded in a ``test_run`` record (``payload["command"]``):

* **full suite?** - was a subset selector used (``-k``, ``-m``, node ids, a
  single file, ``--lf``, ``--deselect``, ``--ignore``, ...)?
* **exit code masked?** - does the exit status of the whole command line still
  reflect the test runner's status (``| tail``, ``|| true``, ``; echo done``,
  ``bash -c "pytest; exit 0"`` all hide a failure)?

Everything here is a pure function over the string: no subprocess, no LLM,
no filesystem. Shell semantics are approximated, not executed.

Full-suite rules (``full_suite`` is True only when ``is_test_run`` and no
subset reason was found):

* pytest: ``-k``, ``-m``, ``--lf/--last-failed``, ``--sw/--stepwise``,
  ``--deselect``, ``--ignore``/``--ignore-glob`` and any node id (``::``) are
  subsets. A positional path is a subset unless it is a conventional
  top-level test directory (``.``, ``tests``, ``test``, ``spec``, ...; see
  :data:`DEFAULT_FULL_SUITE_PATHS`). ``-x``/``--maxfail``, ``--ff``, ``-n``,
  ``--timeout``, ``-p no:...``, ``-q -ra --tb=short`` do not change selection.
  ``--co/--collect-only``, ``--version``, ``--help``, ``--fixtures``,
  ``--markers``, ``--setup-only/--setup-plan`` mean *no test ran*.
* unittest: ``python -m unittest`` and ``... discover`` are full; test names
  or ``-k`` are subsets. ``python path/to/test_x.py`` is a single-file run.
* tox / nox: ``-e env`` / ``-s session`` is still the full suite of that env;
  anything after ``--`` is analysed as pytest args.
* make: ``make test``/``check``/``*test*`` targets are full; a variable such
  as ``PYTEST_ARGS="-k foo"`` is a subset.
* npm / yarn / pnpm / bun ``test`` are full; args after ``--`` are analysed as
  jest args. jest / vitest / mocha: positional patterns, ``-t``,
  ``--testPathPattern``, ``--onlyChanged``, ``--changedSince`` are subsets.
* go: ``go test ./...`` is full; ``-run``, ``-skip``, ``-short`` or a package
  other than ``./...``/``.`` is a subset.
* cargo: ``cargo test`` is full; a name filter, ``-p``, ``--lib``, ``--test``,
  ``--doc``, ``--exclude`` or ``-- --skip/--ignored`` is a subset.
* rspec / mocha / phpunit: positional paths or ``-e/-g/--filter`` are subsets.
* An opaque test script (``./run_tests.sh``) is treated as a full run with a
  note, since its selection cannot be inspected.

Exit-masking rules (evaluated relative to the *last full-suite* test segment,
or the last test segment if none is a full run):

* ``| cmd`` / ``|& cmd`` after the test segment masks (pipeline status is the
  last command's) unless ``set -o pipefail`` (or ``bash -o pipefail``) is in
  effect before it. This includes ``| tee``, ``| cat``, ``| head``,
  ``| tail``, ``| grep``.
* ``|| cmd`` masks unless ``cmd`` itself fails (``exit N`` with N != 0,
  ``false``, bare ``exit`` which re-raises ``$?``).
* ``; cmd`` / newline masks (the list's status is the last command's) unless
  ``cmd`` is ``exit $?`` / ``exit $rc`` after ``rc=$?``, or ``set -e`` is in
  effect (a failing test aborts the list).
* ``&& cmd`` never masks: a failing test short-circuits with its own status.
* ``&`` right after the test segment masks (backgrounded).
* ``set +e`` before the test segment is reported as masking (the agent
  explicitly disabled fail-fast), as requested by the P2 lead.
* ``bash -c "..."``, ``sh -c``, ``( ... )`` and ``{ ...; }`` are analysed
  recursively; inner masking is reported with a "run inside" prefix and the
  outer operators are then applied on top.
* Redirections (``> out.txt 2>&1``, ``2>/dev/null``) never mask by
  themselves.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Iterable

__all__ = [
    "DEFAULT_FULL_SUITE_PATHS",
    "TestCommandInfo",
    "analyse_test_command",
    "analyze_test_command",
    "is_full_unmasked_run",
    "split_shell",
]

#: Positional targets that mean "the whole suite" rather than a subset.
DEFAULT_FULL_SUITE_PATHS: frozenset[str] = frozenset(
    {".", "tests", "test", "testing", "spec", "specs", "unittests", "unit_tests", "src/tests"}
)


# --------------------------------------------------------------------------- #
# Public result type
# --------------------------------------------------------------------------- #

@dataclass
class TestCommandInfo:
    """What a recorded shell command tells us about the test run.

    Attributes:
        command: The raw string that was analysed.
        is_test_run: True when at least one segment invokes a test runner and
            actually runs tests (``pytest --co`` / ``--version`` do not).
        runner: ``"pytest"``, ``"unittest"``, ``"nose"``, ``"tox"``, ``"nox"``,
            ``"make"``, ``"npm"``, ``"yarn"``, ``"pnpm"``, ``"bun"``, ``"jest"``,
            ``"vitest"``, ``"mocha"``, ``"go"``, ``"cargo"``, ``"rspec"``,
            ``"phpunit"``, ``"django"``, ``"python-script"``, ``"script"``
            or ``None`` when no runner was recognised.
        full_suite: True only when ``is_test_run`` and no subset selector
            was found on the segment that counts.
        subset_reasons: Human-readable reasons ``full_suite`` is False.
        exit_masked: True when the command line's overall exit status would
            not reflect the test runner's.
        mask_reasons: Human-readable reasons ``exit_masked`` is True.
        targets: Paths / node ids / patterns handed to the runner.
        notes: Non-verdict observations (wrappers stripped, cd, etc.).
        test_segment: The text of the segment the verdict is about.
    """

    __test__ = False  # the name starts with "Test"; stop pytest trying to collect it

    command: str
    is_test_run: bool = False
    runner: str | None = None
    full_suite: bool = False
    subset_reasons: list[str] = field(default_factory=list)
    exit_masked: bool = False
    mask_reasons: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    test_segment: str | None = None


# --------------------------------------------------------------------------- #
# Shell splitting
# --------------------------------------------------------------------------- #

@dataclass
class _Segment:
    text: str
    op_before: str | None  # operator joining this segment to the previous one
    op_after: str | None = None  # operator following it (``&`` matters even at the end)


def split_shell(command: str) -> list[tuple[str | None, str]]:
    """Split ``command`` on ``&&``, ``||``, ``|``, ``|&``, ``;``, ``&`` and newlines.

    Quotes, backslashes, ``$(...)``, backticks, ``( ... )`` subshells and
    ``{ ...; }`` groups are respected (no split inside them). Comments are
    dropped. Returns ``[(op_before, text), ...]`` with ``op_before`` ``None``
    for the first segment; a trailing ``&`` is returned as a final
    ``("&", "")`` entry so callers can see it.
    """
    return [(s.op_before, s.text) for s in _split(command)]


def _split(command: str) -> list[_Segment]:
    segs: list[_Segment] = []
    buf: list[str] = []
    op_before: str | None = None
    quote: str | None = None
    stack: list[str] = []
    i, n = 0, len(command)

    def flush(op: str | None) -> None:
        nonlocal buf, op_before
        text = "".join(buf).strip()
        buf = []
        if text:
            segs.append(_Segment(text=text, op_before=op_before, op_after=op))
        elif segs and op is not None:
            # ``pytest ;`` / ``pytest &``: keep the operator on the previous segment.
            if segs[-1].op_after is None or op == "&":
                segs[-1].op_after = op
        op_before = op

    while i < n:
        c = command[i]
        if quote:
            buf.append(c)
            if c == "\\" and quote == '"' and i + 1 < n:
                buf.append(command[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            buf.append(c)
            buf.append(command[i + 1])
            i += 2
            continue
        if c in ("'", '"', "`"):
            quote = c
            buf.append(c)
            i += 1
            continue
        prev = command[i - 1] if i > 0 else ""
        nxt = command[i + 1] if i + 1 < n else ""
        if c == "$" and nxt == "(":
            stack.append(")")
            buf.append("$(")
            i += 2
            continue
        if c == "(":
            stack.append(")")
            buf.append(c)
            i += 1
            continue
        if c == ")" and stack and stack[-1] == ")":
            stack.pop()
            buf.append(c)
            i += 1
            continue
        if c == "{" and (prev == "" or prev.isspace() or prev in ";&|(") and (nxt.isspace() or nxt == ""):
            stack.append("}")
            buf.append(c)
            i += 1
            continue
        if c == "}" and stack and stack[-1] == "}" and (prev.isspace() or prev == ";") and (nxt == "" or nxt.isspace() or nxt in ";&|)"):
            stack.pop()
            buf.append(c)
            i += 1
            continue
        if stack:
            buf.append(c)
            i += 1
            continue
        if c == "#" and (prev == "" or prev.isspace()):
            while i < n and command[i] != "\n":
                i += 1
            continue
        two = command[i:i + 2]
        if two in ("&&", "||", "|&"):
            flush(two)
            i += 2
            continue
        if c == ";":
            flush(";")
            i += 1
            while i < n and command[i] == ";":
                i += 1
            continue
        if c == "\n":
            flush(";")
            i += 1
            continue
        if c == "|":
            flush("|")
            i += 1
            continue
        if c == "&":
            if prev in (">", "<") or nxt == ">":
                buf.append(c)
                i += 1
                continue
            flush("&")
            i += 1
            continue
        buf.append(c)
        i += 1
    flush(None)
    return segs


def _argv(text: str) -> list[str]:
    """shlex.split with fallbacks for unbalanced quotes."""
    try:
        return shlex.split(text)
    except ValueError:
        try:
            return shlex.split(text, posix=False)
        except ValueError:
            return text.split()


_REDIRECT_RE = re.compile(r"^(\d*|&)(>>?|<|>\|)(&\d+|&-|\S*)$")


def _strip_redirections(argv: list[str]) -> list[str]:
    out: list[str] = []
    skip_next = False
    for tok in argv:
        if skip_next:
            skip_next = False
            continue
        m = _REDIRECT_RE.match(tok)
        if m:
            if not m.group(3):  # bare ``>`` / ``2>`` / ``<``: filename follows
                skip_next = True
            continue
        out.append(tok)
    return out


# --------------------------------------------------------------------------- #
# Wrapper stripping
# --------------------------------------------------------------------------- #

_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_PYTHON_RE = re.compile(r"^(python|python\d(\.\d+)?|py|pypy3?)(\.exe)?$")
_SHELL_RE = re.compile(r"^(ba|z|da|k|fi|a)?sh$")
_TEST_FILE_RE = re.compile(r"(^|/)(test_[^/]*\.py|[^/]*_tests?\.py|tests?\.py)$")
_TEST_DIR_RE = re.compile(r"(^|/)(tests?|testing|spec|specs|__tests__)(/|$)")
_TEST_SCRIPT_RE = re.compile(r"(^|/)[^/]*(test|check)[^/]*\.(sh|bash|zsh|py|ps1)$", re.I)

# wrapper -> options that consume the following token
_WRAPPERS: dict[str, set[str]] = {
    "sudo": {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-T", "-U"},
    "time": set(),
    "nice": {"-n"},
    "nohup": set(),
    "stdbuf": {"-i", "-o", "-e"},
    "timeout": {"-k", "-s", "--kill-after", "--signal"},
    "xvfb-run": {"-s", "-e", "-f", "-n", "-p", "--server-args", "--server-num"},
    "caffeinate": {"-t", "-w"},
    "env": {"-u", "-C", "-S", "--unset", "--chdir"},
    "uv": {"--with", "--with-editable", "--with-requirements", "--python", "-p", "--group",
           "--extra", "--directory", "--project", "--package", "--env-file", "--index", "--find-links",
           "--cache-dir", "--config-file", "--only-group"},
    "uvx": {"--with", "--python", "-p", "--from", "--index", "--cache-dir"},
    "poetry": {"-C", "--directory", "-P", "--project"},
    "pipenv": set(),
    "pdm": {"-p", "--project"},
    "rye": set(),
    "hatch": {"-e", "--env"},
    "conda": {"-n", "--name", "-p", "--prefix", "--cwd"},
    "mamba": {"-n", "--name", "-p", "--prefix", "--cwd"},
    "micromamba": {"-n", "--name", "-p", "--prefix", "--cwd"},
    "npx": {"-p", "--package", "-c", "--call"},
    "bunx": set(),
    "pnpm": {"-C", "--dir", "--filter", "-F"},
    "yarn": {"--cwd"},
    "npm": {"--prefix", "-C", "-w", "--workspace"},
    "docker": {"-w", "--workdir", "-e", "--env", "-u", "--user", "--env-file", "--entrypoint",
               "-v", "--volume", "--name", "--network", "-p", "--publish"},
    "docker-compose": {"-f", "--file", "-p", "--project-name", "-w", "--workdir", "-e", "--env",
                       "-u", "--user", "--entrypoint", "-v", "--volume"},
}
#: tools whose "run" subcommand must be skipped before the real program
_RUN_SUBCOMMAND = {"uv", "poetry", "pipenv", "pdm", "rye", "hatch", "conda", "mamba", "micromamba"}
_PYTHON_VALUE_FLAGS = {"-W", "-X", "-Q", "--check-hash-based-pycs"}
_TIMEOUT_DURATION_RE = re.compile(r"^\d+(\.\d+)?[smhd]?$")


def _base(tok: str) -> str:
    return PurePosixPath(tok.replace("\\", "/")).name


def _unwrap(argv: list[str], notes: list[str]) -> list[str]:
    """Strip env assignments, launchers and wrappers; return the real argv.

    ``python -m mod args`` becomes ``[mod, *args]`` so callers see ``pytest``
    / ``unittest`` directly. ``coverage run -m pytest`` is stripped too.
    """
    seen: set[int] = set()
    while argv:
        key = (len(argv), argv[0])
        if hash(key) in seen:  # defensive: never loop forever
            break
        seen.add(hash(key))
        head = argv[0]
        name = _base(head)

        if _ENV_ASSIGN_RE.match(head):
            if head.startswith("PYTEST_ADDOPTS="):
                notes.append(f"PYTEST_ADDOPTS={head[len('PYTEST_ADDOPTS='):]}")
            argv = argv[1:]
            continue

        if name in ("sudo", "time", "nice", "nohup", "stdbuf", "env", "caffeinate", "xvfb-run"):
            argv = _skip_options(argv[1:], _WRAPPERS[name])
            if name == "env":
                while argv and _ENV_ASSIGN_RE.match(argv[0]):
                    argv = argv[1:]
            notes.append(f"wrapper `{name}` stripped")
            continue

        if name == "timeout":
            rest = _skip_options(argv[1:], _WRAPPERS["timeout"])
            if rest and _TIMEOUT_DURATION_RE.match(rest[0]):
                rest = rest[1:]
            notes.append("wrapper `timeout` stripped")
            argv = rest
            continue

        if name in _RUN_SUBCOMMAND:
            rest = _skip_options(argv[1:], _WRAPPERS[name])
            if rest and rest[0] in ("run", "r") and name != "hatch":
                argv = _skip_options(rest[1:], _WRAPPERS[name])
                notes.append(f"wrapper `{name} run` stripped")
                continue
            if name == "hatch" and rest:
                if rest[0] == "test":
                    return ["hatch-test", *rest[1:]]
                if rest[0] == "run" and len(rest) > 1:
                    inner = _skip_options(rest[1:], _WRAPPERS["hatch"])
                    if inner and (inner[0] == "test" or inner[0].endswith(":test")):
                        return ["hatch-test", *inner[1:]]
                    argv = inner
                    notes.append("wrapper `hatch run` stripped")
                    continue
            if name in ("uv", "poetry", "pdm", "rye", "pipenv") and rest and rest[0] == "test":
                # ``rye test`` / ``pdm test`` run the configured test command.
                return [f"{name}-test", *rest[1:]]
            return argv  # ``uv pip ...``, ``poetry install`` etc.: not a runner

        if name in ("uvx", "npx", "bunx"):
            argv = _skip_options(argv[1:], _WRAPPERS[name])
            notes.append(f"wrapper `{name}` stripped")
            continue

        if name in ("pnpm", "yarn", "npm", "bun"):
            rest = _skip_options(argv[1:], _WRAPPERS.get(name, set()))
            if not rest:
                return argv
            sub = rest[0]
            if sub in ("exec", "dlx", "x"):
                argv = _skip_options(rest[1:], set())
                if argv and argv[0] == "--":
                    argv = argv[1:]
                notes.append(f"wrapper `{name} {sub}` stripped")
                continue
            if sub in ("run", "run-script") and len(rest) > 1:
                script = rest[1]
                if script == "test" or script.startswith("test:") or script.endswith(":test") or script.endswith("-test"):
                    return [f"{name}-test", *rest[2:]]
                if _base(script) in _RUNNER_NAMES:
                    argv = [script, *rest[2:]]
                    notes.append(f"wrapper `{name} run` stripped")
                    continue
                return argv
            if sub in ("test", "t", "tst"):
                return [f"{name}-test", *rest[1:]]
            if _base(sub) in _RUNNER_NAMES:  # ``yarn jest``, ``bun vitest``
                argv = rest
                notes.append(f"wrapper `{name}` stripped")
                continue
            return argv

        if name in ("docker", "docker-compose", "podman"):
            rest = argv[1:]
            if name != "docker-compose" and rest and rest[0] == "compose":
                rest = rest[1:]
            if rest and rest[0] in ("exec", "run"):
                rest = _skip_options(rest[1:], _WRAPPERS["docker"] | _WRAPPERS["docker-compose"])
                if rest:
                    rest = rest[1:]  # container / service / image
                notes.append(f"wrapper `{name}` stripped")
                argv = rest
                continue
            return argv

        if name == "coverage":
            rest = argv[1:]
            if rest and rest[0] == "run":
                rest = rest[1:]
                cov_value_opts = {"--source", "--include", "--omit", "--context", "--data-file", "--rcfile"}
                while rest and rest[0].startswith("-") and rest[0] != "-m":
                    rest = rest[2:] if rest[0] in cov_value_opts else rest[1:]
                argv = ["python", *rest]
                notes.append("wrapper `coverage run` stripped")
                continue
            return argv

        if _PYTHON_RE.match(name):
            rest = argv[1:]
            while rest and rest[0].startswith("-") and rest[0] not in ("-m", "-c", "-"):
                if rest[0] in _PYTHON_VALUE_FLAGS:
                    rest = rest[2:]
                else:
                    rest = rest[1:]
            if not rest:
                return argv
            if rest[0] == "-m" and len(rest) > 1:
                notes.append(f"`{name} -m {rest[1]}`")
                argv = [rest[1], *rest[2:]]
                continue
            if rest[0] == "-c" and len(rest) > 1:
                return ["python-c", rest[1]]
            return ["python-script", *rest]

        return argv
    return argv


def _skip_options(argv: list[str], value_opts: set[str]) -> list[str]:
    i = 0
    while i < len(argv) and argv[i].startswith("-") and argv[i] != "--":
        if argv[i] in value_opts:
            i += 2
        else:
            i += 1
    if i < len(argv) and argv[i] == "--":
        i += 1
    return argv[i:]


# --------------------------------------------------------------------------- #
# Per-runner analysis
# --------------------------------------------------------------------------- #

@dataclass
class _SegResult:
    is_test_run: bool = False
    runner: str | None = None
    full_suite: bool = False
    subset_reasons: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    inner: TestCommandInfo | None = None  # for ``bash -c``, ``( ... )``, ``{ ...; }``
    inner_label: str = ""

    def subset(self, reason: str) -> None:
        if reason not in self.subset_reasons:
            self.subset_reasons.append(reason)


_RUNNER_NAMES = {
    "pytest", "py.test", "unittest", "nose", "nose2", "nosetests", "tox", "nox", "make",
    "jest", "vitest", "mocha", "go", "cargo", "rspec", "phpunit", "manage.py", "ctest",
    "dotnet", "mvn", "gradle", "gradlew", "ward", "green", "hatch-test", "rye-test",
    "pdm-test", "uv-test", "poetry-test", "pipenv-test", "npm-test", "yarn-test",
    "pnpm-test", "bun-test", "python-script", "python-c", "ava", "tap", "karma",
    "cypress", "playwright", "deno", "rake", "swift", "elixir", "mix",
}

_PYTEST_VALUE_OPTS = {
    "-k", "-m", "-p", "-c", "-o", "-W", "-n", "-r", "--numprocesses", "--maxfail", "--tb",
    "--timeout", "--timeout-method", "--deselect", "--ignore", "--ignore-glob", "--rootdir",
    "--confcutdir", "--basetemp", "--junitxml", "--junit-xml", "--junit-prefix", "--durations",
    "--durations-min", "--cov", "--cov-report", "--cov-config", "--cov-fail-under",
    "--log-level", "--log-cli-level", "--log-file", "--log-file-level", "--log-format",
    "--log-date-format", "--dist", "--import-mode", "--override-ini", "--capture", "--color",
    "--code-highlight", "--reruns", "--reruns-delay", "--pdbcls", "--doctest-glob", "--assert",
    "--pythonwarnings", "--lfnf", "--last-failed-no-failures", "--randomly-seed",
    "--max-worker-restart", "--tx", "--benchmark-sort", "--result-log",
    "--html", "--json-report-file", "--hypothesis-profile",
    "--hypothesis-seed", "--mypy-config-file", "--doctest-report", "--pastebin",
    "--only-rerun", "--rerun-except", "--timeout_method",
}
# short options whose value may be attached (-kexpr) or separate (-k expr)
_PYTEST_SHORT_VALUE = {"-k", "-m", "-p", "-c", "-o", "-W", "-n", "-r"}

_PYTEST_NO_RUN = {
    "--co", "--collect-only", "--collectonly", "--version", "-V", "--help", "-h", "--fixtures",
    "--funcargs", "--markers", "--fixtures-per-test", "--setup-only", "--setup-plan", "--trace-config",
    "--debug", "--listTests",
}


def _norm_path(p: str) -> str:
    p = p.replace("\\", "/")
    if p.startswith("./") and len(p) > 2:
        p = p[2:]
    if len(p) > 1:
        p = p.rstrip("/")
    return p


def _classify_pytest_target(target: str, res: _SegResult, full_paths: frozenset[str]) -> None:
    res.targets.append(target)
    if "::" in target:
        res.subset(f"node id {target}")
        return
    norm = _norm_path(target)
    if norm in full_paths or norm == "":
        return
    if norm.endswith(".py") or "." in _base(norm) and not norm.endswith("/"):
        res.subset(f"single file {target}")
        return
    res.subset(f"subdirectory {target}")


def _safe_split(text: str) -> list[str]:
    import shlex
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def _pytest_args(args: list[str], res: _SegResult, full_paths: frozenset[str]) -> None:
    res.runner = res.runner or "pytest"
    res.is_test_run = True
    i = 0
    positional_only = False
    while i < len(args):
        tok = args[i]
        i += 1
        if positional_only or not tok.startswith("-") or tok == "-":
            _classify_pytest_target(tok, res, full_paths)
            continue
        if tok == "--":
            positional_only = True
            continue
        opt, _, attached = tok.partition("=") if tok.startswith("--") else (tok, "", "")
        value: str | None = attached if _ else None
        if not tok.startswith("--") and len(tok) > 2 and tok[:2] in _PYTEST_SHORT_VALUE:
            opt, value = tok[:2], tok[2:]
        if opt in _PYTEST_NO_RUN:
            res.is_test_run = False
            res.notes.append(f"`{opt}` does not run tests")
            continue
        if value is None and opt in _PYTEST_VALUE_OPTS:
            if i < len(args):
                value = args[i]
                i += 1
            else:
                value = ""
        if opt == "-o" and value and value.startswith("addopts="):
            res.notes.append("`-o addopts=` analysed as pytest arguments")
            _pytest_args(_safe_split(value[len("addopts="):]), res, full_paths)
            continue
        if opt == "-k":
            res.subset(f"-k expression '{value}'")
        elif opt == "-m":
            res.subset(f"-m marker '{value}'")
        elif opt in ("--lf", "--last-failed"):
            res.subset("--lf/--last-failed reruns only previous failures")
        elif opt in ("--sw", "--stepwise"):
            res.subset("--sw/--stepwise resumes from the last failure")
        elif opt == "--deselect":
            res.subset(f"--deselect {value}")
            if value:
                res.targets.append(value)
        elif opt in ("--ignore", "--ignore-glob"):
            res.subset(f"{opt} {value}")
        elif opt in ("--nf", "--new-first", "--ff", "--failed-first", "-x", "--exitfirst", "--maxfail"):
            res.notes.append(f"`{opt}` changes order / stop point only, not selection")
        elif opt in ("--doctest-modules",):
            res.notes.append("--doctest-modules adds doctests")
    # ``pytest tests/ tests/test_x.py``: a file inside an already-full directory
    # does not shrink the selection, so drop those reasons again.
    full_dirs = [_norm_path(t) for t in res.targets if _norm_path(t) in full_paths]
    if full_dirs:
        def _covered(target: str) -> bool:
            n = _norm_path(target.split("::", 1)[0])
            return any(d == "." or n == d or n.startswith(d + "/") for d in full_dirs)
        res.subset_reasons = [
            r for r in res.subset_reasons
            if not any(r == f"{kind} {t}" and _covered(t)
                       for kind in ("single file", "subdirectory", "node id") for t in res.targets)
        ]


def _unittest_args(args: list[str], res: _SegResult) -> None:
    res.runner = "unittest"
    res.is_test_run = True
    i = 0
    if args and args[0] == "discover":
        res.notes.append("unittest discover")
        args = args[1:]
        value_opts = {"-s", "--start-directory", "-p", "--pattern", "-t", "--top-level-directory"}
        while i < len(args):
            tok = args[i]
            i += 1
            opt, _, attached = tok.partition("=")
            value = attached if _ else None
            if opt in value_opts:
                if value is None and i < len(args):
                    value = args[i]
                    i += 1
                if opt in ("-p", "--pattern") and value and value not in ("test*.py", "test_*.py", "*_test.py", "*test*.py"):
                    res.subset(f"discover pattern '{value}'")
                    res.targets.append(value)
                elif opt in ("-s", "--start-directory") and value:
                    res.targets.append(value)
                    if _norm_path(value) not in DEFAULT_FULL_SUITE_PATHS:
                        res.subset(f"discover start directory {value}")
            elif opt == "-k":
                value = args[i] if i < len(args) else ""
                i += 1
                res.subset(f"-k pattern '{value}'")
            elif not tok.startswith("-"):
                # positional start dir / pattern / top dir (legacy form)
                res.targets.append(tok)
        return
    while i < len(args):
        tok = args[i]
        i += 1
        if tok == "-k":
            value = args[i] if i < len(args) else ""
            i += 1
            res.subset(f"-k pattern '{value}'")
        elif tok.startswith("-k") and len(tok) > 2:
            res.subset(f"-k pattern '{tok[2:]}'")
        elif tok in ("-h", "--help"):
            res.is_test_run = False
        elif not tok.startswith("-"):
            res.targets.append(tok)
            res.subset(f"test name {tok}")


def _nose_args(args: list[str], res: _SegResult) -> None:
    res.runner = "nose"
    res.is_test_run = True
    i = 0
    while i < len(args):
        tok = args[i]
        i += 1
        if tok in ("-a", "-A", "--attr", "--eval-attr", "-m", "--match", "-e", "--exclude", "-i", "--include"):
            value = args[i] if i < len(args) else ""
            i += 1
            res.subset(f"{tok} '{value}'")
        elif tok in ("--collect-only", "--version", "-h", "--help"):
            res.is_test_run = False
        elif not tok.startswith("-"):
            res.targets.append(tok)
            if _norm_path(tok) not in DEFAULT_FULL_SUITE_PATHS:
                res.subset(f"target {tok}")


def _tox_args(args: list[str], res: _SegResult, full_paths: frozenset[str], runner: str) -> None:
    res.runner = runner
    res.is_test_run = True
    if runner == "tox" and args and args[0] in ("run", "r", "run-parallel", "p", "legacy", "le"):
        args = args[1:]
    if runner == "tox" and args and args[0] in ("list", "l", "config", "c", "devenv", "d", "exec", "e", "quickstart", "q", "depends", "de"):
        res.is_test_run = False
        return
    value_opts = {"-e", "--env", "-c", "--conf", "--workdir", "--root", "-p", "--parallel", "-s", "--session", "--sessions",
                  "-k", "--keywords", "-t", "--tags", "-f", "--noxfile", "--envdir", "--result-json", "-x", "--skip-env"}
    i = 0
    while i < len(args):
        tok = args[i]
        i += 1
        if tok == "--":
            res.notes.append(f"args after `--` passed to the test runner inside {runner}")
            _pytest_args(args[i:], res, full_paths)
            res.runner = runner
            return
        opt, _, attached = tok.partition("=")
        if opt in ("-l", "--list", "--listenvs", "--showconfig", "--list-sessions", "-ls", "--version", "-h", "--help", "-L"):
            res.is_test_run = False
            continue
        if opt in value_opts:
            value = attached if _ else (args[i] if i < len(args) else "")
            if not _:
                i += 1
            if opt in ("-e", "--env", "-s", "--session", "--sessions"):
                res.targets.append(value)
                res.notes.append(f"{runner} env/session '{value}' (full suite of that env)")
            elif opt in ("-k", "--keywords", "-t", "--tags"):
                res.notes.append(f"{runner} {opt} selects sessions, not tests")
        elif runner == "nox" and not tok.startswith("-"):
            res.targets.append(tok)


def _make_args(args: list[str], res: _SegResult) -> None:
    res.runner = "make"
    targets = []
    i = 0
    while i < len(args):
        tok = args[i]
        i += 1
        if tok in ("-C", "--directory", "-f", "--file", "--makefile", "-j", "--jobs", "-I", "-o", "-W"):
            if i < len(args) and not args[i].startswith("-"):
                i += 1
            continue
        if tok.startswith("-"):
            continue
        if "=" in tok:
            var, _, val = tok.partition("=")
            if re.search(r"(^|\s)-(k|m)\s|::|\.py\b|--lf|--last-failed|--deselect", val):
                res.subset(f"make variable {var}={val!r} restricts selection")
            continue
        targets.append(tok)
    test_targets = [t for t in targets if re.search(r"test|check|spec|verify", t, re.I)]
    if test_targets:
        res.is_test_run = True
        res.targets.extend(test_targets)
        res.notes.append(f"make target(s) {', '.join(test_targets)}: recipe not inspected")
    else:
        res.is_test_run = False


def _jest_args(args: list[str], res: _SegResult, runner: str = "jest") -> None:
    res.runner = res.runner or runner
    res.is_test_run = True
    value_opts = {"-t", "--testNamePattern", "--testPathPattern", "--testPathIgnorePatterns", "--changedSince",
                  "-c", "--config", "--maxWorkers", "-w", "--reporters", "--rootDir", "--roots", "--selectProjects",
                  "--ignoreProjects", "--shard", "--timeout", "--testTimeout", "--coverageDirectory", "--outputFile",
                  "-g", "--grep", "-r", "--require", "--reporter", "--project", "--dir", "--exclude", "--spec",
                  "--testPathPatterns"}
    i = 0
    if runner == "vitest" and args and args[0] in ("run", "watch", "dev"):
        args = args[1:]
    if runner == "vitest" and args and args[0] in ("list", "bench", "typecheck", "init"):
        res.is_test_run = args[0] == "typecheck"
        args = args[1:]
    while i < len(args):
        tok = args[i]
        i += 1
        if tok == "--":
            continue
        opt, _, attached = tok.partition("=")
        value = attached if _ else None
        if opt in value_opts and value is None:
            value = args[i] if i < len(args) else ""
            i += 1
        if opt in ("-t", "--testNamePattern", "-g", "--grep"):
            res.subset(f"{opt} name pattern '{value}'")
        elif opt in ("--testPathPattern", "--testPathPatterns", "--spec"):
            res.subset(f"{opt} '{value}'")
            if value:
                res.targets.append(value)
        elif opt in ("--testPathIgnorePatterns", "--exclude", "--ignoreProjects"):
            res.subset(f"{opt} '{value}'")
        elif opt in ("-o", "--onlyChanged", "--changed"):
            res.subset(f"{opt} runs only changed tests")
        elif opt in ("--changedSince",):
            res.subset(f"--changedSince '{value}' runs only changed tests")
        elif opt in ("--findRelatedTests", "--related"):
            res.subset(f"{opt} runs only related tests")
        elif opt in ("--onlyFailures", "-f"):
            res.subset(f"{opt} reruns only failures")
        elif opt in ("--selectProjects", "--project"):
            res.subset(f"{opt} '{value}'")
        elif opt in ("--shard",):
            res.subset(f"--shard {value} runs one shard")
        elif opt in ("--listTests", "--version", "-v", "--help", "-h", "--showConfig", "--init"):
            res.is_test_run = False
        elif not tok.startswith("-"):
            res.targets.append(tok)
            if _norm_path(tok) not in DEFAULT_FULL_SUITE_PATHS | {"__tests__"}:
                res.subset(f"path pattern {tok}")


def _go_args(args: list[str], res: _SegResult) -> None:
    res.runner = "go"
    if not args or args[0] != "test":
        res.is_test_run = False
        return
    res.is_test_run = True
    args = args[1:]
    value_opts = {"-run", "-skip", "-bench", "-count", "-timeout", "-tags", "-coverprofile", "-covermode",
                  "-coverpkg", "-cpu", "-parallel", "-p", "-o", "-exec", "-ldflags", "-gcflags", "-mod",
                  "-cpuprofile", "-memprofile", "-blockprofile", "-mutexprofile", "-trace", "-outputdir",
                  "-shuffle", "-list", "-fuzz", "-fuzztime", "-benchtime", "-bench"}
    i = 0
    packages: list[str] = []
    while i < len(args):
        tok = args[i]
        i += 1
        opt, _, attached = tok.partition("=")
        value = attached if _ else None
        if opt in value_opts and value is None:
            value = args[i] if i < len(args) else ""
            i += 1
        if opt in ("-run",):
            res.subset(f"-run '{value}' filters tests")
        elif opt == "-skip":
            res.subset(f"-skip '{value}'")
        elif opt == "-short":
            res.subset("-short skips long-running tests")
        elif opt == "-list":
            res.is_test_run = False
        elif opt in ("-bench",) and value and "-run" not in args:
            res.notes.append("-bench without -run still runs tests")
        elif not tok.startswith("-"):
            packages.append(tok)
    res.targets.extend(packages)
    for pkg in packages:
        if pkg in ("./...", "...", "."):
            continue
        if pkg.endswith("/..."):
            res.subset(f"package pattern {pkg}")
        else:
            res.subset(f"package {pkg}")
    if not packages:
        res.notes.append("go test without ./... tests only the current package")


def _cargo_args(args: list[str], res: _SegResult) -> None:
    res.runner = "cargo"
    if not args or args[0] not in ("test", "t", "nextest"):
        res.is_test_run = False
        return
    res.is_test_run = True
    args = args[1:]
    if args and args[0] == "run":  # cargo nextest run
        args = args[1:]
    value_opts = {"-p", "--package", "--test", "--bin", "--example", "--bench", "--exclude", "--features",
                  "-j", "--jobs", "--target", "--target-dir", "--manifest-path", "--profile", "-Z", "--color",
                  "--config", "--message-format", "-E", "--filter-expr", "--partition", "-P"}
    i = 0
    after_dashes = False
    for_harness: list[str] = []
    while i < len(args):
        tok = args[i]
        i += 1
        if after_dashes:
            for_harness.append(tok)
            continue
        if tok == "--":
            after_dashes = True
            continue
        opt, _, attached = tok.partition("=")
        value = attached if _ else None
        if opt in value_opts and value is None:
            value = args[i] if i < len(args) else ""
            i += 1
        if opt in ("-p", "--package", "--exclude", "--test", "--bin", "--example", "--bench", "-E", "--filter-expr", "--partition", "-P"):
            res.subset(f"{opt} {value}")
            if value:
                res.targets.append(value)
        elif opt in ("--lib", "--doc", "--bins", "--examples", "--tests", "--benches"):
            res.subset(f"{opt} restricts to one target kind")
        elif opt == "--no-run":
            res.is_test_run = False
            res.notes.append("--no-run compiles without running")
        elif opt in ("--workspace", "--all", "--all-targets"):
            res.notes.append(f"{opt}")
        elif not tok.startswith("-"):
            res.targets.append(tok)
            res.subset(f"test name filter '{tok}'")
    j = 0
    while j < len(for_harness):
        tok = for_harness[j]
        j += 1
        if tok == "--skip":
            value = for_harness[j] if j < len(for_harness) else ""
            j += 1
            res.subset(f"-- --skip '{value}'")
        elif tok == "--ignored":
            res.subset("-- --ignored runs only ignored tests")
        elif tok == "--exact":
            res.notes.append("-- --exact")
        elif tok == "--list":
            res.is_test_run = False
        elif not tok.startswith("-"):
            res.targets.append(tok)
            res.subset(f"test name filter '{tok}'")


def _generic_positional_runner(args: list[str], res: _SegResult, runner: str, value_opts: set[str],
                               subset_opts: dict[str, str], no_run: set[str]) -> None:
    res.runner = runner
    res.is_test_run = True
    i = 0
    while i < len(args):
        tok = args[i]
        i += 1
        opt, _, attached = tok.partition("=")
        value = attached if _ else None
        if opt in value_opts and value is None:
            value = args[i] if i < len(args) else ""
            i += 1
        if opt in no_run:
            res.is_test_run = False
        elif opt in subset_opts:
            res.subset(f"{subset_opts[opt]} '{value}'" if value else subset_opts[opt])
        elif not tok.startswith("-") and tok != "--":
            res.targets.append(tok)
            if _norm_path(tok) not in DEFAULT_FULL_SUITE_PATHS:
                res.subset(f"target {tok}")


def _analyse_argv(argv: list[str], res: _SegResult, full_paths: frozenset[str]) -> None:
    argv = _strip_redirections(argv)
    argv = _unwrap(argv, res.notes)
    if not argv:
        return
    name = _base(argv[0])
    args = argv[1:]

    if name in ("pytest", "py.test", "pytest-3", "pytest3"):
        _pytest_args(args, res, full_paths)
        for note in list(res.notes):
            if note.startswith("PYTEST_ADDOPTS="):
                res.notes.append("`PYTEST_ADDOPTS` analysed as pytest arguments")
                _pytest_args(_safe_split(note[len("PYTEST_ADDOPTS="):]), res, full_paths)
    elif name in ("ward", "green"):
        _pytest_args(args, res, full_paths)
        res.runner = name
    elif name == "unittest":
        _unittest_args(args, res)
    elif name in ("nose", "nose2", "nosetests"):
        _nose_args(args, res)
    elif name == "tox":
        _tox_args(args, res, full_paths, "tox")
    elif name == "nox":
        _tox_args(args, res, full_paths, "nox")
    elif name in ("make", "gmake"):
        _make_args(args, res)
    elif name in ("npm-test", "yarn-test", "pnpm-test", "bun-test", "hatch-test", "rye-test", "pdm-test",
                  "uv-test", "poetry-test", "pipenv-test"):
        tool = name[: -len("-test")]
        res.runner = tool
        res.is_test_run = True
        res.notes.append(f"`{tool} test` script: configured test command not inspected")
        passthrough = args[1:] if args and args[0] == "--" else args
        if passthrough:
            if tool in ("npm", "yarn", "pnpm", "bun"):
                _jest_args(passthrough, res, runner=tool)
            else:
                _pytest_args(passthrough, res, full_paths)
            res.runner = tool
    elif name in ("jest", "vitest", "mocha", "ava", "tap", "karma", "cypress", "playwright"):
        if name in ("jest", "vitest", "mocha", "ava"):
            _jest_args(args, res, runner=name)
        else:
            sub = args[1:] if args and args[0] in ("run", "test") else args
            if name in ("cypress", "playwright") and args and args[0] not in ("run", "test"):
                res.runner = name
                res.is_test_run = False
                return
            _jest_args(sub, res, runner=name)
    elif name == "deno":
        if args and args[0] == "test":
            _generic_positional_runner(args[1:], res, "deno", {"--filter", "--coverage"}, {"--filter": "--filter"}, set())
        else:
            res.runner = "deno"
    elif name == "go":
        _go_args(args, res)
    elif name == "cargo":
        _cargo_args(args, res)
    elif name == "rspec":
        _generic_positional_runner(args, res, "rspec", {"-e", "--example", "-t", "--tag", "-P", "--pattern", "-r", "-I",
                                                        "-f", "--format", "-o", "--out", "--exclude-pattern", "--seed"},
                                   {"-e": "-e example", "--example": "--example", "-t": "-t tag", "--tag": "--tag",
                                    "--only-failures": "--only-failures reruns only failures",
                                    "--next-failure": "--next-failure reruns only failures", "-P": "-P pattern",
                                    "--pattern": "--pattern", "--exclude-pattern": "--exclude-pattern"},
                                   {"--version", "-v", "--help", "-h", "--dry-run"})
    elif name == "phpunit":
        _generic_positional_runner(args, res, "phpunit", {"--filter", "--group", "--exclude-group", "--testsuite", "-c",
                                                          "--configuration", "--bootstrap", "--log-junit"},
                                   {"--filter": "--filter", "--group": "--group", "--exclude-group": "--exclude-group",
                                    "--testsuite": "--testsuite"},
                                   {"--version", "--help", "-h", "--list-tests", "--list-suites", "--list-groups"})
    elif name in ("rake",):
        tasks = [a for a in args if not a.startswith("-") and "=" not in a]
        res.runner = "rake"
        res.is_test_run = any(re.search(r"test|spec", t) for t in tasks)
        res.targets.extend(t for t in tasks if re.search(r"test|spec", t))
        for a in args:
            if a.startswith("TEST=") or a.startswith("TESTOPTS=") or a.startswith("SPEC="):
                res.subset(f"rake variable {a}")
    elif name in ("ctest",):
        _generic_positional_runner(args, res, "ctest", {"-R", "--tests-regex", "-E", "--exclude-regex", "-L", "--label-regex",
                                                        "-LE", "-I", "-j", "--parallel", "--test-dir", "-C", "--build-config",
                                                        "--timeout", "-O", "--output-log"},
                                   {"-R": "-R regex", "--tests-regex": "--tests-regex", "-E": "-E exclude", "--exclude-regex": "--exclude-regex",
                                    "-L": "-L label", "--label-regex": "--label-regex", "-LE": "-LE", "-I": "-I index range",
                                    "--rerun-failed": "--rerun-failed reruns only failures"},
                                   {"-N", "--show-only", "--version", "--help"})
    elif name == "dotnet":
        if args and args[0] == "test":
            _generic_positional_runner(args[1:], res, "dotnet", {"--filter", "-c", "--configuration", "-f", "--framework",
                                                                 "-l", "--logger", "-r", "--results-directory", "-s", "--settings",
                                                                 "-o", "--output", "-v", "--verbosity", "-a", "--arch", "--os"},
                                       {"--filter": "--filter"}, {"--list-tests", "-t", "--help", "-h"})
            # positional project path is normal for dotnet; a .csproj is not a subset of tests
            res.subset_reasons = [r for r in res.subset_reasons if not re.search(r"target .*\.(sln|csproj|fsproj)$", r)]
        else:
            res.runner = "dotnet"
    elif name in ("mvn", "mvnw"):
        res.runner = "mvn"
        res.is_test_run = any(a in ("test", "verify", "install", "package") for a in args)
        for a in args:
            if a.startswith("-Dtest=") or a.startswith("-Dit.test=") or a.startswith("-Dgroups=") or a.startswith("-Dsurefire.includes"):
                res.subset(f"maven {a}")
            if a in ("-DskipTests", "-Dmaven.test.skip=true"):
                res.is_test_run = False
                res.notes.append(f"{a} skips tests")
        res.targets.extend(a for a in args if a.startswith("-pl"))
        if any(a == "-pl" or a.startswith("-pl=") or a.startswith("--projects") for a in args):
            res.subset("-pl restricts modules")
    elif name in ("gradle", "gradlew"):
        res.runner = "gradle"
        res.is_test_run = any(a == "test" or a.endswith(":test") or a == "check" for a in args)
        i = 0
        while i < len(args):
            if args[i] == "--tests":
                res.subset(f"--tests '{args[i + 1] if i + 1 < len(args) else ''}'")
                i += 2
                continue
            if args[i].startswith("--tests="):
                res.subset(f"--tests '{args[i].split('=', 1)[1]}'")
            if args[i].endswith(":test") and args[i] != ":test":
                res.subset(f"module task {args[i]}")
            i += 1
    elif name == "manage.py":
        if args and args[0] == "test":
            res.runner = "django"
            res.is_test_run = True
            value_opts = {"--settings", "--pythonpath", "-k", "--tag", "--exclude-tag", "--parallel", "-p", "--pattern",
                          "-t", "--top-level-directory"}
            i = 0
            labels: list[str] = []
            rest = args[1:]
            while i < len(rest):
                tok = rest[i]
                i += 1
                opt, _, attached = tok.partition("=")
                value = attached if _ else None
                if opt in value_opts and value is None:
                    value = rest[i] if i < len(rest) else ""
                    i += 1
                if opt in ("-k", "--tag", "--exclude-tag"):
                    res.subset(f"{opt} '{value}'")
                elif opt in ("-p", "--pattern"):
                    res.subset(f"{opt} '{value}'")
                elif not tok.startswith("-"):
                    labels.append(tok)
            res.targets.extend(labels)
            for lbl in labels:
                res.subset(f"test label {lbl}")
        else:
            res.runner = "django"
            res.is_test_run = False
    elif name == "python-script":
        script = args[0] if args else ""
        if _TEST_FILE_RE.search(script.replace("\\", "/")) or script == "manage.py" or _base(script) in ("runtests.py", "run_tests.py", "run-tests.py"):
            if _base(script) == "manage.py":
                _analyse_argv(["manage.py", *args[1:]], res, full_paths)
                return
            res.runner = "python-script"
            res.is_test_run = True
            res.targets.append(script)
            if _TEST_FILE_RE.search(script.replace("\\", "/")) and _base(script) not in ("runtests.py", "run_tests.py", "run-tests.py", "tests.py"):
                res.subset(f"single file {script}")
            else:
                res.notes.append(f"opaque test script {script}: selection not inspected")
            for extra in args[1:]:
                if not extra.startswith("-"):
                    res.targets.append(extra)
                    res.subset(f"argument {extra} may restrict selection")
                elif extra in ("-k",):
                    res.subset("-k pattern")
        else:
            res.runner = None
    elif name == "python-c":
        code = args[0] if args else ""
        if re.search(r"pytest\.main\(|unittest\.main\(", code):
            res.runner = "pytest" if "pytest" in code else "unittest"
            res.is_test_run = True
            res.notes.append("inline python invoking the runner: args not inspected")
            m = re.search(r"pytest\.main\(\s*\[(.*?)\]", code)
            if m:
                inner_args = [a.strip().strip("'\"") for a in m.group(1).split(",") if a.strip()]
                _pytest_args(inner_args, res, full_paths)
    elif _TEST_SCRIPT_RE.search(argv[0].replace("\\", "/")) or (name in ("bash", "sh", "zsh") and args and _TEST_SCRIPT_RE.search(args[0])):
        script = argv[0] if not name in ("bash", "sh", "zsh") else args[0]
        res.runner = "script"
        res.is_test_run = True
        res.targets.append(script)
        res.notes.append(f"opaque test script {script}: selection not inspected, assumed full")
        for extra in (args if not name in ("bash", "sh", "zsh") else args[1:]):
            if not extra.startswith("-"):
                res.targets.append(extra)
                res.subset(f"script argument {extra} may restrict selection")
    else:
        res.runner = None

    if res.is_test_run:
        res.full_suite = not res.subset_reasons
    else:
        res.full_suite = False


# --------------------------------------------------------------------------- #
# Segment-level analysis (shell control structures)
# --------------------------------------------------------------------------- #

_SH_VALUE_FLAGS = {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}


def _shell_c_payload(argv: list[str]) -> tuple[str, dict[str, bool]] | None:
    """If ``argv`` is ``bash [flags] -c "..."``, return (script, {pipefail, errexit})."""
    if not argv or not _SHELL_RE.match(_base(argv[0])):
        return None
    state = {"pipefail": False, "errexit": False}
    i = 1
    while i < len(argv):
        tok = argv[i]
        if tok in ("-o", "+o") and i + 1 < len(argv):
            if argv[i + 1] == "pipefail":
                state["pipefail"] = tok == "-o"
            if argv[i + 1] == "errexit":
                state["errexit"] = tok == "-o"
            i += 2
            continue
        if tok.startswith("-") and not tok.startswith("--") and len(tok) > 1:
            if "e" in tok[1:]:
                state["errexit"] = True
            if "c" in tok[1:]:
                return (argv[i + 1], state) if i + 1 < len(argv) else None
            i += 1
            continue
        if tok.startswith("--"):
            i += 1
            continue
        return None  # ``bash script.sh``
    return None


def _apply_set(argv: list[str], state: dict[str, bool], mask: list[str]) -> None:
    """Update pipefail/errexit from a ``set ...`` segment."""
    i = 1
    while i < len(argv):
        tok = argv[i]
        if tok in ("-o", "+o") and i + 1 < len(argv):
            if argv[i + 1] == "pipefail":
                state["pipefail"] = tok == "-o"
            elif argv[i + 1] == "errexit":
                if tok == "+o":
                    state["errexit"] = False
                    mask.append("`set +o errexit` disables errexit")
                else:
                    state["errexit"] = True
            i += 2
            continue
        if tok.startswith("-") and len(tok) > 1 and tok != "--":
            if "e" in tok[1:]:
                state["errexit"] = True
            if tok.endswith("o") and i + 1 < len(argv):
                if argv[i + 1] == "pipefail":
                    state["pipefail"] = True
                i += 1
        elif tok.startswith("+") and len(tok) > 1:
            if "e" in tok[1:]:
                state["errexit"] = False
                mask.append("`set +e` disables errexit")
            if tok.endswith("o") and i + 1 < len(argv):
                if argv[i + 1] == "pipefail":
                    state["pipefail"] = False
                i += 1
        i += 1


def _analyse_segment(seg: _Segment, full_paths: frozenset[str], state: dict[str, bool]) -> _SegResult:
    res = _SegResult()
    text = seg.text
    # subshell / group: recurse
    if text.startswith("(") and ")" in text:
        inner = text[1:text.rfind(")")]
        res.inner = _analyse(inner, full_paths=full_paths, pipefail=state["pipefail"], errexit=state["errexit"])
        res.inner_label = "subshell `( ... )`"
    elif text.startswith("{") and "}" in text and (len(text) == 1 or text[1].isspace()):
        inner = text[1:text.rfind("}")]
        res.inner = _analyse(inner, full_paths=full_paths, pipefail=state["pipefail"], errexit=state["errexit"])
        res.inner_label = "group `{ ...; }`"
    else:
        argv = _argv(text)
        argv_clean = _strip_redirections(argv)
        payload = _shell_c_payload(argv_clean)
        if payload is not None:
            script, flags = payload
            res.inner = _analyse(script, full_paths=full_paths, pipefail=flags["pipefail"] or state["pipefail"],
                                 errexit=flags["errexit"])
            res.inner_label = f"`{_base(argv_clean[0])} -c '...'`"
        else:
            _analyse_argv(argv, res, full_paths)
            return res
    inner = res.inner
    assert inner is not None
    res.is_test_run = inner.is_test_run
    res.runner = inner.runner
    res.full_suite = inner.full_suite
    res.subset_reasons = list(inner.subset_reasons)
    res.targets = list(inner.targets)
    res.notes = [f"inside {res.inner_label}: {n}" for n in inner.notes]
    return res


# --------------------------------------------------------------------------- #
# Masking
# --------------------------------------------------------------------------- #

_EXIT_RE = re.compile(r"^(exit|return)(\s+(\S+))?\s*$")


def _tail_command(text: str) -> str:
    """Last simple command of a (possibly grouped) segment text."""
    t = text.strip()
    while t and t[0] in "({" and t[-1] in ")}":
        t = t[1:-1].strip().rstrip(";").strip()
    segs = _split(t)
    return segs[-1].text if segs else t


def _is_failing_command(text: str) -> bool:
    """True when ``cmd`` in ``test || cmd`` keeps a non-zero status."""
    tail = _strip_redirections(_argv(_tail_command(text)))
    joined = " ".join(tail)
    if not tail:
        return False
    if tail[0] == "false":
        return True
    m = _EXIT_RE.match(joined)
    if m:
        code = m.group(3)
        if code is None or code.startswith("$"):
            return True  # ``exit`` / ``exit $?`` propagate the failing status
        return code.strip("'\"") not in ("0",)
    return False


def _preserves_status(after: list[_Segment]) -> bool:
    """``test; rc=$?; ...; exit $rc`` or ``test; exit $?`` keep the status."""
    if not after:
        return True
    first = after[0]
    last = after[-1]
    last_argv = _argv(last.text)
    if last.op_before in (";", "&&") and len(last_argv) == 2 and last_argv[0] == "exit":
        if last_argv[1] == "$?" and len(after) == 1:
            return True
        m = re.match(r"^\$\{?(\w+)\}?$", last_argv[1])
        if m and first.op_before == ";" and re.match(rf"^{re.escape(m.group(1))}=\$\?$", first.text):
            return True
    return False


def _short(text: str, limit: int = 40) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _masking(segs: list[_Segment], idx: int, state: dict[str, bool], seg_res: _SegResult) -> list[str]:
    reasons: list[str] = []
    if seg_res.inner is not None and seg_res.inner.exit_masked:
        for r in seg_res.inner.mask_reasons:
            reasons.append(f"run inside {seg_res.inner_label}: {r}")
    test_seg = segs[idx]
    after = segs[idx + 1:]
    if test_seg.op_after == "&":
        reasons.append("backgrounded with `&`: exit status not waited for")
        return reasons
    if _preserves_status(after):
        return reasons
    pipefail = state["pipefail"]
    errexit = state["errexit"]
    for seg in after:
        op = seg.op_before
        head = _base(_argv(seg.text)[0]) if _argv(seg.text) else seg.text
        if op in ("|", "|&"):
            # With pipefail the pipeline's status is the rightmost non-zero one,
            # so a failing test still surfaces; without it, the last command wins.
            if not pipefail:
                reasons.append(f"piped into `{head}` without `set -o pipefail`")
            if seg.op_after == "&":
                reasons.append("backgrounded with `&`: exit status not waited for")
                break
            continue
        if op == "||":
            if _is_failing_command(seg.text):
                continue
            reasons.append(f"`|| {_short(seg.text)}` swallows a failing exit")
            continue
        if op == "&&":
            # a failing test short-circuits; a passing one lets the rhs decide (fine either way)
            if seg.text.startswith("set") and "+e" in seg.text:
                _apply_set(_argv(seg.text), state, reasons)
            continue
        if op in (";", "&"):
            if errexit:
                continue  # failing test aborts the list before this runs
            argv = _argv(seg.text)
            if argv and argv[0] == "set":
                _apply_set(argv, state, reasons)
                errexit = state["errexit"]
                continue
            reasons.append(f"trailing `; {_short(seg.text)}` replaces the test exit status")
            if seg.op_after == "&":
                break
            continue
    return reasons


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #

def _analyse(command: str, *, full_paths: frozenset[str], pipefail: bool, errexit: bool) -> TestCommandInfo:
    info = TestCommandInfo(command=command)
    segs = _split(command)
    if not segs:
        return info
    state = {"pipefail": pipefail, "errexit": errexit}
    pre_mask: list[str] = []
    results: list[_SegResult] = []
    # Pass 1: per-segment results, tracking ``set`` state as we go so that
    # masking for the test segment sees the state that was in effect *before* it.
    states_before: list[dict[str, bool]] = []
    masks_before: list[list[str]] = []
    for seg in segs:
        states_before.append(dict(state))
        masks_before.append(list(pre_mask))
        argv = _argv(seg.text)
        if argv and argv[0] == "set":
            _apply_set(argv, state, pre_mask)
            results.append(_SegResult())
            continue
        if argv and argv[0] == "cd":
            r = _SegResult()
            r.notes.append(f"ran from `{seg.text}`")
            results.append(r)
            continue
        results.append(_analyse_segment(seg, full_paths, state))

    test_idxs = [i for i, r in enumerate(results) if r.is_test_run]
    for r in results:
        info.notes.extend(r.notes)
    if not test_idxs:
        runners = [r.runner for r in results if r.runner]
        info.runner = runners[-1] if runners else None
        return info

    full_idxs = [i for i in test_idxs if results[i].full_suite]
    primary = full_idxs[-1] if full_idxs else test_idxs[-1]
    pr = results[primary]
    info.is_test_run = True
    info.runner = pr.runner
    info.full_suite = pr.full_suite
    info.subset_reasons = list(pr.subset_reasons)
    info.test_segment = segs[primary].text
    for i in test_idxs:
        for t in results[i].targets:
            if t not in info.targets:
                info.targets.append(t)
        if i != primary and results[i].subset_reasons:
            info.notes.append(f"segment `{_short(segs[i].text)}` was a subset run ({'; '.join(results[i].subset_reasons)})")
        elif i != primary:
            info.notes.append(f"segment `{_short(segs[i].text)}` was a separate full run")
    mask_state = dict(states_before[primary])
    reasons = list(masks_before[primary])
    reasons.extend(_masking(segs, primary, mask_state, pr))
    info.mask_reasons = reasons
    info.exit_masked = bool(reasons)
    return info


def analyse_test_command(command: str, *, full_suite_paths: Iterable[str] | None = None) -> TestCommandInfo:
    """Analyse a recorded shell command string. See the module docstring for rules.

    ``full_suite_paths`` overrides :data:`DEFAULT_FULL_SUITE_PATHS` (e.g. the
    repo's ``testpaths``) for deciding whether a positional directory means
    the whole suite.
    """
    paths = DEFAULT_FULL_SUITE_PATHS if full_suite_paths is None else frozenset(_norm_path(p) for p in full_suite_paths) | {"."}
    try:
        return _analyse(command or "", full_paths=paths, pipefail=False, errexit=False)
    except Exception as exc:  # pragma: no cover - never let a weird string crash the auditor
        info = TestCommandInfo(command=command or "")
        info.notes.append(f"analyser error: {exc!r}")
        return info


analyze_test_command = analyse_test_command


def is_full_unmasked_run(command: str, *, full_suite_paths: Iterable[str] | None = None) -> bool:
    """True when ``command`` runs the whole suite and its exit status is trustworthy."""
    info = analyse_test_command(command, full_suite_paths=full_suite_paths)
    return info.is_test_run and info.full_suite and not info.exit_masked
