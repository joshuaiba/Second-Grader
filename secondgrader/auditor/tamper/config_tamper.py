"""Tamper pattern ``config_tamper``: the test runner's configuration was changed
so that fewer tests are collected or failures stop counting.

Looks only at files that configure test collection / execution and flags
ADDED or CHANGED lines that narrow what runs or hide failures. Everything is
deterministic (no LLM) and works both from full base/final text and from a
unified diff alone (records mode), because every rule is driven by the diff's
``+`` / ``-`` lines plus whatever context the hunk carries.

Files and rules (severity in brackets):

* **pytest ini** (``pytest.ini``, ``pytest.cfg``, ``[tool:pytest]`` in
  ``setup.cfg`` / ``tox.ini``, ``[tool.pytest.ini_options]`` in
  ``pyproject.toml``):

  - ``addopts`` gaining ``-k``, ``-m``, ``--ignore``, ``--ignore-glob``,
    ``--deselect``, ``-p no:<plugin>`` (except harmless plugins such as
    ``cacheprovider``), ``--lf``, ``--co``, ``-o <collection key>=``,
    ``--lfnf=none``, ``-c <file>`` [high];
    ``--continue-on-collection-errors``, ``--noconftest`` [medium].
    One finding per newly added offending option. Options already present
    in base are not re-reported. ``-q``, ``-ra``, ``--tb=short``,
    ``--strict-markers``, ``--timeout``, ``-x``, ``--maxfail`` etc. are fine.
  - ``testpaths`` narrowed: an entry removed, or the list replaced by a
    subset [high]. Adding a dir is fine.
  - ``python_files`` / ``python_functions`` / ``python_classes`` changed so
    the conventional ``test_*.py`` / ``test_*`` / ``Test*`` names no longer
    match [high].
  - ``norecursedirs`` / ``collect_ignore`` / ``collect_ignore_glob`` gaining a
    test dir, test file or ``*`` [high].
  - ``markers``, ``filterwarnings`` and everything else: ignored.

* **conftest.py** (any directory): added ``pytest_collection_modifyitems``,
  ``pytest_ignore_collect``, ``pytest_runtest_makereport``,
  ``pytest_pyfunc_call``, ``pytest_runtest_call``, ``pytest_runtest_setup``,
  ``pytest_runtest_protocol``, ``pytest_collection_finish``,
  ``pytest_report_teststatus`` hooks [high] (lines inside a flagged hook's
  body are not reported again); added ``collect_ignore`` /
  ``collect_ignore_glob`` lists [high]; ``pytest.skip(...)`` or
  ``item.add_marker(...skip...)`` [high]; ``sys.exit(0)`` / ``os._exit`` /
  ``SystemExit`` / ``pytest.exit`` [high]; assignments into ``pytest`` /
  ``_pytest`` internals or test reports (``report.outcome = "passed"``,
  ``call.excinfo = None``, ``session.exitstatus = 0``) [high]; an autouse
  fixture whose body gains a bare ``except ...: pass`` [medium, high when the
  conftest.py is newly added].

* **tox.ini** ``[testenv*] commands``: a pytest invocation gaining the
  narrowing options above, a leading ``-`` (tox ignores the exit code), a
  no-op command (``true`` / ``echo`` / ``exit 0``), or the runner disappearing
  from ``commands`` [high]; ``ignore_errors = True`` / ``ignore_outcome =
  True`` [high].

* **Makefile** (``Makefile`` / ``makefile`` / ``GNUmakefile`` / ``*.mk``):
  a recipe line of a ``test``-like target that invokes a test runner and
  gains ``|| true`` / ``|| :`` / ``|| exit 0`` / ``; true``, a leading ``-``,
  or pytest narrowing options; or the target no longer invoking any runner
  (replaced by ``echo``) [high].

* **package.json** ``"test"`` / ``"test:*"`` script changed to a no-op,
  gaining ``|| true`` / ``|| exit 0``, gaining jest/mocha/vitest/pytest
  narrowing flags, or losing its runner [high]; ``--passWithNoTests`` [medium].

* **.github/workflows/*.yml**: ``continue-on-error: true``, ``if: false``,
  a runner step gaining ``|| true`` or pytest narrowing options [medium].

* **noxfile.py**: ``success_codes`` accepting a non-zero code, or a pytest
  call gaining narrowing options [high].

* **.coveragerc** ``[report] fail_under`` (also ``[coverage:report]`` /
  ``[tool.coverage.report]``) lowered [low]. Nothing else about coverage.

Never flagged: formatting, comments, ``markers`` / ``filterwarnings``
additions, ``testpaths`` gaining a dir, benign ``addopts`` flags, a new
``pytest.ini`` that only sets ``testpaths``.
"""

from __future__ import annotations

import fnmatch
import re
import shlex
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from secondgrader.auditor.tamper.base import (
    DiffLine,
    FileChange,
    finding,
    is_test_path,
    make_diff,
)
from secondgrader.auditor.types import TamperFinding

PATTERN_ID = "config_tamper"
HIGH, MEDIUM, LOW = "high", "medium", "low"

# --------------------------------------------------------------------------- #
# File classification
# --------------------------------------------------------------------------- #

_INI_FILES = {"pytest.ini", "pytest.cfg", "tox.ini", "setup.cfg", ".coveragerc"}
_MAKEFILES = {"makefile", "gnumakefile"}
_WORKFLOW_RE = re.compile(r"(^|/)\.github/workflows/[^/]+\.ya?ml$")


def _kind(path: str) -> str | None:
    p = path.replace("\\", "/")
    name = PurePosixPath(p).name
    if name in _INI_FILES:
        return "ini"
    if name == "pyproject.toml":
        return "toml"
    if name == "conftest.py":
        return "conftest"
    if name == "noxfile.py":
        return "nox"
    if name.lower() in _MAKEFILES or name.endswith(".mk"):
        return "make"
    if name == "package.json":
        return "package_json"
    if _WORKFLOW_RE.search(p):
        return "workflow"
    return None


# --------------------------------------------------------------------------- #
# pytest command-line options that narrow collection or hide failures
# --------------------------------------------------------------------------- #

_BENIGN_NO_PLUGINS = {
    "cacheprovider", "warnings", "randomly", "random_order", "random-order",
    "faulthandler", "pastebin", "legacypath", "stepwise", "debugging", "tmpdir",
    "xdist", "cov", "pytest_cov", "timeout", "sugar", "rerunfailures",
}
_COLLECTION_INI_KEYS = {
    "testpaths", "python_files", "python_functions", "python_classes",
    "addopts", "norecursedirs", "collect_ignore", "collect_ignore_glob",
}
_VALUED_OPTS = {
    "-k": "narrows collection by keyword",
    "-m": "deselects tests by marker",
    "--ignore": "skips collecting a path",
    "--ignore-glob": "skips collecting paths",
    "--deselect": "deselects a test",
    "-p": "disables a plugin",
    "-o": "overrides a collection setting",
    "--override-ini": "overrides a collection setting",
    "-c": "swaps the config file",
    "--config-file": "swaps the config file",
    "--lfnf": "runs nothing when no failures are cached",
    "--last-failed-no-failures": "runs nothing when no failures are cached",
}
_FLAG_OPTS = {
    "--lf": ("runs only previously failed tests", HIGH),
    "--last-failed": ("runs only previously failed tests", HIGH),
    "--co": ("collects without running", HIGH),
    "--collect-only": ("collects without running", HIGH),
    "--continue-on-collection-errors": ("hides collection errors", MEDIUM),
    "--noconftest": ("disables conftest.py", MEDIUM),
}
_RUNNER_MODULES = {"pytest", "py.test", "unittest", "nose", "nose2", "coverage", "tox", "nox"}


@dataclass(frozen=True)
class NarrowingOption:
    display: str   # e.g. ``-m "not slow"``
    reason: str
    severity: str
    token: str     # first token, used to locate the line


def _tokens(text: str) -> list[str]:
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        return text.split()


def _fmt(opt: str, value: str) -> str:
    v = f'"{value}"' if (not value or re.search(r"\s", value)) else value
    return f"{opt}={v}" if opt.startswith("--") else f"{opt} {v}"


def pytest_narrowing_options(tokens: list[str]) -> list[NarrowingOption]:
    """Options in a pytest argv (or ``addopts``) that narrow collection or hide failures."""
    out: list[NarrowingOption] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        opt, value, consumed = tok, None, 1
        if "=" in tok and tok.startswith("-"):
            opt, value = tok.split("=", 1)
        elif tok in _VALUED_OPTS:
            value = tokens[i + 1] if i + 1 < len(tokens) else ""
            consumed = 2
        elif len(tok) > 2 and tok[1] != "-" and tok[:2] in _VALUED_OPTS:
            opt, value = tok[:2], tok[2:]  # ``-kslow`` / ``-pno:x``
        if opt in _FLAG_OPTS and value is None:
            reason, sev = _FLAG_OPTS[opt]
            out.append(NarrowingOption(opt, reason, sev, opt))
        elif opt in _VALUED_OPTS and value is not None:
            if opt == "-m" and value.split(".")[0] in _RUNNER_MODULES:
                i += consumed  # ``python -m pytest``: not the marker option
                continue
            if _is_bad_valued(opt, value):
                sev = MEDIUM if opt in ("-c", "--config-file") else HIGH
                out.append(NarrowingOption(_fmt(opt, value), _VALUED_OPTS[opt], sev, opt))
        i += consumed
    return out


def _is_bad_valued(opt: str, value: str) -> bool:
    if opt == "-p":
        return value.startswith("no:") and value[3:] not in _BENIGN_NO_PLUGINS
    if opt in ("-o", "--override-ini"):
        return value.split("=", 1)[0].strip() in _COLLECTION_INI_KEYS
    if opt in ("--lfnf", "--last-failed-no-failures"):
        return value == "none"
    return True


_PYTEST_CMD_RE = re.compile(r"\bpy\.?test\b")
_RUNNER_RE = re.compile(
    r"\b(pytest|py\.test|unittest|nose2?|tox|nox|jest|mocha|vitest|ava|karma|jasmine|"
    r"cypress|playwright|rspec|phpunit|busted|ctest|go test|cargo test|npm test|yarn test|"
    r"pnpm test|make test|dotnet test|mvn test|gradle test|coverage run|node --test)\b"
)
_SHELL_IGNORE_RE = re.compile(r"\|\|\s*(true|:|exit\s+0|echo\b)|;\s*(true|exit\s+0)\s*$")
_NOOP_RE = re.compile(r"^\s*[@+\-]*\s*(true|:|exit\s+0|echo\b.*|python3?\s+-c\s+['\"]pass)\s*$")


def _line_narrowing(text: str) -> list[NarrowingOption]:
    """Narrowing pytest options on a shell / command line that invokes pytest."""
    if not _PYTEST_CMD_RE.search(text):
        return []
    return pytest_narrowing_options(_tokens(text.replace("$(", "").replace("${", "")))


def _old_narrowing(change: FileChange) -> set[str]:
    return {o.display for d in change.removed_lines() for o in _line_narrowing(d.text)}


# --------------------------------------------------------------------------- #
# INI / TOML entry model
# --------------------------------------------------------------------------- #

@dataclass
class _Entry:
    section: str | None
    key: str
    lines: list[DiffLine] = field(default_factory=list)  # key line first

    @property
    def changed_plus(self) -> bool:
        return any(d.op == "+" for d in self.lines)

    @property
    def changed_minus(self) -> bool:
        return any(d.op == "-" for d in self.lines)

    def first_plus(self) -> DiffLine | None:
        return next((d for d in self.lines if d.op == "+"), None)

    def first_minus(self) -> DiffLine | None:
        return next((d for d in self.lines if d.op == "-"), None)

    def line_with(self, token: str) -> DiffLine | None:
        """First added line mentioning ``token`` as a word (or ``token=``)."""
        pat = re.compile(r"(^|\s)" + re.escape(token) + r"(\s|=|$)")
        for d in self.lines:
            if d.op == "+" and pat.search(d.text):
                return d
        return self.first_plus()

    def text(self) -> str:
        return "\n".join(d.text for d in self.lines)

    def snippet(self) -> str:
        return "\n".join(f"{d.op}{d.text}" for d in self.lines if d.op != " ")


_INI_SECTION_RE = re.compile(r"^\[([^\]]+)\]")
_INI_KEY_RE = re.compile(r"^([A-Za-z_][\w.\-]*)\s*[=:]\s*(.*)$")
_TOML_KEY_RE = re.compile(r"""^((?:[\w\-]+|"[^"]*"|'[^']*')(?:\.(?:[\w\-]+|"[^"]*"|'[^']*'))*)\s*=\s*(.*)$""")
_INLINE_COMMENT_RE = re.compile(r"\s+[#;].*$")


def _strip_comment(s: str) -> str:
    return _INLINE_COMMENT_RE.sub("", s).strip()


def _ini_entries(lines: list[DiffLine], default_section: str | None) -> list[_Entry]:
    entries: list[_Entry] = []
    section = default_section
    cur: _Entry | None = None
    for d in lines:
        t = d.text
        s = t.strip()
        if not s or s[0] in "#;":
            continue
        if not t[0].isspace():
            m = _INI_SECTION_RE.match(s)
            if m:
                section, cur = m.group(1).strip(), None
                continue
            m = _INI_KEY_RE.match(t)
            if m:
                cur = _Entry(section, m.group(1).strip(), [d])
                entries.append(cur)
                continue
            cur = None
        elif cur is not None:
            cur.lines.append(d)
    return entries


def _ini_value(entry: _Entry) -> str:
    parts = []
    for i, d in enumerate(entry.lines):
        t = d.text
        if i == 0:
            m = _INI_KEY_RE.match(t)
            t = m.group(2) if m else ""
        parts.append(_strip_comment(t))
    return " ".join(p for p in parts if p)


def _toml_entries(lines: list[DiffLine]) -> list[_Entry]:
    entries: list[_Entry] = []
    section: str | None = None
    cur: _Entry | None = None
    depth = 0
    triple = False
    for d in lines:
        t = d.text
        s = t.strip()
        if cur is not None and (depth > 0 or triple):
            cur.lines.append(d)
            body = _strip_comment(s) if not triple else s
            depth += body.count("[") - body.count("]")
            if body.count('"""') % 2 or body.count("'''") % 2:
                triple = not triple
            continue
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^\[\[?([^\]]+)\]\]?", s)
        if m:
            section, cur = m.group(1).strip(), None
            continue
        m = _TOML_KEY_RE.match(s)
        if m:
            key = m.group(1).replace('"', "").replace("'", "")
            sec = section
            if key.startswith("tool.pytest.ini_options."):
                sec, key = "tool.pytest.ini_options", key.split(".", 3)[3]
            cur = _Entry(sec, key, [d])
            entries.append(cur)
            val = _strip_comment(m.group(2))
            depth = val.count("[") - val.count("]")
            triple = bool(val.count('"""') % 2 or val.count("'''") % 2)
            continue
        cur = None
    return entries


_TOML_STR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"|\'([^\']*)\'')


def _toml_items(entry: _Entry) -> list[str]:
    """Value as a list: array items, or the single (unquoted) string, or raw tokens."""
    parts = []
    for i, d in enumerate(entry.lines):
        t = d.text.strip()
        if i == 0:
            m = _TOML_KEY_RE.match(t)
            t = m.group(2) if m else ""
        parts.append(t if '"""' in t or "'''" in t else _strip_comment(t))
    raw = "\n".join(parts).strip()
    if raw.startswith("["):
        return [a if a else b for a, b in _TOML_STR_RE.findall(raw)]
    if raw.startswith('"""') or raw.startswith("'''"):
        return [raw[3:-3] if raw.endswith(raw[:3]) and len(raw) >= 6 else raw[3:]]
    m = _TOML_STR_RE.fullmatch(raw)
    if m:
        return [m.group(1) if m.group(1) is not None else m.group(2)]
    return [raw]


def _items(entry: _Entry, toml: bool) -> list[str]:
    return _toml_items(entry) if toml else _ini_value(entry).split()


def _argv(entry: _Entry, toml: bool) -> list[str]:
    if toml:
        items = _toml_items(entry)
        return items if len(items) != 1 else _tokens(items[0])
    return _tokens(_ini_value(entry))


_PYTEST_SECTIONS = {"pytest", "tool:pytest", "tool.pytest.ini_options", "tool.pytest"}
_PYTEST_KEYS = _COLLECTION_INI_KEYS
_TOX_KEYS = {"commands", "ignore_errors", "ignore_outcome"}
_COVERAGE_SECTIONS = {"coverage:report", "tool.coverage.report"}


def _section_kind(name: str, section: str | None, key: str) -> str | None:
    if section is not None:
        sec = section.strip().lower()
        if sec in _PYTEST_SECTIONS:
            return "pytest"
        if sec.startswith("testenv") or sec == "tox":
            return "tox"
        if sec in _COVERAGE_SECTIONS or (sec == "report" and name == ".coveragerc"):
            return "coverage"
        return None
    # Section header outside the hunk (records mode): infer from the key.
    if key in _PYTEST_KEYS and name != ".coveragerc":
        return "pytest"
    if key in _TOX_KEYS and name == "tox.ini":
        return "tox"
    if key == "fail_under":
        return "coverage"
    return None


# --------------------------------------------------------------------------- #
# INI / TOML rules
# --------------------------------------------------------------------------- #

_CANON = {
    "python_files": ("test_parser.py", "parser_test.py"),
    "python_functions": ("test_basic",),
    "python_classes": ("TestParser",),
}


def _pat_matches(name: str, pattern: str, glob_only: bool) -> bool:
    if glob_only or any(c in pattern for c in "*?["):
        return fnmatch.fnmatchcase(name, pattern)
    return name.startswith(pattern)


def _looks_like_tests(item: str) -> bool:
    item = item.strip().strip("/")
    if item in ("*", "**", ".", "*/", "**/*"):
        return True
    return is_test_path(item) or bool(re.search(r"(^|/|_|\*)tests?(_|\*|/|$|\.py)", item))


def _ini_toml_findings(change: FileChange, toml: bool) -> list[TamperFinding]:
    name = PurePosixPath(change.path).name
    diff = change.diff_lines()
    old_side = [d for d in diff if d.op in "- "]
    new_side = [d for d in diff if d.op in "+ "]
    if toml:
        old_e, new_e = _toml_entries(old_side), _toml_entries(new_side)
    else:
        default = "pytest" if name in ("pytest.ini", "pytest.cfg") else None
        old_e, new_e = _ini_entries(old_side, default), _ini_entries(new_side, default)
    old_map = {(e.section, e.key): e for e in old_e}
    new_map = {(e.section, e.key): e for e in new_e}

    out: list[TamperFinding] = []
    for sk in sorted(set(old_map) | set(new_map), key=lambda k: (k[0] or "", k[1])):
        o, n = old_map.get(sk), new_map.get(sk)
        if not ((o and o.changed_minus) or (n and n.changed_plus)):
            continue
        section, key = sk
        kind = _section_kind(name, section, key)
        if kind == "pytest":
            out.extend(_pytest_key(change, key, o, n, toml))
        elif kind == "tox":
            out.extend(_tox_key(change, key, o, n, toml))
        elif kind == "coverage" and key == "fail_under":
            out.extend(_coverage_key(change, o, n, toml))
    return out


def _where(n: _Entry | None, o: _Entry | None, token: str | None = None) -> tuple[int | None, str]:
    """``(line, snippet)`` for a finding about entry ``n`` (new) / ``o`` (old)."""
    if n is not None and n.changed_plus:
        d = n.line_with(token) if token else n.first_plus()
        return (d.new_no if d else None), n.snippet()
    if o is not None and o.changed_minus:
        d = o.first_minus()
        return (d.old_no if d else None), o.snippet()
    return None, ""


def _pytest_key(change: FileChange, key: str, o: _Entry | None, n: _Entry | None,
                toml: bool) -> list[TamperFinding]:
    out: list[TamperFinding] = []
    label = f"{change.path}: {key}"
    if key == "addopts" and n is not None and n.changed_plus:
        old = {x.display for x in pytest_narrowing_options(_argv(o, toml))} if o else set()
        for opt in pytest_narrowing_options(_argv(n, toml)):
            if opt.display in old:
                continue
            line, snip = _where(n, o, opt.token)
            out.append(finding(PATTERN_ID, opt.severity, change, line,
                               f"{label} gained '{opt.display}' ({opt.reason})", snip))
    elif key == "testpaths" and o is not None and n is not None:
        old_items, new_items = _items(o, toml), _items(n, toml)
        removed = [p for p in old_items if p not in new_items]
        if removed:
            line, snip = _where(n, o)
            if not (n.changed_plus) and o.changed_minus:
                d = next((d for d in o.lines if d.op == "-" and removed[0] in d.text), None)
                line = d.old_no if d else line
            out.append(finding(PATTERN_ID, HIGH, change, line,
                               f"{label} narrowed: dropped {', '.join(repr(p) for p in removed)} "
                               f"(now {' '.join(new_items) or 'empty'})", snip))
    elif key in _CANON and n is not None and n.changed_plus:
        pats = _items(n, toml)
        glob_only = key == "python_files"
        if pats and not any(_pat_matches(c, p, glob_only) for c in _CANON[key] for p in pats):
            line, snip = _where(n, o)
            out.append(finding(PATTERN_ID, HIGH, change, line,
                               f"{label} changed to '{' '.join(pats)}' "
                               f"(conventional tests no longer match)", snip))
    elif key in ("norecursedirs", "collect_ignore", "collect_ignore_glob") and n is not None \
            and n.changed_plus:
        old_items = set(_items(o, toml)) if o else set()
        bad = [p for p in _items(n, toml) if p not in old_items and _looks_like_tests(p)]
        if bad:
            line, snip = _where(n, o, bad[0])
            out.append(finding(PATTERN_ID, HIGH, change, line,
                               f"{label} gained {', '.join(repr(p) for p in bad)} "
                               f"(tests no longer collected)", snip))
    return out


_TRUE_RE = re.compile(r"^(true|1|yes|on)$", re.I)


def _tox_key(change: FileChange, key: str, o: _Entry | None, n: _Entry | None,
             toml: bool) -> list[TamperFinding]:
    out: list[TamperFinding] = []
    label = f"{change.path}: [{(n or o).section or 'testenv'}] {key}"
    if key in ("ignore_errors", "ignore_outcome"):
        if n is not None and n.changed_plus and _TRUE_RE.match(_ini_value(n)):
            line, snip = _where(n, o)
            out.append(finding(PATTERN_ID, HIGH, change, line,
                               f"{label} = True (failures no longer fail the env)", snip))
        return out
    if key != "commands":
        return out
    old_text = o.text() if o else ""
    old_opts = {x.display for d in (o.lines if o else []) for x in _line_narrowing(d.text)}
    for d in n.lines if n else []:
        if d.op != "+":
            continue
        cmd = _strip_comment(d.text.split("=", 1)[1] if d is n.lines[0] else d.text)
        if not cmd:
            continue
        snip = f"+{d.text}"
        for opt in _line_narrowing(cmd):
            if opt.display not in old_opts:
                out.append(finding(PATTERN_ID, opt.severity, change, d.new_no,
                                   f"{label} gained '{opt.display}' ({opt.reason})", snip))
        if _RUNNER_RE.search(cmd) and cmd.lstrip().startswith("-"):
            out.append(finding(PATTERN_ID, HIGH, change, d.new_no,
                               f"{label}: '{cmd.strip()}' ignores the exit code (leading '-')", snip))
        elif _NOOP_RE.match(cmd):
            out.append(finding(PATTERN_ID, HIGH, change, d.new_no,
                               f"{label} gained no-op command '{cmd.strip()}'", snip))
    if _RUNNER_RE.search(old_text) and (n is None or not _RUNNER_RE.search(n.text())):
        line, snip = _where(n, o)
        out.append(finding(PATTERN_ID, HIGH, change, line,
                           f"{label} no longer runs a test runner", snip))
    return out


def _coverage_key(change: FileChange, o: _Entry | None, n: _Entry | None,
                  toml: bool) -> list[TamperFinding]:
    if o is None or n is None or not n.changed_plus:
        return []
    try:
        old_v = float(_items(o, toml)[0])
        new_v = float(_items(n, toml)[0])
    except (ValueError, IndexError):
        return []
    if new_v < old_v:
        line, snip = _where(n, o)
        return [finding(PATTERN_ID, LOW, change, line,
                        f"{change.path}: fail_under lowered from {old_v:g} to {new_v:g}", snip)]
    return []


# --------------------------------------------------------------------------- #
# conftest.py
# --------------------------------------------------------------------------- #

_HOOKS = (
    "pytest_collection_modifyitems", "pytest_ignore_collect", "pytest_runtest_makereport",
    "pytest_pyfunc_call", "pytest_runtest_call", "pytest_runtest_setup",
    "pytest_runtest_protocol", "pytest_collection_finish", "pytest_report_teststatus",
)
_HOOK_RE = re.compile(r"^(\s*)(?:async\s+)?def\s+(" + "|".join(_HOOKS) + r")\s*\(")
_COLLECT_IGNORE_RE = re.compile(r"^\s*collect_ignore(?:_glob)?\s*(?:\+?=|\.(?:append|extend)\()")
_SKIP_RE = re.compile(
    r"\.add_marker\(\s*[^)]*\bskip|\bpytest\.skip\(|\bpytest\.mark\.skip(?:if)?\([^)]*\)\s*\(|"
    r"\bapplymarker\(\s*[^)]*\bskip"
)
_EXIT_RE = re.compile(r"\bsys\.exit\(|\bos\._exit\(|\bSystemExit\b|\bpytest\.exit\(")
_INTERNALS_RE = re.compile(
    r"(?:^|[^\w.])(?:_pytest\.[\w.]+|pytest\.[\w.]+|TestReport\.\w+|CallInfo\.\w+)\s*=[^=]|"
    r"\bsetattr\(\s*(?:_pytest|pytest|TestReport|CallInfo)\b|"
    r"\b(?:report|rep|result)\.(?:outcome|longrepr|wasxfail)\s*=[^=]|"
    r"\.excinfo\s*=\s*None|\bexitstatus\s*=\s*0\b|\btestsfailed\s*=\s*0\b"
)
_AUTOUSE_RE = re.compile(r"^\s*@(?:pytest\.)?fixture\(.*\bautouse\s*=\s*True")
_DEF_RE = re.compile(r"^(\s*)(?:async\s+)?def\s+\w+\s*\(")
_BARE_EXCEPT_RE = re.compile(r"^\s*except\s*(?:\(?\s*(?:Exception|BaseException)\s*\)?(?:\s+as\s+\w+)?)?\s*:")
_SWALLOW_RE = re.compile(r"^\s*(pass|return(\s+None)?|continue|\.\.\.)\s*(#.*)?$")


def _indent(text: str) -> int:
    return len(text) - len(text.lstrip())


def _conftest_findings(change: FileChange) -> list[TamperFinding]:
    diff = change.diff_lines()
    new_side = [d for d in diff if d.op in "+ "]
    added_file = change.status == "added"
    out: list[TamperFinding] = []

    hook_indent: int | None = None       # inside a flagged hook body
    autouse_pending = False
    fixture_indent: int | None = None    # inside an autouse fixture body
    for i, d in enumerate(new_side):
        text = d.text
        blank = not text.strip()
        if not blank:
            ind = _indent(text)
            if hook_indent is not None and ind <= hook_indent:
                hook_indent = None
            if fixture_indent is not None and ind <= fixture_indent and not text.lstrip().startswith("@"):
                fixture_indent = None
        if blank:
            continue
        snip = f"+{text}" if d.op == "+" else f" {text}"

        if _AUTOUSE_RE.match(text):
            autouse_pending = True
        m = _DEF_RE.match(text)
        if m and autouse_pending:
            autouse_pending = False
            fixture_indent = len(m.group(1))
        elif m is None and autouse_pending and not text.lstrip().startswith("@"):
            autouse_pending = False

        # Swallowed exceptions inside an autouse fixture (either line may be the added one).
        if fixture_indent is not None and _BARE_EXCEPT_RE.match(text):
            nxt = next((x for x in new_side[i + 1:] if x.text.strip()), None)
            if nxt is not None and _SWALLOW_RE.match(nxt.text) and (d.op == "+" or nxt.op == "+"):
                line = d.new_no if d.op == "+" else nxt.new_no
                out.append(finding(PATTERN_ID, HIGH if added_file else MEDIUM, change, line,
                                   f"{change.path}: autouse fixture swallows exceptions "
                                   f"('{text.strip()} {nxt.text.strip()}')",
                                   f"{snip}\n+{nxt.text}"))

        if d.op != "+":
            continue
        if hook_indent is not None:
            continue  # covered by the hook finding
        m = _HOOK_RE.match(text)
        if m:
            hook_indent = len(m.group(1))
            out.append(finding(PATTERN_ID, HIGH, change, d.new_no,
                               f"{change.path}: added {m.group(2)} hook "
                               f"(can skip, drop or rewrite test results)", snip))
            continue
        if _COLLECT_IGNORE_RE.match(text):
            out.append(finding(PATTERN_ID, HIGH, change, d.new_no,
                               f"{change.path}: added collect_ignore (tests no longer collected)", snip))
        elif _SKIP_RE.search(text):
            out.append(finding(PATTERN_ID, HIGH, change, d.new_no,
                               f"{change.path}: skip applied from conftest ('{text.strip()}')", snip))
        elif _EXIT_RE.search(text):
            out.append(finding(PATTERN_ID, HIGH, change, d.new_no,
                               f"{change.path}: process exit from conftest ('{text.strip()}')", snip))
        elif _INTERNALS_RE.search(text):
            out.append(finding(PATTERN_ID, HIGH, change, d.new_no,
                               f"{change.path}: rewrites pytest internals / test outcome "
                               f"('{text.strip()}')", snip))
    return out


# --------------------------------------------------------------------------- #
# Makefile, package.json, workflows, noxfile
# --------------------------------------------------------------------------- #

_MAKE_TARGET_RE = re.compile(r"^([A-Za-z0-9_.\-/ %$(){}]+?)\s*:(?!=)")
_TEST_TARGET_RE = re.compile(r"^(tests?|check|unittests?|pytest|test[-_]\w+|\w+[-_]tests?)$")


def _make_findings(change: FileChange) -> list[TamperFinding]:
    diff = change.diff_lines()
    old_opts = _old_narrowing(change)
    out: list[TamperFinding] = []
    target: str | None = None
    is_test_target = False
    # target -> (had runner in old side, has runner in new side, first added line)
    per_target: dict[str, list] = {}
    for d in diff:
        text = d.text
        if text.startswith("\t"):
            cmd = text[1:]
            if d.op in "- " and target is not None and _RUNNER_RE.search(cmd):
                per_target.setdefault(target, [False, False, None])[0] = True
            if d.op in "+ " and target is not None and _RUNNER_RE.search(cmd):
                per_target.setdefault(target, [False, False, None])[1] = True
            if d.op == "+" and target is not None:
                slot = per_target.setdefault(target, [False, False, None])
                if slot[2] is None:
                    slot[2] = d
            if d.op != "+" or not (is_test_target or target is None):
                continue
            if not _RUNNER_RE.search(cmd):
                continue
            label = f"{change.path}: target '{target or '?'}'"
            snip = f"+{text}"
            if re.match(r"^[@+]*-", cmd.lstrip()):
                out.append(finding(PATTERN_ID, HIGH, change, d.new_no,
                                   f"{label} ignores the runner's exit code (leading '-')", snip))
            if _SHELL_IGNORE_RE.search(cmd):
                out.append(finding(PATTERN_ID, HIGH, change, d.new_no,
                                   f"{label} hides failures ('{_SHELL_IGNORE_RE.search(cmd).group(0).strip()}')",
                                   snip))
            for opt in _line_narrowing(cmd):
                if opt.display not in old_opts:
                    out.append(finding(PATTERN_ID, opt.severity, change, d.new_no,
                                       f"{label} gained '{opt.display}' ({opt.reason})", snip))
            continue
        if text.strip() and not text[0].isspace():
            m = _MAKE_TARGET_RE.match(text)
            if m and "=" not in m.group(1):
                target = m.group(1).strip()
                is_test_target = bool(_TEST_TARGET_RE.match(target.split()[0]))
            elif not text.startswith(("#", ".")):
                target, is_test_target = None, False
    for tgt, (had, has, first_added) in per_target.items():
        if had and not has and _TEST_TARGET_RE.match(tgt.split()[0]):
            out.append(finding(PATTERN_ID, HIGH, change,
                               first_added.new_no if first_added else None,
                               f"{change.path}: target '{tgt}' no longer runs a test runner"))
    return out


_PKG_SCRIPT_RE = re.compile(r'"(?P<key>test(?:[:\-_][\w:\-]+)?)"\s*:\s*"(?P<val>(?:[^"\\]|\\.)*)"')
_JS_NARROW_RE = re.compile(
    r"(?:^|\s)(--testPathIgnorePatterns|--testNamePattern|--testPathPattern|-t|--grep|-g|"
    r"--onlyChanged|--changedSince|--exclude|--ignore|--skip)(?:[=\s]|$)"
)


def _package_json_findings(change: FileChange) -> list[TamperFinding]:
    old_vals: dict[str, str] = {}
    for d in change.removed_lines():
        m = _PKG_SCRIPT_RE.search(d.text)
        if m:
            old_vals[m.group("key")] = m.group("val")
    out: list[TamperFinding] = []
    for d in change.added_lines():
        m = _PKG_SCRIPT_RE.search(d.text)
        if not m:
            continue
        key, val = m.group("key"), m.group("val").replace('\\"', '"')
        old = old_vals.get(key, "")
        label = f"{change.path}: \"{key}\" script"
        snip = f"+{d.text}"
        if _NOOP_RE.match(val):
            out.append(finding(PATTERN_ID, HIGH, change, d.new_no,
                               f"{label} replaced by no-op '{val}'", snip))
            continue
        sm = _SHELL_IGNORE_RE.search(val)
        if sm and not _SHELL_IGNORE_RE.search(old):
            out.append(finding(PATTERN_ID, HIGH, change, d.new_no,
                               f"{label} hides failures ('{sm.group(0).strip()}')", snip))
        old_js = set(_JS_NARROW_RE.findall(old))
        for flag in _JS_NARROW_RE.findall(val):
            if flag not in old_js:
                out.append(finding(PATTERN_ID, HIGH, change, d.new_no,
                                   f"{label} gained '{flag}' (narrows which tests run)", snip))
        if "--passWithNoTests" in val and "--passWithNoTests" not in old:
            out.append(finding(PATTERN_ID, MEDIUM, change, d.new_no,
                               f"{label} gained '--passWithNoTests'", snip))
        old_py = {o.display for o in _line_narrowing(old)}
        for opt in _line_narrowing(val):
            if opt.display not in old_py:
                out.append(finding(PATTERN_ID, opt.severity, change, d.new_no,
                                   f"{label} gained '{opt.display}' ({opt.reason})", snip))
        if _RUNNER_RE.search(old) and not _RUNNER_RE.search(val):
            out.append(finding(PATTERN_ID, HIGH, change, d.new_no,
                               f"{label} no longer runs a test runner ('{val}')", snip))
    return out


_CONTINUE_RE = re.compile(r"^\s*-?\s*continue-on-error\s*:\s*true\b")
_IF_FALSE_RE = re.compile(r"^\s*-?\s*if\s*:\s*(?:\$\{\{\s*)?false\b")


def _workflow_findings(change: FileChange) -> list[TamperFinding]:
    old_opts = _old_narrowing(change)
    old_text = "\n".join(d.text for d in change.removed_lines())
    out: list[TamperFinding] = []
    for d in change.added_lines():
        text = d.text
        snip = f"+{text}"
        label = f"{change.path}"
        if _CONTINUE_RE.match(text):
            out.append(finding(PATTERN_ID, MEDIUM, change, d.new_no,
                               f"{label}: step gained 'continue-on-error: true'", snip))
        elif _IF_FALSE_RE.match(text):
            out.append(finding(PATTERN_ID, MEDIUM, change, d.new_no,
                               f"{label}: step/job disabled with 'if: false'", snip))
        elif _RUNNER_RE.search(text):
            sm = _SHELL_IGNORE_RE.search(text)
            if sm and not _SHELL_IGNORE_RE.search(old_text):
                out.append(finding(PATTERN_ID, MEDIUM, change, d.new_no,
                                   f"{label}: test step hides failures ('{sm.group(0).strip()}')", snip))
            for opt in _line_narrowing(text):
                if opt.display not in old_opts:
                    out.append(finding(PATTERN_ID, MEDIUM, change, d.new_no,
                                       f"{label}: test step gained '{opt.display}' ({opt.reason})", snip))
    return out


_SUCCESS_CODES_RE = re.compile(r"success_codes\s*=\s*[\[(]([^\])]*)[\])]")


def _nox_findings(change: FileChange) -> list[TamperFinding]:
    old_opts = _old_narrowing(change)
    out: list[TamperFinding] = []
    for d in change.added_lines():
        text = d.text
        snip = f"+{text}"
        m = _SUCCESS_CODES_RE.search(text)
        if m and any(c.strip() not in ("0", "") for c in m.group(1).split(",")):
            out.append(finding(PATTERN_ID, HIGH, change, d.new_no,
                               f"{change.path}: success_codes accept a failing exit code", snip))
        for opt in _line_narrowing(text.replace('", "', " ").replace("', '", " ")):
            if opt.display not in old_opts:
                out.append(finding(PATTERN_ID, opt.severity, change, d.new_no,
                                   f"{change.path}: pytest call gained '{opt.display}' ({opt.reason})",
                                   snip))
    return out


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #

def detect(changes: list[FileChange]) -> list[TamperFinding]:
    out: list[TamperFinding] = []
    for change in changes:
        kind = _kind(change.path)
        if kind is None or change.status == "deleted":
            continue
        if kind == "ini":
            out.extend(_ini_toml_findings(change, toml=False))
        elif kind == "toml":
            out.extend(_ini_toml_findings(change, toml=True))
        elif kind == "conftest":
            out.extend(_conftest_findings(change))
        elif kind == "make":
            out.extend(_make_findings(change))
        elif kind == "package_json":
            out.extend(_package_json_findings(change))
        elif kind == "workflow":
            out.extend(_workflow_findings(change))
        elif kind == "nox":
            out.extend(_nox_findings(change))
    return out


def detect_text(path: str, base: str | None, final: str | None) -> list[TamperFinding]:
    """Run the pattern on one file given its full base and final text (dirs mode)."""
    status = "added" if base is None else "deleted" if final is None else "modified"
    return detect([FileChange(path, base, final, make_diff(path, base, final), [], status)])


def detect_added(path: str, added: str, base: str = "") -> list[TamperFinding]:
    """Findings when ``added`` (one or more lines) is appended to ``base`` in ``path``.

    Test helper: ``base`` may be ``""`` for a file that did not exist.
    """
    if base and not base.endswith("\n"):
        base += "\n"
    final = base + added + ("" if added.endswith("\n") else "\n")
    return detect_text(path, base if base else None, final)


__all__ = ["PATTERN_ID", "NarrowingOption", "detect", "detect_added", "detect_text",
           "pytest_narrowing_options"]
