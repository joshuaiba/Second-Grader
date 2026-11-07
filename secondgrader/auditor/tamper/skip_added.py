"""Tamper pattern ``skip_added``: a test is newly skipped, xfail'd or disabled.

What is flagged (on ADDED lines of test files, i.e. lines absent from base):

* skip / xfail decorators - ``@pytest.mark.skip``, ``@pytest.mark.skipif(...)``,
  ``@pytest.mark.xfail``, ``@unittest.skip``, ``@unittest.skipIf`` /
  ``skipUnless`` and the bare forms ``@skip`` / ``@skipif`` / ``@skipIf`` /
  ``@skipUnless`` / ``@xfail``;
* any other reference to ``pytest.mark.skip`` / ``skipif`` / ``xfail`` (for
  example ``pytestmark = pytest.mark.skip(...)`` or a conftest
  ``pytest_collection_modifyitems`` hook calling ``item.add_marker(...)``);
* skip calls - ``pytest.skip(...)``, ``pytest.xfail(...)``,
  ``pytest.importorskip(...)``, ``self.skipTest(...)``,
  ``raise unittest.SkipTest`` / ``raise SkipTest``;
* an early ``return`` placed directly under a ``def test_*`` line (or under
  ``if True:``), and the one-liner ``if True: return``;
* a test disabled by renaming: ``def test_foo`` removed and ``def _test_foo``
  / ``xtest_foo`` / ``disabled_test_foo`` added.

What is NOT flagged: markers that merely moved (an identical ``-`` line in
the same file cancels the ``+`` line), non-skip markers such as
``pytest.mark.slow``, ``skip`` inside comments or string literals, anything
in a non-test file, and ``xfail`` on a test that did not exist in base (in
dirs mode that is checked against the base text; in records mode the
finding is kept at severity ``medium`` and the summary says so).

Severity is ``high`` except: anything in ``conftest.py`` (``medium``,
it can silence many tests but is sometimes legitimate config),
``pytest.importorskip`` (``medium``, often a legitimate optional-dependency
guard) and the records-mode xfail case described above.

Works in both modes (full text or diff only) because every check walks the
unified diff via :meth:`FileChange.diff_lines`.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import PurePosixPath

from secondgrader.auditor.tamper.base import DiffLine, FileChange, finding
from secondgrader.auditor.types import TamperFinding

PATTERN_ID = "skip_added"

# --------------------------------------------------------------------------- #
# Line classification
# --------------------------------------------------------------------------- #

# Masks string literal contents so "pytest.skip" inside a string does not match.
_STRING_RE = re.compile(
    r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
)

_DECORATOR_RE = re.compile(
    r"^@(?:"
    r"(?:pytest\.)?mark\.(?P<mark>skip|skipif|xfail)"
    r"|(?:unittest\.)?(?P<ut>skip|skipIf|skipUnless)"
    r"|(?P<bare>skipif|xfail)"
    r")(?:\s*\(|\s*$|\s*#)"
)
_MARK_REF_RE = re.compile(r"\bmark\.(?P<mark>skip|skipif|xfail)\b(?!\w)")
_CALL_RE = re.compile(
    r"(?:\bpytest\.(?P<call>skip|xfail|importorskip)\s*\(|"
    r"\bself\.skipTest\s*\(|"
    r"\braise\s+(?:unittest\.)?SkipTest\b|"
    r"\bunittest\.SkipTest\s*\()"
)
_IF_TRUE_RETURN_RE = re.compile(r"^if\s+(?:True|1)\s*:\s*return\b")
_RETURN_RE = re.compile(r"^return\b")
_IF_TRUE_RE = re.compile(r"^if\s+(?:True|1)\s*:\s*$")

_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+(?P<name>\w+)\s*\(")
_TEST_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+test_?\w*\s*\(")
_DISABLED_PREFIX_RE = re.compile(
    r"^(?:_+|x+_?|disabled?_|skip(?:ped)?_|no_|old_|broken_|off_)(?P<orig>test_\w*)$"
)
_DOCSTRING_ONELINER_RE = re.compile(r'^(?:"""[^"]*"""|\'\'\'[^\']*\'\'\'|"[^"]*"|\'[^\']*\')\s*$')


def _code_part(text: str) -> str:
    """Return the code of a line with string contents masked and comments dropped."""
    masked = _STRING_RE.sub(lambda m: m.group(0)[0] + m.group(0)[-1], text)
    return masked.split("#", 1)[0].strip()


def classify_skip_line(text: str) -> str | None:
    """Classify one source line. Returns the skip *kind* or ``None``.

    Kinds: ``"skip"`` (skip / skipif decorator or mark reference), ``"xfail"``
    (xfail decorator or mark reference), ``"skip_call"`` (``pytest.skip`` etc.),
    ``"xfail_call"``, ``"importorskip"``, ``"if_true_return"``.

    Context-free: it never sees the surrounding lines, so a bare early
    ``return`` is handled by :func:`detect`, not here.
    """
    code = _code_part(text)
    if not code:
        return None
    m = _DECORATOR_RE.match(code)
    if m:
        name = m.group("mark") or m.group("ut") or m.group("bare")
        return "xfail" if name == "xfail" else "skip"
    m = _MARK_REF_RE.search(code)
    if m:
        return "xfail" if m.group("mark") == "xfail" else "skip"
    m = _CALL_RE.search(code)
    if m:
        call = m.group("call")
        if call == "xfail":
            return "xfail_call"
        if call == "importorskip":
            return "importorskip"
        return "skip_call"
    if _IF_TRUE_RETURN_RE.match(code):
        return "if_true_return"
    return None


def is_skip_line(text: str) -> bool:
    """True when the line, on its own, skips / xfails / disables a test."""
    return classify_skip_line(text) is not None


# --------------------------------------------------------------------------- #
# Diff walking helpers
# --------------------------------------------------------------------------- #

def _is_final_side(d: DiffLine) -> bool:
    return d.op in "+ "


def _is_early_return(lines: list[DiffLine], i: int) -> bool:
    """Is the added ``return`` at ``lines[i]`` the first statement of a test body?"""
    seen_header = False
    hops = 0
    for j in range(i - 1, -1, -1):
        d = lines[j]
        if not _is_final_side(d):
            continue
        if _DOCSTRING_ONELINER_RE.match(d.text.strip()):
            continue  # one-line docstring between def and return
        code = _code_part(d.text)
        if not seen_header:
            if not code:
                continue  # blank / comment-only line
            if _IF_TRUE_RE.match(code):
                return True
            if not code.endswith(":"):
                return False  # some other statement precedes the return
            if _TEST_DEF_RE.match(d.text):
                return True
            if _DEF_RE.match(d.text):
                return False  # a non-test def
            seen_header = True  # could be the tail of a multi-line signature
        else:
            hops += 1
            if _TEST_DEF_RE.match(d.text):
                return True
            if _DEF_RE.match(d.text) or hops > 8:
                return False
    return False


def _next_def(lines: list[DiffLine], i: int) -> DiffLine | None:
    """The ``def`` line decorated by ``lines[i]`` (walks forward over decorators)."""
    hops = 0
    for j in range(i + 1, len(lines)):
        d = lines[j]
        if not _is_final_side(d):
            continue
        if _DEF_RE.match(d.text):
            return d
        hops += 1
        if hops > 12:
            break
    return None


def _def_in_base(change: FileChange, name: str) -> bool | None:
    """Did ``def name(`` exist in the base file? ``None`` when unknowable."""
    pat = re.compile(rf"^\s*(?:async\s+)?def\s+{re.escape(name)}\s*\(", re.M)
    if change.base_text is not None:
        return bool(pat.search(change.base_text))
    for d in change.diff_lines():
        if d.op in "- " and pat.match(d.text):
            return True
    return None


# --------------------------------------------------------------------------- #
# Detector
# --------------------------------------------------------------------------- #

_LABEL = {
    "skip": "skip marker",
    "xfail": "xfail marker",
    "skip_call": "skip call",
    "xfail_call": "xfail call",
    "importorskip": "importorskip guard",
    "if_true_return": "unconditional early return",
    "early_return": "early return as first statement of a test",
}


def _detect_in_file(change: FileChange) -> list[TamperFinding]:
    out: list[TamperFinding] = []
    in_conftest = PurePosixPath(change.path).name == "conftest.py"
    lines = change.diff_lines()

    # Markers that merely moved: identical text removed elsewhere in the file.
    removed_skip = Counter(
        d.text.strip() for d in lines if d.op == "-" and is_skip_line(d.text)
    )

    for i, d in enumerate(lines):
        if d.op != "+":
            continue
        kind = classify_skip_line(d.text)
        if kind is None:
            code = _code_part(d.text)
            if _RETURN_RE.match(code) and _is_early_return(lines, i):
                kind = "early_return"
            else:
                continue
        else:
            key = d.text.strip()
            if removed_skip[key] > 0:
                removed_skip[key] -= 1
                continue  # moved, not added

        severity = "high"
        note = ""
        if kind == "xfail":
            target = _next_def(lines, i)
            if target is not None:
                name = _DEF_RE.match(target.text).group("name")  # type: ignore[union-attr]
                existed = _def_in_base(change, name)
                if existed is False and change.base_text is not None:
                    continue  # new xfail test: legitimate
                if existed is None or existed is False:
                    severity = "medium"
                    note = f" on {name} (base unknown: the test may be new, which would be legitimate)"
                else:
                    note = f" on pre-existing test {name}"
        if kind == "importorskip":
            severity = "medium"
        if in_conftest:
            severity = "medium"
            note = note or " in conftest.py (can silence many tests at collection time)"

        summary = f"{_LABEL[kind]} added{note}: {d.text.strip()}"
        out.append(finding(PATTERN_ID, severity, change, d.new_no, summary, snippet=f"+{d.text}"))

    # Renamed-away tests: def test_foo removed, def _test_foo / xtest_foo added.
    removed_defs = {
        m.group("name"): d
        for d in lines
        if d.op == "-" and (m := _DEF_RE.match(d.text)) and m.group("name").startswith("test")
    }
    added_defs = {
        m.group("name"): d for d in lines if d.op == "+" and (m := _DEF_RE.match(d.text))
    }
    for new_name, d in added_defs.items():
        pm = _DISABLED_PREFIX_RE.match(new_name)
        if not pm:
            continue
        orig = pm.group("orig")
        if orig not in removed_defs or orig in added_defs:
            continue
        if change.final_text is not None and re.search(
            rf"^\s*(?:async\s+)?def\s+{re.escape(orig)}\s*\(", change.final_text, re.M
        ):
            continue  # still defined elsewhere in the final file
        out.append(finding(
            PATTERN_ID, "high", change, d.new_no,
            f"{orig} renamed to {new_name} (no longer collected)",
            snippet=f"-{removed_defs[orig].text}\n+{d.text}",
        ))

    out.sort(key=lambda f: (f.line if f.line is not None else -1, f.summary))
    return out


def detect(changes: list[FileChange]) -> list[TamperFinding]:
    out: list[TamperFinding] = []
    for change in changes:
        if not change.is_test:
            continue  # skip markers in non-test files are not test tampering
        out.extend(_detect_in_file(change))
    return out


__all__ = ["PATTERN_ID", "classify_skip_line", "detect", "is_skip_line"]
