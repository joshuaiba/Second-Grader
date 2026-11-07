"""Tamper pattern ``assert_weakened``: an assertion in a test was made weaker.

Works purely from the unified diff (so it behaves the same in dirs mode and
records mode). The diff is walked hunk by hunk; every maximal run of ``-``/``+``
lines between two context lines is a *region*. Inside a region each removed
``assert`` is paired with the most similar added ``assert`` and the pair is
judged by :func:`is_weaker`. A removed assert with no replacement in its
region is flagged too, unless the whole test function went with it (that is
``test_deleted``'s job) or the same assert was merely moved elsewhere.

Rules (all deterministic, no LLM):

* ``==`` / ``is <literal>`` replaced by ``is not None``, ``!= None``,
  ``is not False``, ``in``, ``len(...) > 0``, ``isinstance(...)``, ``>= 0``,
  ``bool(...)``, a bare name, ``True`` / ``1`` ... -> weaker.
* a top-level ``and`` conjunct dropped, or an ``or`` introduced -> weaker.
* ``x > N`` -> ``x > M`` with ``M < N`` (and the mirror for ``<``) -> weaker.
* assert removed with nothing replacing it, commented out (``# assert ...``)
  or wrapped in ``try: ... except: pass`` -> flagged.
* ``pytest.raises(SpecificError)`` -> ``pytest.raises(Exception)`` /
  ``BaseException`` or a dropped ``match=`` -> weaker.
* NOT flagged: whitespace/formatting-only edits, renames with the same
  operator, a stricter assert, a brand new assert, non-test files.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from dataclasses import dataclass

from secondgrader.auditor.tamper.base import DiffLine, FileChange, finding
from secondgrader.auditor.types import TamperFinding

PATTERN_ID = "assert_weakened"
SEVERITY = "high"

# --------------------------------------------------------------------------- #
# Line classification
# --------------------------------------------------------------------------- #

_ASSERT_RE = re.compile(r"^\s*assert(\s+|$)")
_COMMENTED_ASSERT_RE = re.compile(r"^\s*#\s*assert(\s+|$)")
_RAISES_RE = re.compile(r"\braises\(\s*([A-Za-z_][\w.]*)\s*(,|\))")
_RAISES_MATCH_RE = re.compile(r"\bmatch\s*=")
_DEF_TEST_RE = re.compile(r"^\s*(async\s+)?def\s+test")
_TRY_RE = re.compile(r"^\s*try\s*:")
_EXCEPT_RE = re.compile(r"^\s*except\b")
_PASS_RE = re.compile(r"^\s*(pass|\.\.\.)\s*(#.*)?$")

_BROAD_EXCEPTIONS = {"Exception", "BaseException"}
_NONEISH = {"None", "False"}
_LOOSE_CALLS = {"isinstance", "issubclass", "hasattr", "callable", "len"}
_TRUTHY_CALLS = {"bool", "any", "str", "repr"}

# Operators in the order they must be matched (longest first).
_COMPARISON_OPS = (" is not ", " not in ", " is ", " in ", "==", "!=", "<=", ">=", "<", ">")

# Strength ranks for a single assert expression.
RANK_TRIVIAL = 0    # assert True / assert 1
RANK_TRUTHY = 1     # assert x / assert bool(x) / assert not x
RANK_LOOSE = 2      # is not None / != None / in / len(x) > 0 / isinstance / >= 0
RANK_PREDICATE = 3  # x.startswith("a") / x > 5 / x != 7
RANK_EXACT = 4      # x == y / x is None / x is True


def is_assert_line(text: str) -> bool:
    return bool(_ASSERT_RE.match(text))


def is_raises_line(text: str) -> bool:
    return "raises(" in text and not text.lstrip().startswith("#")


# --------------------------------------------------------------------------- #
# Tiny expression scanner (bracket / string aware, no AST needed)
# --------------------------------------------------------------------------- #

def _scan_top_level(expr: str):
    """Yield ``(index, char)`` for characters at bracket depth 0 outside strings."""
    depth = 0
    quote: str | None = None
    i = 0
    n = len(expr)
    while i < n:
        c = expr[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if expr.startswith(quote, i):
                i += len(quote)
                quote = None
                continue
            i += 1
            continue
        if c in "\"'":
            quote = expr[i:i + 3] if expr.startswith(c * 3, i) else c
            i += len(quote)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0:
            yield i, c
        i += 1


def _split_top_level(expr: str, sep: str) -> list[str]:
    """Split ``expr`` on ``sep`` occurring at depth 0 outside strings."""
    parts: list[str] = []
    last = 0
    positions = {i for i, _ in _scan_top_level(expr)}
    i = 0
    while i <= len(expr) - len(sep):
        if i in positions and expr.startswith(sep, i) and all(
            (i + k) in positions for k in range(len(sep))
        ):
            parts.append(expr[last:i])
            last = i + len(sep)
            i = last
            continue
        i += 1
    parts.append(expr[last:])
    return parts


def _find_comparison(expr: str) -> tuple[str, str, str] | None:
    """Return ``(lhs, op, rhs)`` for the first top-level comparison, else None."""
    positions = {i for i, _ in _scan_top_level(expr)}
    best: tuple[int, str] | None = None
    for op in _COMPARISON_OPS:
        start = 0
        while True:
            idx = expr.find(op, start)
            if idx < 0:
                break
            if all((idx + k) in positions for k in range(len(op))):
                # "<" must not be part of "<=", ">" not part of ">=" or "->", "=" not part of "==".
                nxt = expr[idx + len(op):idx + len(op) + 1]
                prv = expr[idx - 1:idx]
                if op in ("<", ">") and nxt == "=":
                    start = idx + 1
                    continue
                if op == ">" and prv == "-":
                    start = idx + 1
                    continue
                if best is None or idx < best[0]:
                    best = (idx, op)
                break
            start = idx + 1
    if best is None:
        return None
    idx, op = best
    return expr[:idx].strip(), op.strip(), expr[idx + len(op):].strip()


# --------------------------------------------------------------------------- #
# Assert parsing and ranking
# --------------------------------------------------------------------------- #

_WS_RE = re.compile(r"\s+")


def normalize(text: str) -> str:
    """Whitespace-insensitive form of a line: used to detect formatting-only edits."""
    return _WS_RE.sub(" ", text.strip())


def assert_expr(line: str) -> str:
    """The expression of an ``assert`` line, with the optional message dropped."""
    body = line.strip()
    if body.startswith("assert"):
        body = body[len("assert"):].strip()
    # strip a trailing comment (best effort; only at depth 0 outside strings)
    for i, c in _scan_top_level(body):
        if c == "#":
            body = body[:i]
            break
    parts = _split_top_level(body, ",")
    return normalize(parts[0]) if parts else ""


def _is_literal(s: str) -> bool:
    s = s.strip()
    return s in ("True", "False", "None", "...") or bool(re.fullmatch(r"[+-]?\d+(\.\d+)?", s)) or (
        len(s) >= 2 and s[0] in "\"'" and s[-1] == s[0]
    )


def _is_number(s: str) -> float | None:
    try:
        return float(s.strip())
    except ValueError:
        return None


def _call_name(expr: str) -> str | None:
    m = re.match(r"^\s*([A-Za-z_][\w.]*)\s*\(", expr)
    return m.group(1).rsplit(".", 1)[-1] if m else None


def _rank_atom(expr: str) -> int:
    """Rank one comparison-free conjunct."""
    e = expr.strip()
    while e.startswith("(") and e.endswith(")") and _split_top_level(e[1:-1], ",") == [e[1:-1]]:
        e = e[1:-1].strip()
    if _is_literal(e):
        return RANK_TRIVIAL
    if e.startswith("not "):
        return RANK_TRUTHY
    name = _call_name(e)
    if name is not None:
        if name in _TRUTHY_CALLS or name == "len":
            return RANK_TRUTHY
        if name in _LOOSE_CALLS:
            return RANK_LOOSE
        return RANK_PREDICATE
    # bare name / attribute / subscript
    return RANK_TRUTHY


def rank_conjunct(expr: str) -> int:
    """Strength rank of one top-level conjunct (no ``and`` / ``or`` inside)."""
    cmp = _find_comparison(expr)
    if cmp is None:
        return _rank_atom(expr)
    lhs, op, rhs = cmp
    lhs_call = _call_name(lhs)
    if op in ("is not", "!=") and rhs in _NONEISH:
        return RANK_LOOSE
    if op == "is":
        return RANK_EXACT
    if op == "==":
        return RANK_EXACT
    if op == "in":
        return RANK_LOOSE
    if op in ("not in", "!="):
        return RANK_PREDICATE
    # ordering comparisons
    num = _is_number(rhs)
    if num is not None:
        if lhs_call == "len" and op in (">", ">=") and num <= 1:
            return RANK_LOOSE
        if op in (">", ">=") and num <= 0:
            return RANK_LOOSE
        if op in ("<", "<=") and lhs_call == "len" and num <= 0:
            return RANK_PREDICATE
    return RANK_PREDICATE


def rank_assert(expr: str) -> int:
    """Strength rank of a whole assert expression (max over ``and`` conjuncts)."""
    if _split_top_level(expr, " or ") != [expr]:
        # a disjunction is only as strong as its weakest branch
        return min(rank_conjunct(p) for p in _split_top_level(expr, " or "))
    conj = _split_top_level(expr, " and ")
    return max(rank_conjunct(p) for p in conj)


def _ordering_weaker(old: str, new: str) -> bool:
    """``x > 5`` -> ``x > 3`` style loosening with the same LHS and numeric RHS."""
    oc, nc = _find_comparison(old), _find_comparison(new)
    if oc is None or nc is None:
        return False
    if normalize(oc[0]) != normalize(nc[0]):
        return False
    on, nn = _is_number(oc[2]), _is_number(nc[2])
    if on is None or nn is None:
        return False
    if oc[1] in (">", ">=") and nc[1] in (">", ">="):
        return nn < on or (nn == on and oc[1] == ">" and nc[1] == ">=")
    if oc[1] in ("<", "<=") and nc[1] in ("<", "<="):
        return nn > on or (nn == on and oc[1] == "<" and nc[1] == "<=")
    return False


def is_weaker(old: str, new: str) -> bool:
    """True when assert line ``new`` checks less than assert line ``old``.

    Both arguments are full ``assert ...`` lines (or bare expressions).
    Formatting-only changes, renames with the same operator and comparable
    RHS, and strictly stronger rewrites all return False.
    """
    o, n = assert_expr(old), assert_expr(new)
    if not o or not n or o == n:
        return False
    # ``or`` introduced where there was none
    if _split_top_level(o, " or ") == [o] and _split_top_level(n, " or ") != [n]:
        return True
    # a conjunct dropped
    oc = {normalize(p) for p in _split_top_level(o, " and ")}
    nc = {normalize(p) for p in _split_top_level(n, " and ")}
    if nc < oc:
        return True
    if rank_assert(n) < rank_assert(o):
        return True
    if _ordering_weaker(o, n):
        return True
    return False


def raises_weaker(old: str, new: str) -> tuple[str, str] | None:
    """``(old_exc, new_exc)`` when a ``raises(...)`` line got broader, else None."""
    om, nm = _RAISES_RE.search(old), _RAISES_RE.search(new)
    if om is None or nm is None:
        return None
    oexc, nexc = om.group(1).rsplit(".", 1)[-1], nm.group(1).rsplit(".", 1)[-1]
    if nexc in _BROAD_EXCEPTIONS and oexc not in _BROAD_EXCEPTIONS:
        return om.group(1), nm.group(1)
    if oexc == nexc and _RAISES_MATCH_RE.search(old) and not _RAISES_MATCH_RE.search(new):
        return f"{om.group(1)}, match=...", nm.group(1)
    return None


# --------------------------------------------------------------------------- #
# Summaries
# --------------------------------------------------------------------------- #

def _abbrev(expr: str, limit: int = 40) -> str:
    e = expr.strip()
    for o, c in ("{}", "[]", "()"):
        if e.startswith(o) and e.endswith(c) and len(e) > 6:
            return f"{o}...{c}"
    return e if len(e) <= limit else e[: limit - 3] + "..."


def describe(line: str) -> str:
    """Short human form of an assert's check, e.g. ``'== {...}'`` or ``'is not None'``."""
    expr = assert_expr(line)
    cmp = _find_comparison(expr)
    if cmp is None:
        return _abbrev(expr)
    _, op, rhs = cmp
    return f"{op} {_abbrev(rhs)}"


# --------------------------------------------------------------------------- #
# Diff walking
# --------------------------------------------------------------------------- #

@dataclass
class _Region:
    removed: list[DiffLine]
    added: list[DiffLine]


def _regions(lines: list[DiffLine]) -> list[_Region]:
    out: list[_Region] = []
    cur: _Region | None = None
    for d in lines:
        if d.op == " ":
            if cur is not None:
                out.append(cur)
                cur = None
            continue
        if cur is None:
            cur = _Region([], [])
        (cur.removed if d.op == "-" else cur.added).append(d)
    if cur is not None:
        out.append(cur)
    return out


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, assert_expr(a), assert_expr(b)).ratio()


def _pair_asserts(removed: list[DiffLine], added: list[DiffLine]) -> list[tuple[DiffLine, DiffLine | None]]:
    """Greedy best-similarity pairing of removed asserts with added asserts."""
    free = list(added)
    pairs: list[tuple[DiffLine, DiffLine | None]] = []
    for r in removed:
        if not free:
            pairs.append((r, None))
            continue
        best = max(free, key=lambda a: (_similarity(r.text, a.text), -(a.new_no or 0)))
        free.remove(best)
        pairs.append((r, best))
    return pairs


def _wrapped_in_try(region: _Region, added_assert: DiffLine) -> bool:
    """Was ``added_assert`` placed between an added ``try:`` and an added ``except ...: pass``?"""
    texts = region.added
    try_idx = [i for i, d in enumerate(texts) if _TRY_RE.match(d.text)]
    if not try_idx:
        return False
    pos = texts.index(added_assert)
    t = max((i for i in try_idx if i < pos), default=None)
    if t is None:
        return False
    for j in range(pos + 1, len(texts)):
        if _EXCEPT_RE.match(texts[j].text):
            return any(_PASS_RE.match(texts[k].text) for k in range(j + 1, min(j + 3, len(texts))))
    return False


def _detect_file(change: FileChange) -> list[TamperFinding]:
    lines = change.diff_lines()
    all_added_asserts = {assert_expr(d.text) for d in lines if d.op == "+" and is_assert_line(d.text)}
    out: list[TamperFinding] = []

    for region in _regions(lines):
        removed_asserts = [d for d in region.removed if is_assert_line(d.text)]
        added_asserts = [d for d in region.added if is_assert_line(d.text)]
        commented = [d for d in region.added if _COMMENTED_ASSERT_RE.match(d.text)]
        def_removed = any(_DEF_TEST_RE.match(d.text) for d in region.removed)

        for r, a in _pair_asserts(removed_asserts, added_asserts):
            if a is None:
                if assert_expr(r.text) in all_added_asserts:
                    continue  # moved, not removed
                if def_removed:
                    continue  # whole test went away: test_deleted's job
                merged = any(
                    assert_expr(r.text) and _lhs(r.text) and len(_lhs(r.text)) > 3
                    and _lhs(r.text) in assert_expr(x.text)
                    for x in added_asserts
                )
                if merged:
                    continue
                c = next((c for c in commented if _similarity(c.text.lstrip().lstrip("#"), r.text) >= 0.6), None)
                if c is not None:
                    out.append(finding(
                        PATTERN_ID, SEVERITY, change, c.new_no,
                        f"assert in {change.path} commented out: '{describe(r.text)}'",
                        f"-{r.text}\n+{c.text}",
                    ))
                else:
                    out.append(finding(
                        PATTERN_ID, SEVERITY, change, r.old_no,
                        f"assert in {change.path} removed with no replacement: '{_abbrev(assert_expr(r.text))}'",
                        f"-{r.text}",
                    ))
                continue

            if normalize(r.text) == normalize(a.text) or assert_expr(r.text) == assert_expr(a.text):
                if _wrapped_in_try(region, a):
                    out.append(finding(
                        PATTERN_ID, SEVERITY, change, a.new_no,
                        f"assert in {change.path} wrapped in try/except: '{describe(r.text)}'",
                        f"-{r.text}\n+{a.text}",
                    ))
                continue  # formatting only
            if is_weaker(r.text, a.text):
                out.append(finding(
                    PATTERN_ID, SEVERITY, change, a.new_no,
                    f"assert in {change.path} weakened: '{describe(r.text)}' -> '{describe(a.text)}'",
                    f"-{r.text}\n+{a.text}",
                ))
            elif _wrapped_in_try(region, a):
                out.append(finding(
                    PATTERN_ID, SEVERITY, change, a.new_no,
                    f"assert in {change.path} wrapped in try/except: '{describe(r.text)}'",
                    f"-{r.text}\n+{a.text}",
                ))

        # pytest.raises(Specific) -> pytest.raises(Exception)
        removed_raises = [d for d in region.removed if is_raises_line(d.text)]
        added_raises = [d for d in region.added if is_raises_line(d.text)]
        for r, a in zip(removed_raises, added_raises):
            weak = raises_weaker(r.text, a.text)
            if weak is not None:
                out.append(finding(
                    PATTERN_ID, SEVERITY, change, a.new_no,
                    f"pytest.raises in {change.path} weakened: '{weak[0]}' -> '{weak[1]}'",
                    f"-{r.text}\n+{a.text}",
                ))

    return out


def _lhs(line: str) -> str:
    cmp = _find_comparison(assert_expr(line))
    return normalize(cmp[0]) if cmp else ""


def detect(changes: list[FileChange]) -> list[TamperFinding]:
    """Run the pattern over every test-file change."""
    out: list[TamperFinding] = []
    for change in changes:
        if not change.is_test or not change.diff:
            continue
        out.extend(_detect_file(change))
    return out


__all__ = ["PATTERN_ID", "SEVERITY", "describe", "detect", "is_weaker", "raises_weaker", "rank_assert"]
