"""Tamper pattern ``expected_value_edited``: the test keeps its shape, the numbers move.

The sibling pattern ``assert_weakened`` owns assertions that get *looser*
(``==`` -> ``is not None``, removed asserts, ``raises(Exception)``). This one
owns assertions whose operator and shape stay the same but whose LITERALS
change, so that a broken implementation now "passes":

* ``expected_value`` (high) - the right-hand side of an ``assert a == b``
  changed, e.g. ``== {"url": "http://x?y=z"}`` -> ``== {"url": "http://x?y"}``;
* ``test_input`` (medium) - the call arguments on the LEFT side changed while
  the expected value stayed, so the test no longer exercises the bug;
* ``exception_type`` (high) - ``pytest.raises(ValueError)`` ->
  ``pytest.raises(KeyError)`` (a different *specific* exception; widening to
  ``Exception``/``BaseException`` or to a tuple that still contains the old
  one is ``assert_weakened``'s case and is not reported here);
* ``assert_equal_args`` (high) - ``self.assertEqual(...)`` family with
  changed literal arguments;
* ``parametrize`` (high) - ``@pytest.mark.parametrize(...)`` literals changed;
* ``expected_assignment`` (medium) - ``expected = ...`` / ``EXPECTED_X = ...``
  assignments whose literal changed;
* ``match_loosened`` (low) - ``pytest.raises(..., match=...)`` whose pattern
  became looser (empty, or a strict substring of the old one).

Pairing: a removed line and an added line in the same diff region (between
two context lines) are paired by kind (``assert`` with ``assert``,
``raises`` with ``raises``, ``self.assertEqual`` with the same prefix up to
the first ``(``, ...), most similar text first. Each line is parsed with
:mod:`ast` after stripping indentation; lines that do not parse on their own
(multi-line literals, ``assert x == (``) fall back to a token comparison and
are attributed to the enclosing statement found by indentation.

Never flagged: whitespace/format-only changes, variable renames, a new assert
with no removed partner, non-test files, f-strings, and anything whose
comparison operator changed (that is ``assert_weakened``'s job).
Deterministic, no LLM.
"""

from __future__ import annotations

import ast
import copy
import difflib
import io
import re
import tokenize
from dataclasses import dataclass

from secondgrader.auditor.tamper.base import DiffLine, FileChange, finding
from secondgrader.auditor.types import TamperFinding

PATTERN_ID = "expected_value_edited"
SEVERITY = "high"

CATEGORY_SEVERITY: dict[str, str] = {
    "expected_value": "high",
    "test_input": "medium",
    "exception_type": "high",
    "assert_equal_args": "high",
    "parametrize": "high",
    "expected_assignment": "medium",
    "match_loosened": "low",
}

_CATEGORY_LABEL: dict[str, str] = {
    "expected_value": "expected value changed",
    "test_input": "test input changed",
    "exception_type": "expected exception changed",
    "assert_equal_args": "assertion arguments changed",
    "parametrize": "parametrize values changed",
    "expected_assignment": "expected assignment changed",
    "match_loosened": "raises match pattern loosened",
}

# --------------------------------------------------------------------------- #
# Line kinds (what a line *is*, used both for pairing and for classification)
# --------------------------------------------------------------------------- #

_ASSERT_RE = re.compile(r"^assert\b")
_RAISES_RE = re.compile(r"^(?:with\s+)?(?:pytest\.)?raises\s*\(")
_WITH_RE = re.compile(r"^with\s+(?P<expr>.+?)(?:\s+as\s+\w+)?\s*:\s*$")
_PARAMETRIZE_RE = re.compile(r"^@(?:pytest\.)?(?:mark\.)?parametrize\s*\(")
_UNITTEST_RE = re.compile(r"^(?P<prefix>(?:self|cls)\.assert\w+)\s*\(")
_EXPECTED_RE = re.compile(r"^(?P<name>expected(?:_\w+)?|EXPECTED(?:_\w+)?)\s*(?::[^=]*)?=(?!=)")
_BROAD_EXCEPTIONS = {"Exception", "BaseException"}
_CMP_OPS = {"==", "!=", "<", ">", "<=", ">="}
_LITERAL_TOKENS = {tokenize.NUMBER, tokenize.STRING}
_LITERAL_NAMES = {"True", "False", "None"}
_CONT_MIN_RATIO = 0.5


def _kind(text: str) -> tuple[str, str]:
    """``(kind, pairing key)`` for a stripped line."""
    s = text.strip()
    if _ASSERT_RE.match(s):
        return "assert", "assert"
    if _RAISES_RE.match(s):
        return "raises", "raises"
    if _PARAMETRIZE_RE.match(s):
        return "parametrize", "parametrize"
    m = _UNITTEST_RE.match(s)
    if m:
        return "unittest", "unittest:" + m.group("prefix")
    m = _EXPECTED_RE.match(s)
    if m:
        return "expected", "expected:" + m.group("name")
    return "cont", "cont"


# --------------------------------------------------------------------------- #
# AST helpers
# --------------------------------------------------------------------------- #

_NOLIT = object()


def _parse_expr(text: str) -> ast.AST | None:
    """Parse one stripped line as a statement; ``with``/decorator lines become their expression."""
    s = text.strip()
    if not s:
        return None
    m = _WITH_RE.match(s)
    if m:
        s = m.group("expr")
    elif s.startswith("@"):
        s = s[1:]
    try:
        mod = ast.parse(s, mode="exec")
    except (SyntaxError, ValueError):
        return None
    if len(mod.body) != 1:
        return None
    return mod.body[0]


def _has_fstring(node: ast.AST) -> bool:
    return any(isinstance(n, ast.JoinedStr) for n in ast.walk(node))


def _try_literal(node: ast.AST):
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return _NOLIT


def _skeleton(node: ast.AST) -> str:
    """``ast.dump`` with every constant masked; names are kept so renames differ."""
    masked = copy.deepcopy(node)
    for n in ast.walk(masked):
        if isinstance(n, ast.Constant):
            n.value = "<lit>"
    return ast.dump(masked)


def _values_differ(a, b) -> bool:
    try:
        return a != b or type(a) is not type(b)
    except Exception:  # unorderable / weird __eq__
        return True


def _literal_edit(a: ast.AST, b: ast.AST) -> bool:
    """True when ``a`` and ``b`` differ *only* in literal values."""
    if _has_fstring(a) or _has_fstring(b):
        return False
    if ast.dump(a) == ast.dump(b):
        return False
    la, lb = _try_literal(a), _try_literal(b)
    if la is not _NOLIT and lb is not _NOLIT:
        return _values_differ(la, lb)
    return _skeleton(a) == _skeleton(b)


def _same(a: ast.AST, b: ast.AST) -> bool:
    return ast.dump(a) == ast.dump(b)


def _show(node: ast.AST) -> str:
    lit = _try_literal(node)
    if lit is not _NOLIT:
        return repr(lit)
    try:
        return ast.unparse(node)
    except Exception:
        return ast.dump(node)


def _is_len_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "len"


def _is_loose_constant(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and (node.value is None or node.value is True)


def _call_name(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    f = node.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return None


def _kwarg(node: ast.Call, name: str) -> ast.AST | None:
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _exception_names(node: ast.AST) -> set[str] | None:
    """Names in a ``raises(...)`` first argument; ``None`` if not a plain name/tuple."""
    if isinstance(node, (ast.Name, ast.Attribute)):
        return {ast.unparse(node)}
    if isinstance(node, ast.Tuple):
        names: set[str] = set()
        for elt in node.elts:
            if not isinstance(elt, (ast.Name, ast.Attribute)):
                return None
            names.add(ast.unparse(elt))
        return names
    return None


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #

@dataclass
class Classification:
    category: str
    old: str
    new: str

    @property
    def severity(self) -> str:
        return CATEGORY_SEVERITY[self.category]


def _classify_assert(old: ast.Assert, new: ast.Assert) -> Classification | None:
    ot, nt = old.test, new.test
    if not isinstance(ot, ast.Compare) or not isinstance(nt, ast.Compare):
        return None
    if [type(o) for o in ot.ops] != [type(o) for o in nt.ops] or len(ot.comparators) != len(nt.comparators):
        return None  # operator changed: assert_weakened's job
    if len(ot.comparators) != 1:
        return None
    ol, nl, orh, nrh = ot.left, nt.left, ot.comparators[0], nt.comparators[0]
    if _is_len_call(nl) and not _is_len_call(ol):
        return None  # == len(...) loosening
    if _is_loose_constant(nrh) and not isinstance(orh, ast.Constant):
        return None  # == True / == None loosening
    if _literal_edit(orh, nrh):
        return Classification("expected_value", _show(orh), _show(nrh))
    if _same(orh, nrh) and _literal_edit(ol, nl):
        return Classification("test_input", _show(ol), _show(nl))
    return None


def _classify_raises(old: ast.Call, new: ast.Call) -> Classification | None:
    if not old.args or not new.args:
        return None
    o_names, n_names = _exception_names(old.args[0]), _exception_names(new.args[0])
    if o_names is None or n_names is None:
        return None
    if o_names != n_names:
        if n_names & _BROAD_EXCEPTIONS or o_names <= n_names:
            return None  # widened: assert_weakened's job
        return Classification("exception_type", ast.unparse(old.args[0]), ast.unparse(new.args[0]))
    om, nm = _kwarg(old, "match"), _kwarg(new, "match")
    if om is None or nm is None or _same(om, nm):
        return None
    ov, nv = _try_literal(om), _try_literal(nm)
    if isinstance(ov, str) and isinstance(nv, str) and nv != ov and (nv == "" or nv in ov):
        return Classification("match_loosened", repr(ov), repr(nv))
    return None


def _classify_unittest(old: ast.Call, new: ast.Call) -> Classification | None:
    name = _call_name(old)
    if name != _call_name(new) or name is None:
        return None  # assertEqual -> assertTrue etc.: assert_weakened's job
    if len(old.args) != len(new.args):
        return None
    if name.startswith("assertRaises") and old.args and new.args:
        o_names, n_names = _exception_names(old.args[0]), _exception_names(new.args[0])
        if o_names and n_names and o_names != n_names:
            if n_names & _BROAD_EXCEPTIONS or o_names <= n_names:
                return None
            return Classification("exception_type", ast.unparse(old.args[0]), ast.unparse(new.args[0]))
    for oa, na in zip(old.args, new.args):
        if _literal_edit(oa, na):
            return Classification("assert_equal_args", _show(oa), _show(na))
    return None


def _classify_parametrize(old: ast.Call, new: ast.Call) -> Classification | None:
    if _call_name(old) != "parametrize" or _call_name(new) != "parametrize":
        return None
    if len(old.args) != len(new.args):
        return None
    for oa, na in zip(old.args, new.args):
        if _literal_edit(oa, na):
            return Classification("parametrize", _show(oa), _show(na))
    return None


def _classify_expected(old: ast.AST, new: ast.AST) -> Classification | None:
    ov = getattr(old, "value", None)
    nv = getattr(new, "value", None)
    if ov is None or nv is None:
        return None
    if _literal_edit(ov, nv):
        return Classification("expected_assignment", _show(ov), _show(nv))
    return None


def _classify_ast(kind: str, old: ast.AST, new: ast.AST) -> Classification | None:
    if kind == "assert":
        if isinstance(old, ast.Assert) and isinstance(new, ast.Assert):
            return _classify_assert(old, new)
        return None
    if isinstance(old, ast.Expr):
        old = old.value
    if isinstance(new, ast.Expr):
        new = new.value
    if kind == "raises":
        if isinstance(old, ast.Call) and isinstance(new, ast.Call):
            return _classify_raises(old, new)
        return None
    if kind == "unittest":
        if isinstance(old, ast.Call) and isinstance(new, ast.Call):
            return _classify_unittest(old, new)
        return None
    if kind == "parametrize":
        if isinstance(old, ast.Call) and isinstance(new, ast.Call):
            return _classify_parametrize(old, new)
        return None
    if kind == "expected":
        return _classify_expected(old, new)
    return None


# -- token fallback for lines that do not parse on their own ---------------- #

_SKIP_TOKENS = {tokenize.NEWLINE, tokenize.NL, tokenize.INDENT, tokenize.DEDENT,
                tokenize.COMMENT, tokenize.ENDMARKER}


def _tokens(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text.strip() + "\n").readline):
            if tok.type in _SKIP_TOKENS:
                continue
            out.append((tok.type, tok.string))
    except (tokenize.TokenError, SyntaxError, IndentationError):
        pass
    return out


def _is_literal_token(tok: tuple[int, str]) -> bool:
    typ, s = tok
    return typ in _LITERAL_TOKENS or (typ == tokenize.NAME and s in _LITERAL_NAMES)


def _token_literal_diff(old: str, new: str) -> list[int] | None:
    """Indexes at which ``old``/``new`` differ, if they differ only in literal tokens."""
    ot, nt = _tokens(old), _tokens(new)
    if not ot or len(ot) != len(nt):
        return None
    diff: list[int] = []
    for i, (a, b) in enumerate(zip(ot, nt)):
        if a == b:
            continue
        if _is_literal_token(a) and _is_literal_token(b):
            diff.append(i)
        else:
            return None
    return diff or None


def _first_cmp_index(toks: list[tuple[int, str]]) -> int | None:
    for i, (typ, s) in enumerate(toks):
        if (typ == tokenize.OP and s in _CMP_OPS) or (typ == tokenize.NAME and s in ("is", "in")):
            return i
    return None


def _classify_tokens(kind: str, old: str, new: str, enclosing: str | None) -> Classification | None:
    diff = _token_literal_diff(old, new)
    if diff is None:
        return None
    toks = _tokens(old)
    o_show, n_show = old.strip(), new.strip()
    if kind == "assert":
        cmp_i = _first_cmp_index(toks)
        if cmp_i is None:
            return None
        cat = "expected_value" if any(i > cmp_i for i in diff) else "test_input"
        return Classification(cat, o_show, n_show)
    if kind == "raises":
        return None  # the exception name is not a literal; nothing to attribute here
    if kind == "unittest":
        return Classification("assert_equal_args", o_show, n_show)
    if kind == "parametrize":
        return Classification("parametrize", o_show, n_show)
    if kind == "expected":
        return Classification("expected_assignment", o_show, n_show)
    # Continuation line: attribute to the enclosing statement.
    if enclosing is None:
        return None
    enc_kind, enc_text = enclosing
    if enc_kind == "assert":
        cat = "expected_value" if _first_cmp_index(_tokens(enc_text)) is not None else "test_input"
        return Classification(cat, o_show, n_show)
    if enc_kind == "raises":
        return Classification("test_input", o_show, n_show)
    if enc_kind == "unittest":
        return Classification("assert_equal_args", o_show, n_show)
    if enc_kind == "parametrize":
        return Classification("parametrize", o_show, n_show)
    if enc_kind == "expected":
        return Classification("expected_assignment", o_show, n_show)
    return None


def classify(old: str, new: str, enclosing: tuple[str, str] | None = None) -> Classification | None:
    """Classify a removed/added line pair. ``enclosing`` is ``(kind, text)`` of the
    statement a continuation line belongs to, when known."""
    if old.strip() == new.strip():
        return None
    kind, _ = _kind(old)
    if _kind(new)[0] != kind:
        return None
    if kind != "cont":
        o_ast, n_ast = _parse_expr(old), _parse_expr(new)
        if o_ast is not None and n_ast is not None:
            return _classify_ast(kind, o_ast, n_ast)
    return _classify_tokens(kind, old, new, enclosing)


def classify_pair(old: str, new: str, enclosing: tuple[str, str] | None = None) -> str | None:
    """Category name for a removed/added pair, or ``None`` when it is not this pattern."""
    c = classify(old, new, enclosing)
    return c.category if c else None


# --------------------------------------------------------------------------- #
# Pairing removed with added lines
# --------------------------------------------------------------------------- #

def _pair_block(removed: list[tuple[int, DiffLine]], added: list[tuple[int, DiffLine]]) -> list[tuple[int, DiffLine, DiffLine]]:
    """Pair each removed line with the most similar unpaired added line of the same key."""
    pairs: list[tuple[int, DiffLine, DiffLine]] = []
    pool = list(added)
    for idx, r in removed:
        if not r.text.strip():
            continue
        kind, key = _kind(r.text)
        best, best_ratio = None, 0.0
        for cand in pool:
            if _kind(cand[1].text)[1] != key:
                continue
            ratio = difflib.SequenceMatcher(None, r.text.strip(), cand[1].text.strip()).ratio()
            if ratio > best_ratio:
                best, best_ratio = cand, ratio
        if best is None:
            continue
        if kind == "cont" and best_ratio < _CONT_MIN_RATIO:
            continue
        pool.remove(best)
        pairs.append((idx, r, best[1]))
    return pairs


def _pairs(diff_lines: list[DiffLine]) -> list[tuple[int, DiffLine, DiffLine]]:
    out: list[tuple[int, DiffLine, DiffLine]] = []
    removed: list[tuple[int, DiffLine]] = []
    added: list[tuple[int, DiffLine]] = []

    def flush() -> None:
        if removed and added:
            out.extend(_pair_block(removed, added))
        removed.clear()
        added.clear()

    for i, d in enumerate(diff_lines):
        if d.op == "-":
            removed.append((i, d))
        elif d.op == "+":
            added.append((i, d))
        else:
            flush()
    flush()
    return out


def _indent(text: str) -> int:
    return len(text) - len(text.lstrip())


def _enclosing(change: FileChange, diff_lines: list[DiffLine], idx: int) -> tuple[str, str] | None:
    """``(kind, text)`` of the nearest less-indented base-side statement above ``diff_lines[idx]``."""
    d = diff_lines[idx]
    my_indent = _indent(d.text)
    if change.base_text is not None and d.old_no is not None:
        lines = change.base_text.splitlines()
        candidates = reversed(lines[: d.old_no - 1])
    else:
        prev: list[str] = []
        last_no = d.old_no
        for p in reversed(diff_lines[:idx]):
            if p.op == "+":
                continue
            if last_no is not None and p.old_no is not None and p.old_no != last_no - 1:
                break  # hunk boundary
            last_no = p.old_no
            prev.append(p.text)
        candidates = iter(prev)
    for text in candidates:
        if not text.strip():
            continue
        if _indent(text) < my_indent:
            kind, _ = _kind(text)
            return (kind, text) if kind != "cont" else None
    return None


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def detect(changes: list[FileChange]) -> list[TamperFinding]:
    out: list[TamperFinding] = []
    for change in changes:
        if not change.is_test or change.status in ("added", "deleted"):
            continue
        diff_lines = change.diff_lines()
        for idx, old, new in _pairs(diff_lines):
            kind, _ = _kind(old.text)
            enclosing = _enclosing(change, diff_lines, idx) if kind == "cont" else None
            c = classify(old.text, new.text, enclosing)
            if c is None:
                continue
            line = new.new_no
            where = f"{change.path}:{line}" if line is not None else change.path
            out.append(finding(
                PATTERN_ID, c.severity, change, line,
                f"{_CATEGORY_LABEL[c.category]} in {where}: {c.old} -> {c.new}",
                snippet=f"-{old.text}\n+{new.text}",
            ))
    return out


__all__ = ["CATEGORY_SEVERITY", "Classification", "PATTERN_ID", "SEVERITY", "classify", "classify_pair", "detect"]
