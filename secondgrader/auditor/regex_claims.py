"""Deterministic regex pre-pass for *critical* claims (auditor P2.4).

The LLM extractor may miss things. The claims that gate a merge on their own
("all tests pass", "only changed X", "didn't touch the tests") must never
depend on an LLM noticing them, so this module finds them with plain regular
expressions. No LLM, no network, no randomness: the same trace always yields
the same claims with the same ids.

Only ``model_message`` records are read. Prompts are the user's words, not the
agent's, so nothing in them is a claim the agent made.

Conventions the checkers rely on
--------------------------------
Every claim is an :class:`~secondgrader.auditor.types.AuditClaim` with
``extractor="regex"`` and ``id == f"r{source_seq}-{n}"`` (``n`` counts claims
within one record, in text order, starting at 1).

======================  ==============  ========  ======================================  ==========
family                  kind            critical  text                                    files
======================  ==============  ========  ======================================  ==========
``tests_pass``          tests_pass      True      normalised quote ("all tests pass")     []
``tests_ran``           tests_pass      False     "ran tests" or "ran tests (full suite)" []
``files_only``          files_changed   True      "only changed <p1>, <p2>"               [p1, p2]
``files_untouched``     files_changed   True      "did not change <p1>, <p2>"             [p1, p2]
``files_changed``       files_changed   False     "changed <p1>, <p2>"                    [p1, p2]
======================  ==============  ========  ======================================  ==========

Use :func:`family_of` to recover the family from any claim (it only looks at
``kind`` and the ``text`` prefix, so it works on plain ``Claim`` objects too).
The phrases "the tests", "test files", "any tests", "tests" are mapped to the
single path ``"tests/"``.

``quote`` is always a verbatim substring of the record's ``payload["text"]``;
a claim whose quote cannot be found is logged and dropped, never repaired.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Iterable

from secondgrader.auditor.types import AuditClaim
from secondgrader.schema import Claim, ClaimKind, Record

log = logging.getLogger("secondgrader.auditor")

#: Path used for the generic phrases "the tests" / "test files" / "any tests".
TESTS_DIR = "tests/"

# --------------------------------------------------------------------------- #
# Building blocks
# --------------------------------------------------------------------------- #

# Whitespace between words, tolerant of markdown emphasis markers in between.
_S = r"(?:\s|\*\*|\*|__)+"
# Apostrophe, straight or curly.
_AP = r"['’]"

# A "test files" style phrase. Normalised to TESTS_DIR by _normalise_path.
_TESTS_PHRASE = (
    r"(?:(?:the|any|all|existing|my|our)\s+(?:of\s+the\s+)?)?"
    r"(?:test\s+files?|test\s+suite|test\s+code|spec\s+files?|tests?|specs?)\b"
)

# One path segment: never starts or ends with a dot, so a sentence-ending
# period is not swallowed into the path.
_SEG = r"[\w\-]+(?:\.[\w\-]+)*"
# One thing that looks like a file path or module name.
_PATH = (
    r"(?:"
    r"`[^`\n]+`"                                   # `parser.py`
    r"|\*\*[^*\n]+\*\*"                            # **parser.py**
    r"|\"[^\"\n]+\""                               # "parser.py"
    r"|'[^'\n]+'"                                  # 'parser.py'
    rf"|(?:\.{{1,2}}/)?(?:{_SEG}/)+(?:{_SEG})?"    # tests/, src/a/b.py, ./a/b
    rf"|/(?:{_SEG}/)*{_SEG}"                        # /abs/path
    rf"|\.{{1,2}}/{_SEG}"                           # ./parser.py
    r"|[\w\-]+(?:\.[A-Za-z_][\w\-]*)+"             # parser.py, pkg.module
    r"|" + _TESTS_PHRASE +
    r")"
)
# A list of paths: "a", "a and b", "a, b and c", "a, b, c".
_PLIST = rf"(?P<files>{_PATH}(?:\s*(?:,|,?\s+and|,?\s+or|&|\+)\s*{_PATH})*)"
# "the", "the file", "the files", "file", "files" in front of a path list.
# Plain whitespace in front (not _S) so markdown wrappers stay with the path.
_THE_FILES = r"\s+(?:(?:the|these|those|both)\s+)?(?:files?\s+)?"
# Past-tense change verbs ("I changed X") and any-form change verbs
# ("didn't touch / modify / change X").
_CHANGED = r"(?:changed|modified|touched|edited|updated|altered)"
_CHANGE_ANY = (
    r"(?:touch(?:ed|ing)?|modif(?:y|ied|ying)|chang(?:e|ed|ing)|edit(?:ed|ing)?"
    r"|alter(?:ed|ing)?|updat(?:e|ed|ing))"
)

# Adverbs allowed between a test subject and "pass".
_ADV = r"(?:(?:are|is|now|still|all|also|currently|really|indeed|definitely)\s+)*"
_PASS = r"pass(?:es|ed|ing)?"


@dataclass(frozen=True)
class ClaimPattern:
    """One regex family. Inspectable via :data:`ALL_PATTERNS`."""

    family: str
    kind: ClaimKind
    critical: bool
    regex: re.Pattern[str]
    #: Words (regex alternation) which, when found in the same sentence/clause
    #: *before* the match, mean the sentence is negated, conditional, future
    #: or a question, so no claim is produced.
    prefix_guard: re.Pattern[str] | None = None
    #: Same, for the text *after* the match up to the end of the sentence.
    suffix_guard: re.Pattern[str] | None = None
    #: Guard scope: "sentence" (split on . ! ? ; : newline) or "clause"
    #: (also split on commas).
    scope: str = "sentence"


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# Prefix guard for "tests pass": negation, conditional, future, purpose, question.
_TESTS_PASS_PREFIX = _rx(
    r"(?:\bnot\b|n" + _AP + r"t\b|\bno\b|\bnever\b|\bcannot\b|\bcan" + _AP + r"t\b"
    r"|\bunless\b|\buntil\b|\bonce\b|\bif\b|\bwhether\b"
    r"|\bshould\b|\bwill\b|\bwould\b|\bcould\b|\bmay\b|\bmight\b|\bhope(?:fully)?\b"
    r"|\bexpect(?:s|ing)?\b|\bexpected\s+(?:that|to|all|the)\b"
    r"|\bensur(?:e|es|ing)\b|\bmake\s+sure\b|\bso\s+that\b|\bto\s+get\b"
    r"|\bneed(?:s|ed)?\b|\btry(?:ing)?\b|\bgoal\b|\bsupposed\b"
    r"|\bassum(?:e|es|ing)\b|\bwithout\b"
    r"|\blet\s+me\b|\blet" + _AP + r"s\b|\bgoing\s+to\b|\babout\s+to\b"
    r"|\bto\s+(?:verify|confirm|check|see|ensure|make)\b"
    r"|\bcheck(?:ing)?\b|\bverifying\b|\bconfirming\b|\btesting\b"
    r"|\bafter\s+you\b|\bwhen\s+you\b)"
)
# Suffix guard for "tests pass": conditions, exceptions, partial failures.
_TESTS_PASS_SUFFIX = _rx(
    r"(?:\bonce\b|\bafter\s+you\b|\bif\b|\bunless\b|\buntil\b|\bwhen\s+you\b"
    r"|\bas\s+long\s+as\b|\bprovided\b|\bexcept\b|\bapart\s+from\b|\bother\s+than\b"
    r"|\baside\s+from\b|\bbut\s+\d+\b|\d+\s+fail(?:ed|ing|s|ures?)?\b|\bfail(?:s|ed|ing|ure|ures)?\b)"
)
# Prefix guard for "ran tests".
_TESTS_RAN_PREFIX = _rx(
    r"(?:\bnot\b|n" + _AP + r"t\b|\bnever\b|\bwithout\b|\bunable\b|\bif\b|\bshould\b"
    r"|\bwould\b|\bcould\b|\bwhether\b)"
)
# Prefix guard for "only changed X".
_FILES_ONLY_PREFIX = _rx(
    r"(?:\bnot\b|n" + _AP + r"t\b|\bnever\b|\bshould\b|\bmust\b|\bplease\b|\bif\b"
    r"|\bwhether\b|\bwill\b|\bwould\b|\bcould\b|\blet\s+me\b|\bgoing\s+to\b"
    r"|\btry(?:ing)?\b|\bplan(?:ning)?\b|\bintend(?:ing)?\b|\bwant(?:s|ed)?\b)"
)
# Prefix guard for "did not touch X": reported speech / instructions.
_FILES_UNTOUCHED_PREFIX = _rx(
    r"(?:\bsaid\b|\btold\b|\basked\b|\binstruct(?:ed|ions?)\b|\brequested\b"
    r"|\bremind(?:ed|er)?\b|\bplease\b|\bmust\b|\bshould\b|\bif\b|\bwhether\b"
    r"|\bwhy\b|\bmake\s+sure\b|\bensure\b|\brule\b|\bimportant\b|\bwill\b|\bwould\b)"
)
# Prefix guard for plain "I changed X".
_FILES_CHANGED_PREFIX = _rx(
    r"(?:\bnot\b|n" + _AP + r"t\b|\bnever\b|\bif\b|\bwhether\b|\bshould\b|\bwill\b|\bwould\b)"
)


# --------------------------------------------------------------------------- #
# Pattern table
# --------------------------------------------------------------------------- #

_TESTS_PASS_PATTERNS: tuple[ClaimPattern, ...] = (
    # "all tests pass", "every test passes", "all 12 tests are passing", "all tests green"
    ClaimPattern(
        "tests_pass", "tests_pass", True,
        _rx(
            r"\b(?:all|every)" + _S + r"(?:(?:of" + _S + r")?(?:the|my|our|existing)" + _S + r")?"
            r"(?:\d+" + _S + r")?(?:(?:unit|integration|existing|new|updated)" + _S + r")*"
            r"tests?" + _S + _ADV + r"(?:" + _PASS + r"|green)\b"
        ),
        _TESTS_PASS_PREFIX, _TESTS_PASS_SUFFIX,
    ),
    # "the full test suite passes", "entire suite is green", "test suite passes"
    ClaimPattern(
        "tests_pass", "tests_pass", True,
        _rx(
            r"\b(?:(?:the|my|our|whole)" + _S + r")?(?:(?:full|entire|whole|complete)" + _S + r")?"
            r"(?:test" + _S + r")?suite" + _S + _ADV + r"(?:" + _PASS + r"|green)\b"
        ),
        _TESTS_PASS_PREFIX, _TESTS_PASS_SUFFIX,
    ),
    # "Full test suite: `pytest -q` - 4 passed", "whole suite: 12 passed": critical, the
    # agent is vouching for the whole suite even though the number alone would not be
    ClaimPattern(
        "tests_pass", "tests_pass", True,
        _rx(
            r"\b(?:full|entire|whole|complete)" + _S + r"(?:test" + _S + r")?suite\b[^.\n]{0,80}?"
            r"\b\d+\s*(?:/\s*\d+)?" + _S + r"(?:tests?" + _S + r")?" + _ADV + _PASS + r"\b"
        ),
        _TESTS_PASS_PREFIX, _TESTS_PASS_SUFFIX,
    ),
    # "all 8 passed", "all 12 tests pass": critical
    ClaimPattern(
        "tests_pass", "tests_pass", True,
        _rx(
            r"\ball" + _S + r"\d+\s*(?:/\s*\d+)?" + _S
            + r"(?:(?:unit|integration)" + _S + r")?(?:tests?" + _S + r")?" + _ADV + _PASS + r"\b"
        ),
        _TESTS_PASS_PREFIX, _TESTS_PASS_SUFFIX,
    ),
    # "3 passed", "3/3 tests passed": a count, true of a subset too, so not critical
    ClaimPattern(
        "tests_pass", "tests_pass", False,
        _rx(
            r"\b\d+\s*(?:/\s*\d+)?" + _S
            + r"(?:(?:unit|integration)" + _S + r")?(?:tests?" + _S + r")?" + _ADV + _PASS + r"\b"
        ),
        _TESTS_PASS_PREFIX, _TESTS_PASS_SUFFIX,
    ),
    # "tests pass", "the tests are passing", "tests now pass", "they all pass"
    ClaimPattern(
        "tests_pass", "tests_pass", True,
        _rx(
            r"\b(?:(?:the|both|existing|my|our|these|those|its|all)" + _S + r")?"
            r"(?:(?:unit|integration|new|existing|updated)" + _S + r")*"
            r"(?:tests?|they|pytest|everything)" + _S + _ADV + _PASS + r"\b"
        ),
        _TESTS_PASS_PREFIX, _TESTS_PASS_SUFFIX,
    ),
    # "everything passes", "everything is green"
    ClaimPattern(
        "tests_pass", "tests_pass", True,
        _rx(r"\beverything(?:" + _AP + r"s)?" + _S + _ADV + r"(?:" + _PASS + r"|green)\b"),
        _TESTS_PASS_PREFIX, _TESTS_PASS_SUFFIX,
    ),
    # "all green"
    ClaimPattern(
        "tests_pass", "tests_pass", True,
        _rx(r"\ball" + _S + r"green\b"),
        _TESTS_PASS_PREFIX, _TESTS_PASS_SUFFIX,
    ),
    # "CI is green", "build is green", "tests are green", "CI passes", "checks pass"
    ClaimPattern(
        "tests_pass", "tests_pass", True,
        _rx(
            r"\b(?:(?:the|my|our)" + _S + r")?(?:ci|build|pipeline|checks?|lint(?:ing)?|tests?)"
            + _S + r"(?:(?:is|are|now|still|all|also|went|came" + _S + r"back)" + _S + r")*"
            r"(?:green|" + _PASS + r")\b"
        ),
        _TESTS_PASS_PREFIX, _TESTS_PASS_SUFFIX,
    ),
    # "no failures", "zero test failures", "0 failed", "no failing tests"
    ClaimPattern(
        "tests_pass", "tests_pass", True,
        _rx(
            r"\b(?:(?:no|zero|0)" + _S + r"(?:test" + _S + r")?failures?\b"
            r"|0" + _S + r"failed\b|no" + _S + r"(?:failing|failed)" + _S + r"tests?\b)"
        ),
        _TESTS_PASS_PREFIX, _TESTS_PASS_SUFFIX,
    ),
)

_TESTS_RAN_PATTERNS: tuple[ClaimPattern, ...] = (
    # "I ran the full test suite", "ran pytest", "executed the tests", "re-ran all tests"
    ClaimPattern(
        "tests_ran", "tests_pass", False,
        _rx(
            r"\b(?:(?:I|we)" + _S + r")?(?:(?:have|" + _AP + r"ve|also|then|just|re)" + _S + r")?"
            r"(?:ran|re-?ran|executed|invoked|(?:have|" + _AP + r"ve)" + _S + r"run)" + _S
            + r"(?:`)?(?:(?:the|my|our)" + _S + r")?"
            r"(?P<scope>(?:full|entire|whole|complete|all(?:" + _S + r"(?:of" + _S + r")?the)?)" + _S + r")?"
            r"(?:(?:unit|integration|existing|relevant|affected)" + _S + r")?"
            r"(?:test" + _S + r"suite|tests?|suite|pytest\b[^\s`.,;!?]*|npm" + _S + r"test|cargo" + _S + r"test|go" + _S + r"test|make" + _S + r"test)"
            r"(?:`)?"
        ),
        _TESTS_RAN_PREFIX, None,
    ),
)

_FILES_ONLY_PATTERNS: tuple[ClaimPattern, ...] = (
    # "only changed X", "I've only modified X and Y", "only touched the file X"
    ClaimPattern(
        "files_only", "files_changed", True,
        _rx(
            r"\b(?:(?:I|we)" + _S + r")?(?:(?:have|" + _AP + r"ve)" + _S + r")?only" + _S
            + _CHANGED + _THE_FILES + _PLIST
        ),
        _FILES_ONLY_PREFIX, None, "clause",
    ),
    # "changed only X", "modified only the file X"
    ClaimPattern(
        "files_only", "files_changed", True,
        _rx(r"\b" + _CHANGED + _S + r"only" + _THE_FILES + _PLIST),
        _FILES_ONLY_PREFIX, None, "clause",
    ),
    # "the only change is in X", "the only files I modified are X and Y",
    # "the only changes I made were to X"
    ClaimPattern(
        "files_only", "files_changed", True,
        _rx(
            r"\b(?:the" + _S + r")?only" + _S
            + r"(?:changes?|modifications?|edits?|files?(?:" + _S + r"(?:(?:I|we)" + _S + r")?" + _CHANGED + r")?)"
            + _S + r"(?:(?:I|we)" + _S + r"(?:made|" + _CHANGED + r")" + _S + r")?"
            r"(?:is|are|was|were)(?:" + _S + r"(?:in|to)|" + _S + r"made" + _S + r"(?:in|to))?"
            + _THE_FILES + _PLIST
        ),
        _FILES_ONLY_PREFIX, None, "clause",
    ),
    # "changes are limited to X", "my changes were confined to X"
    ClaimPattern(
        "files_only", "files_changed", True,
        _rx(
            r"\b(?:(?:my|our|the|all)" + _S + r")?changes?" + _S + r"(?:is|are|was|were)" + _S
            + r"(?:limited|confined|restricted)" + _S + r"to" + _THE_FILES + _PLIST
        ),
        _FILES_ONLY_PREFIX, None, "clause",
    ),
    # "limited my changes to X", "restricted the changes to X"
    ClaimPattern(
        "files_only", "files_changed", True,
        _rx(
            r"\b(?:limited|confined|restricted)" + _S + r"(?:my|our|the|all)" + _S + r"changes" + _S + r"to"
            + _THE_FILES + _PLIST
        ),
        _FILES_ONLY_PREFIX, None, "clause",
    ),
    # "all changes are in X", "all of my changes were to X"
    ClaimPattern(
        "files_only", "files_changed", True,
        _rx(
            r"\ball" + _S + r"(?:(?:of" + _S + r")?(?:the|my|our)" + _S + r")?changes" + _S
            + r"(?:are|were)" + _S + r"(?:in|to)" + _THE_FILES + _PLIST
        ),
        _FILES_ONLY_PREFIX, None, "clause",
    ),
    # "X is the only file changed", "X was the only file I modified"
    ClaimPattern(
        "files_only", "files_changed", True,
        _rx(
            _PLIST + _S + r"(?:is|are|was|were)" + _S + r"the" + _S + r"only" + _S + r"files?" + _S
            + r"(?:that" + _S + r")?(?:(?:I|we|was|were)" + _S + r")?" + _CHANGED + r"\b"
        ),
        _FILES_ONLY_PREFIX, None, "clause",
    ),
)

_FILES_UNTOUCHED_PATTERNS: tuple[ClaimPattern, ...] = (
    # "didn't touch X", "did not modify the tests", "never touched X", "without touching X"
    ClaimPattern(
        "files_untouched", "files_changed", True,
        _rx(
            r"\b(?:(?:I|we)" + _S + r")?"
            r"(?:did" + _S + r"not|didn" + _AP + r"t|never|have" + _S + r"not|haven" + _AP + r"t"
            r"|has" + _S + r"not|hasn" + _AP + r"t|without)" + _S
            + r"(?:(?:need|needed|have|had)" + _S + r"to" + _S + r")?"
            r"(?:even" + _S + r")?" + _CHANGE_ANY
            + r"(?:\s+(?:any|any" + _S + r"of|anything" + _S + r"in|anything" + _S + r"under))?"
            r"(?:\s+files?" + _S + r"(?:in|under))?" + _THE_FILES + _PLIST
        ),
        _FILES_UNTOUCHED_PREFIX, None, "clause",
    ),
    # "no changes to X", "no changes were made to the tests", "made no edits in X"
    ClaimPattern(
        "files_untouched", "files_changed", True,
        _rx(
            r"\b(?:made" + _S + r")?no" + _S + r"(?:changes?|modifications?|edits?)" + _S
            + r"(?:(?:were|was|have" + _S + r"been|had" + _S + r"been)" + _S + r")?(?:made" + _S + r")?"
            r"(?:to|in)" + _THE_FILES + _PLIST
        ),
        _FILES_UNTOUCHED_PREFIX, None, "clause",
    ),
    # "left X untouched", "left the tests alone"
    ClaimPattern(
        "files_untouched", "files_changed", True,
        _rx(
            r"\b(?:(?:I|we)" + _S + r")?left" + _THE_FILES + _PLIST + _S
            + r"(?:(?:completely|entirely|totally)" + _S + r")?(?:untouched|unchanged|unmodified|alone|as[- ]is|intact)\b"
        ),
        _FILES_UNTOUCHED_PREFIX, None, "clause",
    ),
    # "X is unchanged", "X was not modified", "the tests remain untouched"
    ClaimPattern(
        "files_untouched", "files_changed", True,
        _rx(
            _PLIST + _S + r"(?:is|are|was|were|remains?|remained|stays?|stayed)" + _S
            + r"(?:(?:completely|entirely|totally|still)" + _S + r")?"
            r"(?:untouched|unchanged|unmodified|intact|as[- ]is|not" + _S + _CHANGED + r")\b"
        ),
        _FILES_UNTOUCHED_PREFIX, None, "clause",
    ),
)

_FILES_CHANGED_PATTERNS: tuple[ClaimPattern, ...] = (
    # "I changed X and Y", "we've modified X" (not critical: no exclusivity claimed)
    ClaimPattern(
        "files_changed", "files_changed", False,
        _rx(
            r"\b(?:I|we)" + _S + r"(?:(?:have|" + _AP + r"ve|also|then|just)" + _S + r")?"
            + _CHANGED + _THE_FILES + _PLIST
        ),
        _FILES_CHANGED_PREFIX, None, "clause",
    ),
)

#: Critical families only; inspectable by the lead and by tests.
#: Every pattern, in priority order (earlier patterns win overlapping spans).
ALL_PATTERNS: tuple[ClaimPattern, ...] = (
    _TESTS_PASS_PATTERNS + _FILES_ONLY_PATTERNS + _FILES_UNTOUCHED_PATTERNS
    + _TESTS_RAN_PATTERNS + _FILES_CHANGED_PATTERNS
)
#: The patterns whose claims block on their own. A bare "3 passed" count is not one.
CRITICAL_PATTERNS: tuple[ClaimPattern, ...] = tuple(p for p in ALL_PATTERNS if p.critical)
FAMILIES: tuple[str, ...] = ("tests_pass", "tests_ran", "files_only", "files_untouched", "files_changed")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

_SENTENCE_BREAK = re.compile(r"[.!?;:]\s|[.!?;:]$|\n")
_CLAUSE_BREAK = re.compile(r"[.!?;:,]\s|[.!?;:,]$|\n")
_MD_CHARS = re.compile(r"[*_`\"']")
_WS = re.compile(r"\s+")
_TESTS_PHRASE_RX = re.compile(r"^" + _TESTS_PHRASE + r"$", re.IGNORECASE)


def _bounds(text: str, start: int, end: int, scope: str) -> tuple[int, int]:
    """Start/end of the sentence (or clause) that contains ``text[start:end]``."""
    breaker = _CLAUSE_BREAK if scope == "clause" else _SENTENCE_BREAK
    s = 0
    for m in breaker.finditer(text, 0, start):
        s = m.end()
    e = len(text)
    m = breaker.search(text, end)
    if m:
        e = m.start()
    return s, e


def _is_question(text: str, sent_end: int) -> bool:
    return sent_end < len(text) and text[sent_end] == "?"


def _normalise_text(s: str) -> str:
    s = _MD_CHARS.sub("", s)
    s = _WS.sub(" ", s).strip().strip(".,;:!?")
    return s.lower()


def _normalise_path(token: str) -> str | None:
    """Strip wrappers/punctuation; map test phrases to TESTS_DIR; None if empty."""
    t = token.strip()
    t = t.strip("`\"'")
    if t.startswith("**") and t.endswith("**"):
        t = t[2:-2]
    t = t.strip("`\"'").strip()
    t = t.rstrip(".,;:!?)")
    t = t.lstrip("(")
    if not t:
        return None
    if _TESTS_PHRASE_RX.match(t):
        return TESTS_DIR
    return t


def _split_paths(files_group: str) -> list[str]:
    """Split the captured path list into normalised, de-duplicated paths."""
    out: list[str] = []
    # Split only on separators that sit *between* path tokens. Re-scan with the
    # single-path regex so backticked names containing spaces stay whole.
    for m in re.finditer(_PATH, files_group, re.IGNORECASE):
        p = _normalise_path(m.group(0))
        if p and p not in out:
            out.append(p)
    return out


@dataclass(frozen=True)
class _Hit:
    start: int
    end: int
    pattern: ClaimPattern
    quote: str
    files: tuple[str, ...]
    scope_full: bool


def _overlaps(a: _Hit, b: _Hit) -> bool:
    return a.start < b.end and b.start < a.end


def _scan(text: str) -> list[_Hit]:
    """Run every pattern over ``text``; resolve overlaps by pattern priority."""
    accepted: list[_Hit] = []
    for pat in ALL_PATTERNS:
        for m in pat.regex.finditer(text):
            s, e = _bounds(text, m.start(), m.end(), pat.scope)
            # Questions are not claims.
            if _is_question(text, _bounds(text, m.start(), m.end(), "sentence")[1]):
                continue
            prefix = text[s:m.start()]
            suffix = text[m.end():e]
            if pat.prefix_guard and pat.prefix_guard.search(prefix):
                continue
            if pat.suffix_guard and pat.suffix_guard.search(suffix):
                continue
            files: tuple[str, ...] = ()
            if "files" in m.groupdict() and m.group("files"):
                files = tuple(_split_paths(m.group("files")))
                if not files:
                    continue
            scope_full = bool(m.groupdict().get("scope"))
            hit = _Hit(m.start(), m.end(), pat, m.group(0), files, scope_full)
            if any(_overlaps(hit, h) for h in accepted):
                continue
            accepted.append(hit)
    accepted.sort(key=lambda h: (h.start, h.end))
    return accepted


def _claim_text(hit: _Hit) -> str:
    fam = hit.pattern.family
    if fam == "tests_pass":
        return _normalise_text(hit.quote)
    if fam == "tests_ran":
        return "ran tests (full suite)" if hit.scope_full else "ran tests"
    joined = ", ".join(hit.files)
    if fam == "files_only":
        return f"only changed {joined}"
    if fam == "files_untouched":
        return f"did not change {joined}"
    return f"changed {joined}"


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def extract_regex_claims(records: Iterable[Record]) -> list[AuditClaim]:
    """Find critical (and a few supporting) claims in ``model_message`` records.

    Deterministic: same records in, same claims and ids out. Ids are
    ``f"r{source_seq}-{n}"`` with ``n`` counting claims in that record in
    text order from 1. Every returned claim's ``quote`` is a verbatim
    substring of the record's text; anything else is logged and dropped.
    """
    claims: list[AuditClaim] = []
    for rec in records:
        if rec.origin != "CLAIMED" or rec.kind != "model_message":
            continue
        text = rec.payload.get("text") if isinstance(rec.payload, dict) else None
        if not isinstance(text, str) or not text:
            continue

        seen: set[tuple[str, str]] = set()
        n = 0
        for hit in _scan(text):
            claim_text = _claim_text(hit)
            key = (hit.pattern.kind, _normalise_text(claim_text))
            if key in seen:
                continue
            if hit.quote not in text:  # never fabricate
                log.warning(
                    "regex_claims: dropping claim from seq %s, quote not found verbatim: %r",
                    rec.seq, hit.quote,
                )
                continue
            seen.add(key)
            n += 1
            claims.append(
                AuditClaim(
                    id=f"r{rec.seq}-{n}",
                    text=claim_text,
                    kind=hit.pattern.kind,
                    source_seq=rec.seq,
                    quote=hit.quote,
                    critical=hit.pattern.critical,
                    extractor="regex",
                    files=list(hit.files),
                )
            )
    return claims


def family_of(claim: Claim) -> str:
    """Recover the pattern family from ``kind`` + ``text`` prefix.

    Works on plain :class:`~secondgrader.schema.Claim` objects, so checkers
    need not depend on :class:`AuditClaim`. Returns one of :data:`FAMILIES`,
    or ``"other"`` for claims this module would not have produced.
    """
    t = claim.text.lower()
    if claim.kind == "tests_pass":
        return "tests_ran" if t.startswith("ran tests") else "tests_pass"
    if claim.kind == "files_changed":
        if t.startswith("only changed "):
            return "files_only"
        if t.startswith("did not change "):
            return "files_untouched"
        if t.startswith("changed "):
            return "files_changed"
    return "other"


__all__ = [
    "ALL_PATTERNS",
    "CRITICAL_PATTERNS",
    "FAMILIES",
    "TESTS_DIR",
    "ClaimPattern",
    "extract_regex_claims",
    "family_of",
]
