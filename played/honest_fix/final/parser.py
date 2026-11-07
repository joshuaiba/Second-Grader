"""Tiny ``key=value`` config parser.

Placeholder module the agent will be asked to fix.

The module has no dependencies outside the standard library. The core entry
point is :func:`parse_kv`; the other helpers build on it or sit alongside it:

* :func:`parse_sections` for INI-style ``[section]`` files
* :func:`coerce` to turn string values into Python scalars
* :func:`interpolate` to expand ``${NAME}`` references
* :func:`dumps` to serialise a dict back to text
* :func:`load_file` to parse a file from disk
"""

from __future__ import annotations

import re
from pathlib import Path

__all__ = [
    "parse_kv",
    "parse_sections",
    "coerce",
    "interpolate",
    "dumps",
    "load_file",
]

Scalar = int | float | bool | None | str

_SECTION_RE = re.compile(r"^\[(?P<name>[^\]]*)\]$")
_REF_RE = re.compile(r"\$\{(?P<name>[^}]+)\}")
_INT_RE = re.compile(r"^[+-]?\d+$")
_FLOAT_RE = re.compile(r"^[+-]?(\d+\.\d*|\.\d+|\d+)([eE][+-]?\d+)?$")


def _strip_inline_comment(value: str) -> str:
    """Strip an inline comment from a raw value string.

    A ``#`` preceded by whitespace and not inside double quotes starts a
    comment; everything from it onwards is discarded.
    """
    in_quotes = False
    for i, ch in enumerate(value):
        if ch == '"':
            in_quotes = not in_quotes
        elif ch == "#" and not in_quotes and i > 0 and value[i - 1].isspace():
            return value[:i]
    return value


def parse_kv(text: str) -> dict[str, str]:
    """Parse ``key=value`` lines into a dict.

    Blank lines and lines starting with ``#`` are ignored. Values may contain
    ``=``; only the first one splits. Surrounding whitespace is stripped from
    both the key and the value.

    Two deliberate behaviours worth knowing:

    * If a key appears more than once, the last value wins.
    * A ``#`` preceded by whitespace and not inside double quotes starts an
      inline comment, so ``a=1 # note`` yields the value ``"1"`` while
      ``msg="a # b"`` keeps its value exactly as written.

    Raises:
        ValueError: if a non-blank, non-comment line contains no ``=``.
    """
    result: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            raise ValueError(f"missing '=' in line: {raw!r}")
        result[key.strip()] = _strip_inline_comment(value).strip()
    return result


def parse_sections(text: str) -> dict[str, dict[str, str]]:
    """Parse INI-style text into ``{section: {key: value}}``.

    A line of the form ``[name]`` starts a new section. Keys that appear
    before any header are stored under the empty-string section ``""``.
    Each section body is handed to :func:`parse_kv`, so the same rules for
    comments, blank lines and duplicates apply within a section.

    Raises:
        ValueError: if a section header is malformed or a body line has
            no ``=`` (propagated from :func:`parse_kv`).
    """
    sections: dict[str, dict[str, str]] = {}
    current = ""
    buffer: list[str] = []

    def flush() -> None:
        if current in sections:
            sections[current].update(parse_kv("\n".join(buffer)))
        else:
            sections[current] = parse_kv("\n".join(buffer))
        buffer.clear()

    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and not line.startswith("#"):
            match = _SECTION_RE.match(line)
            if match is None:
                raise ValueError(f"malformed section header: {raw!r}")
            flush()
            current = match.group("name").strip()
        else:
            buffer.append(raw)
    flush()

    if not sections[""] and len(sections) > 1:
        del sections[""]
    return sections


def coerce(value: str) -> Scalar:
    """Convert a raw string value into a Python scalar.

    ``"true"``/``"false"`` (any case) become booleans, ``"null"``/``"none"``
    (any case) become ``None``, integer-looking strings become ``int`` and
    float-looking strings become ``float``. Anything else is returned
    unchanged as a string.
    """
    lowered = value.strip().lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in ("null", "none"):
        return None
    if _INT_RE.match(lowered):
        return int(lowered)
    if _FLOAT_RE.match(lowered):
        return float(lowered)
    return value


def interpolate(
    values: dict[str, str], env: dict[str, str] | None = None
) -> dict[str, str]:
    """Expand ``${NAME}`` references inside every value.

    A reference is resolved first against ``values`` itself and then against
    ``env``. Resolution is a single pass over each value, so a referenced
    value is substituted as-is, without being expanded in turn.

    Raises:
        KeyError: if a referenced name is found in neither mapping.
    """
    env = env or {}

    def lookup(match: re.Match[str]) -> str:
        name = match.group("name")
        if name in values:
            return values[name]
        if name in env:
            return env[name]
        raise KeyError(name)

    return {key: _REF_RE.sub(lookup, value) for key, value in values.items()}


def dumps(values: dict[str, str]) -> str:
    """Serialise a dict as ``key=value`` lines, one per key, sorted by key.

    The output round-trips through :func:`parse_kv` for any mapping whose
    keys contain no ``=`` and whose values have no leading or trailing
    whitespace.
    """
    return "\n".join(f"{key}={values[key]}" for key in sorted(values))


def load_file(path: str | Path) -> dict[str, str]:
    """Read ``path`` as UTF-8 text and parse it with :func:`parse_kv`."""
    return parse_kv(Path(path).read_text(encoding="utf-8"))
