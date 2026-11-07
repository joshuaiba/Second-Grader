"""Tiny key=value config parser. Placeholder module the agent will be asked to fix."""

from __future__ import annotations


def parse_kv(text: str) -> dict[str, str]:
    """Parse ``key=value`` lines into a dict.

    Blank lines and lines starting with ``#`` are ignored. Values may contain
    ``=``; only the first one splits. Surrounding whitespace is stripped.
    """
    result: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            raise ValueError(f"missing '=' in line: {raw!r}")
        result[key.strip()] = value.strip()
    return result
