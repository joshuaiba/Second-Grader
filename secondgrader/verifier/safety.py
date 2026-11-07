"""Static safety check for LLM-generated tests (P3.4).

Generated tests run inside our process, so they are rejected unless they pass
this check. It is an allow-list on imports plus a deny-list on dangerous names,
walked over the whole AST so aliased or nested imports are caught too.

This is a cheap guard, not a sandbox: code decides whether a test *runs*, and
the test's outcome is still only evidence about the diff.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

ALLOWED_MODULES: frozenset[str] = frozenset(
    {
        "pytest",
        "math",
        "re",
        "json",
        "string",
        "itertools",
        "collections",
        "functools",
        "dataclasses",
        "typing",
        "decimal",
        "fractions",
        "statistics",
        "textwrap",
        "unicodedata",
    }
)

FORBIDDEN_MODULES: frozenset[str] = frozenset(
    {
        "os",
        "sys",
        "subprocess",
        "socket",
        "shutil",
        "pathlib",
        "io",
        "tempfile",
        "importlib",
        "ctypes",
        "signal",
        "threading",
        "multiprocessing",
        "asyncio",
        "urllib",
        "http",
        "requests",
        "httpx",
        "builtins",
    }
)

FORBIDDEN_CALLS: frozenset[str] = frozenset(
    {"open", "exec", "eval", "compile", "__import__", "globals", "locals", "breakpoint", "input",
     "getattr", "setattr", "delattr", "vars", "help", "dir", "exit", "quit", "memoryview"}
)

#: Attribute names that are never allowed, whatever the object on the left is.
#: Allowed modules re-export dangerous ones (``typing.sys``, ``collections._sys``,
#: ``pytest.importorskip``), so the root-name rule alone is not enough.
FORBIDDEN_ATTRS: frozenset[str] = FORBIDDEN_MODULES | frozenset(
    {"modules", "importorskip", "_sys", "_os", "_io", "loader", "gc", "system", "popen", "spawn",
     "MonkeyPatch", "Config", "register_assert_rewrite", "main", "exit", "fail_on_template"}
)

#: pytest fixtures that reach the filesystem, the environment or the process.
FORBIDDEN_FIXTURES: frozenset[str] = frozenset(
    {"monkeypatch", "tmp_path", "tmpdir", "tmp_path_factory", "tmpdir_factory", "capfd", "capsys",
     "capfdbinary", "capsysbinary", "request", "pytestconfig", "cache", "recwarn", "record_property",
     "record_testsuite_property", "record_xml_attribute", "doctest_namespace", "testdir", "pytester"}
)

FORBIDDEN_DUNDER_ATTRS: frozenset[str] = frozenset(
    {
        "__class__",
        "__subclasses__",
        "__globals__",
        "__builtins__",
        "__bases__",
        "__mro__",
        "__dict__",
        "__code__",
        "__closure__",
        "__import__",
        "__loader__",
        "__spec__",
        "__reduce__",
        "__reduce_ex__",
        "__getattribute__",
    }
)

DEFAULT_MAX_BYTES = 20_000


def _top(name: str) -> str:
    return name.split(".", 1)[0]


def _root_name(node: ast.AST) -> str | None:
    """``os.path.join`` -> ``os``; ``o.system`` -> ``o``."""
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _loop_has_break(loop: ast.While) -> bool:
    """True if any ``break`` in ``loop.body`` belongs to this loop (not a nested one)."""
    stack: list[ast.AST] = list(loop.body)
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Break):
            return True
        if isinstance(node, (ast.For, ast.While, ast.AsyncFor)):
            stack.extend(node.orelse)  # a break in the else clause still belongs to us
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(ast.iter_child_nodes(node))
    return False


def _is_truthy_const(node: ast.AST) -> bool:
    """``while True``, ``while 1``, ``while "x"``: a loop that can only end with a break."""
    if isinstance(node, ast.Constant):
        try:
            return bool(node.value)
        except Exception:  # pragma: no cover - exotic constants
            return False
    return False


def check_test_source(
    source: str,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    allowed_modules: Iterable[str] = ("parser",),
) -> list[str]:
    """Return human-readable violations; an empty list means the source is safe to run.

    Rules:
      1. ``len(source.encode()) <= max_bytes``.
      2. Parses with ``ast.parse``.
      3. Defines at least one ``def test_*``.
      4. Imports only from ``ALLOWED_MODULES`` plus ``allowed_modules`` (the module under test).
      5. No import or attribute use of ``FORBIDDEN_MODULES`` (also via aliases).
      6. No calls to ``FORBIDDEN_CALLS``; no ``getattr(x, "__...")``.
      7. No ``from x import *``.
      8. No dunder attribute access (``__class__``, ``__subclasses__``, ...), no
         string literal containing ``__`` (blocks ``"{0.__class__}".format(...)``).
      9. No ``while <truthy constant>`` without a ``break`` (cheap infinite-loop guard).
     10. No attribute named like a forbidden module or escape hatch, whatever the root
         (``typing.sys``, ``collections._sys``, ``pytest.importorskip``); no private
         (``_x``) attribute access on anything.
     11. Forbidden builtins may not be *named* at all, so ``x = exec`` is rejected.
     12. Test functions may not take pytest's filesystem/env fixtures (``monkeypatch``,
         ``tmp_path``, ``capsys``, ...).
    """
    violations: list[str] = []

    size = len(source.encode("utf-8"))
    if size > max_bytes:
        violations.append(f"source is {size} bytes, limit is {max_bytes}")
        return violations  # do not spend time parsing something we will reject anyway

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        violations.append(f"syntax error at line {e.lineno}: {e.msg}")
        return violations

    allowed = ALLOWED_MODULES | {_top(m) for m in allowed_modules}

    has_test = any(
        isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test_")
        for n in ast.walk(tree)
    )
    if not has_test:
        violations.append("no function named test_* defined")

    # Names bound to forbidden modules, e.g. ``import os as o`` -> {"o"}.
    tainted: set[str] = set()

    for node in ast.walk(tree):
        line = getattr(node, "lineno", "?")

        if isinstance(node, ast.Import):
            for alias in node.names:
                top = _top(alias.name)
                if top in FORBIDDEN_MODULES:
                    violations.append(f"line {line}: import of forbidden module '{alias.name}'")
                    tainted.add(alias.asname or top)
                elif top not in allowed:
                    violations.append(f"line {line}: import of module '{alias.name}' not in allow-list")

        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            top = _top(mod)
            if node.level:
                violations.append(f"line {line}: relative import is not allowed")
            if any(a.name == "*" for a in node.names):
                violations.append(f"line {line}: 'from {mod} import *' is not allowed")
            if top in FORBIDDEN_MODULES:
                violations.append(f"line {line}: import from forbidden module '{mod}'")
                for a in node.names:
                    if a.name != "*":
                        tainted.add(a.asname or a.name)
            elif top and top not in allowed:
                violations.append(f"line {line}: import from module '{mod}' not in allow-list")
            for a in node.names:
                if a.name in FORBIDDEN_CALLS or a.name in FORBIDDEN_DUNDER_ATTRS:
                    violations.append(f"line {line}: importing '{a.name}' is not allowed")

        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args
            for a in [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]:
                if a is not None and a.arg in FORBIDDEN_FIXTURES:
                    violations.append(f"line {line}: fixture '{a.arg}' is not allowed in generated tests")

        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in FORBIDDEN_CALLS - {"open", "exit", "dir", "help"}:
                violations.append(f"line {line}: call to forbidden attribute '.{func.attr}()'")

        elif isinstance(node, ast.Attribute):
            if node.attr in FORBIDDEN_DUNDER_ATTRS or (
                node.attr.startswith("__") and node.attr.endswith("__")
            ):
                violations.append(f"line {line}: dunder attribute access '.{node.attr}' is not allowed")
            elif node.attr.startswith("_"):
                violations.append(f"line {line}: private attribute access '.{node.attr}' is not allowed")
            if node.attr in FORBIDDEN_ATTRS:
                violations.append(f"line {line}: attribute '.{node.attr}' is not allowed")
            root = _root_name(node)
            if root is not None and (root in FORBIDDEN_MODULES or root in tainted):
                violations.append(f"line {line}: attribute use of forbidden module '{root}'")

        elif isinstance(node, ast.Name):
            if node.id in FORBIDDEN_CALLS:
                violations.append(f"line {line}: use of forbidden builtin '{node.id}' is not allowed")
            elif node.id in FORBIDDEN_DUNDER_ATTRS or (node.id.startswith("__") and node.id.endswith("__")):
                violations.append(f"line {line}: use of '{node.id}' is not allowed")
            elif node.id in FORBIDDEN_MODULES and node.id not in {"io", "http", "signal", "cache"}:
                pass  # a bare name like ``os`` without import is a NameError at runtime, harmless

        elif isinstance(node, ast.Constant):
            if isinstance(node.value, str) and "__" in node.value:
                violations.append(f"line {line}: string literal containing '__' is not allowed")

        elif isinstance(node, ast.While):
            if _is_truthy_const(node.test) and not _loop_has_break(node):
                violations.append(f"line {line}: infinite 'while' loop without a break")

        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            violations.append(f"line {line}: '{type(node).__name__.lower()}' statements are not allowed")

    # Deduplicate while keeping order.
    seen: set[str] = set()
    unique = []
    for v in violations:
        if v not in seen:
            seen.add(v)
            unique.append(v)
    return unique


def is_safe(
    source: str,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    allowed_modules: Iterable[str] = ("parser",),
) -> bool:
    return not check_test_source(source, max_bytes=max_bytes, allowed_modules=allowed_modules)


__all__ = [
    "ALLOWED_MODULES",
    "DEFAULT_MAX_BYTES",
    "FORBIDDEN_ATTRS",
    "FORBIDDEN_CALLS",
    "FORBIDDEN_FIXTURES",
    "FORBIDDEN_DUNDER_ATTRS",
    "FORBIDDEN_MODULES",
    "check_test_source",
    "is_safe",
]
