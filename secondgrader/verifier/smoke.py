"""P3.1 smoke test: one Gemini call writes a pytest file for demo_repo/parser.py, we run it.

    uv run python -m secondgrader.verifier.smoke [--offline] [--model NAME]

Exit 0 on success. The response is cached (see client.py), so a second run makes
no network call. ``run_smoke(client)`` is the unit-testable core.
"""

from __future__ import annotations

import argparse
import ast
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .client import REPO_ROOT, GeminiClient, MissingApiKey, OfflineCacheMiss
from .safety import check_test_source

PARSER_PATH = REPO_ROOT / "demo_repo" / "parser.py"
TEST_FILENAME = "test_verifier_smoke.py"
PYTEST_TIMEOUT_S = 60

SYSTEM = (
    "You write small, deterministic pytest test files. Reply with Python source "
    "code only: no prose, no markdown fences."
)

_FENCE_RE = re.compile(r"^\s*```[a-zA-Z0-9_-]*\s*\n(.*?)\n\s*```\s*$", re.DOTALL)


def read_docstring(path: Path, func_name: str) -> str:
    """Return the docstring of ``func_name`` in ``path`` using ast only (never the tests)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            return ast.get_docstring(node) or ""
    raise LookupError(f"{func_name} not found in {path}")


def build_prompt(docstring: str, module: str = "parser", func: str = "parse_kv") -> str:
    return (
        f"Write ONE pytest test file for the function `{func}` in the module `{module}`.\n"
        f"Signature: `def {func}(text: str) -> dict[str, str]`\n"
        f"Docstring:\n\"\"\"\n{docstring}\n\"\"\"\n\n"
        "Requirements:\n"
        f"- Start with `from {module} import {func}` and `import pytest`.\n"
        "- Import nothing else (no os, sys, pathlib, subprocess, io, or network modules).\n"
        "- Define 3 to 6 functions named `test_*`, each with plain `assert` statements "
        "or `pytest.raises`.\n"
        "- Test only behaviour stated in the docstring. Keep it under 60 lines.\n"
        "- Output only the Python source. No explanation, no markdown fences."
    )


def strip_fences(text: str) -> str:
    """Remove a surrounding ``` block if the model added one anyway."""
    m = _FENCE_RE.match(text)
    if m:
        return m.group(1).strip() + "\n"
    # Fallback: drop any fence lines wherever they are.
    lines = [ln for ln in text.splitlines() if not ln.strip().startswith("```")]
    return "\n".join(lines).strip() + "\n"


def run_generated_test(test_source: str, module_path: Path = PARSER_PATH) -> dict:
    """Copy the module and the generated test into a temp dir and run pytest there."""
    with tempfile.TemporaryDirectory(prefix="sg_smoke_") as tmp:
        tmpdir = Path(tmp)
        shutil.copy(module_path, tmpdir / module_path.name)
        (tmpdir / TEST_FILENAME).write_text(test_source, encoding="utf-8")
        cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", TEST_FILENAME]
        try:
            proc = subprocess.run(
                cmd, cwd=tmpdir, capture_output=True, text=True, timeout=PYTEST_TIMEOUT_S
            )
        except subprocess.TimeoutExpired as e:
            return {
                "exit_code": None,
                "timed_out": True,
                "output": (e.stdout or "") if isinstance(e.stdout, str) else "",
            }
        return {
            "exit_code": proc.returncode,
            "timed_out": False,
            "output": (proc.stdout or "") + (proc.stderr or ""),
        }


def run_smoke(client: GeminiClient, module_path: Path = PARSER_PATH) -> dict:
    """Generate a test with ``client``, safety-check it, run it. Never raises for a bad test.

    Returns a dict with keys: ``ok``, ``stage`` ("generated", "safety", "pytest"),
    ``cache_hit``, ``cache_key``, ``violations``, ``test_source``, ``exit_code``, ``output``.
    """
    docstring = read_docstring(module_path, "parse_kv")
    prompt = build_prompt(docstring, module=module_path.stem, func="parse_kv")
    raw = client.generate(prompt, system=SYSTEM)
    test_source = strip_fences(raw)
    result: dict = {
        "ok": False,
        "stage": "generated",
        "cache_hit": client.last_hit,
        "cache_key": client.last_key,
        "violations": [],
        "test_source": test_source,
        "exit_code": None,
        "output": "",
        "timed_out": False,
    }

    violations = check_test_source(test_source, allowed_modules=(module_path.stem,))
    result["stage"] = "safety"
    result["violations"] = violations
    if violations:
        return result

    run = run_generated_test(test_source, module_path)
    result.update(run)
    result["stage"] = "pytest"
    result["ok"] = run["exit_code"] == 0
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--offline", action="store_true", help="never call the network; fail on cache miss")
    ap.add_argument("--model", default=None, help="override SG_VERIFIER_MODEL / gemini-4-argon")
    ap.add_argument("--show", action="store_true", help="print the generated test source")
    args = ap.parse_args(argv)

    client = GeminiClient(model=args.model, offline=True if args.offline else None)
    print(f"model: {client.model}")
    print(f"cache dir: {client.cache_dir}")
    try:
        result = run_smoke(client)
    except OfflineCacheMiss as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    except MissingApiKey as e:
        print(f"error: {e}", file=sys.stderr)
        return 4

    print("cache: hit" if result["cache_hit"] else "cache: miss (network call)")
    print(f"cache key: {result['cache_key']}")
    if args.show or not result["ok"]:
        print("--- generated test ---")
        print(result["test_source"].rstrip())
        print("----------------------")
    if result["violations"]:
        print("rejected by safety check:")
        for v in result["violations"]:
            print(f"  - {v}")
        return 2
    if result.get("timed_out"):
        print(f"pytest timed out after {PYTEST_TIMEOUT_S}s")
        return 1
    print(result["output"].rstrip())
    print(f"pytest exit code: {result['exit_code']}")
    print("smoke: OK" if result["ok"] else "smoke: FAILED")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
