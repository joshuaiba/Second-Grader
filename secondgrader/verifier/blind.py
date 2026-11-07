"""Blinded verifier core (P3.2, P3.3, P3.5, P3.6).

The verifier is a different model family from the agent (Gemini vs Muse) and
it is **blind**: its prompt is built from an allow-list only:

    1. the task spec,
    2. the agent's diff with every test file removed,
    3. a summary of OBSERVED records (commands run, exit codes, files touched).

It never sees CLAIMED records (the agent's prompt and messages) and never sees
test-file contents. :func:`assert_blind` checks that mechanically before any
network call. The model only *writes tests*; whether they pass is decided by
running them (:func:`run_tests`). Errors inside a verifier test (syntax,
import, a wrong attribute) are retried once and never block. Only assertion
failures count.

Blind phase and probe phase (P3.6) are **separate calls with separate
prompts**, so claim text from the agent never shapes the blind tests.
"""

from __future__ import annotations

import ast
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Protocol

from secondgrader.schema import Record, VerifierResult

from .safety import check_test_source


class BlindnessViolation(ValueError):
    """Raised when the verifier's input would contain something it may not see."""


class TextModel(Protocol):
    def generate(self, prompt: str, *, system: str | None = None) -> str: ...


# --------------------------------------------------------------------------- #
# What counts as a test file
# --------------------------------------------------------------------------- #

_TEST_FILE_RE = re.compile(
    r"(^|/)(tests?|testing|specs?)/"          # tests/, test/, spec/ directories
    r"|(^|/)tests?_[^/]*\.py$"               # test_x.py, tests_x.py
    r"|(^|/)tests?\.py$"                     # tests.py
    r"|_(tests?|spec)\.py$"                  # x_test.py, x_spec.py
    r"|\.(tests?|spec)\.py$"                # x.test.py
    r"|(^|/)conftest\.py$",
    re.IGNORECASE,
)
_TEST_CONFIG = {"pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml", ".coveragerc"}


def is_test_path(path: str) -> bool:
    """True for test modules, test directories and test configuration files."""
    p = path.strip().lstrip("./")
    if p.startswith(("a/", "b/")):
        p = p[2:]
    return bool(_TEST_FILE_RE.search(p)) or Path(p).name in _TEST_CONFIG


# --------------------------------------------------------------------------- #
# P3.2 Build the blind input from the allow-list
# --------------------------------------------------------------------------- #

@dataclass
class BlindInput:
    spec: str
    non_test_diff: str
    observed_summary: str
    removed_test_paths: list[str] = field(default_factory=list)


_DIFF_HEADER_RE = re.compile(r"^(?:diff --git a/(?P<g>\S+) b/\S+|--- (?:a/)?(?P<m>\S+))", re.M)


def split_diff_by_file(diff: str) -> list[tuple[str, str]]:
    """Split a unified diff into ``(path, chunk)`` pairs, one per file."""
    if not diff.strip():
        return []
    starts = [m.start() for m in re.finditer(r"^(?=diff --git |--- )", diff, re.M)]
    # "--- " lines that immediately follow a "diff --git" belong to the same file
    chunks: list[tuple[str, str]] = []
    i = 0
    while i < len(starts):
        start = starts[i]
        end = starts[i + 1] if i + 1 < len(starts) else len(diff)
        if diff.startswith("diff --git", start) and i + 1 < len(starts) and diff.startswith("--- ", starts[i + 1]):
            end = starts[i + 2] if i + 2 < len(starts) else len(diff)
            i += 1
        chunk = diff[start:end]
        m = _DIFF_HEADER_RE.match(chunk)
        path = (m.group("g") or m.group("m")) if m else "?"
        if path == "/dev/null":
            m2 = re.search(r"^\+\+\+ (?:b/)?(\S+)", chunk, re.M)
            path = m2.group(1) if m2 else path
        chunks.append((path, chunk))
        i += 1
    return chunks


def strip_test_files(diff: str) -> tuple[str, list[str]]:
    """Remove every test-file hunk from a unified diff. Returns (diff, removed paths)."""
    kept: list[str] = []
    removed: list[str] = []
    for path, chunk in split_diff_by_file(diff):
        if is_test_path(path):
            removed.append(path)
        else:
            kept.append(chunk)
    return "".join(kept), removed


_WRITE_MARKERS = (">", "<<", "tee ", "sed -i", "cat >", "echo ", "printf ", "python -c", "python3 -c")


def _safe_command(command: str) -> str:
    """Reduce a shell command to something that cannot carry file contents.

    Anything that writes or embeds data (heredocs, redirects, ``echo``, inline
    python) is reduced to its first word. Everything else is cut to its first
    line, at most 80 characters.
    """
    first_line = command.strip().splitlines()[0] if command.strip() else ""
    if any(m in command for m in _WRITE_MARKERS) or "\n" in command.strip():
        head = first_line.split()[0] if first_line.split() else "?"
        return f"{head} ... (command body withheld)"
    return first_line[:80] + ("..." if len(first_line) > 80 else "")


def summarize_observed(observed: list[Record]) -> str:
    """One line per OBSERVED record: what happened, never what was said.

    Test-file diffs are reduced to their path. Tool output contents are
    reduced to size and hash. ``output_tail`` of test runs is dropped because
    it can quote test names and assertions.
    """
    lines: list[str] = []
    for r in observed:
        if r.origin != "OBSERVED":
            raise BlindnessViolation(f"record seq {r.seq} is {r.origin}; the verifier may only see OBSERVED records")
        p = r.payload or {}
        if r.kind == "tool_call":
            args = p.get("args") or {}
            detail = _safe_command(str(args.get("command") or args.get("path") or ""))
            lines.append(f"seq {r.seq}: tool_call {p.get('tool', '?')} {detail}".rstrip())
        elif r.kind == "tool_output":
            lines.append(f"seq {r.seq}: tool_output {p.get('tool', '?')} path={p.get('path', '')} bytes={p.get('bytes', '?')} exit={p.get('exit_code', '')}".rstrip(" exit="))
        elif r.kind == "diff":
            path = str(p.get("path", "?"))
            if is_test_path(path):
                lines.append(f"seq {r.seq}: diff {path} (test file; contents withheld)")
            else:
                lines.append(f"seq {r.seq}: diff {path} +{p.get('lines_added', '?')} -{p.get('lines_removed', '?')}")
        elif r.kind == "test_run":
            lines.append(
                f"seq {r.seq}: test_run `{p.get('command', '?')}` exit={p.get('exit_code', '?')} "
                f"passed={p.get('passed', '?')} failed={p.get('failed', '?')} "
                f"selected={p.get('selected', '?')}/{p.get('collected', '?')}"
            )
        elif r.kind in ("verifier_test", "verdict"):
            continue  # our own earlier output; not evidence about the code
        else:
            lines.append(f"seq {r.seq}: {r.kind}")
    return "\n".join(lines)


def build_blind_input(spec: str, diff: str, observed: list[Record]) -> BlindInput:
    """Assemble the allow-listed input. Raises BlindnessViolation on CLAIMED records."""
    for r in observed:
        if r.origin != "OBSERVED":
            raise BlindnessViolation(f"record seq {r.seq} is {r.origin}; pass schema.observed(records)")
    non_test, removed = strip_test_files(diff)
    return BlindInput(spec=spec.strip(), non_test_diff=non_test, observed_summary=summarize_observed(observed), removed_test_paths=removed)


def _claimed_snippets(records: list[Record], min_len: int = 20) -> list[str]:
    """Sentences of the agent's own words. ``prompt`` records are our task text (written by the
    runner, allowed input by definition), so they are not agent text."""
    out: list[str] = []
    for r in records:
        if r.origin != "CLAIMED" or r.kind == "prompt":
            continue
        text = str((r.payload or {}).get("text", ""))
        for sent in re.split(r"(?<=[.!?])\s+|\n", text):
            s = sent.strip()
            if len(s) >= min_len:
                out.append(s)
    return out


def _test_diff_lines(records: list[Record], diff: str) -> list[str]:
    out: list[str] = []
    sources = [str((r.payload or {}).get("diff", "")) for r in records if r.kind == "diff" and is_test_path(str((r.payload or {}).get("path", "")))]
    for path, chunk in split_diff_by_file(diff):
        if is_test_path(path):
            sources.append(chunk)
    for src in sources:
        for line in src.splitlines():
            if line[:1] in "+-" and not line.startswith(("+++", "---")) and len(line.strip()) > 8:
                out.append(line[1:].strip())
    return out


def assert_blind(prompt: str, all_records: list[Record], diff: str = "", *, allow: Iterable[str] = ()) -> None:
    """Mechanical check (P3.2 done-when): the prompt holds no agent text and no test code.

    Args:
        prompt: The exact text that will be sent to the model.
        all_records: The **full** trace, CLAIMED included, so leaks can be found.
        diff: The agent's full diff, so test-file lines can be found.
        allow: Text that is permitted in this prompt on purpose (the probe
            claims in the probe phase). It is removed before scanning.
    """
    for text in allow:
        if text:
            prompt = prompt.replace(text, "")
    for snippet in _claimed_snippets(all_records):
        if snippet in prompt:
            raise BlindnessViolation(f"prompt contains agent text: {snippet[:60]!r}")
    for line in _test_diff_lines(all_records, diff):
        if line in prompt:
            raise BlindnessViolation(f"prompt contains test-file code: {line[:60]!r}")


# --------------------------------------------------------------------------- #
# P3.3 / P3.6 Prompts
# --------------------------------------------------------------------------- #

SYSTEM = (
    "You are an independent test author. You write pytest tests from a specification and a diff. "
    "You have not seen and must not guess the author's own tests. Reply with Python code only, no prose, no fences."
)


def render_blind_prompt(bi: BlindInput, module_name: str) -> str:
    return (
        f"Write a pytest test module for the Python module `{module_name}` that checks the SPECIFICATION below.\n"
        f"Rules:\n"
        f"- Import only `pytest` and `from {module_name} import ...`. No other imports.\n"
        f"- Write 3 to 6 small test functions named test_*. Each tests ONE sentence of the specification.\n"
        f"- Put the exact specification sentence each test checks as its docstring, prefixed `spec: `.\n"
        f"- Use only plain asserts and pytest.raises. No files, network, subprocess, or environment access.\n"
        f"- Do not test behaviour the specification does not mention.\n"
        f"- Output only the Python source of the test module.\n\n"
        f"SPECIFICATION:\n{bi.spec}\n\n"
        f"DIFF (non-test files only):\n{bi.non_test_diff or '(no diff provided)'}\n\n"
        f"OBSERVED RUN SUMMARY (facts only):\n{bi.observed_summary or '(none)'}\n"
    )


def render_probe_prompt(bi: BlindInput, module_name: str, probes: list[str]) -> str:
    bullet = "\n".join(f"- {p.strip()}" for p in probes if p.strip())
    return (
        f"Write a pytest test module for the Python module `{module_name}`.\n"
        f"Someone asserts the following behaviours about the code in the DIFF. Write exactly one test per "
        f"bullet that would FAIL if the behaviour does not hold.\n"
        f"Rules:\n"
        f"- Import only `pytest` and `from {module_name} import ...`. No other imports.\n"
        f"- Name each test test_probe_<n> in bullet order, and put the bullet text as its docstring, prefixed `probe: `.\n"
        f"- Use only plain asserts and pytest.raises. No files, network, subprocess, or environment access.\n"
        f"- Output only the Python source of the test module.\n\n"
        f"BEHAVIOURS TO PROBE:\n{bullet}\n\n"
        f"SPECIFICATION (for context):\n{bi.spec}\n\n"
        f"DIFF (non-test files only):\n{bi.non_test_diff or '(no diff provided)'}\n"
    )


_FENCE_RE = re.compile(r"^```[a-zA-Z0-9_-]*\n(.*?)\n```\s*$", re.S | re.M)


def parse_test_source(response: str) -> str:
    """Strip markdown fences and surrounding prose from a model response."""
    text = response.strip()
    m = _FENCE_RE.search(text)
    if m:
        return m.group(1).strip() + "\n"
    if "```" in text:
        inner = text.split("```", 2)
        if len(inner) >= 2:
            body = inner[1]
            body = body.split("\n", 1)[1] if body.startswith(("python", "py")) else body
            return body.strip() + "\n"
    return text + "\n"


def tag_tests(source: str, prefix: str = "spec") -> dict[str, str]:
    """Map each test function name to the spec (or probe) sentence in its docstring."""
    tags: dict[str, str] = {}
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return tags
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
            doc = ast.get_docstring(node) or ""
            tags[node.name] = re.sub(rf"^{prefix}\s*:\s*", "", doc.strip(), flags=re.I).strip()
    return tags


# --------------------------------------------------------------------------- #
# P3.5 Run the tests in a fresh copy of the final code
# --------------------------------------------------------------------------- #

_IGNORE = shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", "*.pyc", ".venv", "node_modules")

_ASSERTION_MARKERS = ("assert", "AssertionError", "Failed:", "DID NOT RAISE")
_TB_FRAME_RE = re.compile(r"^(?P<path>[^\s:]+\.py):(?P<line>\d+):", re.M)


def _is_assertion_failure(message: str, test_file_name: str = "") -> bool:
    """Decide whether a pytest ``<failure>`` is the code under test failing the spec.

    - plain asserts, ``pytest.fail`` and ``pytest.raises`` not raising: failure
    - an exception whose innermost frame is in the **code under test** (the
      spec says it should not raise there): failure
    - an exception whose innermost frame is in the generated test file itself
      (a wrong attribute, a typo, a bad fixture): the verifier's own error,
      never blocking
    """
    msg = message.strip()
    first = msg.split("\n", 1)[0]
    if first.startswith(_ASSERTION_MARKERS) or "AssertionError" in first:
        return True
    frames = [m.group("path") for m in _TB_FRAME_RE.finditer(msg)]
    if not frames:
        return False
    innermost = Path(frames[-1]).name
    return bool(test_file_name) and innermost != test_file_name


def _fresh_copy(final_code_dir: Path, dest: Path) -> None:
    shutil.copytree(final_code_dir, dest, ignore=_IGNORE, dirs_exist_ok=True)
    for p in list(dest.rglob("*")):
        if p.exists() and is_test_path(str(p.relative_to(dest))) and p.name not in _TEST_CONFIG:
            shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink(missing_ok=True)


def _run_pytest_once(workdir: Path, test_file: Path, timeout: int) -> tuple[list[dict[str, Any]], str]:
    junit = workdir / "verifier_junit.xml"
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "no:monkeypatch", "-p", "no:tmpdir", "--tb=short",
           f"--junitxml={junit}", "--rootdir", str(workdir), str(test_file)]
    try:
        proc = subprocess.run(cmd, cwd=workdir, capture_output=True, text=True, timeout=timeout,
                              env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(workdir), "PYTHONDONTWRITEBYTECODE": "1", "HOME": str(workdir)})
        log = (proc.stdout + proc.stderr)[-4000:]
    except subprocess.TimeoutExpired:
        return [{"name": test_file.stem, "passed": False, "outcome": "error", "output": f"timeout after {timeout}s"}], "timeout"
    results: list[dict[str, Any]] = []
    if not junit.exists():
        return [{"name": test_file.stem, "passed": False, "outcome": "error", "output": log}], log
    root = ET.parse(junit).getroot()
    for case in root.iter("testcase"):
        name = case.get("name", "?")
        failure = case.find("failure")
        error = case.find("error")
        skipped = case.find("skipped")
        if failure is not None:
            msg = (failure.get("message") or "") + "\n" + (failure.text or "")
            if _is_assertion_failure(msg, test_file.name):
                results.append({"name": name, "passed": False, "outcome": "failed", "output": msg.strip()[:2000]})
            else:
                results.append({"name": name, "passed": False, "outcome": "error", "output": msg.strip()[:2000]})
        elif error is not None:
            msg = (error.get("message") or "") + "\n" + (error.text or "")
            results.append({"name": name, "passed": False, "outcome": "error", "output": msg.strip()[:2000]})
        elif skipped is not None:
            results.append({"name": name, "passed": False, "outcome": "error", "output": "skipped"})
        else:
            results.append({"name": name, "passed": True, "outcome": "passed", "output": ""})
    if not results:  # collection error: pytest emits a single testcase with <error>, or nothing
        results.append({"name": test_file.stem, "passed": False, "outcome": "error", "output": log})
    return results, log


def run_tests(final_code_dir: str | Path, test_source: str, *, name: str = "test_verifier_blind.py",
              timeout: int = 60, retries: int = 1) -> list[dict[str, Any]]:
    """Run ``test_source`` against a fresh copy of ``final_code_dir``.

    Returns one dict per test: ``{"name", "passed", "outcome", "output"}`` where
    outcome is ``passed`` / ``failed`` (assertion failed) / ``error`` (the test
    itself is broken). Errors are retried ``retries`` times; they never count
    as failures. The agent's own test files are removed from the copy.
    """
    final_code_dir = Path(final_code_dir)
    attempt = 0
    while True:
        with tempfile.TemporaryDirectory(prefix="sg-verify-") as tmp:
            work = Path(tmp) / "code"
            _fresh_copy(final_code_dir, work)
            test_file = work / name
            test_file.write_text(test_source, encoding="utf-8")
            results, _log = _run_pytest_once(work, test_file, timeout)
        had_error = any(r["outcome"] == "error" for r in results)
        if not had_error or attempt >= retries:
            return results
        attempt += 1


# --------------------------------------------------------------------------- #
# The whole verifier
# --------------------------------------------------------------------------- #

RecorderAppend = Callable[[dict[str, Any]], Any]


def _record(append: RecorderAppend | None, payload: dict[str, Any]) -> int | None:
    if append is None:
        return None
    rec = append({"kind": "verifier_test", "origin": "OBSERVED", "payload": payload})
    return getattr(rec, "seq", None)


def mark_weak_tests(details: list[dict[str, Any]], base_code_dir: Path, source: str, *, phase: str,
                    timeout: int) -> None:
    """P3.12: a test that also passes on the *base* code did not check the change.

    Sets ``detail["weak"] = True`` for tests that passed on both base and
    final. Weak tests are shown, never block, and stay counted as passed.
    """
    base_results = {r["name"]: r["outcome"] for r in run_tests(base_code_dir, source, name=f"test_verifier_{phase}_base.py",
                                                                timeout=timeout, retries=0)}
    for d in details:
        d["weak"] = d["outcome"] == "passed" and base_results.get(d["name"]) == "passed"


def _phase(
    client: TextModel, prompt: str, *, phase: str, final_code_dir: Path, module_name: str,
    append: RecorderAppend | None, timeout: int, tag_prefix: str, base_code_dir: Path | None = None,
) -> tuple[list[dict[str, Any]], list[int], str]:
    source = parse_test_source(client.generate(prompt, system=SYSTEM))
    violations = check_test_source(source, allowed_modules=(module_name,))
    details: list[dict[str, Any]] = []
    seqs: list[int] = []
    if violations:
        payload = {"name": f"{phase}:rejected", "source": source, "passed": None, "phase": phase,
                   "output": "rejected by static safety check: " + "; ".join(violations)}
        seq = _record(append, payload)
        if seq is not None:
            seqs.append(seq)
        return details, seqs, source
    tags = tag_tests(source, prefix=tag_prefix)
    results = run_tests(final_code_dir, source, name=f"test_verifier_{phase}.py", timeout=timeout)
    details = [{**r, "phase": phase, "spec_sentence": tags.get(r["name"], "")} for r in results]
    if base_code_dir is not None:
        mark_weak_tests(details, base_code_dir, source, phase=phase, timeout=timeout)
    for d in details:
        payload = {"name": d["name"], "source": source, "passed": d["passed"], "phase": phase,
                   "outcome": d["outcome"], "spec_sentence": d["spec_sentence"], "output": d["output"]}
        if "weak" in d:
            payload["weak"] = d["weak"]
        seq = _record(append, payload)
        if seq is not None:
            d["seq"] = seq
            seqs.append(seq)
    return details, seqs, source


def verify(
    spec: str,
    diff: str,
    observed: list[Record],
    *,
    client: TextModel,
    final_code_dir: str | Path,
    module_name: str = "parser",
    probes: list[str] | None = None,
    all_records: list[Record] | None = None,
    recorder_append: RecorderAppend | None = None,
    timeout: int = 60,
    base_code_dir: str | Path | None = None,
) -> VerifierResult:
    """Blind phase, then (optionally) probe phase. Each is its own model call.

    ``base_code_dir`` (P3.12, optional): the code before the agent's change.
    Tests that pass there too are flagged ``weak`` in the details.

    Raises:
        BlindnessViolation (a ValueError) if ``observed`` holds a CLAIMED record
        or the built prompt leaks agent text / test code. Checked before any
        model call.
    """
    bi = build_blind_input(spec, diff, observed)
    blind_prompt = render_blind_prompt(bi, module_name)
    # The spec is allowed input by definition, even though the runner's prompt record (CLAIMED) quotes it.
    assert_blind(blind_prompt, all_records or observed, diff, allow=[bi.spec])
    blind_without_spec = blind_prompt.replace(bi.spec, "")
    for p in probes or []:
        if p.strip() and p.strip() in blind_without_spec:
            raise BlindnessViolation("probe claim text leaked into the blind prompt")

    final_code_dir = Path(final_code_dir)
    base = Path(base_code_dir) if base_code_dir else None
    details, seqs, _ = _phase(client, blind_prompt, phase="blind", final_code_dir=final_code_dir,
                              module_name=module_name, append=recorder_append, timeout=timeout, tag_prefix="spec",
                              base_code_dir=base)

    if probes:
        probe_prompt = render_probe_prompt(bi, module_name, probes)
        assert_blind(probe_prompt, all_records or observed, diff, allow=[bi.spec, *probes])
        d2, s2, _ = _phase(client, probe_prompt, phase="probe", final_code_dir=final_code_dir,
                           module_name=module_name, append=recorder_append, timeout=timeout, tag_prefix="probe",
                           base_code_dir=base)
        details += d2
        seqs += s2

    counted = [d for d in details if d["outcome"] in ("passed", "failed")]
    return VerifierResult(
        tests_written=[d["name"] for d in details],
        passed=sum(1 for d in counted if d["outcome"] == "passed"),
        failed=sum(1 for d in counted if d["outcome"] == "failed"),
        details=details,
        record_seqs=seqs,
    )


__all__ = [
    "BlindInput", "BlindnessViolation", "SYSTEM", "assert_blind", "build_blind_input", "is_test_path", "mark_weak_tests",
    "parse_test_source", "render_blind_prompt", "render_probe_prompt", "run_tests", "split_diff_by_file",
    "strip_test_files", "summarize_observed", "tag_tests", "verify",
]
