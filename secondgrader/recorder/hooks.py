"""Map raw Muse Code hook events to records.

Event names and payload fields are from P1.1 discovery (docs/MUSE_HOOKS.md).
Several fields are only third-party observed, so the mapping accepts the
known variants (``command`` or ``cmd``, ``tool_response`` as a dict or as a
JSON string) and never guesses beyond them.

Each event becomes zero or more ``(kind, payload)`` pairs. The service adds
the code fingerprint (``tree``) and, when the tree moved, ``diff`` records,
so shell edits (``sed -i``, ``cat >``) are caught as well as edit-tool edits.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

SHELL_TOOLS = {"bash", "shell", "exec_command", "run_shell_command", "terminal"}
#: Events after which the code may have changed: fingerprint the working copy.
POST_TOOL_EVENTS = {"PostToolUse", "PostToolUseFailure"}
#: Events that may carry the model's own words.
MESSAGE_EVENTS = {"Stop", "PostLLMCall"}
CONTENT_LIMIT = 4000

_TEST_CMD = re.compile(r"(^|[\s;&|(])(\S*/)?(python3?(\.\d+)?\s+-m\s+)?(\S*/)?(pytest|py\.test)(?=[\s;&|)]|$)")
_SUMMARY = re.compile(r"^=+ .* in [\d.]+s.* =+$|^\d+ \w+.* in [\d.]+s")
_COUNT = re.compile(r"(\d+) (passed|failed|errors?|skipped|deselected|xfailed|xpassed)")
_COLLECTED = re.compile(r"collected (\d+) items?")


def _event_name(event: dict[str, Any]) -> str:
    return str(event.get("hook_event_name") or event.get("event") or "")


def _maybe_json(value: Any) -> Any:
    if isinstance(value, str):
        s = value.strip()
        if s[:1] in "{[":
            try:
                return json.loads(s)
            except json.JSONDecodeError:
                return value
    return value


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def shell_command(tool_input: Any) -> str | None:
    if isinstance(tool_input, dict):
        cmd = tool_input.get("command", tool_input.get("cmd"))
        if isinstance(cmd, list):
            cmd = " ".join(map(str, cmd))
        return cmd if isinstance(cmd, str) else None
    return None


def _result_dict(value: Any) -> tuple[int | None, str] | None:
    """``(exit_code, text)`` from a shell result object, or None if it isn't one."""
    value = _maybe_json(value)
    if not isinstance(value, dict):
        return None
    exit_code = _as_int(value.get("exit_code", value.get("exitCode", value.get("returncode"))))
    parts = [value.get(k) for k in ("output", "stdout", "stderr", "content", "result")]
    text = "\n".join(p for p in parts if isinstance(p, str) and p)
    if not text and exit_code is None:
        text = json.dumps(value, sort_keys=True)
    return exit_code, text


def tool_result(event: dict[str, Any]) -> tuple[int | None, str]:
    """``(exit_code, output text)`` from a PostToolUse(/Failure) event.

    Real Muse Code 1.4.14 shapes (captured): PostToolUse has ``tool_response``
    as a JSON string ``{"exit_code", "output", ...}``. PostToolUseFailure has
    no ``tool_response``; the same JSON string is in ``error``.
    """
    exit_code: int | None = None
    text = ""
    resp = event.get("tool_response", event.get("tool_output"))
    parsed = _result_dict(resp)
    if parsed:
        exit_code, text = parsed
    elif resp is not None:
        text = str(resp)
    if _event_name(event) == "PostToolUseFailure":
        err = event.get("error")
        parsed_err = _result_dict(err)
        if parsed_err:
            code, err_text = parsed_err
            exit_code = exit_code if exit_code is not None else code
            text = (text + "\n" + err_text).strip()
        elif err:
            text = (text + "\n" + str(err)).strip()
            m = re.search(r"exit(?:ed)?(?: with)? (?:status|code) (\d+)", str(err))
            if exit_code is None and m:
                exit_code = int(m.group(1))
    return exit_code, text


def is_test_command(cmd: str | None) -> bool:
    return bool(cmd and _TEST_CMD.search(cmd))


def parse_pytest(output: str) -> dict[str, int | None]:
    """Counts from pytest's summary line. Missing counts are 0; ``collected`` may be None."""
    counts = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0, "deselected": 0}
    lines = [ln.strip() for ln in output.splitlines()]
    summary = [ln for ln in lines if _COUNT.search(ln) and _SUMMARY.search(ln)]
    summary = summary or [ln for ln in lines if _COUNT.search(ln)]
    if summary:
        for n, word in _COUNT.findall(summary[-1]):
            key = "errors" if word.startswith("error") else word
            if key in counts:
                counts[key] = int(n)
    m = _COLLECTED.search(output)
    collected = int(m.group(1)) if m else None
    selected = counts["passed"] + counts["failed"] + counts["errors"] + counts["skipped"]
    return {**counts, "selected": selected, "collected": collected}


def _clip(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {"content_sha256": hashlib.sha256(text.encode()).hexdigest(),
                           "bytes": len(text.encode())}
    out["content"] = text if len(text) <= CONTENT_LIMIT else text[-CONTENT_LIMIT:]
    out["truncated"] = len(text) > CONTENT_LIMIT
    return out


def _subagent_session(event: dict[str, Any], main_session: str | None) -> str | None:
    """The session id if this event comes from one of Muse Code's helper agents, else None."""
    sid = event.get("session_id")
    if main_session and sid and sid != main_session:
        return str(sid)
    return None


def map_event(event: dict[str, Any], main_session: str | None = None) -> list[tuple[str, dict[str, Any]]]:
    """Records for one hook event, without fingerprints (the service adds those).

    Only the main agent's words become CLAIMED ``model_message`` records:
    the final answer from ``Stop.last_assistant_message``, and text the model
    wrote alongside tool calls from ``PostLLMCall.output_text_preview``. Muse
    Code's internal helper agents (``SubagentStart``/``SubagentStop``, other
    session ids) never produce claims; their tool use is still recorded, marked
    with ``subagent_session``.
    """
    name = _event_name(event)
    common = {k: event[k] for k in ("tool_use_id", "turn_id") if event.get(k) is not None}
    sub = _subagent_session(event, main_session)
    if sub:
        common["subagent_session"] = sub
    tool = event.get("tool_name")
    if name == "UserPromptSubmit":
        prompt = event.get("prompt")
        return [("prompt", {"text": prompt, "source": "hook"})] if isinstance(prompt, str) and not sub else []
    if name == "PreToolUse":
        return [("tool_call", {"tool": tool, "args": event.get("tool_input") or {}, **common})]
    if name in POST_TOOL_EVENTS:
        exit_code, text = tool_result(event)
        failed = name == "PostToolUseFailure"
        out: dict[str, Any] = {"tool": tool, "exit_code": exit_code, "failed": failed, **common, **_clip(text)}
        cmd = shell_command(event.get("tool_input"))
        if cmd is not None:
            out["command"] = cmd
        records = [("tool_output", out)]
        if str(tool).lower() in SHELL_TOOLS and is_test_command(cmd):
            records.append(("test_run", {"command": cmd, "exit_code": exit_code, "source": "agent",
                                         "tool_failed": failed,
                                         **parse_pytest(text), "output_tail": text[-1500:], **common}))
        return records
    if sub:
        return []
    if name == "Stop":
        text = event.get("last_assistant_message")
        return [("model_message", {"text": text, "event": "Stop", "final": True,
                                   **common})] if isinstance(text, str) and text.strip() else []
    if name == "PostLLMCall":
        text = event.get("output_text_preview")
        if not (isinstance(text, str) and text.strip()) or not event.get("tool_call_count"):
            return []  # the final answer (no tool calls) is recorded from Stop, in full
        return [("model_message", {"text": text, "event": "PostLLMCall", "step": event.get("step"),
                                   "truncated": text.endswith("[truncated]"), **common})]
    return []
