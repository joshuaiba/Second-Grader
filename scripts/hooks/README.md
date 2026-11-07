# Muse Code hooks (P1, Kevin)

## How recording works

```
muse exec  --hook-->  forward.py  --unix socket-->  recorder service  -->  trace.jsonl + .seal.json
                      (stdlib only,                 (holds the key in memory,
                       no key, exit 2               maps events, sets OBSERVED/CLAIMED,
                       on any error)                fingerprints the code, signs)
```

- `forward.py --sock <path>`: the only hook. It forwards the raw event and exits 0 only when the
  recorder confirms the write. On any error, or after 1.5 s, it exits 2. We set Muse Code's hook
  timeout to 2 s, so our script always fails before Muse Code's timeout does, because a timeout lets
  the action through.
- The runner writes `.muse/hooks.json` into each throwaway clone and hides it with `.git/info/exclude`.
  It registers `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `PostLLMCall`,
  `Stop` and `SubagentStop`.
- `scripted_agent.py` is a stand-in that fires the same hooks around real shell actions. We use it
  for tests and rehearsal only. Its runs are signed as `agent: "scripted"` and must never be shown
  as Muse Code runs.
- Measured hook overhead (scripted end-to-end test): p95 is under the 150 ms target, and the test
  enforces it.

## P1.1 discovery note (confirmed on Muse Code 1.4.14, Kevin's machine)

These are captured from real runs (`muse exec` with a hook that dumps every event's stdin).
Anything not confirmed is marked.

| Topic | What we know |
|---|---|
| Install | Installed at `~/.local/bin/muse` (1.4.14-R7309.1). |
| Headless command | `muse exec --json --model muse-spark-1.3 --session-id <uuid> --reasoning-effort medium --max-model-steps 40 --trust-workspace --disable-sandbox --disable-approval --disable-request-user-input --disable-reminders --disable-web-tools "<prompt>"` |
| Hooks load | `<repo>/.muse/hooks.json` **does** load with `--trust-workspace` (stderr shows `workspace trust: trusted source=run-flag`). |
| Format | `{"hooks": {"<Event>": [{"hooks": [{"type": "command", "command": "...", "timeout": 2}]}]}}` |
| Hook environment | `PATH`, `HOME`, `USER`, `SHELL`, `TMPDIR`, `PWD`, `MUSE_SESSION_ID`, `MUSE_THREAD_ID`, `TRACEPARENT`. Nothing else, so the socket path goes on the command line. |
| Common fields | `hook_event_name`, `session_id`, `turn_id`, `cwd`, `transcript_path` (always null), `model`, `permission_mode`, `model_provider` |
| UserPromptSubmit | `prompt` |
| PreToolUse | `tool_name` (`bash`, `read_file`, `search`, ...), `tool_input` (bash: `command`, `description`, `workdir`), `tool_use_id` |
| PostToolUse | Adds `tool_response`: for bash, a **JSON string** `{"chunk_id", "command", "exit_code", "terminal_status", "output", "truncated", ...}` |
| PostToolUseFailure | **Fires instead of PostToolUse when a command exits non-zero.** It has no `tool_response`: the same JSON string (with `exit_code`, `output` and `terminal_reason`) is in **`error`**. Also has `is_interrupt` and `duration_ms`. |
| Stop | `last_assistant_message`: the agent's **final answer, in full**. This is our main CLAIMED record. |
| PostLLMCall | `output_text_preview` (may end in `...[truncated]`), `tool_call_count`, `step`, `usage`, `messages`. We record the preview only when the call also made tool calls (narration); the final answer comes from Stop. |
| Helper agents | Muse Code runs internal "reminder" subagents (`SubagentStart`/`SubagentStop`, own `session_id`). Their text is system boilerplate, **never** an agent claim. The recorder takes the main session id from `SessionStart` and ignores helper text; `--disable-reminders` turns them off. |
| Transcript | `muse export --session <uuid> --out file.json` writes Muse Code's own session log. The runner saves it as `muse_session.json` (for humans, not evidence). |
| Not confirmed | Muse Code's default hook timeout (we set 2 s) and what happens on a timeout. Our hook gives up at 1.5 s and exits 2 either way. |

## Record conventions the recorder writes (for P2 and P3)

- Every `tool_output`, `test_run` and `diff` record written after a tool event carries
  `"tree"`: the git tree hash of the working copy right after that step. A test run counts as fresh
  only if its `tree` equals the final tree.
- `diff` records come from the **fingerprint**, not from edit-tool events. Each has `path`, `status`,
  `diff`, `lines_added`, `lines_removed`, `tree_before`, `tree` and `via_tool`. Shell edits show up
  here too.
- `test_run` with `"source": "agent"`: a pytest command the agent ran. `exit_code` is the exit code
  of the **whole shell command**, so it is masked when the output is piped (`| tail`). It may be
  `null` if Muse Code didn't report one.
- `test_run` with `"source": "ground_truth"` and `"ground_truth": true`: our own runs on clean copies. `phase` is one of
  `collect_base`, `collect_final` (with `node_ids`) or `full_final`. A `diff` with
  `"source": "ground_truth"` is the true base-to-final change, one record per file.
- The first record is a `prompt` written by the runner (`"source": "runner"`, plus `task_id`).
- An agent `test_run` also has `tool_failed: true` when Muse Code reported the tool as failed
  (`PostToolUseFailure`).

## Verifying a trace (for P3's gate and page)

- `recorder.verify_chain(path)` returns `(ok, first_bad_seq)`. `recorder.verify_report(path)` returns
  the full report: `reason`, `detail`, per-record `statuses` (`ok`/`bad`/`untrusted`), `signed`,
  `sealed`, `pubkey`, `head_hash`, `count` and `run` (the signed run metadata).
- **For real runs, pass `require_signed=True` (or set `SG_REQUIRE_SIGNED=1`) and
  `expect_run_id=<run_id>`.** Without them, an all-`UNSIGNED` trace with no seal passes on hashes
  alone. That is only meant for the hand-written fixtures.
- Seal file `<trace>.seal.json` keys (stable): `version`, `pubkey`, `count`, `head_hash`,
  `sealed_at`, `sig`, and `run` = {`run_id`, `task_id`, `mode` (`LIVE`/`REPLAY`), `recorded_at`,
  `base_commit`, `base_tree`, `agent` (`muse-code`/`scripted`), and on replays `replayed_at` and
  `recorded_run_id`}.
- Replays are labelled `mode: "REPLAY"` inside the signed seal, so the label can't be removed without
  breaking the seal.
- Writing results into the chain: call `recorder.append({"kind": ..., "payload": ...}, trace_path)` after the
  agent has stopped. The recorder sets the seq, the timestamp and the OBSERVED/CLAIMED tag. The socket only
  takes hook events, so the agent can't use it to write arbitrary records.
- Known limit (say it openly in Q&A): the agent runs as the same OS user, so it could read `keys/` or send
  fake hook events. The real fix is a separate user or a container.
