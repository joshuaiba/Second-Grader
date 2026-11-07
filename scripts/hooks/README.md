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

## P1.1 discovery note (Muse Code 1.4.x)

Sources: dev.meta.ai/docs/muse-code (`/extending`, `/configuration`, `/permissions`, `/changelog`),
docs.arcjet.com/coding-agents/muse-code. Items marked *(3rd party)* come from public issue
threads, not Meta's docs. Items marked *(unverified)* need one real run to confirm.

| Topic | What we know |
|---|---|
| Install | `brew install --cask muse-code` or Meta's install script. The binary is `muse`. **Not installed on Kevin's machine yet.** |
| Headless | `muse exec "<prompt>" --json` writes JSONL events to stdout. `--model muse-spark-1.3`. Exit code 0 means the turn completed (it does not mean the work is correct). |
| Flags | `--disable-sandbox` turns the sandbox off but keeps approvals on. A headless run probably also needs `--disable-approval` so it doesn't hang on a prompt *(unverified)*. Override with `$SG_MUSE_FLAGS`. |
| Config | Project hooks go in `<repo>/.muse/hooks.json` and load only in a trusted workspace. Since 1.4.4, `--trust-workspace` may only gate skills and rules *(unverified)*. |
| Format | `{"hooks": {"<Event>": [{"matcher": "...", "hooks": [{"type": "command", "command": "...", "timeout": 2}]}]}}` (timeout in seconds) |
| Environment | Hooks run with a **cleared environment** plus an allowlist that includes `MUSE_SESSION_ID`. Because of that, the socket path goes on the command line. |
| Events | SessionStart, UserPromptSubmit, PreToolUse, PermissionRequest, PostToolUse, **PostToolUseFailure**, PostToolBatch, PreLLMCall, PostLLMCall, Pre/PostCompact, SubagentStart/Stop, Notification, Stop, StopFailure, SessionEnd |
| Payload, common fields *(3rd party)* | `hook_event_name`, `session_id`, `turn_id`, `cwd`, `permission_mode`, `model`, `transcript_path` (null under `muse exec`) |
| PreToolUse | `tool_name`, `tool_input`, `tool_use_id`. Example: `{"hook_event_name":"PreToolUse","tool_name":"edit_file","tool_input":{"find":"two","path":"probe-new.txt","replace":"three"}}` |
| PostToolUse | Adds `tool_response`. For shell tools it is a **JSON string** holding `{exit_code, output}`, so it must be parsed twice *(3rd party)*. |
| PostToolUseFailure | **A failing tool, including bash with a non-zero exit, fires this event and not PostToolUse.** Adds `error`, `duration_ms` and `is_interrupt`. We hook both, or we would miss failing test runs. |
| Tool names | `bash`, `shell`, `exec_command`, `read_file`, `write_file`, `edit_file`, `search` *(3rd party)* |
| Model text | SubagentStop has `last_assistant_message`. The Stop and PostLLMCall payloads are **undocumented**. As a fallback, the runner also reads assistant text from `--json` stdout (`source: "agent_stdout"`). |
| Exit codes | Exit 2 denies the action on PreToolUse and UserPromptSubmit. On PostToolUse, exit 2 replaces the tool result the model sees, but the action has already happened. |
| Default timeout | **Not documented.** We set 2 s explicitly. |
| API key | `META_API_KEY` |

Still unknown, to settle with the first real run: the default hook timeout and what happens on a
timeout; the Stop payload; whether `bash` input uses `command` or `cmd` (we accept both); whether
project hooks load under `--trust-workspace`; and where the session log lives.

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
