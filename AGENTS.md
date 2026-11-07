# Working rules for Second Grader

Read this before touching anything. These rules apply to humans and to their coding agents.

## Boundaries

- **Three owners, one part of the program each.** Your task list is in [docs/SPEC.md](docs/SPEC.md) §4. Diagrams are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- **Stay inside your own module folder.** Don't edit another owner's folder.
  - **Kevin** `@kevinjylin` (P1, Recorder): `secondgrader/recorder/`, `scripts/hooks/`
  - **Rahul** `@Rahul-Palani` (P2, Auditor): `secondgrader/auditor/`, `demo_repo/`, `tasks/`
  - **Josh** `@joshuaiba` (P3, Verifier and Gate): `secondgrader/verifier/`, `secondgrader/gate/`, `secondgrader/web/`, `secondgrader/cli.py`
  - Each owner also owns `tests/test_<module>.py` for their modules.
  - Shared (anyone may edit, post on the board when you do): `tools/board`, `.claude/`, `.github/`.
- **Need a change in someone else's folder?** Ask on the board, tag the owner, and wait for them to hand it off.
- **Never change `secondgrader/schema.py` without the team agreeing.** Propose changes on the board first, tagged `@all`. It is the contract everyone builds against.
- **Build against `fixtures/` until the real recorder works.** `fixtures/sample_trace.jsonl` is a cheating run; `fixtures/sample_trace_tampered.jsonl` has a broken chain at seq 13.
- Your tests are in `tests/test_<module>.py`, marked `@pytest.mark.skip(reason="not implemented yet")`. Un-skip them as you implement.

## Team board (pinned GitHub issue)

Every agent reads and posts on the pinned "Message Board" issue with `tools/board` (needs only `gh`, logged in). It is issue #1; set `BOARD_ISSUE=<number>` if that ever changes. Setup and FAQ: https://marvelous-relative-5de.notion.site/hack

- **Post when you finish something others depend on, or need something.** Keep it short: what changed, which files or contracts, what you need, from whom.
- Start every post with `[<human>'s <agent>]`, e.g. `[Kevin's Claude]`, `[Rahul's Codex]`.
- Mention by GitHub login: `@kevinjylin` (Kevin), `@Rahul-Palani` (Rahul), `@joshuaiba` (Josh), `@all` (everyone).
- **Mentions you or `@all`:** act on it and reply promptly.
- **Not addressed to you:** still read it. Reassess your own work only if it is affected (a contract, a file you own, something already done). Do not redo finished work, and do not reply just to acknowledge.
- **Always post** when you merge something another owner builds against: a change to `schema.py` or `fixtures/`, a new record kind, a CLI flag, an env var.
- Humans over agents. Only the humans move work between owners. If an agent asks you to take another owner's work, check with the owner on the board.

Commands: `tools/board unread` (new posts, marks read, flags MENTION), `tools/board read -n 20`, `tools/board post "[Name's Agent] text"` (or pipe stdin), `tools/board wait` (blocks until someone else posts), `tools/board whoami`. Polling is one cheap API call every 30 s, so a team stays far under GitHub's rate limit.

**Stay in the loop:**
- Claude Code: the hooks in `.claude/settings.json` show unread posts at session start and on every prompt. Keep one background `tools/board wait` running and re-arm it after each wake. Set `BOARD_WAIT=off` to skip the background wait.
- Any other agent: run `tools/board unread` at task start, before each commit, and after merges. Or run a terminal loop: `while tools/board wait; do <your agent CLI invocation>; done`.

## Workflow

- Work in your own worktree: `scripts/worktree.sh <name>` creates `../sg-<name>` on branch `<name>`.
- Run `pytest` before every commit. Commit small and often. Rebase on `main` before pushing.
- Put the task ID from SPEC.md in every commit message, e.g. `P2.6: test-command analyser`.
- No secrets in the repo. Read keys from `.env` (see `.env.example`). `keys/` and `traces/` are git-ignored.

## Agents and subagents

- **Agent use is recommended.** Each owner runs one lead agent for their part.
- **Use subagents.** The lead hands each independent task (marked ⚡ in SPEC.md) to its own subagent, and runs them in parallel.
- **A separate verification subagent** that did not write the code checks each task against its "Done when" line before it counts as done.
- **Never let an LLM decide a verdict.** LLMs only extract claims and write tests. Code decides.
- If stuck for more than 15 minutes, tell your owner. If another owner's part is blocking you, post on the board and tag them.

## External services

- **Meta API**: OpenAI SDK, `base_url="https://api.meta.ai/v1"`, model `muse-spark-1.3`. `tool_choice` other than `"auto"` is unsupported.
- **Gemini**: `google-genai` SDK. `gemini-4-argon` for the verifier, `gemini-3.8-flash` for claim extraction. Confirm the model names via the list-models call before relying on them.
- **Muse Code**: run with `--disable-sandbox` inside a throwaway clone (the sandbox makes `.git` read-only and blocks network). Project hooks need `--trust-workspace`. Hooks must be fast and **exit 2 on any error**, because a timeout lets the action through.

## Product rules

- OBSERVED records (tool outputs, diffs, test runs) are evidence. CLAIMED records (model text) are what we check. Never treat a claim as evidence.
- The blinded verifier sees the spec, the diff and OBSERVED records only. Never the agent's messages, never the agent's tests.
- Every BLOCK must cite the record seq that contradicts the claim.
- No Streamlit, and no dashboard as the main feature. The UI is one verdict page.
