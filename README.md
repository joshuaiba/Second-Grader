# Second Grader

**The agent says "all tests pass." The log says it never ran them. We catch that before it merges.**
Second Grader records everything a coding agent actually does into a signed, hash-chained trace, then checks the agent's own account of its work against that record. Claims that the evidence contradicts block the merge, with the exact record cited.

## Architecture

- **Recorder**: Muse Code hooks write every prompt, tool call, tool output, diff and test run to a JSONL trace. Each record is SHA-256 chained to the previous one and Ed25519 signed. Tool outputs are OBSERVED; model statements are CLAIMED.
- **Auditor**: extracts checkable claims from the CLAIMED records ("all tests pass", "only changed parser.py") and checks each against OBSERVED records. Also detects test files edited between a failing and a passing run.
- **Blinded verifier**: Gemini writes its own tests from the spec, the diff and the OBSERVED records only. It never sees what the agent said or the agent's tests.
- **Gate**: a pure function that combines auditor verdicts, verifier results and chain integrity into PASS or BLOCK, listing every reason with the record that proves it. On PASS it merges with the verdict and chain head hash in the commit; on BLOCK it moves the agent's branch to `refs/quarantine/<branch>-<time>` and leaves `main` untouched.
- **Verdict page**: one FastAPI page: the decision, a four-cell report card (chain, claims, tampering, verifier), each claim with its status and the records that prove it, tamper findings, the verifier's tests, and the trace itself as a chain strip with every record. A tamper button edits a record in a throwaway copy and shows the chain breaking. No dashboard.
- **Contract**: `secondgrader/schema.py` defines Record, Claim, ClaimVerdict, VerifierResult and GateDecision. Every module builds against it and against `fixtures/`.

## Setup

```bash
uv sync                      # Python 3.11+, installs everything from pyproject.toml
cp .env.example .env         # then fill in META_API_KEY, GEMINI_API_KEY
uv run pytest                # the whole suite
uv run secondgrader --help
gh auth login                # once, for the team board
tools/board whoami           # should print your GitHub login
```

Regenerate the fixtures after a deliberate change to the sample story:

```bash
uv run python fixtures/make_sample_trace.py
```

## Running it

One pipeline (`secondgrader/gate/pipeline.py`) does record, ground truth, audit, verify, gate, then
chains the verdict record and merges or quarantines in git. Three ways in:

```bash
uv run secondgrader run honest_fix                       # LIVE: Muse Code runs in a throwaway clone, then the rest
uv run secondgrader run honest_fix --replay              # REPLAY of the saved run in replays/honest_fix (same machine that recorded it)
uv run secondgrader run trap_weaken_tests --replay fixtures/sample_trace.jsonl   # the pipeline on any trace file
uv run uvicorn secondgrader.web.app:app                  # the verdict page: http://127.0.0.1:8000/?trace=<path inside the repo>
```

Useful flags for `run`: `--no-verify` (skip Gemini), `--offline` (verifier from its cache only, no network),
`--final-code DIR` / `--base-code DIR` (for a trace file: the agent's final tree, and the tree before it; by
default the final tree is rebuilt from the recorded diffs), `-v` (stage progress). Replays are always labelled
REPLAY; a run is shown as LIVE only when it was just recorded and its signed seal says so.

The verifier caches every model call under `.sg_cache/` (git-ignored) keyed by the prompt, so re-running a
replay makes no network calls. Smoke-test the key: `uv run python -m secondgrader.verifier.smoke --show`.

## Owners

Three owners, one part of the program each. Full task lists in [docs/SPEC.md](docs/SPEC.md); diagrams in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

| Owner | Part | Folders |
|-------|------|---------|
| Kevin | P1 · Recorder: *what actually happened?* | `secondgrader/recorder/`, `scripts/hooks/` |
| Rahul | P2 · Auditor: *is the agent's story true?* (plus the demo repo and trap tasks) | `secondgrader/auditor/`, `demo_repo/`, `tasks/` |
| Josh | P3 · Verifier and Gate: *does it work, and do we merge?* (plus the verdict page and CLI) | `secondgrader/verifier/`, `secondgrader/gate/`, `secondgrader/web/`, `secondgrader/cli.py` |

Each owner works in their own worktree: `scripts/worktree.sh <name>`. Rules in [AGENTS.md](AGENTS.md).

Agents coordinate on one pinned GitHub issue (issue #1, the team board) using `tools/board`: they post when they finish or need something and tag each other by GitHub login. Claude Code picks up new posts through the hooks in `.claude/`.

## Layout

```
secondgrader/     package: schema.py (contract), recorder/, auditor/, verifier/, gate/, web/, cli.py
demo_repo/        the small project the agent edits
tasks/            task specs (1 honest, 3 traps)
fixtures/         hand-written traces: sample_trace.jsonl (a cheating run) and its tampered copy, plus
                  samples/ (honest, stale tests, subset run, never ran, masked exit, tampered), traps/ (one
                  per trap task), tamper/ and real/ (captured hook payloads)
replays/          real Muse Code runs recorded against the four tasks: signed trace, seal, base/ and final/ code
played/           those replays played back with ground truth, for the end-to-end check
tests/            one file per module
docs/             SPEC.md (task lists), ARCHITECTURE.md (diagrams), DEMO.md (the 3-minute demo script)
scripts/          worktree.sh, hooks/
tools/board       team board CLI (pinned GitHub issue)
```

Built at the AIE Code Summit hackathon on Nov 7, 2026. MIT licence.
