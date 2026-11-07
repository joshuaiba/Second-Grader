# Second Grader

**The agent says "all tests pass." The log says it never ran them. We catch that before it merges.**
Second Grader records everything a coding agent actually does into a signed, hash-chained trace, then checks the agent's own account of its work against that record. Claims that the evidence contradicts block the merge, with the exact record cited.

## Architecture

- **Recorder**: Muse Code hooks write every prompt, tool call, tool output, diff and test run to a JSONL trace. Each record is SHA-256 chained to the previous one and Ed25519 signed. Tool outputs are OBSERVED; model statements are CLAIMED.
- **Auditor**: extracts checkable claims from the CLAIMED records ("all tests pass", "only changed parser.py") and checks each against OBSERVED records. Also detects test files edited between a failing and a passing run.
- **Blinded verifier**: Gemini writes its own tests from the spec, the diff and the OBSERVED records only. It never sees what the agent said or the agent's tests.
- **Gate**: combines auditor verdicts, verifier results and chain integrity into PASS or BLOCK. On BLOCK it rolls the throwaway clone back and cites the contradicting record.
- **Verdict page**: one FastAPI page showing the decision, each claim with its status, and the cited records. No dashboard.
- **Contract**: `secondgrader/schema.py` defines Record, Claim, ClaimVerdict, VerifierResult and GateDecision. Every module builds against it and against `fixtures/`.

## Setup

```bash
uv sync                      # Python 3.11+, installs everything from pyproject.toml
cp .env.example .env         # then fill in META_API_KEY, GEMINI_API_KEY
uv run pytest                # schema tests run; module tests are skipped until implemented
uv run secondgrader --help
gh auth login                # once, for the team board
tools/board whoami           # should print your GitHub login
```

Regenerate the fixtures after a deliberate change to the sample story:

```bash
uv run python fixtures/make_sample_trace.py
```

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
fixtures/         hand-written traces: a cheating run, and a tampered copy
tests/            one file per module; schema tests run, the rest are skipped stubs
scripts/          worktree.sh, hooks/
tools/board       team board CLI (pinned GitHub issue)
```

Built at the AIE Code Summit hackathon on Nov 7, 2026. MIT licence.
