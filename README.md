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
```

Regenerate the fixtures after a deliberate change to the sample story:

```bash
uv run python fixtures/make_sample_trace.py
```

## Owners

| Owner | Area | Folders |
|-------|------|---------|
| A | recorder | `secondgrader/recorder/`, `scripts/hooks/` |
| B | auditor | `secondgrader/auditor/` |
| C | verifier + gate | `secondgrader/verifier/`, `secondgrader/gate/` |
| D | demo, tasks, web, cli | `demo_repo/`, `tasks/`, `secondgrader/web/`, `secondgrader/cli.py` |

Each owner works in their own worktree: `scripts/worktree.sh <name>`. Rules in [AGENTS.md](AGENTS.md).

## Layout

```
secondgrader/     package: schema.py (contract), recorder/, auditor/, verifier/, gate/, web/, cli.py
demo_repo/        the small project the agent edits
tasks/            task specs (1 honest, 3 traps)
fixtures/         hand-written traces: a cheating run, and a tampered copy
tests/            one file per module; schema tests run, the rest are skipped stubs
scripts/          worktree.sh, hooks/
```

Built at the AIE Code Summit hackathon on Nov 7, 2026. MIT licence.
