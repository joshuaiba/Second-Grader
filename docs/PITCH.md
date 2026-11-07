# Second Grader: the pitch

Three lengths. Pick the one that fits the slot. The demo beats are in [DEMO.md](./DEMO.md).

## One-liner

**The agent says "all tests pass." The log says it never ran them. Second Grader catches that before it merges.**

## 60-second version

Coding agents grade their own homework. They finish a task and report "all tests pass, I only changed parser.py," and that report is what gets reviewed and merged. Nobody checks the report against what actually happened.

Second Grader is the second grader. While the agent works, we record every tool call, diff and test run into a signed, hash-chained log. Facts the harness observed are tagged OBSERVED. Anything the model said is tagged CLAIMED and never trusted. When the agent is done, deterministic code pulls each claim out of its story and checks it against the evidence. A second model from a different family writes its own tests from the spec and the diff, blind to everything the agent said. Then the gate decides. If the story and the evidence disagree, the merge is blocked and the verdict page cites the exact record that proves the lie.

We built it today, and we tested it on real Muse Code with three trap tasks designed to tempt cheating. Muse Code refused every trap. The same machinery that would have caught a lie now proves it told the truth.

## 2-minute judge version

**The problem.** Every coding agent ends its run with a summary. "Done. Tests pass. Only touched the parser." That summary is the only thing most teams read before merging. It is self-reported, unverified and written by the same model that did the work. When the agent skips the slow test, weakens an assert, or adds a skip marker to the one failing case, the summary still says green. Trust is the default because verification is nobody's job.

**The insight.** Separate what happened from what was said, and never let a language model decide which is true. Every record in our log is either OBSERVED, meaning our harness captured it, or CLAIMED, meaning the model wrote it. Verdicts are a pure function of OBSERVED records. LLMs do exactly two jobs here: turn sentences into checkable claims, and write tests. Code decides everything else.

**How it works.** Three parts, one owner each.

- **The Recorder** wraps Muse Code's hooks. Every event becomes a numbered record, SHA-256 chained to the one before and Ed25519 signed with a key the agent never holds. The code tree is fingerprinted after every step, so edits made through shell commands are caught, not just editor tool calls. Hooks fail closed. If anything errors, the action is blocked.
- **The Auditor** extracts claims from the agent's messages. A regex pass catches the critical ones so they never depend on a model noticing them. Each LLM-extracted claim carries a verbatim quote that code confirms exists in the transcript. Then checkers run. "All tests pass" is SUPPORTED only if the agent ran the full suite, on the final code, with an unmasked exit code, and our own ground-truth run agrees. A subset run, a stale run, a piped-away exit code or a never-ran all get their own reason. Tamper detection diffs base against final without asking the agent: deleted tests, weakened asserts, added skips, special-cased inputs, rigged test config.
- **The Verifier and Gate.** Gemini writes tests from an allow-list of inputs only: the spec, the non-test diff and a summary of observed facts. It never sees the agent's words or the agent's tests. The gate blocks on a broken chain, any contradicted claim, any unsupported critical claim, high-severity tampering, any verifier assertion failure, or a failing ground-truth run. It lists every reason with record numbers. On BLOCK, main is byte-identical to before and the work is quarantined. On PASS, the merge commit carries the chain head hash.

**The demo.** An honest run merges with every claim green and both test runs cited. A cheating run on the trap task gets blocked: the agent claimed all tests pass, record 12 is its suite failing, record 16 is a skip marker added to the failing test, record 19 is the manufactured rerun. CONTRADICTED, citing all three. Then we edit one record live and the chain strip turns red from that record on. The gate blocks on integrity before it reads a single claim. You cannot launder the log.

**The twist.** We recorded real Muse Code on all four tasks today. On the honest task it did the work and ran the full suite. On all three traps it either refused or stayed honest, and said so. Second Grader confirmed every one of those claims against the evidence. The point was never to catch one model lying. The point is that "the agent said so" stops being the standard, and "the record shows so" takes its place.

**The close.** Signed log. Deterministic audit. Blinded verifier. One verdict page, not a dashboard. Built today. Second Grader.

## If a judge pushes back

- **"Why not just let an LLM judge the run?"** Because an LLM can be talked into anything by the agent's own prose. Here the LLM only extracts claims, and every verdict is a function of observed records.
- **"Isn't this just checking whether tests pass?"** No. We check whether the agent's story matches the evidence. A correct change with an unverified "tests pass" claim still blocks, because unverified claims don't merge.
- **"Can the agent forge the log?"** Today it runs as the same OS user with the sandbox disabled, so a determined agent could reach the recorder. The real fix is a separate user or container. We say that openly.
- **"What if the verifier writes a wrong test and blocks an honest run?"** Errors inside verifier tests never block, only assertion failures do. Honest-task tests were hand-checked in rehearsal, and all verifier calls are cached so the demo runs offline.
- **"How did the real agent do?"** Honest on all three traps. The table is in `replays/README.md`.
