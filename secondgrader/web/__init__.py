"""Web (P3, Josh): one verdict page. FastAPI + a single HTML page. No dashboard.

The page shows, in this order: the MERGED/BLOCKED stamp, the gate's one-line
reasons, the chain status, each claim with its status and the cited
record(s), tamper findings, the verifier's tests, and the record viewer
(chain strip + collapsible records). That is all.

Everything is rendered server-side with inline CSS/JS so it works offline.
All user-controlled text goes through :func:`html.escape`.
"""

from __future__ import annotations

import html
import json
import re
from typing import Any, Iterable

from secondgrader.schema import Claim, ClaimVerdict, GateDecision, Record, VerifierResult

MODES: tuple[str, ...] = ("REPLAY", "LIVE")

_SEQ_RE = re.compile(r"\bseq (\d+)\b")
_SEVERITY_RE = re.compile(r"^\s*\[(high|medium|low)\]\s*", re.IGNORECASE)
_CHIP_CLASS = {"ok": "good", "bad": "bad"}  # any other recorder status (e.g. "untrusted") -> "untrusted"


def split_severity(reason: str | None) -> tuple[str | None, str]:
    """Split a leading ``[high]``/``[medium]``/``[low]`` off a verdict reason -> ``(severity, rest)``."""
    text = reason or ""
    m = _SEVERITY_RE.match(text)
    if not m:
        return None, text
    return m.group(1).lower(), text[m.end():]


def _e(value: Any) -> str:
    """html.escape anything (None becomes empty string)."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _short(h: str | None, n: int = 12) -> str:
    h = h or ""
    return _e(h[:n]) + ("&hellip;" if len(h) > n else "")


def _seq_link(seq: int) -> str:
    return f'<a class="seq" href="#rec-{int(seq)}">#{int(seq)}</a>'


def _seq_links(seqs: Iterable[int]) -> str:
    seqs = list(seqs)
    if not seqs:
        return '<span class="muted">none</span>'
    return " ".join(_seq_link(s) for s in seqs)


def _link_seqs_in_text(text: str) -> str:
    """Escape ``text`` and turn ``seq N`` mentions into record links."""
    return _SEQ_RE.sub(
        lambda m: f'seq <a class="seq" href="#rec-{m.group(1)}">#{m.group(1)}</a>',
        _e(text),
    )


# --------------------------------------------------------------------------- #
# Payload summaries
# --------------------------------------------------------------------------- #

def _diff_html(diff: str) -> str:
    lines = []
    for line in diff.splitlines():
        cls = ""
        if line.startswith("+") and not line.startswith("+++"):
            cls = "add"
        elif line.startswith("-") and not line.startswith("---"):
            cls = "del"
        elif line.startswith("@@"):
            cls = "hunk"
        lines.append(f'<span class="{cls}">{_e(line)}</span>' if cls else _e(line))
    return "\n".join(lines)


def _payload_html(rec: Record) -> str:
    p = rec.payload or {}
    kind = rec.kind
    if kind == "diff":
        head = (
            f'<div class="kv"><b>path</b> {_e(p.get("path"))} '
            f'<span class="muted">+{_e(p.get("lines_added", 0))} / -{_e(p.get("lines_removed", 0))}</span></div>'
        )
        return head + f'<pre class="diff">{_diff_html(str(p.get("diff", "")))}</pre>'
    if kind == "test_run":
        ok = p.get("exit_code") == 0
        badge = (
            '<span class="pill ok">exit 0</span>'
            if ok
            else f'<span class="pill bad">exit {_e(p.get("exit_code"))}</span>'
        )
        out = (
            f'<div class="kv"><b>command</b> <code>{_e(p.get("command"))}</code> {badge}</div>'
            f'<div class="kv"><b>passed</b> {_e(p.get("passed", 0))} &nbsp; <b>failed</b> {_e(p.get("failed", 0))} '
            f'&nbsp; <b>selected</b> {_e(p.get("selected", ""))} &nbsp; <b>collected</b> {_e(p.get("collected", ""))}</div>'
        )
        if p.get("output_tail"):
            out += f'<pre>{_e(p.get("output_tail"))}</pre>'
        return out
    if kind in ("model_message", "prompt"):
        out = ""
        if p.get("task_id"):
            out += f'<div class="kv"><b>task</b> {_e(p.get("task_id"))}</div>'
        out += f'<blockquote class="claimed-text">{_e(p.get("text", ""))}</blockquote>'
        return out
    if kind == "tool_call":
        args = p.get("args", {})
        return (
            f'<div class="kv"><b>tool</b> <code>{_e(p.get("tool"))}</code></div>'
            f'<pre>{_e(json.dumps(args, indent=2, ensure_ascii=False, sort_keys=True, default=str))}</pre>'
        )
    if kind == "tool_output":
        out = f'<div class="kv"><b>tool</b> <code>{_e(p.get("tool"))}</code>'
        if p.get("path"):
            out += f' <b>path</b> {_e(p.get("path"))}'
        if "exit_code" in p:
            out += f' <b>exit</b> {_e(p.get("exit_code"))}'
        out += "</div>"
        if "content" in p:
            out += f'<pre>{_e(p.get("content"))}</pre>'
        elif "content_sha256" in p:
            out += f'<div class="kv"><b>content_sha256</b> <code>{_e(p.get("content_sha256"))}</code>'
            if "bytes" in p:
                out += f' <span class="muted">({_e(p.get("bytes"))} bytes)</span>'
            out += "</div>"
        return out
    if kind == "verifier_test":
        outcome = str(p.get("outcome") or ("passed" if p.get("passed") else "failed" if p.get("passed") is False else "error"))
        pill = {"passed": "ok", "failed": "bad"}.get(outcome, "warn")
        badge = f'<span class="pill {pill}">{_e(outcome)}</span>'
        if p.get("weak"):
            badge += ' <span class="pill warn">weak</span>'
        out = f'<div class="kv"><b>name</b> <code>{_e(p.get("name"))}</code> {badge}</div>'
        if p.get("source"):
            out += f'<pre>{_e(p.get("source"))}</pre>'
        if p.get("output"):
            out += f'<pre>{_e(p.get("output"))}</pre>'
        return out
    # verdict or unknown kind: dump the JSON
    return f'<pre>{_e(json.dumps(p, indent=2, ensure_ascii=False, sort_keys=True, default=str))}</pre>'


# --------------------------------------------------------------------------- #
# Record viewer
# --------------------------------------------------------------------------- #

def _chip_states(records: list[Record], chain_ok: bool, first_bad: int | None, statuses: list[str] | None) -> list[str]:
    """One of ``good``/``bad``/``untrusted`` per record, from the recorder's statuses when they line up."""
    if statuses and len(statuses) == len(records):
        return [_CHIP_CLASS.get(str(s).lower(), "untrusted") for s in statuses]
    out = []
    for rec in records:
        broken = (not chain_ok) and first_bad is not None and rec.seq >= first_bad
        out.append("bad" if broken else "good")
    return out


def _chain_strip(records: list[Record], states: list[str]) -> str:
    chips = []
    notes = {"good": "", "bad": " - chain broken here", "untrusted": " - after the break, untrusted"}
    for rec, state in zip(records, states):
        title = f"seq {rec.seq} {rec.kind} ({rec.origin})" + notes.get(state, "")
        chips.append(
            f'<a id="chip-{rec.seq}" class="chip {state}" href="#rec-{rec.seq}" title="{_e(title)}" '
            f'data-seq="{rec.seq}" data-kind="{_e(rec.kind)}"></a>'
        )
    return '<div class="strip" aria-label="hash chain">' + "".join(chips) + "</div>"


def _record_details(rec: Record, cited: set[int], state: str) -> str:
    is_cited = rec.seq in cited
    is_broken = state != "good"
    cls = "rec" + (" cited" if is_cited else "") + (" broken" if is_broken else "")
    origin_cls = "origin observed" if rec.origin == "OBSERVED" else "origin claimed"
    flags = ""
    if is_cited:
        flags += ' <span class="flag bad">cited by the gate</span>'
    if state == "bad":
        flags += ' <span class="flag bad">chain broken here</span>'
    elif is_broken:
        flags += ' <span class="flag warn">untrusted</span>'
    return (
        f'<details id="rec-{rec.seq}" class="{cls}"{" open" if is_cited else ""}>'
        f'<summary><span class="seqno">{rec.seq}</span>'
        f'<span class="kind">{_e(rec.kind)}</span>'
        f'<span class="{origin_cls}">{_e(rec.origin)}</span>'
        f'<span class="ts">{_e(rec.ts)}</span>{flags}</summary>'
        f'<div class="body">{_payload_html(rec)}'
        f'<div class="hashes">'
        f'<span><b>prev</b> <code>{_short(rec.prev_hash)}</code></span>'
        f'<span><b>hash</b> <code>{_short(rec.hash)}</code></span>'
        f'<span><b>sig</b> <code>{_short(rec.sig)}</code></span>'
        f"</div></div></details>"
    )


def render_records(
    records: list[Record],
    *,
    chain_ok: bool = True,
    first_bad_seq: int | None = None,
    cited_seqs: Iterable[int] = (),
    statuses: list[str] | None = None,
) -> str:
    """Chain strip + collapsible record list (the record viewer fragment).

    Each chip has ``id="chip-<seq>"`` and links to ``#rec-<seq>``. With the
    recorder's per-record ``statuses`` (one per record) chips are ``good`` for
    ``ok``, ``bad`` for ``bad`` and ``untrusted`` for anything else. Without
    them, chips are ``good`` when intact and ``bad`` from ``first_bad_seq`` on
    when ``chain_ok`` is False. Records in ``cited_seqs`` are highlighted and opened.
    """
    cited = {int(s) for s in cited_seqs}
    states = _chip_states(records, chain_ok, first_bad_seq, statuses)
    strip = _chain_strip(records, states)
    body = "".join(_record_details(r, cited, st) for r, st in zip(records, states))
    n_obs = sum(1 for r in records if r.origin == "OBSERVED")
    n_cl = len(records) - n_obs
    return (
        '<section id="records" class="card records">'
        '<div class="sec-head"><h2>Trace</h2>'
        f'<span class="count">{len(records)} records &middot; {n_obs} observed &middot; {n_cl} claimed</span></div>'
        f"{strip}"
        '<div class="legend"><span class="chip good"></span> intact '
        '<span class="chip bad"></span> broken here '
        '<span class="chip untrusted"></span> after the break'
        '<span class="legend-sep"></span>'
        '<span class="origin observed">OBSERVED</span> evidence '
        '<span class="origin claimed">CLAIMED</span> agent text</div>'
        f'<div class="reclist">{body}</div>'
        "</section>"
    )


# --------------------------------------------------------------------------- #
# Page sections
# --------------------------------------------------------------------------- #

def _task_picker(tasks: list[dict[str, Any]] | None, mode: str, selected_task: str) -> str:
    if tasks is None:
        return ""
    opts = []
    for t in tasks:
        tid = str(t.get("id", ""))
        label = f'{tid}  ·  {t.get("title", "")}  ·  expects {t.get("expected_gate", "?")}'
        sel = " selected" if tid == selected_task else ""
        opts.append(f'<option value="{_e(tid)}"{sel}>{_e(label)}</option>')
    live = " checked" if mode == "LIVE" else ""
    replay = " checked" if mode != "LIVE" else ""
    return (
        '<form id="runform" class="toolbar" onsubmit="return sgRun(event)">'
        '<label class="field"><span class="field-label">Task</span>'
        '<select name="task" id="task">' + "".join(opts) + "</select></label>"
        '<div class="segmented" role="radiogroup" aria-label="run mode">'
        f'<label><input type="radio" name="runmode" value="LIVE"{live}><span>Live</span></label>'
        f'<label><input type="radio" name="runmode" value="REPLAY"{replay}><span>Replay</span></label>'
        "</div>"
        '<button type="submit" class="primary">Run</button>'
        '<span id="runmsg" class="runmsg"></span>'
        '<ol id="stages" class="stages" hidden></ol>'
        "</form>"
    )


def _summary_cells(
    decision: GateDecision,
    plain: list[ClaimVerdict],
    tampers: list[ClaimVerdict],
    vr: VerifierResult | None,
    chain: dict[str, Any] | None,
) -> str:
    """The report card row under the verdict: chain, claims, tampering, verifier, one cell each."""
    chain = chain or {}
    # chain
    if decision.chain_ok:
        c_dot, c_val = "ok", "Intact"
        c_sub = "signed and sealed" if chain.get("signed") and chain.get("sealed") else (
            "signed" if chain.get("signed") else "hashes verified")
    else:
        c_dot, c_val = "bad", (f"Broken at #{int(decision.first_bad_seq)}" if decision.first_bad_seq is not None else "Broken")
        c_sub = "later records untrusted"
    # claims
    n = len(plain)
    contradicted = sum(1 for v in plain if v.status == "CONTRADICTED")
    unsupported = sum(1 for v in plain if v.status == "UNSUPPORTED")
    supported = sum(1 for v in plain if v.status == "SUPPORTED")
    if n == 0:
        k_dot, k_val, k_sub = "muted", "None extracted", "nothing to check"
    elif contradicted:
        k_dot, k_val = "bad", f"{contradicted} of {n} contradicted"
        k_sub = f"{unsupported} unsupported" if unsupported else f"{supported} supported"
    elif unsupported:
        k_dot, k_val, k_sub = "warn", f"{unsupported} of {n} unsupported", f"{supported} supported"
    else:
        k_dot, k_val, k_sub = "ok", f"All {n} supported", "each one cites its evidence"
    # tampering
    blocking = [t for t in tampers if t.status == "CONTRADICTED"]
    if not tampers:
        t_dot, t_val, t_sub = "ok", "None found", "protected files untouched"
    elif blocking:
        sev = {split_severity(t.reason)[0] for t in blocking} - {None}
        t_dot, t_val = "bad", f"{len(blocking)} finding{'s' if len(blocking) != 1 else ''}"
        t_sub = ", ".join(sorted(sev, key=lambda s: ("high", "medium", "low").index(s))) + " severity" if sev else "blocking"
    else:
        t_dot, t_val, t_sub = "warn", f"{len(tampers)} informational", "does not block"
    # verifier
    if vr is None:
        v_dot, v_val, v_sub = "muted", "Did not run", "no independent tests"
    else:
        errored = max(0, len(vr.details) - int(vr.passed) - int(vr.failed))
        if int(vr.passed) + int(vr.failed) == 0:
            v_dot, v_val, v_sub = "warn", "No countable tests", f"{errored} errored"
        elif vr.failed:
            v_dot, v_val, v_sub = "bad", f"{int(vr.failed)} of {int(vr.passed) + int(vr.failed)} failed", "independent tests"
        else:
            v_dot, v_val, v_sub = "ok", f"{int(vr.passed)} passed", "independent tests" + (f", {errored} errored" if errored else "")

    def cell(label: str, dot: str, value: str, sub: str, href: str) -> str:
        return (
            f'<a class="cell" href="{href}"><span class="cell-label">{label}</span>'
            f'<span class="cell-value"><span class="dot {dot}"></span>{value}</span>'
            f'<span class="cell-sub">{_e(sub)}</span></a>'
        )

    return (
        '<div class="cells">'
        + cell("Hash chain", c_dot, c_val, c_sub, "#chain")
        + cell("Claims", k_dot, k_val, k_sub, "#claims")
        + cell("Tampering", t_dot, t_val, t_sub, "#tampers")
        + cell("Verifier", v_dot, v_val, v_sub, "#verifier")
        + "</div>"
    )


def _stamp(decision: GateDecision, mode: str, cells: str = "") -> str:
    blocked = decision.decision == "BLOCK"
    word = "BLOCKED" if blocked else "MERGED"
    n = len(decision.reasons)
    if blocked:
        lead = f"The gate blocked this change on {n} finding{'s' if n != 1 else ''}."
        if decision.citing_seqs:
            lead += " Records cited: " + _seq_links(decision.citing_seqs) + "."
    else:
        lead = "The gate found no contradiction between what the agent said and what was observed."
    return (
        f'<section class="verdict {"BLOCK" if blocked else "PASS"}">'
        '<div class="verdict-main">'
        f'<div class="stamp {"block" if blocked else "pass"}" data-decision="{_e(decision.decision)}">{word}</div>'
        f'<p class="lead">{lead}</p>'
        f'<div class="stamp-sub">Gate decision <b>{_e(decision.decision)}</b> &middot; '
        f'<span class="mode mode-{mode.lower()}">{mode}</span></div>'
        "</div>"
        f"{cells}"
        "</section>"
    )


def _reasons(decision: GateDecision) -> str:
    if not decision.reasons:
        txt = "No blocking findings." if decision.decision == "PASS" else "Blocked without stated reasons."
        items = f'<li class="muted">{txt}</li>'
    else:
        items = "".join(f"<li>{_link_seqs_in_text(r)}</li>" for r in decision.reasons)
    return (
        '<section class="card reasons"><div class="sec-head"><h2>Why</h2>'
        f'<span class="count">{len(decision.reasons)} reason{"s" if len(decision.reasons) != 1 else ""}</span></div>'
        f"<ol>{items}</ol>"
        f'<div class="kv"><b>Citing records</b> {_seq_links(decision.citing_seqs)}</div>'
        "</section>"
    )


def _chain_card(decision: GateDecision, n_records: int | None, chain: dict[str, Any] | None) -> str:
    chain = chain or {}
    if decision.chain_ok:
        status = '<span class="status ok">INTACT</span>'
        detail = "every hash and prev_hash verified"
        if chain.get("signed"):
            detail = "every hash, prev_hash and signature verified"
        if chain.get("sealed"):
            detail += ", seal matches"
        if n_records is not None:
            detail = f"{n_records} records, " + detail
    else:
        status = '<span class="status bad">BROKEN</span>'
        bad = _seq_link(decision.first_bad_seq) if decision.first_bad_seq is not None else "unknown"
        detail = f"first bad record: {bad}"
    lines = [
        f'<div class="kv">{status} <span class="muted">{detail}</span>'
        + (f' <span class="muted mono">first_bad_seq = {_e(decision.first_bad_seq)}</span>' if decision.first_bad_seq is not None else "")
        + "</div>"
    ]
    if not decision.chain_ok and (chain.get("reason") or chain.get("detail")):
        reason = f'<code class="reason">{_e(chain.get("reason"))}</code> ' if chain.get("reason") else ""
        lines.append(f'<div class="kv chain-why">{reason}{_link_seqs_in_text(str(chain.get("detail") or ""))}</div>')
    if chain:
        if chain.get("signed"):
            badge = '<span class="badge signed">signed' + (" &middot; sealed" if chain.get("sealed") else "") + "</span>"
        elif chain.get("sealed"):
            badge = '<span class="badge signed">sealed</span>'
        else:
            badge = '<span class="badge unsigned">UNSIGNED fixture</span>'
        # On a broken chain the recorder reports the genesis hash: not worth showing.
        head = (chain.get("head_hash") or "") if chain.get("ok") else ""
        meta = [badge]
        if head:
            meta.append(f'<span><b>head</b> <code class="hash" title="{_e(head)}">{_short(head)}</code></span>')
        if chain.get("count") is not None:
            meta.append(f'<span><b>count</b> {_e(chain.get("count"))}</span>')
        run = chain.get("run") or {}
        if run.get("run_id"):
            meta.append(f'<span><b>run</b> <code>{_e(run.get("run_id"))}</code></span>')
        if run.get("recorded_at"):
            meta.append(f'<span><b>recorded</b> {_e(run.get("recorded_at"))}</span>')
        if run.get("base_commit"):
            meta.append(f'<span><b>base</b> <code title="{_e(run.get("base_commit"))}">{_short(str(run.get("base_commit")))}</code></span>')
        if chain.get("pubkey"):
            meta.append(f'<span><b>pubkey</b> <code title="{_e(chain.get("pubkey"))}">{_short(str(chain.get("pubkey")))}</code></span>')
        lines.append('<div class="kv chain-meta">' + "".join(meta) + "</div>")
    return '<section id="chain" class="card chain"><div class="sec-head"><h2>Hash chain</h2></div>' + "".join(lines) + "</section>"


def _claims_table(verdicts: list[ClaimVerdict], claims: dict[str, Claim]) -> str:
    rows = []
    for v in verdicts:
        c = claims.get(v.claim_id)
        text = _e(c.text) if c else '<span class="muted">(claim text not available)</span>'
        src = f' <span class="muted nowrap">said at {_seq_link(c.source_seq)}</span>' if c else ""
        kind = f'<div class="muted small">{_e(c.kind)}</div>' if c else ""
        status = _e(v.status)
        rows.append(
            f'<tr class="status-{status.lower()}">'
            f'<td class="col-id"><code>{_e(v.claim_id)}</code></td>'
            f'<td class="col-claim">{text}{src}{kind}</td>'
            f'<td class="col-status"><span class="status {status.lower()}">{status}</span></td>'
            f'<td class="col-reason">{_e(v.reason)}</td>'
            f'<td class="col-evidence">{_seq_links(v.evidence_seqs)}</td>'
            "</tr>"
        )
    if not rows:
        rows.append('<tr><td colspan="5" class="muted">No claims extracted.</td></tr>')
    return (
        '<section id="claims" class="card claims"><div class="sec-head"><h2>Claims</h2>'
        f'<span class="count">{len(verdicts)}</span></div>'
        "<table><thead><tr><th>id</th><th>claim</th><th>status</th><th>reason</th><th>evidence</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></section>"
    )


def _tamper_section(tampers: list[ClaimVerdict]) -> str:
    head = '<section id="tampers" class="card tampers"><div class="sec-head"><h2>Tamper findings</h2>'
    if not tampers:
        return head + '</div><p class="muted">None: no edits to protected files were observed.</p></section>'
    items = []
    for t in tampers:
        target = t.claim_id.split(":", 1)[1] if ":" in t.claim_id else t.claim_id
        severity, reason = split_severity(t.reason)
        sev = f'<span class="sev {severity}">{severity}</span>' if severity else ""
        note = (
            ' <span class="muted">informational, does not block</span>'
            if t.status != "CONTRADICTED"
            else ""
        )
        items.append(
            f'<li class="tamper-{_e(t.status.lower())}">'
            f'<div class="tamper-head"><span class="status {_e(t.status.lower())}">{_e(t.status)}</span>{sev}'
            f"<code>{_e(target)}</code>{note}</div>"
            f'<div class="tamper-body">{_e(reason)} '
            f'<span class="muted nowrap">evidence {_seq_links(t.evidence_seqs)}</span></div></li>'
        )
    return head + f'<span class="count">{len(tampers)}</span></div><ul>{"".join(items)}</ul></section>'


def _verifier_section(vr: VerifierResult | None) -> str:
    head = '<section id="verifier" class="card verifier"><div class="sec-head"><h2>Blind verifier</h2>'
    if vr is None:
        return (
            head + '</div><p class="muted">Verifier did not run. No independent tests were written for this trace.</p></section>'
        )
    errored = max(0, len(vr.details) - int(vr.passed) - int(vr.failed))
    summary = (
        f'<div class="kv"><span class="status ok">{int(vr.passed)} passed</span> '
        f'<span class="status {"bad" if vr.failed else "muted"}">{int(vr.failed)} failed</span> '
        + (f'<span class="status warn">{errored} errored</span> ' if errored else "")
        + f'<span class="muted">{len(vr.tests_written)} tests written from the spec alone</span></div>'
    )
    if int(vr.passed) + int(vr.failed) == 0:
        summary += (
            '<p class="note"><b>No countable verifier tests.</b> The generated tests were rejected or '
            "every one of them errored. This never blocks, but nothing here was independently verified.</p>"
        )
    written = "".join(f"<li><code>{_e(t)}</code></li>" for t in vr.tests_written) or '<li class="muted">none</li>'
    rows = []
    for d in vr.details:
        outcome = str(d.get("outcome") or ("passed" if d.get("passed") else "failed"))
        pill = {"passed": "ok", "failed": "bad"}.get(outcome, "warn")
        out = str(d.get("output", ""))
        snippet = out if len(out) <= 400 else out[:400] + "..."
        sentence = _e(d.get("spec_sentence", ""))
        weak = ' <span class="flag warn">weak</span>' if d.get("weak") else ""
        rows.append(
            f"<tr><td><code>{_e(d.get('name'))}</code>{weak}"
            + (f'<div class="muted small">{sentence}</div>' if sentence else "")
            + f'</td><td class="col-status"><span class="status {pill}">{_e(outcome)}</span></td>'
            f"<td><pre>{_e(snippet)}</pre></td></tr>"
        )
    details = (
        "<table><thead><tr><th>test</th><th>result</th><th>output</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
        if rows
        else ""
    )
    recs = (
        f'<div class="kv"><b>verifier_test records</b> {_seq_links(vr.record_seqs)}</div>'
        if vr.record_seqs
        else ""
    )
    return (
        head + f'<span class="count">{len(vr.details)}</span></div>'
        f'{summary}<details class="plain"><summary>tests written</summary><ul>{written}</ul></details>{details}{recs}'
        "</section>"
    )


def _tamper_form(n_records: int, trace: str, mode: str) -> str:
    default = min(13, n_records) if n_records else 1
    return (
        '<form class="card tamperform" method="post" action="/api/tamper">'
        '<div class="sec-head"><h2>Tamper demo</h2></div>'
        '<p class="muted">Changes one byte of record N in a throwaway copy of the trace and re-verifies the chain. '
        "Chip N turns red and everything after it is untrusted. The trace on disk is never changed.</p>"
        '<div class="row">'
        f'<label class="field"><span class="field-label">Record</span>'
        f'<input type="number" name="seq" min="1" max="{n_records}" value="{default}" required></label>'
        f'<input type="hidden" name="trace" value="{_e(trace)}">'
        f'<input type="hidden" name="mode" value="{_e(mode)}">'
        '<button type="submit">Tamper with it</button>'
        "</div></form>"
    )


_CSS = """
:root { color-scheme: light dark;
  --bg:#f7f7f5; --fg:#1a1d21; --fg-2:#3c4249; --muted:#6b7280; --card:#ffffff; --line:#e4e6ea; --line-2:#d3d6db;
  --code:#f1f2f4; --code-fg:#2b3036;
  --green:#1d7a46; --green-bg:#eaf5ee; --red:#b3261e; --red-bg:#fbeeec; --amber:#9a5b00; --amber-bg:#fff4e0;
  --observed:#1f5fbf; --observed-bg:#e9f0fb; --claimed:#6b4fbb; --claimed-bg:#f0ecfa;
  --focus:#1f5fbf; }
@media (prefers-color-scheme: dark) { :root {
  --bg:#0f1114; --fg:#e7e9ec; --fg-2:#c4c9d0; --muted:#8b939e; --card:#16191d; --line:#262a30; --line-2:#333841;
  --code:#1d2126; --code-fg:#d6dae0;
  --green:#4cc38a; --green-bg:#122a1d; --red:#f0655c; --red-bg:#331a18; --amber:#e3a33a; --amber-bg:#33270f;
  --observed:#7fb0ff; --observed-bg:#152238; --claimed:#b9a3f0; --claimed-bg:#241d38;
  --focus:#7fb0ff; } }
* { box-sizing:border-box }
html { -webkit-text-size-adjust:100% }
body { margin:0; background:var(--bg); color:var(--fg);
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  font-feature-settings:"cv11","ss01"; -webkit-font-smoothing:antialiased }
main { max-width:62rem; margin:0 auto; padding:0 1.25rem 4rem }
a { color:inherit }
code, pre, .mono, .seqno, .ts, a.seq { font-family: ui-monospace, "SF Mono", Menlo, "JetBrains Mono", Consolas, monospace }
code { font-size:.86em; color:var(--code-fg) }
pre { font-size:.8rem; line-height:1.45; background:var(--code); color:var(--code-fg); padding:.6rem .75rem; border-radius:6px;
  overflow:auto; margin:.45rem 0; max-height:22rem; white-space:pre-wrap; word-break:break-word }
pre.diff .add { color:var(--green) } pre.diff .del { color:var(--red) } pre.diff .hunk { color:var(--observed) }
.muted { color:var(--muted) } .small { font-size:.82rem } .nowrap { white-space:nowrap }

/* record links */
a.seq { display:inline-block; font-size:.78rem; line-height:1.3; padding:.05em .4em; border:1px solid var(--line-2);
  border-radius:4px; text-decoration:none; color:var(--fg-2); background:var(--card); margin:0 .05em }
a.seq:hover { border-color:var(--fg); color:var(--fg) }

/* top */
.top { display:flex; align-items:center; gap:.75rem; padding:1rem 0 .25rem; flex-wrap:wrap }
.brand { font-weight:600; font-size:.95rem; letter-spacing:-.005em }
.brand::before { content:""; display:inline-block; width:.6em; height:.6em; border-radius:2px; background:var(--fg); margin-right:.5em; vertical-align:baseline; opacity:.9 }
.top .spacer { flex:1 }
.top .trace { font-size:.78rem; color:var(--muted) } .top .trace code { color:var(--muted) }
h1 { margin:.4rem 0 .15rem; font-size:1.45rem; line-height:1.25; font-weight:600; letter-spacing:-.015em }
.subline { color:var(--muted); font-size:.9rem; margin:0 0 1rem }

/* mode tag */
.mode { display:inline-flex; align-items:center; gap:.4em; font-size:.72rem; font-weight:600; letter-spacing:.06em;
  padding:.15em .55em; border-radius:4px; border:1px solid var(--line-2); color:var(--fg-2); vertical-align:middle; background:var(--card) }
.mode::before { content:""; width:.5em; height:.5em; border-radius:50%; background:var(--muted) }
.mode-live { color:var(--red); border-color:var(--red) } .mode-live::before { background:var(--red) }

/* toolbar */
.toolbar { display:flex; align-items:center; gap:.75rem; flex-wrap:wrap; padding:.75rem 0 1rem; border-top:1px solid var(--line); margin:0 0 .5rem }
.field { display:inline-flex; align-items:center; gap:.5rem }
.field-label { font-size:.82rem; color:var(--muted) }
select, input[type=number] { font:inherit; font-size:.9rem; color:var(--fg); background:var(--card); border:1px solid var(--line-2); border-radius:6px; padding:.35rem .6rem }
select { max-width:30rem } input[type=number] { width:5.5em }
select:focus, input:focus, button:focus-visible { outline:2px solid var(--focus); outline-offset:1px }
.segmented { display:inline-flex; border:1px solid var(--line-2); border-radius:6px; overflow:hidden; background:var(--card) }
.segmented label { position:relative } .segmented input { position:absolute; opacity:0; inset:0; margin:0; cursor:pointer }
.segmented span { display:block; padding:.35rem .8rem; font-size:.88rem; color:var(--muted); cursor:pointer; border-left:1px solid var(--line-2) }
.segmented label:first-child span { border-left:0 }
.segmented input:checked + span { color:var(--fg); background:var(--code); font-weight:500 }
button { font:inherit; font-size:.9rem; padding:.38rem .95rem; border-radius:6px; border:1px solid var(--line-2); background:var(--card); color:var(--fg); cursor:pointer }
button:hover { border-color:var(--fg-2) }
button.primary { background:var(--fg); color:var(--bg); border-color:var(--fg) } button.primary:hover { opacity:.9 }
.runmsg { font-size:.85rem; color:var(--muted) }
.stages { flex-basis:100%; display:flex; gap:0; list-style:none; margin:.25rem 0 0; padding:0; font-size:.8rem; color:var(--muted) }
.stages[hidden] { display:none }
.stages li { display:flex; align-items:center; gap:.4em; padding-right:1.25rem; position:relative }
.stages li::before { content:""; width:.55em; height:.55em; border-radius:50%; background:var(--line-2); flex:none }
.stages li.done { color:var(--fg-2) } .stages li.done::before { background:var(--green) }
.stages li.active { color:var(--fg); font-weight:500 } .stages li.active::before { background:var(--fg); box-shadow:0 0 0 3px var(--code) }
.stages li.error { color:var(--red) } .stages li.error::before { background:var(--red) }
.stages .detail { font-weight:400; color:var(--muted) }

/* notice */
.flash { border:1px solid var(--line); border-left:3px solid var(--amber); background:var(--card); border-radius:8px; padding:.7rem 1rem; margin:.25rem 0 1rem; font-size:.92rem }

/* verdict */
.verdict { border:1px solid var(--line); border-radius:10px; background:var(--card); margin:0 0 1rem; overflow:hidden }
.verdict-main { padding:1.4rem 1.5rem 1.2rem; border-left:4px solid transparent }
.verdict.BLOCK .verdict-main { border-left-color:var(--red) } .verdict.PASS .verdict-main { border-left-color:var(--green) }
.stamp { font-size:2.1rem; font-weight:700; letter-spacing:.02em; line-height:1.1 }
.stamp.block { color:var(--red) } .stamp.pass { color:var(--green) }
.lead { margin:.5rem 0 .4rem; font-size:1rem; color:var(--fg-2); max-width:48rem }
.stamp-sub { color:var(--muted); font-size:.85rem } .stamp-sub b { color:var(--fg-2); font-weight:600 }
.cells { display:grid; grid-template-columns:repeat(4,1fr); border-top:1px solid var(--line) }
.cell { display:flex; flex-direction:column; gap:.15rem; padding:.85rem 1.25rem; text-decoration:none; border-left:1px solid var(--line); min-width:0 }
.cell:first-child { border-left:0 } .cell:hover { background:var(--code) }
.cell-label { font-size:.74rem; color:var(--muted); letter-spacing:.02em }
.cell-value { font-size:.95rem; font-weight:600; display:flex; align-items:center; gap:.45em; white-space:nowrap; overflow:hidden; text-overflow:ellipsis }
.cell-sub { font-size:.78rem; color:var(--muted) }
.dot { width:.55em; height:.55em; border-radius:50%; flex:none; background:var(--muted) }
.dot.ok { background:var(--green) } .dot.bad { background:var(--red) } .dot.warn { background:var(--amber) }
@media (max-width:720px) { .cells { grid-template-columns:1fr 1fr } .cell:nth-child(3) { border-left:0 } .cell:nth-child(n+3) { border-top:1px solid var(--line) } }

/* cards */
.card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:1rem 1.25rem 1.1rem; margin:0 0 1rem }
.sec-head { display:flex; align-items:baseline; gap:.6rem; margin:0 0 .6rem }
.sec-head h2 { margin:0; font-size:.95rem; font-weight:600; letter-spacing:-.005em }
.sec-head .count { font-size:.8rem; color:var(--muted) }
.kv { margin:.3rem 0; font-size:.92rem } .kv b { color:var(--muted); font-weight:500; margin-right:.35em }
.reasons ol { margin:.2rem 0 .7rem 1.25rem; padding:0 } .reasons li { margin:.3rem 0; padding-left:.2rem }
.reasons li::marker { color:var(--muted) }

/* statuses */
.status { display:inline-flex; align-items:center; gap:.4em; font-size:.74rem; font-weight:600; letter-spacing:.04em; white-space:nowrap; color:var(--fg-2) }
.status::before { content:""; width:.5em; height:.5em; border-radius:50%; background:currentColor; opacity:.9 }
.status.supported, .status.ok { color:var(--green) }
.status.contradicted, .status.bad { color:var(--red) }
.status.unsupported, .status.warn { color:var(--amber) }
.status.muted { color:var(--muted) }
.flag { display:inline-block; font-size:.72rem; font-weight:500; padding:.05em .5em; border-radius:4px; white-space:nowrap }
.flag.bad { color:var(--red); background:var(--red-bg) } .flag.warn { color:var(--amber); background:var(--amber-bg) }
.pill { display:inline-block; font-size:.74rem; font-weight:600; padding:.05em .5em; border-radius:4px; vertical-align:baseline }
.pill.ok { color:var(--green); background:var(--green-bg) } .pill.bad { color:var(--red); background:var(--red-bg) } .pill.warn { color:var(--amber); background:var(--amber-bg) }
.badge { display:inline-block; font-size:.74rem; font-weight:600; padding:.05em .5em; border-radius:4px }
.badge.signed { color:var(--green); background:var(--green-bg) } .badge.unsigned { color:var(--muted); background:var(--code) }
.sev { display:inline-block; font-size:.7rem; font-weight:600; text-transform:uppercase; letter-spacing:.06em; padding:.05em .45em; border-radius:4px }
.sev.high { color:var(--red); background:var(--red-bg) } .sev.medium { color:var(--amber); background:var(--amber-bg) } .sev.low { color:var(--muted); background:var(--code) }

/* tables */
table { width:100%; border-collapse:collapse; font-size:.9rem }
th, td { text-align:left; vertical-align:top; padding:.55rem .6rem; border-top:1px solid var(--line) }
th { font-size:.74rem; font-weight:500; color:var(--muted); letter-spacing:.03em; border-top:0; padding-top:0 }
td:first-child, th:first-child { padding-left:0 } td:last-child, th:last-child { padding-right:0 }
.claims table { table-layout:fixed } .claims th:nth-child(1) { width:14% } .claims th:nth-child(2) { width:28% } .claims th:nth-child(3) { width:13% } .claims th:nth-child(5) { width:13% }
td.col-id code { overflow-wrap:anywhere } td.col-status { white-space:nowrap } td.col-reason { color:var(--fg-2) }
.verifier th:nth-child(1) { width:34% } .verifier th:nth-child(2) { width:10% }
td pre { margin:0; max-height:12rem }

/* chain */
.chain-meta { display:flex; flex-wrap:wrap; gap:.3rem 1.25rem; align-items:center; font-size:.84rem; color:var(--muted); margin-top:.5rem }
.chain-meta b { color:var(--muted); font-weight:500 } .chain-meta code { color:var(--fg-2) }
.chain-why { color:var(--fg-2) } .chain-why code.reason { color:var(--red); background:var(--red-bg); padding:.05em .4em; border-radius:4px }

/* tampers */
.tampers ul { list-style:none; margin:0; padding:0 }
.tampers li { padding:.6rem 0; border-top:1px solid var(--line) } .tampers li:first-child { border-top:0; padding-top:.1rem }
.tamper-head { display:flex; align-items:center; gap:.6rem; flex-wrap:wrap } .tamper-head code { font-size:.86rem }
.tamper-body { margin-top:.25rem; color:var(--fg-2); font-size:.92rem }

/* verifier */
.note { margin:.5rem 0; padding:.6rem .85rem; border-radius:6px; background:var(--amber-bg); color:var(--fg-2); font-size:.9rem } .note b { color:var(--amber) }
details.plain { margin:.4rem 0 } details.plain summary { cursor:pointer; color:var(--muted); font-size:.88rem } details.plain ul { margin:.3rem 0 .5rem 1.25rem; padding:0; font-size:.9rem }

/* records */
.strip { display:flex; flex-wrap:wrap; gap:3px; margin:.5rem 0 }
.chip { display:inline-block; width:14px; height:14px; border-radius:3px; background:var(--line-2) }
.chip.good { background:var(--green) } .chip.bad { background:var(--red) } .chip.untrusted { background:var(--amber) }
a.chip:hover, a.chip:focus-visible { outline:2px solid var(--fg); outline-offset:1px }
.legend { display:flex; align-items:center; gap:.4rem; flex-wrap:wrap; font-size:.78rem; color:var(--muted); margin:.4rem 0 .8rem }
.legend .chip { width:10px; height:10px; border-radius:2px; margin-left:.5rem } .legend .chip:first-child { margin-left:0 }
.legend-sep { width:1px; height:.9em; background:var(--line-2); margin:0 .5rem }
.legend .origin { margin-left:.5rem }
.origin { display:inline-block; font-size:.66rem; font-weight:600; letter-spacing:.06em; padding:.1em .45em; border-radius:3px; line-height:1.5 }
.origin.observed { color:var(--observed); background:var(--observed-bg) }
.origin.claimed { color:var(--claimed); background:var(--claimed-bg) }
.reclist { border-top:1px solid var(--line) }
details.rec { border-bottom:1px solid var(--line) }
details.rec summary { cursor:pointer; display:flex; gap:.7rem; align-items:center; flex-wrap:wrap; padding:.5rem .5rem .5rem .25rem; list-style:none }
details.rec summary::-webkit-details-marker { display:none }
details.rec summary:hover { background:var(--code) }
details.rec .seqno { font-size:.8rem; color:var(--muted); min-width:2.2em; text-align:right }
details.rec .kind { font-weight:500; font-size:.92rem }
details.rec .ts { font-size:.75rem; color:var(--muted); margin-left:auto }
details.rec[open] summary .kind { color:var(--fg) }
details.rec.cited { background:var(--red-bg); box-shadow:inset 3px 0 0 var(--red) }
details.rec.cited summary:hover { background:transparent }
details.rec.broken summary .seqno { color:var(--red); text-decoration:line-through }
details.rec .body { padding:.1rem .5rem .8rem 3.1rem; font-size:.9rem }
.body .kv b { font-weight:500 }
blockquote.claimed-text { margin:.4rem 0; padding:.5rem .9rem; border-left:3px solid var(--claimed); background:var(--claimed-bg); border-radius:4px; white-space:pre-wrap; font-size:.9rem }
.hashes { font-size:.76rem; display:flex; gap:1.25rem; flex-wrap:wrap; margin-top:.5rem; color:var(--muted) }
.hashes b { font-weight:500; margin-right:.35em } .hashes code { color:var(--muted) }
:target { scroll-margin-top:1rem } details:target { outline:2px solid var(--focus); outline-offset:-2px }

/* tamper demo */
.tamperform p { margin:0 0 .6rem; font-size:.9rem }
.row { display:flex; align-items:center; gap:.75rem; flex-wrap:wrap }

footer { margin-top:2.5rem; font-size:.8rem; color:var(--muted); border-top:1px solid var(--line); padding-top:1rem }
@media (max-width:640px) { main { padding:0 1rem 3rem } .stamp { font-size:1.7rem } details.rec .body { padding-left:.5rem } }
"""

_JS = """
function sgRun(ev) {
  ev.preventDefault();
  var f = ev.target, msg = document.getElementById('runmsg');
  var mode = (f.querySelector('input[name=runmode]:checked') || {}).value || 'REPLAY';
  msg.textContent = 'starting\\u2026';
  fetch('/api/run', {method:'POST', headers:{'Content-Type':'application/json'},
         body: JSON.stringify({task: f.task.value, mode: mode})})
    .then(function(r){ return r.json().then(function(j){ return {ok:r.ok, status:r.status, body:j}; }); })
    .then(function(res){
      var b = res.body || {};
      msg.textContent = res.ok ? '' : ((b.status || ('HTTP ' + res.status)) + (b.message ? ': ' + b.message : ''));
      if (res.ok && b.redirect) { window.location = b.redirect; }
      else if (res.ok) { window.sgRunStarted = true; sgPollStatus(); }
    })
    .catch(function(e){ msg.textContent = 'run failed: ' + e; });
  return false;
}
function sgRenderStages(el, s) {
  var names = (s.stages || []).map(function(st){ return typeof st === 'string' ? st : st.name; });
  var at = names.indexOf(s.stage);
  el.innerHTML = '';
  names.forEach(function(name, i) {
    var li = document.createElement('li');
    var cls = i < at ? 'done' : (i === at ? 'active' : '');
    if (s.stage === 'error' && i === at) cls = 'error';
    if (s.stage === 'done') cls = 'done';
    li.className = cls;
    li.appendChild(document.createTextNode(name.replace('_', ' ')));
    if (i === at && s.detail) {
      var d = document.createElement('span'); d.className = 'detail'; d.textContent = '\\u2014 ' + s.detail; li.appendChild(d);
    }
    el.appendChild(li);
  });
  if (s.stage === 'error') {
    var li = document.createElement('li'); li.className = 'error'; li.textContent = 'error: ' + (s.detail || '');
    el.appendChild(li);
  }
}
function sgPollStatus() {
  var el = document.getElementById('stages');
  if (!el) return;
  fetch('/api/status').then(function(r){ return r.json(); }).then(function(s){
    var running = s.stage && s.stage !== 'idle';
    el.hidden = !running;
    if (running) sgRenderStages(el, s);
    if (s.stage === 'done' && s.redirect && window.sgRunStarted) { window.location = s.redirect; return; }
    if (running && s.stage !== 'done' && s.stage !== 'error') setTimeout(sgPollStatus, 1000);
  }).catch(function(){ el.hidden = true; });
}
document.addEventListener('DOMContentLoaded', sgPollStatus);
"""


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #

def render_verdict(
    decision: GateDecision,
    verdicts: list[ClaimVerdict],
    verifier_result: VerifierResult | None,
    records: list[Record] | None = None,
    *,
    task_title: str = "",
    mode: str = "REPLAY",
    claims: list[Claim] | None = None,
    tasks: list[dict[str, Any]] | None = None,
    selected_task: str = "",
    trace_name: str = "",
    flash: str = "",
    chain: dict[str, Any] | None = None,
) -> str:
    """Return the verdict page as a complete HTML string.

    Args:
        decision: the gate's :class:`GateDecision` (PASS shown as MERGED, BLOCK as BLOCKED).
        verdicts: one :class:`ClaimVerdict` per claim. Verdicts whose ``claim_id``
            starts with ``"tamper:"`` are shown in the tamper-findings section.
        verifier_result: the blind verifier's result, or ``None`` if it did not run.
        records: the trace; when given, the chain strip, record viewer and
            tamper form are rendered.
        task_title: shown in the header.
        mode: ``"REPLAY"`` (default) or ``"LIVE"``; always visible.
        claims: the extracted :class:`Claim` objects, matched to verdicts by id.
        tasks: task picker entries (``{"id", "title", "expected_gate"}``); ``None`` hides the picker.
        selected_task: task id pre-selected in the picker.
        trace_name: trace identifier echoed in the header and the tamper form.
        flash: a one-line notice shown under the header (escaped).
        chain: the recorder's chain report as a plain dict with keys ``ok``,
            ``first_bad_seq``, ``reason``, ``detail``, ``count``, ``head_hash``,
            ``signed``, ``sealed``, ``pubkey``, ``run`` and ``statuses``
            (``secondgrader.web.app.CHAIN_KEYS``). Drives the chain card's
            badges and reason text and the per-record chip colours. Optional:
            without it the card and strip fall back to ``decision.chain_ok`` /
            ``decision.first_bad_seq``.
    """
    mode = (mode or "REPLAY").upper()
    if mode not in MODES:
        mode = "REPLAY"
    claim_map = {c.id: c for c in (claims or [])}
    tampers = [v for v in verdicts if v.claim_id.startswith("tamper:")]
    plain = [v for v in verdicts if not v.claim_id.startswith("tamper:")]

    cited: set[int] = set()
    if decision.decision == "BLOCK":
        cited.update(decision.citing_seqs)
        for v in verdicts:
            if v.status == "CONTRADICTED":
                cited.update(v.evidence_seqs)

    title = "Second Grader - " + ("BLOCKED" if decision.decision == "BLOCK" else "MERGED")
    if task_title:
        title += f" - {task_title}"

    replay_note = (
        "Replay of a recorded trace. Nothing is running; every record below was captured earlier."
        if mode == "REPLAY"
        else "Live run: records are appended to the trace as the agent works."
    )
    cells = _summary_cells(decision, plain, tampers, verifier_result, chain) if records is not None or verdicts or verifier_result else ""

    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{_e(title)}</title>",
        f"<style>{_CSS}</style></head><body><main>",
        '<div class="top"><span class="brand">Second Grader</span>',
        f'<span class="mode mode-{mode.lower()}" title="{_e(replay_note)}">{mode}</span>',
        '<span class="spacer"></span>',
        f'<span class="trace">trace <code>{_e(trace_name)}</code></span>' if trace_name else "",
        "</div>",
        f"<h1>{_e(task_title)}</h1>" if task_title else '<h1 class="muted">Verdict</h1>',
        f'<p class="subline">{_e(replay_note)}</p>',
        _task_picker(tasks, mode, selected_task),
        f'<div class="flash" role="status">{_e(flash)}</div>' if flash else "",
        _stamp(decision, mode, cells),
        _reasons(decision),
        _chain_card(decision, len(records) if records is not None else None, chain),
        _claims_table(plain, claim_map),
        _tamper_section(tampers),
        _verifier_section(verifier_result),
    ]
    if records is not None:
        parts.append(
            render_records(
                records,
                chain_ok=decision.chain_ok,
                first_bad_seq=decision.first_bad_seq,
                cited_seqs=cited,
                statuses=(chain or {}).get("statuses"),
            )
        )
        parts.append(_tamper_form(len(records), trace_name, mode))
    parts.append(
        '<footer>OBSERVED records are evidence. CLAIMED records are what gets checked. '
        "Code, not a model, decided this verdict.</footer>"
    )
    parts.append(f"</main><script>{_JS}</script></body></html>")
    return "\n".join(p for p in parts if p)


__all__ = ["MODES", "render_records", "render_verdict", "split_severity"]
