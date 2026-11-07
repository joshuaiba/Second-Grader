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
        ok = bool(p.get("passed"))
        badge = '<span class="pill ok">passed</span>' if ok else '<span class="pill bad">failed</span>'
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

def _chain_strip(records: list[Record], chain_ok: bool, first_bad: int | None) -> str:
    chips = []
    for rec in records:
        bad = (not chain_ok) and first_bad is not None and rec.seq >= first_bad
        cls = "chip bad" if bad else "chip good"
        title = f"seq {rec.seq} {rec.kind} ({rec.origin})" + (" - chain broken" if bad else "")
        chips.append(
            f'<a id="chip-{rec.seq}" class="{cls}" href="#rec-{rec.seq}" title="{_e(title)}" '
            f'data-seq="{rec.seq}" data-kind="{_e(rec.kind)}"></a>'
        )
    return '<div class="strip" aria-label="hash chain">' + "".join(chips) + "</div>"


def _record_details(rec: Record, cited: set[int], broken_from: int | None) -> str:
    is_cited = rec.seq in cited
    is_broken = broken_from is not None and rec.seq >= broken_from
    cls = "rec" + (" cited" if is_cited else "") + (" broken" if is_broken else "")
    origin_cls = "origin observed" if rec.origin == "OBSERVED" else "origin claimed"
    flags = ""
    if is_cited:
        flags += ' <span class="pill bad">cited by BLOCK</span>'
    if is_broken:
        flags += ' <span class="pill bad">chain broken</span>'
    return (
        f'<details id="rec-{rec.seq}" class="{cls}"{" open" if is_cited else ""}>'
        f'<summary><span class="seqno">#{rec.seq}</span> '
        f'<span class="kind">{_e(rec.kind)}</span> '
        f'<span class="{origin_cls}">{_e(rec.origin)}</span> '
        f'<span class="ts muted">{_e(rec.ts)}</span>{flags}</summary>'
        f'<div class="body">{_payload_html(rec)}'
        f'<div class="hashes muted">'
        f'<span><b>prev</b> <code>{_short(rec.prev_hash)}</code></span> '
        f'<span><b>hash</b> <code>{_short(rec.hash)}</code></span> '
        f'<span><b>sig</b> <code>{_short(rec.sig)}</code></span>'
        f"</div></div></details>"
    )


def render_records(
    records: list[Record],
    *,
    chain_ok: bool = True,
    first_bad_seq: int | None = None,
    cited_seqs: Iterable[int] = (),
) -> str:
    """Chain strip + collapsible record list (the record viewer fragment).

    Each chip has ``id="chip-<seq>"`` and links to ``#rec-<seq>``; chips are
    ``good`` when intact and ``bad`` from ``first_bad_seq`` on when
    ``chain_ok`` is False. Records in ``cited_seqs`` are highlighted and opened.
    """
    cited = {int(s) for s in cited_seqs}
    broken_from = None if chain_ok else first_bad_seq
    strip = _chain_strip(records, chain_ok, first_bad_seq)
    body = "".join(_record_details(r, cited, broken_from) for r in records)
    return (
        '<section id="records" class="card">'
        f'<h2>Trace <span class="muted">{len(records)} records</span></h2>'
        f"{strip}"
        '<div class="legend muted"><span class="chip good"></span> intact '
        '<span class="chip bad"></span> broken chain &nbsp; '
        '<span class="origin observed">OBSERVED</span> evidence &nbsp; '
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
        label = f'{tid} - {t.get("title", "")} (expects {t.get("expected_gate", "?")})'
        sel = " selected" if tid == selected_task else ""
        opts.append(f'<option value="{_e(tid)}"{sel}>{_e(label)}</option>')
    live = " checked" if mode == "LIVE" else ""
    replay = " checked" if mode != "LIVE" else ""
    return (
        '<form id="runform" class="card picker" onsubmit="return sgRun(event)">'
        '<label>Task <select name="task" id="task">' + "".join(opts) + "</select></label>"
        f'<label><input type="radio" name="runmode" value="LIVE"{live}> Live</label>'
        f'<label><input type="radio" name="runmode" value="REPLAY"{replay}> Replay</label>'
        '<button type="submit">Run</button>'
        '<span id="runmsg" class="muted"></span>'
        '<div id="stages" class="stages muted">stage: &hellip;</div>'
        "</form>"
    )


def _stamp(decision: GateDecision, mode: str) -> str:
    blocked = decision.decision == "BLOCK"
    word = "BLOCKED" if blocked else "MERGED"
    return (
        f'<section class="verdict {"BLOCK" if blocked else "PASS"}">'
        f'<div class="stamp {"block" if blocked else "pass"}" data-decision="{_e(decision.decision)}">{word}</div>'
        f'<div class="stamp-sub">gate decision: <b>{_e(decision.decision)}</b> &middot; '
        f'<span class="mode mode-{mode.lower()}">{mode}</span></div>'
        "</section>"
    )


def _reasons(decision: GateDecision) -> str:
    if not decision.reasons:
        txt = "No blocking findings." if decision.decision == "PASS" else "Blocked without stated reasons."
        items = f'<li class="muted">{txt}</li>'
    else:
        items = "".join(f"<li>{_link_seqs_in_text(r)}</li>" for r in decision.reasons)
    return (
        '<section class="card reasons"><h2>Why</h2>'
        f"<ol>{items}</ol>"
        f'<div class="kv"><b>Citing records</b> {_seq_links(decision.citing_seqs)}</div>'
        "</section>"
    )


def _chain_card(decision: GateDecision, n_records: int | None) -> str:
    if decision.chain_ok:
        status = '<span class="pill ok">INTACT</span>'
        detail = "every hash and prev_hash verified"
        if n_records is not None:
            detail = f"{n_records} records, " + detail
    else:
        status = '<span class="pill bad">BROKEN</span>'
        bad = _seq_link(decision.first_bad_seq) if decision.first_bad_seq is not None else "unknown"
        detail = f"first bad record: {bad}"
    return (
        '<section class="card chain"><h2>Hash chain</h2>'
        f'<div class="kv">{status} <span class="muted">{detail}</span>'
        + (f' <span class="muted">first_bad_seq = {_e(decision.first_bad_seq)}</span>' if decision.first_bad_seq is not None else "")
        + "</div>"
        "</section>"
    )


def _claims_table(verdicts: list[ClaimVerdict], claims: dict[str, Claim]) -> str:
    rows = []
    for v in verdicts:
        c = claims.get(v.claim_id)
        text = _e(c.text) if c else '<span class="muted">(claim text not available)</span>'
        src = f' <span class="muted">said at {_seq_link(c.source_seq)}</span>' if c else ""
        kind = f'<span class="muted">{_e(c.kind)}</span>' if c else ""
        status = _e(v.status)
        rows.append(
            f'<tr class="status-{status.lower()}">'
            f"<td><code>{_e(v.claim_id)}</code></td>"
            f"<td>{text}{src}<br>{kind}</td>"
            f'<td><span class="status {status.lower()}">{status}</span></td>'
            f"<td>{_e(v.reason)}</td>"
            f"<td>{_seq_links(v.evidence_seqs)}</td>"
            "</tr>"
        )
    if not rows:
        rows.append('<tr><td colspan="5" class="muted">No claims extracted.</td></tr>')
    return (
        '<section class="card claims"><h2>Claims</h2>'
        "<table><thead><tr><th>id</th><th>claim</th><th>status</th><th>reason</th><th>evidence</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></section>"
    )


def _tamper_section(tampers: list[ClaimVerdict]) -> str:
    if not tampers:
        return (
            '<section class="card tampers"><h2>Tamper findings</h2>'
            '<p class="muted">None: no edits to protected files were observed.</p></section>'
        )
    items = []
    for t in tampers:
        target = t.claim_id.split(":", 1)[1] if ":" in t.claim_id else t.claim_id
        items.append(
            f'<li><span class="status {_e(t.status.lower())}">{_e(t.status)}</span> '
            f"<code>{_e(target)}</code> &mdash; {_e(t.reason)} "
            f'<span class="muted">evidence</span> {_seq_links(t.evidence_seqs)}</li>'
        )
    return f'<section class="card tampers"><h2>Tamper findings</h2><ul>{"".join(items)}</ul></section>'


def _verifier_section(vr: VerifierResult | None) -> str:
    if vr is None:
        return (
            '<section class="card verifier"><h2>Blind verifier</h2>'
            '<p class="muted">Verifier did not run.</p></section>'
        )
    errored = max(0, len(vr.details) - int(vr.passed) - int(vr.failed))
    summary = (
        f'<div class="kv"><span class="pill ok">{int(vr.passed)} passed</span> '
        f'<span class="pill {"bad" if vr.failed else "ok"}">{int(vr.failed)} failed</span> '
        + (f'<span class="pill warn">{errored} errored</span> ' if errored else "")
        + f'<span class="muted">tests written: {len(vr.tests_written)}</span></div>'
    )
    if int(vr.passed) + int(vr.failed) == 0:
        summary += (
            '<p class="note warn-text"><b>No countable verifier tests.</b> The generated tests were rejected or '
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
        rows.append(
            f"<tr><td><code>{_e(d.get('name'))}</code>"
            + (f'<div class="muted small">{sentence}</div>' if sentence else "")
            + f'</td><td><span class="pill {pill}">{_e(outcome)}</span></td>'
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
        '<section class="card verifier"><h2>Blind verifier</h2>'
        f"{summary}<details open><summary>tests written</summary><ul>{written}</ul></details>{details}{recs}"
        "</section>"
    )


def _tamper_form(n_records: int, trace: str, mode: str) -> str:
    default = min(13, n_records) if n_records else 1
    return (
        '<form class="card tamperform" method="post" action="/api/tamper">'
        "<h2>Tamper demo</h2>"
        '<p class="muted">Flips one byte in the payload of record N <em>in memory</em> and re-checks the chain. '
        "The strip turns red from N onwards. The trace file on disk is never changed.</p>"
        f'<label>Tamper with record <input type="number" name="seq" min="1" max="{n_records}" value="{default}" required></label> '
        f'<input type="hidden" name="trace" value="{_e(trace)}">'
        f'<input type="hidden" name="mode" value="{_e(mode)}">'
        '<button type="submit">Tamper</button>'
        "</form>"
    )


_CSS = """
:root { color-scheme: light dark;
  --bg:#f6f7f9; --fg:#1b1f24; --card:#fff; --muted:#5f6b7a; --line:#d9dee5;
  --green:#1b7f3b; --red:#b00020; --amber:#9a6700; --green-bg:#e4f5ea; --red-bg:#fbe6ea; --amber-bg:#fff4d6;
  --observed:#1f4e9a; --observed-bg:#e3ecfa; --claimed:#6e4b9a; --claimed-bg:#efe6fa; --code:#eef1f5; }
@media (prefers-color-scheme: dark) { :root {
  --bg:#0f1216; --fg:#e6e9ee; --card:#171b21; --muted:#98a2b3; --line:#2a313b;
  --green:#4cc36d; --red:#ff5c6c; --amber:#f0b429; --green-bg:#13301d; --red-bg:#3a1218; --amber-bg:#3a2d0b;
  --observed:#86b0ff; --observed-bg:#182742; --claimed:#c7a5f2; --claimed-bg:#2a1e3d; --code:#0d1117; } }
* { box-sizing:border-box }
body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; background:var(--bg); color:var(--fg);
  max-width:64rem; margin:0 auto; padding:1rem 1rem 4rem; line-height:1.4 }
a { color:inherit }
a.seq { font-family:ui-monospace,monospace; font-size:.85em; padding:0 .3em; border:1px solid var(--line);
  border-radius:4px; text-decoration:none; background:var(--code) }
a.seq:hover { border-color:var(--fg) }
header { display:flex; align-items:baseline; gap:1rem; flex-wrap:wrap; margin-bottom:.3rem }
header h1 { margin:0; font-size:1.25rem } header .task { color:var(--muted) }
.mode { font-weight:700; letter-spacing:.08em; padding:.1em .5em; border-radius:4px; font-size:.8em; vertical-align:middle }
.mode-replay { background:repeating-linear-gradient(45deg,var(--code),var(--code) 6px,var(--line) 6px,var(--line) 12px);
  color:var(--fg); border:1px dashed var(--muted) }
.mode-live { background:var(--red); color:#fff; animation: sgpulse 1.2s infinite alternate }
@keyframes sgpulse { from { opacity:1 } to { opacity:.6 } }
.modebar { font-size:.9rem; color:var(--muted); margin-bottom:1rem }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:.9rem 1rem; margin:.8rem 0 }
.card h2 { font-size:.95rem; margin:0 0 .5rem; text-transform:uppercase; letter-spacing:.06em; color:var(--muted) }
.verdict { text-align:center; padding:1.2rem 0 .4rem }
.stamp { display:inline-block; font-size:3.5rem; font-weight:900; letter-spacing:.12em; padding:.1em .5em;
  border:6px solid currentColor; border-radius:14px; transform:rotate(-3deg); text-transform:uppercase }
.stamp.block { color:var(--red); background:var(--red-bg) } .stamp.pass { color:var(--green); background:var(--green-bg) }
.stamp-sub { margin-top:.8rem; color:var(--muted); font-size:.95rem }
.reasons ol { margin:.2rem 0 .6rem 1.2rem; padding:0 } .reasons li { margin:.25rem 0 }
.kv { margin:.25rem 0 } .kv b { color:var(--muted); font-weight:600; margin-right:.3em }
.muted { color:var(--muted) }
.pill { display:inline-block; padding:.05em .55em; border-radius:999px; font-size:.8em; font-weight:700 }
.pill.ok { background:var(--green-bg); color:var(--green) } .pill.warn{background:var(--amber-bg,#4a3a10);color:var(--amber,#e0b84a)}
.pill.bad { background:var(--red-bg); color:var(--red) }
.status { font-weight:700; padding:.1em .5em; border-radius:4px; font-size:.85em; white-space:nowrap }
.status.supported { background:var(--green-bg); color:var(--green) }
.status.contradicted { background:var(--red-bg); color:var(--red) }
.status.unsupported { background:var(--amber-bg); color:var(--amber) }
table { width:100%; border-collapse:collapse; font-size:.92rem }
th, td { text-align:left; vertical-align:top; padding:.4rem .5rem; border-top:1px solid var(--line) }
th { color:var(--muted); font-weight:600; border-top:0 }
tr.status-contradicted td:first-child { border-left:3px solid var(--red) }
tr.status-supported td:first-child { border-left:3px solid var(--green) }
tr.status-unsupported td:first-child { border-left:3px solid var(--amber) }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:.85em }
pre { background:var(--code); padding:.5rem .6rem; border-radius:6px; overflow:auto; margin:.3rem 0; max-height:22rem; white-space:pre-wrap }
pre.diff .add { color:var(--green) } pre.diff .del { color:var(--red) } pre.diff .hunk { color:var(--observed) }
blockquote.claimed-text { margin:.3rem 0; padding:.4rem .8rem; border-left:3px solid var(--claimed); background:var(--claimed-bg); border-radius:4px }
.strip { display:flex; flex-wrap:wrap; gap:4px; margin:.4rem 0 }
.chip { display:inline-block; width:18px; height:18px; border-radius:3px; border:1px solid rgba(0,0,0,.2) }
.chip.good { background:var(--green) } .chip.bad { background:var(--red) }
.chip:hover { outline:2px solid var(--fg) }
.legend { font-size:.8rem; margin:.3rem 0 .6rem } .legend .chip { width:12px; height:12px; vertical-align:middle }
.origin { font-size:.72em; font-weight:700; letter-spacing:.06em; padding:.1em .45em; border-radius:3px }
.origin.observed { background:var(--observed-bg); color:var(--observed); border:1px solid var(--observed) }
.origin.claimed { background:var(--claimed-bg); color:var(--claimed); border:1px dashed var(--claimed); font-style:italic }
details.rec { border-top:1px solid var(--line); padding:.3rem 0 }
details.rec summary { cursor:pointer; display:flex; gap:.6rem; align-items:center; flex-wrap:wrap }
details.rec .seqno { font-family:ui-monospace,monospace; min-width:2.6em; color:var(--muted) }
details.rec .kind { font-weight:600 } details.rec .ts { font-size:.8em }
details.rec.cited { background:var(--red-bg); border-left:4px solid var(--red); padding-left:.6rem; margin-left:-.6rem; border-radius:4px }
details.rec.broken summary .seqno { color:var(--red); text-decoration:line-through }
details.rec .body { padding:.3rem 0 .4rem 3.2em }
.hashes { font-size:.8em; display:flex; gap:1rem; flex-wrap:wrap; margin-top:.3rem }
:target { scroll-margin-top:1rem } details:target { outline:2px solid var(--fg) }
.picker { display:flex; gap:1rem; align-items:center; flex-wrap:wrap } .picker select { max-width:28rem }
.picker .stages { flex-basis:100%; font-size:.85rem }
button { font:inherit; padding:.3em .9em; border-radius:6px; border:1px solid var(--line); background:var(--code); color:var(--fg); cursor:pointer }
button:hover { border-color:var(--fg) }
input[type=number] { width:5em } select, input { font:inherit }
.tamperform p { margin:.2rem 0 .5rem }
.flash { border-color:var(--amber); background:var(--amber-bg) }
footer { margin-top:2rem; font-size:.8rem }
"""

_JS = """
function sgRun(ev) {
  ev.preventDefault();
  var f = ev.target, msg = document.getElementById('runmsg');
  var mode = (f.querySelector('input[name=runmode]:checked') || {}).value || 'REPLAY';
  msg.textContent = 'starting...';
  fetch('/api/run', {method:'POST', headers:{'Content-Type':'application/json'},
         body: JSON.stringify({task: f.task.value, mode: mode})})
    .then(function(r){ return r.json().then(function(j){ return {ok:r.ok, status:r.status, body:j}; }); })
    .then(function(res){
      var b = res.body || {};
      msg.textContent = (b.status || ('HTTP ' + res.status)) + (b.message ? ': ' + b.message : '');
      if (res.ok && b.redirect) { window.location = b.redirect; }
      else if (res.ok) { sgPollStatus(); }
    })
    .catch(function(e){ msg.textContent = 'run failed: ' + e; });
  return false;
}
function sgPollStatus() {
  var el = document.getElementById('stages');
  if (!el) return;
  fetch('/api/status').then(function(r){ return r.json(); }).then(function(s){
    var parts = (s.stages || []).map(function(st){
      var name = typeof st === 'string' ? st : st.name;
      return name === s.stage ? '[' + name + ']' : name;
    });
    el.textContent = 'stage: ' + (s.stage || '?') + '   ' + parts.join(' > ');
    if (s.stage !== 'done' && s.stage !== 'error') setTimeout(sgPollStatus, 1000);
  }).catch(function(){ el.textContent = 'stage: unavailable'; });
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

    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{_e(title)}</title>",
        f"<style>{_CSS}</style></head><body>",
        "<header><h1>Second Grader</h1>",
        f'<span class="mode mode-{mode.lower()}">{mode}</span>',
        f'<span class="task">{_e(task_title)}</span>' if task_title else "",
        f'<span class="task muted">trace: <code>{_e(trace_name)}</code></span>' if trace_name else "",
        "</header>",
        f'<div class="modebar">{replay_note}</div>',
        f'<div class="card flash">{_e(flash)}</div>' if flash else "",
        _task_picker(tasks, mode, selected_task),
        _stamp(decision, mode),
        _reasons(decision),
        _chain_card(decision, len(records) if records is not None else None),
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
            )
        )
        parts.append(_tamper_form(len(records), trace_name, mode))
    parts.append(
        '<footer class="muted">OBSERVED records are evidence. CLAIMED records are what gets checked. '
        "Code, not a model, decided this verdict.</footer>"
    )
    parts.append(f"<script>{_JS}</script></body></html>")
    return "\n".join(p for p in parts if p)


__all__ = ["MODES", "render_records", "render_verdict"]
