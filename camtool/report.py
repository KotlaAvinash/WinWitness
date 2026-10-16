"""Write CSV / JSON / SQLite / HTML outputs and a SHA-256 manifest."""
from __future__ import annotations

import csv
import hashlib
import html
import json
import os
import sqlite3


def _flat(v):
    if isinstance(v, (dict, list, tuple)):
        return json.dumps(v, default=str, ensure_ascii=False)
    if isinstance(v, bytes):
        return v.hex()
    return v


def write_csv(path: str, rows: list[dict], cols: list[str] | None = None):
    cols = cols or _cols(rows)
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in rows:
            w.writerow([_safe_cell(_flat(r.get(c, ""))) for c in cols])


def _safe_cell(v):
    # Neutralise spreadsheet formula injection from evidence strings (=, +, -, @ at start).
    if isinstance(v, str) and v[:1] in ("=", "+", "@") or (isinstance(v, str) and v[:1] == "-" and not _isnum(v)):
        return "'" + v
    return v


def _isnum(s):
    try:
        float(s)
        return True
    except ValueError:
        return False


def _cols(rows):
    cols = []
    for r in rows:
        for k in r:
            if k not in cols:
                cols.append(k)
    return cols


def write_sqlite(path: str, datasets: dict[str, list[dict]]):
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    try:
        for name, rows in datasets.items():
            cols = _cols(rows) or ["empty"]
            con.execute(f'CREATE TABLE "{name}" ({", ".join(chr(34) + c + chr(34) for c in cols)})')
            con.executemany(f'INSERT INTO "{name}" VALUES ({",".join("?" * len(cols))})',
                            [[_flat(r.get(c)) for c in cols] for r in rows])
        con.commit()
    finally:
        con.close()


def manifest(outdir: str) -> str:
    lines = []
    for root, _d, files in os.walk(outdir):
        for f in sorted(files):
            if f == "MANIFEST.sha256":
                continue
            p = os.path.join(root, f)
            h = hashlib.sha256(open(p, "rb").read()).hexdigest()
            lines.append(f"{h} *{os.path.relpath(p, outdir)}")
    mp = os.path.join(outdir, "MANIFEST.sha256")
    with open(mp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return mp


# --------------------------------------------------------------------------- HTML
CSS = """
:root{--bg:#fbfbfa;--fg:#1d1d1b;--mut:#6b6b66;--line:#e2e1dc;--card:#fff;--acc:#2f5d8a;--hi:#b3261e;--med:#a15c00;--ok:#2e7d32;--chip:#f0efe9}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe6;--mut:#a3a29c;--line:#33332f;--card:#1e1e1c;--acc:#8ab4e0;--hi:#f2867e;--med:#e8a64a;--ok:#7cc884;--chip:#2a2a27}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,sans-serif}
header{padding:20px 24px;border-bottom:1px solid var(--line)}h1{margin:0;font-size:20px}h2{font-size:16px;margin:28px 0 8px}
.sub{color:var(--mut)}nav{position:sticky;top:0;background:var(--bg);border-bottom:1px solid var(--line);padding:8px 24px;z-index:3;overflow-x:auto;white-space:nowrap}
nav a{color:var(--acc);margin-right:14px;text-decoration:none;font-size:13px}main{padding:0 24px 60px;max-width:1600px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin:16px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}.card b{font-size:22px;display:block}
.tw{overflow:auto;max-height:560px;border:1px solid var(--line);border-radius:8px;background:var(--card)}
table{border-collapse:collapse;width:100%;font-size:12px}th,td{padding:4px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;white-space:nowrap}
th{position:sticky;top:0;background:var(--chip);cursor:pointer;user-select:none}td.w{white-space:normal;min-width:320px}
.sev-HIGH{color:var(--hi);font-weight:600}.sev-MEDIUM{color:var(--med);font-weight:600}.sev-INFO{color:var(--mut)}
input.f{margin:6px 0;padding:5px 8px;width:320px;max-width:100%;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg)}
.pill{display:inline-block;padding:0 6px;border-radius:9px;background:var(--chip);font-size:11px}
code{background:var(--chip);padding:0 4px;border-radius:4px}.ok{color:var(--ok)}.bad{color:var(--hi)}
details{margin:6px 0}summary{cursor:pointer;color:var(--acc)}
"""
JS = """
document.querySelectorAll('input.f').forEach(inp=>inp.addEventListener('input',()=>{const q=inp.value.toLowerCase();
document.querySelectorAll('#'+inp.dataset.t+' tbody tr').forEach(tr=>{tr.style.display=tr.textContent.toLowerCase().includes(q)?'':'none'})}));
document.querySelectorAll('th').forEach(th=>th.addEventListener('click',()=>{const tb=th.closest('table').tBodies[0];const i=[...th.parentNode.children].indexOf(th);
const asc=th.dataset.a!=='1';th.dataset.a=asc?'1':'0';[...tb.rows].sort((a,b)=>{const x=a.cells[i].textContent,y=b.cells[i].textContent;
const nx=parseFloat(x),ny=parseFloat(y);const c=(!isNaN(nx)&&!isNaN(ny))?nx-ny:x.localeCompare(y);return asc?c:-c}).forEach(r=>tb.appendChild(r))}));
"""


def _table(tid: str, rows: list[dict], cols: list[str] | None = None, wide: tuple = (), limit: int = 20000) -> str:
    cols = cols or _cols(rows)
    if not rows:
        return '<p class="sub">(no rows)</p>'
    e = html.escape
    h = [f'<input class="f" data-t="{tid}" placeholder="filter {len(rows)} rows…">',
         f'<div class="tw"><table id="{tid}"><thead><tr>' + "".join(f"<th>{e(c)}</th>" for c in cols) + "</tr></thead><tbody>"]
    for r in rows[:limit]:
        cells = []
        for c in cols:
            v = _flat(r.get(c, ""))
            v = "" if v is None else str(v)
            cls = ' class="w"' if c in wide else ""
            if c == "severity":
                cls = f' class="sev-{e(v)}"'
            cells.append(f"<td{cls}>{e(v)}</td>")
        h.append("<tr>" + "".join(cells) + "</tr>")
    h.append("</tbody></table></div>")
    if len(rows) > limit:
        h.append(f'<p class="sub">showing first {limit} of {len(rows)} rows; full data in CSV</p>')
    return "".join(h)


def write_html(path: str, ctx: dict):
    e = html.escape
    S = []
    S.append(f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
             f"<title>CAM Forensic Report</title><style>{CSS}</style></head><body>")
    S.append(f"<header><h1>Capability Access Manager — forensic report</h1><div class=sub>{e(ctx['tool'])} · "
             f"generated {e(ctx['generated_utc'])} UTC · evidence: <code>{e(ctx['evidence_dir'])}</code> · "
             f"local time column = UTC{e(ctx['tz_label'])}</div></header>")
    secs = [("summary", "Summary"), ("findings", "Findings"), ("integrity", "Evidence & integrity"), ("timeline", "Timeline"),
            ("usage", "Usage history"), ("recovered", "Recovered / deleted"), ("wal", "WAL transactions"),
            ("prompts", "Prompts & identities"), ("consent", "Consent DB"), ("corr", "Corroboration"),
            ("structure", "File structure"), ("raw", "Raw tables"), ("method", "Method & limits")]
    S.append("<nav>" + "".join(f'<a href="#{a}">{b}</a>' for a, b in secs) + "</nav><main>")
    # summary
    S.append('<h2 id="summary">Summary</h2><div class="cards">')
    for k, v in ctx["cards"]:
        S.append(f'<div class="card"><span class="sub">{e(k)}</span><b>{e(str(v))}</b></div>')
    S.append("</div>")
    S.append('<h2 id="findings">Findings</h2><p class=sub>basis: <span class=pill>measured</span> = verified on this evidence; '
             '<span class=pill>published</span> = public research; <span class=pill>observed</span> = pattern seen, meaning not proven.</p>')
    S.append(_table("t_find", ctx["findings"], ["severity", "category", "title", "detail", "basis"], wide=("detail", "title")))
    # integrity
    S.append('<h2 id="integrity">Evidence &amp; integrity</h2>')
    S.append(_table("t_ev", ctx["evidence"], ["role", "name", "size", "sha256", "md5", "mtime_utc", "unchanged_after_run"]))
    S.append(f"<p>All inputs were hashed before and after the run; the sqlite3 library only ever opened a temporary copy. "
             f"Result: <b class={'ok' if ctx['integrity_ok'] else 'bad'}>{'inputs unchanged' if ctx['integrity_ok'] else 'INPUT CHANGED'}</b></p>")
    # timeline
    S.append('<h2 id="timeline">Unified timeline</h2>')
    S.append(_table("t_tl", ctx["timeline"], ["time_utc", "time_local", "event", "subject", "detail", "source", "ref"], wide=("subject",)))
    # usage
    S.append('<h2 id="usage">Usage history (live, WAL applied)</h2>')
    S.append(_table("t_use", ctx["usage"], ["table", "ID", "start_utc", "stop_utc", "start_local", "duration_s", "access", "capability",
                                             "app", "app_name", "user_sid", "file_id", "program_id", "Label", "Context"]))
    S.append('<h2 id="recovered">Recovered records (not in the live tables)</h2>')
    S.append(_table("t_rec", ctx["carved_usage"], ["status", "table", "ID", "id_basis", "start_utc", "stop_utc", "start_local",
                                                    "duration_s", "access", "capability", "app", "app_name", "user_sid",
                                                    "Label", "Context", "found_at", "offset", "file"]))
    S.append("<details><summary>All carved records incl. duplicates of live rows</summary>" +
             _table("t_carv", ctx["carved_all"], wide=("values",)) + "</details>")
    S.append('<h2 id="wal">WAL transactions (row-level diff, snapshot by snapshot)</h2>')
    S.append(_table("t_wal", ctx["wal_changes"], ["db", "step", "table", "rowid", "change", "from_slack", "before", "after"], wide=("after", "before")))
    S.append('<h2 id="prompts">Location prompts &amp; binary identities</h2>')
    S.append(_table("t_pr", ctx["prompts"], ["ID", "shown_utc", "shown_local", "capability", "binary", "binary_name", "sha1", "program_id", "user_sid"]))
    S.append(_table("t_id", ctx["identity"], ["ID", "first_observed_utc", "first_observed_local", "binary", "sha1", "program_id"]))
    S.append('<h2 id="consent">CapabilityConsentStorage.db (decoded)</h2>')
    for t, rows in ctx["consent"].items():
        S.append(f"<h3>{e(t)} <span class=pill>{len(rows)}</span></h3>" + _table(f"t_c_{t}", rows))
    S.append('<h2 id="corr">Corroboration</h2>')
    for title, rows in ctx["corroboration"]:
        S.append(f"<h3>{e(title)}</h3>" + (_table("t_x" + str(abs(hash(title))), rows) if isinstance(rows, list) else f"<p>{e(str(rows))}</p>"))
    S.append('<h2 id="structure">File structure</h2>')
    for t, rows in ctx["structure"]:
        S.append(f"<h3>{e(t)}</h3>" + (_table("t_s" + str(abs(hash(t))), rows) if isinstance(rows, list) else f"<pre>{e(json.dumps(rows, indent=1, default=str))}</pre>"))
    S.append('<h2 id="raw">Raw tables (every column, undecoded)</h2>')
    for t, rows in ctx["raw"].items():
        S.append(f"<details><summary>{e(t)} ({len(rows)})</summary>" + _table("t_r" + str(abs(hash(t))), rows) + "</details>")
    S.append('<h2 id="method">Method &amp; limits</h2><div>' + ctx["method_html"] + "</div>")
    S.append(f"</main><script>{JS}</script></body></html>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("".join(S))
