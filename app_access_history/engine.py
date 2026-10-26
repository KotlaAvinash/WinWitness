"""Analysis engine: evidence intake -> structure -> logical rows -> WAL history -> carving."""
from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import model as M
from .carver import Carver, Carved, dedupe, repair_freeblock
from .sqlite_low import (BTreeReader, FormatError, PageImage, page_free_regions, parse_db_header,
                         parse_shm, parse_wal, BTREE_TYPES)

TOOL_NAME = "App Access History"
TOOL_VERSION = "2.2.0"


# --------------------------------------------------------------------------- evidence intake
@dataclass
class EvidenceFile:
    path: str
    name: str
    size: int
    sha256: str
    md5: str
    mtime_utc: str
    data: bytes = field(repr=False, default=b"")


def hash_file(path: str) -> tuple[str, str, int]:
    h, m, n = hashlib.sha256(), hashlib.md5(), 0
    with open(path, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            h.update(b)
            m.update(b)
            n += len(b)
    return h.hexdigest(), m.hexdigest(), n


def load_evidence(path: str, keep_data: bool = True) -> EvidenceFile:
    sha, md5, n = hash_file(path)
    st = os.stat(path)
    data = b""
    if keep_data:
        with open(path, "rb") as f:
            data = f.read()
        if hashlib.sha256(data).hexdigest() != sha:
            raise IOError(f"{path} changed while being read")
    return EvidenceFile(path, os.path.basename(path), n, sha, md5,
                        datetime.fromtimestamp(st.st_mtime, timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                        data)


def discover(folder: str) -> dict[str, str]:
    """Map role -> path for the files App Access History understands (case-insensitive, top level + 1 deep)."""
    roles = {}
    cands = []
    for root, dirs, files in os.walk(folder):
        depth = os.path.relpath(root, folder).count(os.sep)
        if depth > 1:
            dirs[:] = []
            continue
        # never descend into our own output or into the working copy area
        dirs[:] = [d for d in dirs if d.lower() not in ("testing", "working tool", "app_access_history_output", "__pycache__")]
        for f in files:
            cands.append(os.path.join(root, f))
    for p in sorted(cands, key=lambda x: (x.count(os.sep), x)):
        n = os.path.basename(p).lower()
        for base in (M.CAM_DB, M.CONSENT_DB):
            b = base.lower()
            for suffix, role in (("", ""), ("-wal", "-wal"), ("-shm", "-shm"),
                                 (".fileslack", ".FileSlack"), ("-wal.fileslack", "-wal.FileSlack"),
                                 ("-shm.fileslack", "-shm.FileSlack")):
                if n == b + suffix:
                    roles.setdefault(base + role, p)
        if n == "$i30" or n.endswith("$i30") or n.endswith(".i30"):
            roles.setdefault("$I30", p)
        # optional registry hives (used only when present)
        if n == "ntuser.dat":
            roles.setdefault("NTUSER.DAT:" + os.path.relpath(p, folder), p)
        if n == "software":
            roles.setdefault("SOFTWARE", p)
    return roles


# --------------------------------------------------------------------------- one database
@dataclass
class DbAnalysis:
    name: str
    main: EvidenceFile | None
    wal: EvidenceFile | None
    shm: EvidenceFile | None
    header: object = None
    wal_info: object = None
    shm_info: dict | None = None
    schema: list = field(default_factory=list)
    sigs: list = field(default_factory=list)
    tables: dict = field(default_factory=dict)          # final state: name -> list[dict]
    tables_main_only: dict = field(default_factory=dict)
    wal_changes: list = field(default_factory=list)
    page_map: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    library_check: dict = field(default_factory=dict)
    carved: list = field(default_factory=list)
    beyond_eof_pages: list = field(default_factory=list)


def _rows_from_cells(cells, sig) -> list[dict]:
    rows = []
    for c in cells:
        vals = list(c.values)
        names = [col.name for col in sig.columns] if sig else [f"c{i}" for i in range(len(vals))]
        # Missing trailing columns (rows older than an ALTER TABLE) take the declared default.
        d = {}
        for i, n in enumerate(names):
            if i < len(vals):
                v = vals[i]
            else:
                col = sig.columns[i]
                v = col.default
            if sig and sig.columns[i].pk_alias:
                v = c.rowid
            d[n] = v
        d["_rowid"] = c.rowid
        d["_page"] = c.page
        d["_ncols_stored"] = len(vals)
        rows.append(d)
    return rows


def _read_image(img: PageImage, sigs_by_name: dict):
    r = BTreeReader(img)
    res = r.read_all()
    tables = {}
    for name, cells in res["tables"].items():
        tables[name] = _rows_from_cells(cells, sigs_by_name.get(name))
    return res, tables


def _library_read(main: EvidenceFile, wal: EvidenceFile | None, tmpdir: str) -> dict:
    """Second, independent method: let the sqlite3 library read a *copy* (WAL applied)."""
    d = tempfile.mkdtemp(dir=tmpdir)
    p = os.path.join(d, main.name)
    with open(p, "wb") as f:
        f.write(main.data)
    if wal is not None:
        with open(p + "-wal", "wb") as f:
            f.write(wal.data)
    out = {}
    con = sqlite3.connect(p)
    try:
        con.text_factory = lambda b: b.decode("utf-8", "replace")
        names = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
        for n in names:
            out[n] = sorted(tuple(r) for r in con.execute(f'select rowid, * from "{n}"'))
        out["__integrity_check__"] = [r[0] for r in con.execute("pragma integrity_check")]
    finally:
        con.close()
        shutil.rmtree(d, ignore_errors=True)
    return out


def analyze_db(name: str, main: EvidenceFile, wal: EvidenceFile | None, shm: EvidenceFile | None,
               tmpdir: str, log, wal_slack: EvidenceFile | None = None) -> DbAnalysis:
    A = DbAnalysis(name, main, wal, shm)
    h = parse_db_header(main.data)
    A.header = h
    if wal is not None and len(wal.data):
        try:
            # WAL slack is appended so frames that continue past the logical size can be checked
            ext = wal.data + wal_slack.data if wal_slack is not None and len(wal_slack.data) else wal.data
            A.wal_info = parse_wal(ext, len(wal.data))
            if A.wal_info and A.wal_info.page_size != h.page_size:
                A.errors.append(f"WAL page size {A.wal_info.page_size} != db page size {h.page_size}")
        except FormatError as e:
            A.errors.append(f"WAL: {e}")
    if shm is not None:
        A.shm_info = parse_shm(shm.data)

    base = PageImage(main.data, h)
    # schema from the final state (schema could only change inside the WAL in theory)
    overlay_final, final_pages = {}, base.db_pages
    if A.wal_info:
        for fr in A.wal_info.valid_frames:
            overlay_final[fr.pgno] = fr.data
            if fr.is_commit:
                final_pages = fr.commit_size
    final_img = PageImage(main.data, h, overlay_final, final_pages)
    sch = [x for x in BTreeReader(final_img).schema() if isinstance(x.get("name"), str)]
    A.schema = sch
    A.sigs = [s for s in (M.sig_from_sql(name, x["name"], x["sql"]) for x in sch if x["type"] == "table") if s]
    sigs_by_name = {s.table: s for s in A.sigs}

    # --- main-only snapshot (what the database looked like at the last checkpoint)
    res0, t0 = _read_image(base, sigs_by_name)
    A.tables_main_only = t0
    A.errors += [f"main-only: {e}" for e in res0["errors"]]

    resF, tF = _read_image(final_img, sigs_by_name)
    A.tables = tF
    A.errors += [f"final: {e}" for e in resF["errors"]]

    # --- WAL history: one row-level diff per committed transaction (incremental, page based)
    A.slack_rows = set()
    if A.wal_info:
        live_frames = A.wal_info.valid_frames
        slack_valid = [f for f in A.wal_info.frames if f.valid and f.in_slack]
        A.wal_changes = wal_history(main.data, h, base, live_frames + slack_valid, sch, sigs_by_name, A.errors)
        for w in A.wal_changes:
            if w["from_slack"] and w["after"] is not None:
                sig = sigs_by_name.get(w["table"])
                if sig:
                    A.slack_rows.add((w["table"], w["rowid"],
                                      tuple(w["after"][c.name] for c in sig.columns if not c.pk_alias)))
        if slack_valid:
            log(f"{name}: {len(slack_valid)} checksum-valid WAL frame(s) recovered from WAL file slack")

    # --- page map of the main file (+ which pages the WAL replaces)
    roles = resF["roles"]
    roles_main = res0["roles"]
    wal_pages = defaultdict(list)
    if A.wal_info:
        for fr in A.wal_info.frames:
            wal_pages[fr.pgno].append(fr.index)
    for n in range(1, base.file_pages + 1):
        pg = main.data[(n - 1) * h.page_size: n * h.page_size]
        off = 100 if n == 1 else 0
        t = pg[off]
        nz = len(pg) - pg.count(0)
        role = roles_main.get(n) or roles.get(n)
        if n > base.db_pages:
            role = "beyond logical EOF" + (" (has data)" if nz else " (zeroed)")
            if nz:
                A.beyond_eof_pages.append(n)
        elif not role:
            role = "orphan (unreferenced)"
        A.page_map.append(dict(page=n, offset=(n - 1) * h.page_size, type=t if t in BTREE_TYPES else None,
                               role=role, nonzero_bytes=nz, wal_frames=wal_pages.get(n, [])))

    # --- library cross-check (second method)
    try:
        lib = _library_read(main, wal, tmpdir)
        mism = []
        for tname, rows in A.tables.items():
            sig = sigs_by_name.get(tname)
            mine = sorted(tuple([r["_rowid"]] + [r[c.name] for c in sig.columns]) for r in rows) if sig else []
            theirs = lib.get(tname)
            if theirs is None or (sig and mine != theirs):
                mism.append(tname)
        A.library_check = dict(match=not mism, mismatched_tables=mism,
                               integrity_check=lib.get("__integrity_check__"),
                               tables_compared=len(A.tables))
    except Exception as e:  # pragma: no cover - reported, not fatal
        A.library_check = dict(match=None, error=str(e))
    log(f"{name}: {sum(len(v) for v in A.tables.values())} live rows in {len(A.tables)} tables; "
        f"library cross-check match={A.library_check.get('match')}")
    return A


# --------------------------------------------------------------------------- WAL history
def _strip(r):
    return {k: v for k, v in r.items() if not k.startswith("_")}


def wal_history(main: bytes, h, base: PageImage, frames: list, schema: list, sigs_by_name: dict,
                errors: list) -> list[dict]:
    """Row-level INSERT/UPDATE/DELETE per committed WAL transaction.

    Only the pages a transaction touched are read: rows on the old versions of the table's
    changed leaf pages are compared with rows on the new versions; a row that merely moved
    between pages (b-tree balancing) has the same rowid and values on both sides and cancels out.
    """
    roots = {x["name"]: x["rootpage"] for x in schema
             if x.get("type") == "table" and isinstance(x.get("rootpage"), int) and x["rootpage"] > 0}

    def owners(img):
        r = BTreeReader(img)
        own, inner = {}, set()
        for t, root in roots.items():
            lv, it = r.table_leaves(root, t)
            for p in lv:
                own[p] = t
            inner.update(it)
        return own, inner

    overlay: dict = {}
    img = base
    own, inner = owners(base)
    root_pages = set(roots.values())
    changes = []
    txn_frames: list = []
    for fr in frames:
        txn_frames.append(fr)
        if not fr.is_commit:
            continue
        changed = {}
        for f in txn_frames:
            changed[f.pgno] = f.data           # last version in the txn wins
        # capture the pre-transaction version of every touched page BEFORE updating the overlay
        old_pages = {}
        for p in changed:
            try:
                old_pages[p] = img.page(p)
            except FormatError:
                old_pages[p] = None        # page did not exist before this transaction
        overlay.update(changed)
        new_img = PageImage(main, h, overlay, fr.commit_size)
        # Page 1 (sqlite_master + header counters) changes often and never belongs to a user table.
        structural = any(p in inner or p in root_pages or (p not in own and p != 1) for p in changed)
        own_new, inner_new = owners(new_img) if structural else (own, inner)
        removed, added = defaultdict(dict), defaultdict(dict)
        new_rd = BTreeReader(new_img)
        # Pages that left (or joined) a table's b-tree without being rewritten - e.g. a leaf that a
        # rebalance put on the freelist - still held rows before this transaction: include them.
        moved = ({p for p in set(own) | set(own_new) if own.get(p) != own_new.get(p) and p not in changed}
                 if structural else set())
        for p in moved:
            try:
                old_pages[p] = img.page(p)     # unchanged by this txn, so current == old content
            except FormatError:
                old_pages[p] = None
        old_rd = BTreeReader(PageImage(main, h, {}, None).with_pages(
            {p: b for p, b in old_pages.items() if b is not None}))
        for p in list(changed) + sorted(moved):
            t_old, t_new = own.get(p), own_new.get(p)
            if t_old and old_pages.get(p) is not None:
                for r in _rows_from_cells(old_rd.leaf_cells(p, t_old), sigs_by_name.get(t_old)):
                    removed[t_old][r["_rowid"]] = _strip(r)
            if t_new:
                for r in _rows_from_cells(new_rd.leaf_cells(p, t_new), sigs_by_name.get(t_new)):
                    added[t_new][r["_rowid"]] = _strip(r)
        label = (f"WAL SLACK: txn {fr.txn} (frame {fr.index}, beyond WAL logical size)" if fr.in_slack
                 else f"WAL txn {fr.txn} (frame {fr.index})")
        for t in sorted(set(removed) | set(added)):
            ra, rb = removed[t], added[t]
            for rid in sorted(set(ra) | set(rb)):
                va, vb = ra.get(rid), rb.get(rid)
                if va == vb:
                    continue
                kind = "INSERT" if va is None else "DELETE" if vb is None else "UPDATE"
                changes.append(dict(step=label, table=t, rowid=rid, change=kind, before=va, after=vb,
                                    from_slack=fr.in_slack))
        errors += [f"{label}: {e}" for e in old_rd.errors + new_rd.errors]
        img, own, inner = new_img, own_new, inner_new     # shares `overlay`; safe, see capture above
        txn_frames = []
    return changes


def full_snapshot_history(main: bytes, h, base: PageImage, frames: list, sigs_by_name: dict) -> list:
    """Reference implementation (slow, O(txns x rows)) used by the tests as an oracle."""
    snaps = []
    _, t0 = _read_image(base, sigs_by_name)
    snaps.append((None, {k: {r["_rowid"]: _strip(r) for r in v} for k, v in t0.items()}))
    overlay = {}
    for fr in frames:
        overlay[fr.pgno] = fr.data
        if fr.is_commit:
            _, ts = _read_image(PageImage(main, h, dict(overlay), fr.commit_size), sigs_by_name)
            snaps.append((fr, {k: {r["_rowid"]: _strip(r) for r in v} for k, v in ts.items()}))
    out = []
    for (_, a), (fr, b) in zip(snaps, snaps[1:]):
        for t in sorted(set(a) | set(b)):
            ra, rb = a.get(t, {}), b.get(t, {})
            for rid in sorted(set(ra) | set(rb)):
                if ra.get(rid) != rb.get(rid):
                    out.append((fr.txn, t, rid, "INSERT" if rid not in ra else "DELETE" if rid not in rb else "UPDATE"))
    return out


# --------------------------------------------------------------------------- carving
def _pk_columns(sig) -> list[str]:
    import re as _re
    return []


def carve_db(A: DbAnalysis, slack_files: list[EvidenceFile], log) -> list[Carved]:
    carver = Carver(A.sigs)
    h = A.header
    ps, usable = h.page_size, h.page_size - h.reserved
    out: list[Carved] = []
    data = A.main.data

    def carve_page(pg, n, s, e, src, fname, base, fbs=None, kind=""):
        res = carver.carve(pg, s, e, src, fname, base, fbs)
        t = pg[100 if n == 1 else 0]
        if t in (2, 10):              # index b-tree page: records are (key..., rowid)
            for c in res:
                c.extra["index_entry"] = True
        elif t == 13 and kind == "freeblock" and not any(base + s <= c.offset < base + s + 10 for c in res):
            starts = {c.offset - base - j for c in res for j in range(2, 10)}
            res += repair_freeblock(carver, pg, s, e - s, starts, src, fname, base)
        return res

    for pm in A.page_map:
        n = pm["page"]
        pg = data[(n - 1) * ps: n * ps]
        if pm["nonzero_bytes"] == 0:
            continue
        role = pm["role"]
        live_btree = role.startswith(("table:", "index:"))
        if live_btree:
            regions = page_free_regions(pg, n, usable)
            fbs = {r[0] for r in regions if r[2] == "freeblock"}
            for s, e, kind in regions:
                out += carve_page(pg, n, s, e, f"main:page{n}:{kind}", A.main.name, (n - 1) * ps, fbs, kind)
        else:
            # freelist / orphan / beyond-EOF / overflow: the whole page is non-live space
            regions = page_free_regions(pg, n, usable) if pg[100 if n == 1 else 0] in BTREE_TYPES else []
            fbs = {r[0] for r in regions if r[2] == "freeblock"}
            tag = role.split(" (")[0].replace(" ", "-")
            out += carve_page(pg, n, 0, ps, f"main:page{n}:{tag}", A.main.name, (n - 1) * ps, fbs)
    tail = len(data) % ps
    if tail:
        out += carver.carve(data, len(data) - tail, len(data), "main:partial-page", A.main.name)

    if A.wal_info:
        wd = A.wal.data
        valid = A.wal_info.valid_frames
        for fr in A.wal_info.frames:
            base_off = fr.offset + 24
            pg = fr.data
            tagp = f"wal:frame{fr.index}(page{fr.pgno})"
            if fr.in_slack:
                tagp = tagp.replace("wal:", "wal-slack:")
            if fr.valid and not fr.in_slack:
                regions = page_free_regions(pg, fr.pgno, usable)
                fbs = {r[0] for r in regions if r[2] == "freeblock"}
                for s, e, kind in regions:
                    out += carve_page(pg, fr.pgno, s, e, f"{tagp}:{kind}", A.wal.name, base_off, fbs, kind)
                if any(f.pgno == fr.pgno and f.index > fr.index for f in valid):
                    out += carve_page(pg, fr.pgno, 0, ps, f"{tagp}:superseded", A.wal.name, base_off)
            elif fr.in_slack:
                state = "valid-continuation" if fr.valid else "unverified"
                out += carve_page(pg, fr.pgno, 0, ps, f"{tagp}:{state}", A.wal.name + ".FileSlack", base_off)
            else:
                out += carve_page(pg, fr.pgno, 0, ps, f"{tagp}:invalid-or-stale", A.wal.name, base_off)
        if A.wal_info.trailing_bytes:
            s = len(wd) - A.wal_info.trailing_bytes
            out += carver.carve(wd, s, len(wd), "wal:trailing-bytes", A.wal.name)

    for sf in slack_files:
        if A.wal_info and sf.name.lower().endswith("-wal.fileslack"):
            # already walked frame by frame above; carve only what lies past the last whole frame
            used = sum(24 + ps for f in A.wal_info.frames if f.in_slack)
            first_slack_off = A.wal_info.logical_len
            start = max(0, 32 + len(A.wal_info.frames) * (24 + ps) - first_slack_off)
            if start < len(sf.data):
                out += carver.carve(sf.data, start, len(sf.data), f"slack:{sf.name}", sf.name)
            continue
        out += carver.carve(sf.data, 0, len(sf.data), f"slack:{sf.name}", sf.name)

    out = dedupe(out)
    classify_carved(A, out)
    A.carved = out
    log(f"{A.name}: carved {len(out)} unique records "
        f"({sum(1 for c in out if c.status.startswith('DELETED'))} not in live data)")
    return out


def classify_carved(A: DbAnalysis, carved: list[Carved]):
    live = {}
    live_nk = defaultdict(set)              # table -> {non-key value tuples}
    sig_by = {s.table: s for s in A.sigs}
    for t, rows in A.tables.items():
        sig = sig_by.get(t)
        for r in rows:
            vals = tuple(r[c.name] for c in sig.columns) if sig else ()
            live[(t, r["_rowid"])] = vals
            if sig:
                live_nk[t].add(tuple(v for v, col in zip(vals, sig.columns) if not col.pk_alias))
    live_rows = {t: rows for t, rows in A.tables.items()}
    key_index: dict = {}                    # (table, n_key_cols) -> {key tuple: [rowids]}
    for c in carved:
        if c.extra.get("index_entry"):
            _classify_index_entry(c, sig_by, live_rows, key_index)
            continue
        tabs = c.table.split("|")
        full = None
        for t in tabs:
            sig = sig_by.get(t)
            if not sig:
                continue
            vals = list(c.values) + [col.default for col in sig.columns[len(c.values):]]
            if c.rowid is not None:
                vals[0] = c.rowid if sig.columns[0].pk_alias else vals[0]
            full = (t, tuple(vals), sig)
            if c.rowid is not None and (t, c.rowid) in live:
                lv = live[(t, c.rowid)]
                cmp = tuple(v for v, col in zip(vals, sig.columns) if not col.pk_alias)
                lcmp = tuple(v for v, col in zip(lv, sig.columns) if not col.pk_alias)
                if cmp == lcmp:
                    c.status = "LIVE-DUPLICATE"
                else:
                    c.status = "HISTORICAL-VERSION"
                    c.note = "same ID exists live with different values (row was updated)"
                break
            # compare by non-key values
            nk = tuple(v for v, col in zip(vals, sig.columns) if not col.pk_alias)
            if nk in live_nk[t]:
                if c.rowid is None:
                    c.status = "LIVE-DUPLICATE"
                else:
                    c.status = "DELETED (same values live under another ID)"
                    c.note = "row was deleted and the same values re-inserted with a new rowid"
                break
        if not c.status and full is not None:
            t, vals, sig = full
            nk = tuple(v for v, col in zip(vals, sig.columns) if not col.pk_alias)
            if (t, c.rowid, nk) in getattr(A, "slack_rows", set()):
                c.status = "RECOVERED (WAL slack txn)"
                c.note = "row only exists in a checksum-valid WAL frame found past the WAL's logical size"
        if not c.status:
            c.status = "DELETED" if c.rowid is not None else "DELETED (ID lost)"
        if full and not c.table.count("|"):
            c.extra["resolved_table"] = full[0]


def _classify_index_entry(c: Carved, sig_by: dict, live_rows: dict, key_index: dict | None = None):
    """An index record is (indexed columns..., rowid). Compare the key with live table rows."""
    keyvals = list(c.values[:-1])
    c.rowid = c.values[-1] if isinstance(c.values[-1], int) else None
    c.rowid_basis = "index-entry"
    for t in c.table.split("|"):
        sig = sig_by.get(t)
        if not sig:
            continue
        keycols = [col.name for col in sig.columns][:len(keyvals)]
        c.columns = keycols + ["(rowid)"]
        c.table = t
        ik = (t, len(keycols))
        if key_index is None:
            key_index = {}
        if ik not in key_index:
            idx = defaultdict(list)
            for r in live_rows.get(t, []):
                idx[tuple(r[k] for k in keycols)].append(r)
            key_index[ik] = idx
        hits = key_index[ik].get(tuple(keyvals), [])
        if not hits:
            c.status = "DELETED (index residue)"
            c.note = f"index entry for a {t} key that no longer exists live (old rowid {c.rowid})"
        elif any(r["_rowid"] == c.rowid for r in hits):
            c.status = "LIVE-DUPLICATE"
            c.note = "index entry of a live row"
        else:
            c.status = "INDEX-RESIDUE (row re-written)"
            c.note = (f"key is live under rowid {hits[0]['_rowid']}; this stale entry points to old rowid "
                      f"{c.rowid}, so the row was deleted and inserted again")
        return
    c.status = "UNCLASSIFIED (index residue)"
