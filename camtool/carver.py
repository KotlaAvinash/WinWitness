"""Schema-aware record carver.

Signatures are built from the evidence database's own CREATE TABLE statements, so the carver
follows whatever column layout that Windows build used (including rows written before an
ALTER TABLE ADD COLUMN, which are shorter than the current schema).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .sqlite_low import FormatError, parse_record, read_varint
from .model import TableSig, classify_lookup_string, LOOKUP_TABLES


@dataclass
class Carved:
    source: str            # e.g. "main:page18:beyond-eof", "wal:frame3:freeblock", "slack:<file>"
    file: str
    offset: int            # absolute offset of the record header in `file`
    table: str             # candidate table (may be 'A|B' for ambiguous lookups)
    db: str
    rowid: int | None
    rowid_basis: str       # 'cell-prefix' | 'freeblock-overwritten' | 'unknown'
    columns: list
    values: list
    record_len: int
    status: str = ""       # filled in by classification against live data
    note: str = ""
    extra: dict = field(default_factory=dict)

    def key(self):
        return (self.db, self.table.split("|")[0] if "|" not in self.table else self.table,
                self.rowid, tuple(self.values))


def _prefix_candidates(sig: TableSig) -> list[bytes]:
    """Byte prefixes (header-length byte [+ first serial]) a record of `sig` can start with."""
    pref = set()
    for n in range(sig.min_cols, sig.max_cols + 1):
        # each serial type varint is 1 byte when < 128; TEXT serials may need 2-3 bytes
        text_cols = sum(1 for c in sig.columns[:n] if c.affinity == "TEXT")
        for extra in range(0, 2 * text_cols + 1):
            hlen = 1 + n + extra
            if hlen < 128:
                first = sig.columns[0]
                if first.pk_alias:
                    pref.add(bytes([hlen, 0]))
                else:
                    pref.add(bytes([hlen]))
    return sorted(pref)


_ALL_SIGS: dict = {}


class Carver:
    def __init__(self, sigs: list[TableSig]):
        self.sigs = sigs
        for s in sigs:
            _ALL_SIGS.setdefault(s.db, [])
            if s not in _ALL_SIGS[s.db]:
                _ALL_SIGS[s.db].append(s)
        self.by_prefix: dict[bytes, list[TableSig]] = {}
        for s in sigs:
            for p in _prefix_candidates(s):
                self.by_prefix.setdefault(p, []).append(s)
        alts = sorted(self.by_prefix, key=len, reverse=True)
        self.rx = re.compile(b"(?=(" + b"|".join(re.escape(p) for p in alts) + b"))", re.S)

    def _recover_rowid(self, buf: bytes, p: int, rec_len: int, region_start: int):
        """Look backwards for [payload-len varint][rowid varint] ending exactly at p."""
        for L in range(2, 19):
            s = p - L
            if s < region_start:
                break
            try:
                plen, a = read_varint(buf, s)
                if plen != rec_len or s + a >= p:
                    continue
                rowid, b = read_varint(buf, s + a)
                if s + a + b == p:
                    return rowid, "cell-prefix"
            except IndexError:
                continue
        return None, "unknown"

    def carve(self, buf: bytes, start: int, end: int, source: str, file: str, base_offset: int = 0,
              freeblock_starts: set | None = None) -> list[Carved]:
        out = []
        region = buf[start:end]
        taken_until = -1
        for m in self.rx.finditer(region):
            p = m.start()
            if p < taken_until:
                continue
            prefix2 = region[p:p + 2]
            cands = self.by_prefix.get(prefix2, []) + self.by_prefix.get(region[p:p + 1], [])
            try:
                types, vals, rlen = parse_record(region, p)
            except (FormatError, IndexError):
                continue
            ok = [s for s in cands if s.check_types(types) and s.plausible(vals)]
            if not ok:
                continue
            sig = ok[0]
            if True:  # noqa: SIM108 - keeps the block structure readable
                cols = [c.name for c in sig.columns[:len(vals)]]
                names = sorted({s.table for s in ok})
                table = "|".join(names)
                if all(n in LOOKUP_TABLES for n in names) and len(vals) == 2 and isinstance(vals[1], str):
                    if len(vals[1]) < 2:
                        continue
                    table = classify_lookup_string(vals[1])
                elif sig.db.endswith("ConsentStorage.db") and len(names) > 1:
                    table = _classify_consent(names, cols, vals)
                rowid, basis = self._recover_rowid(region, p, rlen, 0)
                if rowid is None and freeblock_starts:
                    # A freeblock header (4 bytes) overwrites payload-length + rowid varints.
                    abs_p = start + p
                    for fb in freeblock_starts:
                        if 0 < abs_p - fb <= 4:
                            basis = "freeblock-overwritten"
                            break
                out.append(Carved(source, file, base_offset + start + p, table, sig.db, rowid, basis,
                                  cols, vals, rlen))
                taken_until = p + rlen
        return out


def _decode_body(buf, p, types):
    from .sqlite_low import serial_len, decode_value
    vals = []
    for st in types:
        ln = serial_len(st)
        if ln < 0 or p + ln > len(buf):
            return None, p
        vals.append(decode_value(st, buf[p:p + ln]))
        p += ln
    return vals, p


def repair_freeblock(carver: "Carver", pg: bytes, fb: int, size: int, ends: set, source: str, file: str,
                     base_offset: int) -> list:
    """Recover cells of a freeblock whose record headers were partly overwritten.

    SQLite writes (next-freeblock u16, size u16) over the first 4 bytes of a freed cell. Those 4
    bytes held [payload-len varint][rowid varint][record header ...]. When the two varints take
    k < 4 bytes, the first 4-k header bytes (header-length and maybe the first serial type) are
    lost. With the schema known they can be rebuilt: the unknown serial is constrained by the
    column's type and, for TEXT, its length is solved from where the record must end.

    Neighbouring cells deleted one after another each receive such a header before SQLite merges
    them into one freeblock, so the block is walked cell by cell: a reading is accepted only when
    the chain of readings ends exactly where the freeblock (or an intact carved record) ends.
    """
    import struct as _st
    end_lim = fb + size
    terminal = set(ends) | {end_lim - e for e in range(0, 4)}
    # old (merged) freeblock headers inside the block mark where earlier freed cells began
    inner = set()
    for q in range(fb + 4, end_lim - 4):
        nxt, sz = _st.unpack(">HH", pg[q:q + 4])
        if 4 <= sz <= end_lim - q and (nxt == 0 or q < nxt < len(pg)) and (q + sz in terminal or q + sz <= end_lim):
            inner.add(q)
    memo: dict = {}

    def chain(pos: int, depth: int = 0):
        if pos in memo:
            return memo[pos]
        memo[pos] = None
        if depth > 64 or end_lim - pos < 6:
            return None
        cands = _readings_at(carver, pg, pos, end_lim, terminal | inner)
        # exact fit to the block end beats an intact neighbour, which beats 1-3 spare bytes, which beats a chain
        rank = lambda e: 0 if e == end_lim else 1 if e in ends else 2 if e in terminal else 3  # noqa: E731
        cands.sort(key=lambda c: (rank(c[3][1]), -c[0]))
        for lost, sig, types, r, k in cands:
            e = r[1]
            if e in terminal:
                memo[pos] = [(pos, sig, r, types, k)]
                break
            rest = chain(e, depth + 1)
            if rest:
                memo[pos] = [(pos, sig, r, types, k)] + rest
                break
        return memo[pos]

    found = chain(fb) or []
    return [_mk(sig, r, types, pos, k, source, file, base_offset) for pos, sig, r, types, k in found]


def _readings_at(carver, pg, pos, end_lim, text_ends):
    """All schema-consistent readings of a cell whose first 4 bytes (at pos) were overwritten."""
    from .sqlite_low import read_varint, serial_len
    out = []
    for k in (3, 2):                     # bytes used by payload-len + rowid varints
        lost = 4 - k                     # header bytes destroyed
        for sig in carver.sigs:
            for n in range(sig.min_cols, sig.max_cols + 1):
                known_from = 1 if lost == 2 else 0
                p = pos + 4
                types_rest = []
                try:
                    for _ in range(n - known_from):
                        st, ln = read_varint(pg, p)
                        types_rest.append(st)
                        p += ln
                except IndexError:
                    continue
                body_start = p
                if lost == 2:
                    col0 = sig.columns[0]
                    heads = [0] if col0.pk_alias else [1, 2, 3, 4, 5, 6, 8, 9] if col0.affinity == "INTEGER" else None
                else:
                    heads = [None]
                if heads is None:            # TEXT first column: solve its length from a possible end
                    rest_len = sum(max(serial_len(t), 0) for t in types_rest)
                    for end in sorted(text_ends):
                        L = end - body_start - rest_len
                        if 1 <= L <= 57:
                            types = [2 * L + 13] + types_rest
                            r = _try(sig, pg, body_start, types, end_lim)
                            if r:
                                out.append((lost, sig, types, r, k))
                else:
                    for c0 in heads:
                        types = ([c0] if c0 is not None else []) + types_rest
                        if len(types) != n:
                            continue
                        r = _try(sig, pg, body_start, types, end_lim)
                        if r:
                            out.append((lost, sig, types, r, k))
    return out


def _try(sig, pg, body_start, types, end_lim):
    if not sig.check_types(types):
        return None
    vals, end = _decode_body(pg, body_start, types)
    if vals is None or end > end_lim or not sig.plausible(vals):
        return None
    return vals, end


def _mk(sig, r, types, fb, k, source, file, base_offset):
    vals, end = r
    cols = [c.name for c in sig.columns[:len(vals)]]
    table = sig.table
    if sig.table in LOOKUP_TABLES and isinstance(vals[-1], str):
        table = classify_lookup_string(vals[-1])
    elif sig.db.endswith("ConsentStorage.db"):
        lay = [c.affinity for c in sig.columns]
        same = sorted({s.table for s in _ALL_SIGS.get(sig.db, []) if [c.affinity for c in s.columns] == lay})
        if len(same) > 1:
            table = _classify_consent(same, cols, vals)
    c = Carved(source + ":header-repaired", file, base_offset + fb, table, sig.db, None, "freeblock-overwritten",
               cols, vals, end - fb)
    c.extra["repair"] = f"{4 - k} header byte(s) rebuilt from schema; payload-len+rowid took {k} bytes"
    return c


_SIDLIKE = re.compile(r"^(S-1-[\d-]+|system)$", re.I)


def _classify_consent(names: list[str], cols: list[str], vals: list) -> str:
    """Narrow consent-table candidates that share an identical record layout. [observed]"""
    first = vals[0] if vals else ""
    if "MigratedUsers" in names and isinstance(first, str):
        return "MigratedUsers" if _SIDLIKE.match(first) else "SystemGlobal"
    if len(vals) >= 3 and isinstance(vals[2], str):
        third = vals[2]
        if re.match(r"^[\w.\-]+_[a-z0-9]{13}$", third, re.I):
            return "App"
        return "|".join(n for n in names if "ConsentID" in n) or "|".join(names)
    return "|".join(names)


def dedupe(carved: list[Carved]) -> list[Carved]:
    """Collapse identical records found in several places; keep every location in extra['seen_at']."""
    seen: dict = {}
    for c in carved:
        k = (c.db, c.table, c.rowid, tuple(c.values))
        if k in seen:
            seen[k].extra.setdefault("seen_at", []).append(f"{c.source}@{c.offset}")
        else:
            c.extra.setdefault("seen_at", [f"{c.source}@{c.offset}"])
            seen[k] = c
    # A record with unknown rowid that equals a record with a known rowid is the same record.
    known = {(c.db, c.table, tuple(c.values)): c for c in seen.values() if c.rowid is not None}
    out = []
    for c in seen.values():
        if c.rowid is None and (c.db, c.table, tuple(c.values)) in known:
            known[(c.db, c.table, tuple(c.values))].extra["seen_at"] += c.extra["seen_at"]
            continue
        out.append(c)
    return out
