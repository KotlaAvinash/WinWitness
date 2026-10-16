"""Independent, read-only SQLite file-format reader.

Implements just enough of the SQLite on-disk format (https://www.sqlite.org/fileformat.html)
to: walk table b-trees without the sqlite3 library, rebuild the database at every WAL
commit point, classify every page, and carve deleted records out of free space.

Nothing here ever writes to an input file. All inputs are read once into memory.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

SQLITE_MAGIC = b"SQLite format 3\x00"
WAL_MAGIC_LE = 0x377F0682
WAL_MAGIC_BE = 0x377F0683

LEAF_TABLE, INTERIOR_TABLE, LEAF_INDEX, INTERIOR_INDEX = 13, 5, 10, 2
BTREE_TYPES = (LEAF_TABLE, INTERIOR_TABLE, LEAF_INDEX, INTERIOR_INDEX)


class FormatError(Exception):
    pass


# --------------------------------------------------------------------------- varints / records
def read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    """Return (value, length). Raises IndexError if buf ends mid-varint."""
    v = 0
    for i in range(8):
        b = buf[pos + i]
        v = (v << 7) | (b & 0x7F)
        if b < 0x80:
            return v, i + 1
    return (v << 8) | buf[pos + 8], 9


def serial_len(st: int) -> int:
    if st < 12:
        return (0, 1, 2, 3, 4, 6, 8, 8, 0, 0, -1, -1)[st]
    return (st - 12) // 2 if st % 2 == 0 else (st - 13) // 2


def decode_value(st: int, raw: bytes):
    if st == 0:
        return None
    if 1 <= st <= 6:
        return int.from_bytes(raw, "big", signed=True)
    if st == 7:
        return struct.unpack(">d", raw)[0]
    if st == 8:
        return 0
    if st == 9:
        return 1
    if st >= 12 and st % 2 == 0:
        return bytes(raw)
    if st >= 13:
        return raw.decode("utf-8", errors="replace")
    raise FormatError(f"reserved serial type {st}")


def parse_record(payload: bytes, pos: int = 0, limit: int | None = None):
    """Parse a record starting at payload[pos]. Returns (serial_types, values, total_len)."""
    end = len(payload) if limit is None else limit
    hlen, n = read_varint(payload, pos)
    if hlen < 1 or pos + hlen > end:
        raise FormatError("bad header length")
    p = pos + n
    types = []
    while p < pos + hlen:
        st, n = read_varint(payload, p)
        if st in (10, 11):
            raise FormatError("reserved serial type")
        types.append(st)
        p += n
    if p != pos + hlen:
        raise FormatError("header overrun")
    vals = []
    for st in types:
        ln = serial_len(st)
        if p + ln > end:
            raise FormatError("body overrun")
        vals.append(decode_value(st, payload[p:p + ln]))
        p += ln
    return types, vals, p - pos


# --------------------------------------------------------------------------- database header
@dataclass
class DbHeader:
    page_size: int
    write_version: int
    read_version: int
    reserved: int
    change_counter: int
    page_count: int
    freelist_trunk: int
    freelist_count: int
    schema_cookie: int
    schema_format: int
    text_encoding: int
    user_version: int
    auto_vacuum_root: int
    incremental_vacuum: int
    application_id: int
    version_valid_for: int
    sqlite_version: int

    @property
    def sqlite_version_str(self) -> str:
        v = self.sqlite_version
        return f"{v // 1000000}.{(v // 1000) % 1000}.{v % 1000}"

    @property
    def header_page_count_valid(self) -> bool:
        # The in-header page count is only trusted when version-valid-for == change counter.
        return self.page_count > 0 and self.version_valid_for == self.change_counter


def parse_db_header(b: bytes) -> DbHeader:
    if len(b) < 100 or b[:16] != SQLITE_MAGIC:
        raise FormatError("not an SQLite 3 database (magic mismatch)")
    ps = struct.unpack(">H", b[16:18])[0]
    ps = 65536 if ps == 1 else ps
    if ps < 512 or ps & (ps - 1):
        raise FormatError(f"invalid page size {ps}")
    u = lambda o: struct.unpack(">I", b[o:o + 4])[0]
    return DbHeader(ps, b[18], b[19], b[20], u(24), u(28), u(32), u(36), u(40), u(44), u(56), u(60),
                    u(52), u(64), u(68), u(92), u(96))


# --------------------------------------------------------------------------- WAL
@dataclass
class WalFrame:
    index: int
    offset: int
    pgno: int
    commit_size: int
    salt1: int
    salt2: int
    cksum1: int
    cksum2: int
    data: bytes
    salt_ok: bool = False
    cksum_ok: bool = False
    valid: bool = False          # part of the committed, checksum-valid prefix
    is_commit: bool = False
    txn: int = -1                # transaction number among valid commits (0-based)
    in_slack: bool = False       # frame lies beyond the WAL file's logical size (read from file slack)


@dataclass
class WalInfo:
    magic: int
    version: int
    page_size: int
    checkpoint_seq: int
    salt1: int
    salt2: int
    cksum1: int
    cksum2: int
    header_cksum_ok: bool
    frames: list = field(default_factory=list)
    trailing_bytes: int = 0
    last_valid_frame: int = -1   # index of last frame in a committed valid txn

    logical_len: int = 0

    @property
    def valid_frames(self):
        """Committed, checksum-valid frames inside the WAL's logical size (what SQLite would use)."""
        return [f for f in self.frames if f.valid and not f.in_slack]

    @property
    def slack_frames(self):
        return [f for f in self.frames if f.in_slack]


def _wal_cksum(data: bytes, s1: int, s2: int, big: bool) -> tuple[int, int]:
    fmt = (">" if big else "<") + f"{len(data) // 4}I"
    words = struct.unpack(fmt, data)
    for i in range(0, len(words), 2):
        s1 = (s1 + words[i] + s2) & 0xFFFFFFFF
        s2 = (s2 + words[i + 1] + s1) & 0xFFFFFFFF
    return s1, s2


def parse_wal(b: bytes, logical_len: int | None = None) -> WalInfo | None:
    """Parse a WAL. If `b` is WAL + its file slack, pass the WAL's logical length so frames
    beyond it are flagged in_slack (their checksum chain is still verified)."""
    logical_len = len(b) if logical_len is None else logical_len
    if len(b) < 32:
        return None
    magic, ver, ps, ck, s1, s2, c1, c2 = struct.unpack(">8I", b[:32])
    if magic not in (WAL_MAGIC_LE, WAL_MAGIC_BE):
        raise FormatError("WAL magic mismatch")
    if ps < 512 or ps > 65536 or ps & (ps - 1):
        raise FormatError(f"WAL invalid page size {ps}")
    big = magic == WAL_MAGIC_BE
    h1, h2 = _wal_cksum(b[:24], 0, 0, big)
    info = WalInfo(magic, ver, ps, ck, s1, s2, c1, c2, (h1, h2) == (c1, c2))
    run1, run2 = h1, h2
    chain_ok = info.header_cksum_ok
    off, idx = 32, 0
    pending = []
    txn = 0
    fsz = 24 + ps
    while off + fsz <= len(b):
        pg, commit, fs1, fs2, fc1, fc2 = struct.unpack(">6I", b[off:off + 24])
        data = b[off + 24:off + fsz]
        fr = WalFrame(idx, off, pg, commit, fs1, fs2, fc1, fc2, data)
        fr.in_slack = off + fsz > logical_len
        fr.salt_ok = (fs1, fs2) == (s1, s2)
        if chain_ok and fr.salt_ok and pg > 0:
            r1, r2 = _wal_cksum(b[off:off + 8], run1, run2, big)
            r1, r2 = _wal_cksum(data, r1, r2, big)
            fr.cksum_ok = (r1, r2) == (fc1, fc2)
            if fr.cksum_ok:
                run1, run2 = r1, r2
                pending.append(fr)
                if commit:
                    fr.is_commit = True
                    for p in pending:
                        p.valid = True
                        p.txn = txn
                    info.last_valid_frame = idx
                    txn += 1
                    pending = []
            else:
                chain_ok = False
        else:
            chain_ok = False
        info.frames.append(fr)
        off += fsz
        idx += 1
    info.trailing_bytes = max(0, logical_len - off)
    info.logical_len = logical_len
    return info


# --------------------------------------------------------------------------- SHM (wal-index)
def parse_shm(b: bytes) -> dict | None:
    if len(b) < 136:
        return None

    def hdr(o):
        (ver, _u, chg, init, bigend, szp, mx, npage, fc1, fc2, s1, s2, c1, c2) = struct.unpack(
            "<IIIBBHII2I2I2I", b[o:o + 48])
        return dict(iVersion=ver, iChange=chg, isInit=init, bigEndCksum=bigend,
                    szPage=65536 if szp == 1 else szp, mxFrame=mx, nPage=npage,
                    aSalt=(s1, s2), aCksum=(c1, c2))

    h1, h2 = hdr(0), hdr(48)
    nbackfill = struct.unpack("<I", b[96:100])[0]
    readmarks = list(struct.unpack("<5I", b[100:120]))
    nbf_attempted = struct.unpack("<I", b[128:132])[0]
    return dict(header=h1, header_copies_match=b[0:48] == b[48:96], nBackfill=nbackfill,
                aReadMark=readmarks, nBackfillAttempted=nbf_attempted, size=len(b))


# --------------------------------------------------------------------------- page images
class PageImage:
    """A database as a set of page images: main file pages overlaid with chosen WAL frames."""

    def __init__(self, main: bytes, header: DbHeader, overlay: dict[int, bytes] | None = None,
                 db_pages: int | None = None):
        self.main = main
        self.h = header
        self.ps = header.page_size
        self.usable = self.ps - header.reserved
        self.overlay = overlay or {}
        self.file_pages = len(main) // self.ps
        if db_pages is None:
            db_pages = header.page_count if header.header_page_count_valid else self.file_pages
        self.db_pages = db_pages

    def with_pages(self, extra: dict) -> "PageImage":
        """Cheap view with a few pages replaced (no copy of the existing overlay)."""
        from collections import ChainMap
        v = PageImage.__new__(PageImage)
        v.__dict__.update(self.__dict__)
        v.overlay = ChainMap(extra, self.overlay)
        return v

    def page(self, n: int) -> bytes:
        if n in self.overlay:
            return self.overlay[n]
        if n < 1 or n > self.file_pages:
            raise FormatError(f"page {n} out of range")
        return self.main[(n - 1) * self.ps: n * self.ps]

    def header_page1(self) -> bytes:
        return self.page(1)


@dataclass
class Cell:
    page: int
    offset: int
    rowid: int
    types: list
    values: list
    overflow: bool = False
    truncated: bool = False


class BTreeReader:
    """Walks table b-trees on a PageImage."""

    def __init__(self, img: PageImage):
        self.img = img
        self.page_role: dict[int, str] = {}
        self.errors: list[str] = []

    def _page_hdr(self, n: int):
        pg = self.img.page(n)
        off = 100 if n == 1 else 0
        t = pg[off]
        if t not in BTREE_TYPES:
            raise FormatError(f"page {n}: not a b-tree page (type {t})")
        first_fb, ncells, content = struct.unpack(">HHH", pg[off + 1:off + 7])
        content = 65536 if content == 0 else content
        right = struct.unpack(">I", pg[off + 8:off + 12])[0] if t in (INTERIOR_TABLE, INTERIOR_INDEX) else None
        hsz = 12 if right is not None else 8
        ptrs = [struct.unpack(">H", pg[off + hsz + 2 * i: off + hsz + 2 * i + 2])[0] for i in range(ncells)]
        return pg, off, t, first_fb, ncells, content, right, hsz, ptrs

    def _payload(self, pg: bytes, p: int, plen: int) -> tuple[bytes, bool, bool]:
        U = self.img.usable
        X = U - 35
        if plen <= X:
            return pg[p:p + plen], False, False
        M = ((U - 12) * 32 // 255) - 23
        K = M + ((plen - M) % (U - 4))
        local = K if K <= X else M
        data = bytearray(pg[p:p + local])
        nxt = struct.unpack(">I", pg[p + local:p + local + 4])[0]
        seen = set()
        while nxt and len(data) < plen:
            if nxt in seen:
                self.errors.append(f"overflow loop at page {nxt}")
                return bytes(data), True, True
            seen.add(nxt)
            self.page_role[nxt] = "overflow"
            try:
                op = self.img.page(nxt)
            except FormatError:
                self.errors.append(f"overflow page {nxt} out of range")
                return bytes(data), True, True
            nxt = struct.unpack(">I", op[:4])[0]
            data += op[4:U][:plen - len(data)]
        return bytes(data), True, len(data) < plen

    def walk_table(self, root: int, label: str, _depth: int = 0, _seen=None):
        """Yield Cell objects for every row of the table rooted at `root`."""
        if _seen is None:
            _seen = set()
        if root in _seen or _depth > 40:
            self.errors.append(f"{label}: cycle/depth at page {root}")
            return
        _seen.add(root)
        try:
            pg, off, t, fb, n, content, right, hsz, ptrs = self._page_hdr(root)
        except (FormatError, struct.error, IndexError) as e:
            self.errors.append(f"{label}: {e}")
            return
        self.page_role[root] = f"table:{label}"
        if t == INTERIOR_TABLE:
            for p in ptrs:
                if p + 4 > len(pg):
                    self.errors.append(f"{label}: page {root} cell pointer {p} outside page")
                    continue
                child = struct.unpack(">I", pg[p:p + 4])[0]
                yield from self.walk_table(child, label, _depth + 1, _seen)
            yield from self.walk_table(right, label, _depth + 1, _seen)
        elif t == LEAF_TABLE:
            for p in ptrs:
                try:
                    plen, a = read_varint(pg, p)
                    rowid, b2 = read_varint(pg, p + a)
                    payload, ovf, trunc = self._payload(pg, p + a + b2, plen)
                    types, vals, _ = parse_record(payload)
                    yield Cell(root, p, rowid, types, vals, ovf, trunc)
                except (FormatError, IndexError, struct.error) as e:
                    self.errors.append(f"{label}: page {root} cell@{p}: {e}")
        elif t in (LEAF_INDEX, INTERIOR_INDEX):
            # Index b-tree reached from a table root: should not happen.
            self.errors.append(f"{label}: page {root} is an index page")

    def table_leaves(self, root: int, label: str) -> tuple[list[int], list[int]]:
        """(leaf pages, interior pages) of a table b-tree, reading interior pages only."""
        leaves, interior, stack, seen = [], [], [root], set()
        while stack:
            n = stack.pop()
            if n in seen:
                self.errors.append(f"{label}: cycle at page {n}")
                continue
            seen.add(n)
            try:
                pg, off, t, fb, nc, content, right, hsz, ptrs = self._page_hdr(n)
            except (FormatError, struct.error, IndexError) as e:
                self.errors.append(f"{label}: {e}")
                continue
            if t == LEAF_TABLE:
                leaves.append(n)
            elif t == INTERIOR_TABLE:
                interior.append(n)
                kids = [struct.unpack(">I", pg[p:p + 4])[0] for p in ptrs if p + 4 <= len(pg)] + [right]
                # children that are leaves need only their type byte, not a full header parse
                for k in reversed(kids):
                    if k in seen:
                        continue
                    try:
                        kt = self.img.page(k)[100 if k == 1 else 0]
                    except (FormatError, IndexError):
                        self.errors.append(f"{label}: child page {k} unreadable")
                        continue
                    if kt == LEAF_TABLE:
                        seen.add(k)
                        leaves.append(k)
                    else:
                        stack.append(k)
        return leaves, interior

    def leaf_cells(self, n: int, label: str) -> list:
        """Cells of one leaf page only (no descent)."""
        try:
            if self._page_hdr(n)[2] != LEAF_TABLE:
                return []
        except (FormatError, struct.error, IndexError):
            return []
        return list(self.walk_table(n, label))

    def walk_index_pages(self, root: int, label: str, _seen=None):
        """Mark pages of an index b-tree (contents not needed)."""
        if _seen is None:
            _seen = set()
        if root in _seen:
            return
        _seen.add(root)
        try:
            pg, off, t, fb, n, content, right, hsz, ptrs = self._page_hdr(root)
        except (FormatError, struct.error, IndexError) as e:
            self.errors.append(f"{label}: {e}")
            return
        self.page_role[root] = f"index:{label}"
        if t == INTERIOR_INDEX:
            for p in ptrs:
                if p + 4 <= len(pg):
                    self.walk_index_pages(struct.unpack(">I", pg[p:p + 4])[0], label, _seen)
            self.walk_index_pages(right, label, _seen)

    def schema(self) -> list[dict]:
        out = []
        for c in self.walk_table(1, "sqlite_master"):
            v = c.values + [None] * (5 - len(c.values))
            out.append(dict(type=v[0], name=v[1], tbl_name=v[2], rootpage=v[3], sql=v[4]))
        return out

    def freelist_pages(self) -> tuple[list[int], list[int]]:
        trunks, leaves = [], []
        img = self.img
        p1 = img.page(1)
        t = struct.unpack(">I", p1[32:36])[0]
        seen = set()
        while t and t not in seen and t <= img.file_pages:
            seen.add(t)
            trunks.append(t)
            pg = img.page(t)
            nxt, cnt = struct.unpack(">II", pg[:8])
            cnt = min(cnt, (img.usable - 8) // 4)
            leaves += list(struct.unpack(f">{cnt}I", pg[8:8 + 4 * cnt]))
            t = nxt
        for p in trunks:
            self.page_role[p] = "freelist-trunk"
        for p in leaves:
            self.page_role[p] = "freelist-leaf"
        return trunks, leaves

    def read_all(self) -> dict:
        """Return {schema, tables:{name:[Cell]}, roles, errors}."""
        sch = self.schema()
        tables = {}
        for s in sch:
            if not isinstance(s.get("rootpage"), int) or not isinstance(s.get("name"), str):
                self.errors.append(f"sqlite_master row damaged: {s!r:.120}")
                continue
            if s["type"] == "table" and s["rootpage"]:
                tables[s["name"]] = list(self.walk_table(s["rootpage"], s["name"]))
            elif s["type"] == "index" and s["rootpage"]:
                self.walk_index_pages(s["rootpage"], s["name"])
        self.freelist_pages()
        return dict(schema=sch, tables=tables, roles=dict(self.page_role), errors=list(self.errors))


def page_free_regions(pg: bytes, n: int, usable: int) -> list[tuple[int, int, str]]:
    """Return [(start, end, kind)] of unallocated space and freeblocks in a b-tree page."""
    off = 100 if n == 1 else 0
    t = pg[off]
    if t not in BTREE_TYPES:
        return []
    first_fb, ncells, content = struct.unpack(">HHH", pg[off + 1:off + 7])
    content = 65536 if content == 0 else content
    hsz = 12 if t in (INTERIOR_TABLE, INTERIOR_INDEX) else 8
    ptr_end = off + hsz + 2 * ncells
    regions = []
    if ptr_end < content <= usable:
        regions.append((ptr_end, content, "unallocated"))
    fb, seen = first_fb, set()
    while fb and fb not in seen and fb + 4 <= usable:
        seen.add(fb)
        nxt, size = struct.unpack(">HH", pg[fb:fb + 4])
        if size < 4 or fb + size > usable:
            break
        regions.append((fb, fb + size, "freeblock"))
        fb = nxt
    return regions
