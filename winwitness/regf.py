"""Read-only offline Windows registry hive (regf) reader.

Enough of the format to walk keys and read values from NTUSER.DAT / SOFTWARE: nk/vk records,
lf/lh/li/ri subkey lists and db big data. Transaction logs (.LOG1/.LOG2) are not replayed,
so a dirty hive shows its last flushed state. Every offset is bounds-checked; damaged
structures are skipped, never raised past the public API (except RegfError for non-hives).
"""
from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone

HBIN_BASE = 0x1000
_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


class RegfError(Exception):
    pass


def _ft(v: int) -> str:
    if not v or v > 2650467743999999999:
        return ""
    return (_EPOCH + timedelta(microseconds=v // 10)).strftime("%Y-%m-%d %H:%M:%S")


class Hive:
    def __init__(self, data: bytes):
        if len(data) < 0x30 or data[:4] != b"regf":
            raise RegfError("not a registry hive (regf signature missing)")
        self.data = data
        self.root_off = struct.unpack_from("<I", data, 0x24)[0]

    # ------------------------------------------------------------------ cells
    def cell(self, off: int) -> bytes | None:
        """Data of the cell at hive-bin offset `off` (without its 4-byte size), or None."""
        if off in (0xFFFFFFFF, None):
            return None
        a = HBIN_BASE + off
        if a + 4 > len(self.data) or off < 0:
            return None
        size = abs(struct.unpack_from("<i", self.data, a)[0])
        if size < 8 or a + size > len(self.data):
            return None
        return self.data[a + 4:a + size]

    def root(self) -> "Key | None":
        return Key.at(self, self.root_off)

    def key(self, path: str) -> "Key | None":
        k = self.root()
        for part in [p for p in path.replace("/", "\\").split("\\") if p]:
            if k is None:
                return None
            k = k.subkey(part)
        return k


class Key:
    __slots__ = ("hive", "off", "raw")

    def __init__(self, hive: Hive, off: int, raw: bytes):
        self.hive, self.off, self.raw = hive, off, raw

    @classmethod
    def at(cls, hive: Hive, off: int) -> "Key | None":
        c = hive.cell(off)
        if c is None or len(c) < 0x4C or c[:2] != b"nk":
            return None
        return cls(hive, off, c)

    @property
    def flags(self) -> int:
        return struct.unpack_from("<H", self.raw, 2)[0]

    @property
    def name(self) -> str:
        n = struct.unpack_from("<H", self.raw, 0x48)[0]
        b = self.raw[0x4C:0x4C + n]
        return b.decode("latin-1") if self.flags & 0x20 else b.decode("utf-16le", "replace")

    @property
    def last_write(self) -> int:
        return struct.unpack_from("<Q", self.raw, 4)[0]

    @property
    def last_write_utc(self) -> str:
        return _ft(self.last_write)

    # ------------------------------------------------------------------ subkeys
    def _list_offsets(self, off: int, depth=0, seen=None) -> list[int]:
        seen = set() if seen is None else seen
        if depth > 4 or off in seen:
            return []
        seen.add(off)
        c = self.hive.cell(off)
        if c is None or len(c) < 4:
            return []
        sig, n = c[:2], struct.unpack_from("<H", c, 2)[0]
        out = []
        if sig in (b"lf", b"lh"):
            for i in range(n):
                p = 4 + 8 * i
                if p + 4 > len(c):
                    break
                out.append(struct.unpack_from("<I", c, p)[0])
        elif sig in (b"li", b"ri"):
            for i in range(n):
                p = 4 + 4 * i
                if p + 4 > len(c):
                    break
                o = struct.unpack_from("<I", c, p)[0]
                out += self._list_offsets(o, depth + 1, seen) if sig == b"ri" else [o]
        return out

    def subkeys(self) -> list["Key"]:
        if struct.unpack_from("<I", self.raw, 0x14)[0] == 0:
            return []
        out = []
        for o in self._list_offsets(struct.unpack_from("<I", self.raw, 0x1C)[0]):
            k = Key.at(self.hive, o)
            if k is not None:
                out.append(k)
        return out

    def subkey(self, name: str) -> "Key | None":
        low = name.lower()
        for k in self.subkeys():
            if k.name.lower() == low:
                return k
        return None

    # ------------------------------------------------------------------ values
    def values(self) -> dict:
        n = struct.unpack_from("<I", self.raw, 0x24)[0]
        lst = self.hive.cell(struct.unpack_from("<I", self.raw, 0x28)[0])
        out = {}
        if not n or lst is None:
            return out
        for i in range(min(n, len(lst) // 4)):
            vk = self.hive.cell(struct.unpack_from("<I", lst, 4 * i)[0])
            if vk is None or len(vk) < 0x14 or vk[:2] != b"vk":
                continue
            try:
                name, val = self._value(vk)
            except (struct.error, ValueError, IndexError):
                continue
            out[name] = val
        return out

    def _value(self, vk: bytes):
        nlen, size, doff, vtype, vflags = struct.unpack_from("<HIIIH", vk, 2)
        nb = vk[0x14:0x14 + nlen]
        name = (nb.decode("latin-1") if vflags & 1 else nb.decode("utf-16le", "replace")) if nlen else "(default)"
        if size & 0x80000000:
            data = struct.pack("<I", doff)[:size & 0x7FFFFFFF]
        else:
            c = self.hive.cell(doff)
            if c is None:
                return name, None
            if c[:2] == b"db" and size > 16344:
                cnt, lst_off = struct.unpack_from("<HI", c, 2)
                lst = self.hive.cell(lst_off) or b""
                data = b""
                for j in range(min(cnt, len(lst) // 4)):
                    seg = self.hive.cell(struct.unpack_from("<I", lst, 4 * j)[0]) or b""
                    data += seg[:16344]
                data = data[:size]
            else:
                data = c[:size]
        return name, _decode(vtype, data)


def _decode(t: int, d: bytes):
    if t in (1, 2):                       # REG_SZ / REG_EXPAND_SZ
        s = d.decode("utf-16le", "replace")
        return s.split("\x00", 1)[0]
    if t == 4 and len(d) >= 4:            # REG_DWORD
        return struct.unpack_from("<I", d)[0]
    if t == 5 and len(d) >= 4:            # REG_DWORD_BIG_ENDIAN
        return struct.unpack_from(">I", d)[0]
    if t == 11 and len(d) >= 8:           # REG_QWORD
        return struct.unpack_from("<Q", d)[0]
    if t == 7:                            # REG_MULTI_SZ
        return [x for x in d.decode("utf-16le", "replace").split("\x00") if x]
    return bytes(d)
