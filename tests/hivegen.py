"""Test utility: write a minimal, valid Windows registry hive (regf) from a dict.

build({"Path\\To\\Key": {"ValueName": value, ...}, ...}) -> bytes
  str -> REG_SZ, int -> REG_DWORD, ("qword", int) -> REG_QWORD, bytes -> REG_BINARY,
  list[str] -> REG_MULTI_SZ. Intermediate keys are created automatically.
Subkey lists use 'lf'; more than 500 children are split into an 'ri' of 'lf' lists.
Values larger than 16,344 bytes are stored as 'db' big data.
"""
import struct

FT = 134365667394199327


class _Node:
    def __init__(self, name):
        self.name = name
        self.children = {}
        self.values = {}


def _tree(spec):
    root = _Node("ROOT")
    for path, vals in spec.items():
        n = root
        for part in [p for p in path.split("\\") if p]:
            n = n.children.setdefault(part.lower(), _Node(part))
        n.values.update(vals or {})
    return root


class _Cells:
    def __init__(self):
        self.buf = bytearray(32)          # hbin header placeholder

    def alloc(self, data: bytes) -> int:
        off = len(self.buf)
        size = (len(data) + 4 + 7) & ~7
        self.buf += struct.pack("<i", -size) + data + b"\x00" * (size - 4 - len(data))
        return off


def _value_cell(c: _Cells, name, v):
    if isinstance(v, tuple) and v[0] == "qword":
        t, data = 11, struct.pack("<Q", v[1])
    elif isinstance(v, bool) or isinstance(v, int):
        t, data = 4, struct.pack("<I", v)
    elif isinstance(v, str):
        t, data = 1, (v + "\x00").encode("utf-16le")
    elif isinstance(v, list):
        t, data = 7, ("\x00".join(v) + "\x00\x00").encode("utf-16le")
    else:
        t, data = 3, bytes(v)
    if len(data) <= 4:
        size, off = len(data) | 0x80000000, struct.unpack("<I", data.ljust(4, b"\x00"))[0]
    elif len(data) > 16344:
        segs = [c.alloc(data[i:i + 16344]) for i in range(0, len(data), 16344)]
        lst = c.alloc(b"".join(struct.pack("<I", s) for s in segs))
        off = c.alloc(b"db" + struct.pack("<HI", len(segs), lst))
        size = len(data)
    else:
        off, size = c.alloc(data), len(data)
    nm = name.encode("ascii")
    return c.alloc(b"vk" + struct.pack("<HIIIHH", len(nm), size, off, t, 1, 0) + nm)


def _key_cell(c: _Cells, node: _Node, parent: int, is_root=False) -> int:
    vals = [_value_cell(c, n, v) for n, v in node.values.items()]
    vlist = c.alloc(b"".join(struct.pack("<I", o) for o in vals)) if vals else 0xFFFFFFFF
    kids = sorted(node.children.values(), key=lambda n: n.name.upper())
    # parent offsets of children are patched after the parent is written
    kid_offs = [_key_cell(c, k, 0) for k in kids]
    if not kid_offs:
        slist = 0xFFFFFFFF
    elif len(kid_offs) <= 500:
        slist = c.alloc(b"lf" + struct.pack("<H", len(kid_offs)) +
                        b"".join(struct.pack("<I", o) + k.name.encode()[:4].ljust(4, b"\x00")
                                 for o, k in zip(kid_offs, kids)))
    else:
        parts = []
        for i in range(0, len(kid_offs), 500):
            chunk = list(zip(kid_offs[i:i + 500], kids[i:i + 500]))
            parts.append(c.alloc(b"lf" + struct.pack("<H", len(chunk)) +
                                 b"".join(struct.pack("<I", o) + k.name.encode()[:4].ljust(4, b"\x00")
                                          for o, k in chunk)))
        slist = c.alloc(b"ri" + struct.pack("<H", len(parts)) + b"".join(struct.pack("<I", p) for p in parts))
    nm = node.name.encode("ascii")
    flags = 0x20 | (0x04 if is_root else 0)
    body = (b"nk" + struct.pack("<HQ" + "I" * 15 + "HH", flags, FT, 0, parent, len(kid_offs), 0, slist,
                                0xFFFFFFFF, len(vals), vlist, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 0, 0,
                                len(nm), 0) + nm)
    me = c.alloc(body)
    for o in kid_offs:                    # patch parent pointer (nk offset 0x10 -> cell +4 +0x10)
        struct.pack_into("<I", c.buf, o + 4 + 0x10, me)
    return me


def build(spec: dict) -> bytes:
    c = _Cells()
    root = _key_cell(c, _tree(spec), 0xFFFFFFFF, is_root=True)
    hb = c.buf
    hb_size = (len(hb) + 4095) & ~4095
    if hb_size > len(hb):                 # trailing free cell
        free = hb_size - len(hb)
        hb += struct.pack("<i", free) + b"\x00" * (free - 4)
    hb[0:32] = b"hbin" + struct.pack("<II", 0, hb_size) + b"\x00" * 20
    base = bytearray(4096)
    base[0:4] = b"regf"
    struct.pack_into("<IIQIIIIIII", base, 4, 1, 1, FT, 1, 5, 0, 1, root, hb_size, 1)
    chk = 0
    for (d,) in struct.iter_unpack("<I", bytes(base[:508])):
        chk ^= d
    struct.pack_into("<I", base, 508, chk)
    return bytes(base) + bytes(hb)
