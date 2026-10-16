"""Minimal NTFS $I30 (INDX) parser: live entries + entries recovered from index slack.

$FILE_NAME timestamps/sizes inside an index entry are a copy taken when the entry was last
updated (create/rename/move, sometimes on size change), so they are usually OLDER than the file's
$STANDARD_INFORMATION values. Treat them as 'at least this old', not as current values.
"""
from __future__ import annotations

import struct

from .model import ft_str

NAMESPACES = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32&DOS"}


def apply_fixups(rec: bytearray, sector: int = 512) -> list[str]:
    errs = []
    usa_off, usa_cnt = struct.unpack("<HH", rec[4:8])
    if usa_cnt < 2 or usa_off + 2 * usa_cnt > len(rec):
        return ["bad update sequence array"]
    usn = rec[usa_off:usa_off + 2]
    for i in range(1, usa_cnt):
        end = i * sector
        if end > len(rec):
            break
        if rec[end - 2:end] != usn:
            errs.append(f"fixup mismatch in sector {i} (torn write or not an INDX record)")
        rec[end - 2:end] = rec[usa_off + 2 * i: usa_off + 2 * i + 2]
    return errs


def _parse_fn(b: bytes, o: int):
    """Parse a $FILE_NAME attribute body at offset o. Returns dict or None."""
    if o + 66 > len(b):
        return None
    parent = struct.unpack("<Q", b[o:o + 8])[0]
    cr, mo, mft, ac, alloc, real, flags, _rep = struct.unpack("<QQQQQQII", b[o + 8:o + 64])
    nlen, ns = b[o + 64], b[o + 65]
    if nlen == 0 or ns > 3 or o + 66 + 2 * nlen > len(b):
        return None
    try:
        name = b[o + 66:o + 66 + 2 * nlen].decode("utf-16le")
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 0x20 for c in name):
        return None
    times = (cr, mo, mft, ac)
    if not all(116444736000000000 <= t <= 159725088000000000 for t in times):
        return None
    if real > alloc and alloc:
        return None
    return dict(name=name, namespace=NAMESPACES.get(ns, ns), parent_ref=parent & 0xFFFFFFFFFFFF,
                parent_seq=parent >> 48, created=ft_str(cr), modified=ft_str(mo), mft_modified=ft_str(mft),
                accessed=ft_str(ac), alloc_size=alloc, real_size=real, flags=hex(flags),
                _raw_times=times)


def parse_i30(data: bytes, block: int = 4096) -> dict:
    out = dict(records=0, entries=[], errors=[])
    for base in range(0, len(data) - 0x18, block):
        rec = bytearray(data[base:base + block])
        if rec[:4] != b"INDX":
            continue
        out["records"] += 1
        out["errors"] += apply_fixups(rec)
        vcn = struct.unpack("<Q", rec[16:24])[0]
        ent_off, total, alloc = struct.unpack("<III", rec[0x18:0x24])
        start, end_used, end_alloc = 0x18 + ent_off, 0x18 + total, min(0x18 + alloc, len(rec))
        o = start
        live_spans = []
        while o + 16 <= end_used:
            mref, elen, slen, eflags = struct.unpack("<QHHI", rec[o:o + 16])
            if elen < 16 or o + elen > end_alloc:
                out["errors"].append(f"record {base}: bad entry length at {o}")
                break
            if eflags & 2:      # last entry
                break
            fn = _parse_fn(rec, o + 16) if slen >= 66 else None
            if fn:
                fn.update(state="live", mft_ref=mref & 0xFFFFFFFFFFFF, mft_seq=mref >> 48,
                          record_vcn=vcn, offset=base + o)
                out["entries"].append(fn)
            live_spans.append((o, o + elen))
            o += elen
        # slack: scan 8-byte aligned positions after the end of the used area for $FILE_NAME bodies
        seen = {(e["name"], e["_raw_times"]) for e in out["entries"]}
        p = (end_used + 7) & ~7
        while p + 16 + 66 <= end_alloc:
            fn = _parse_fn(rec, p + 16)
            if fn and (fn["name"], fn["_raw_times"]) not in seen:
                mref = struct.unpack("<Q", rec[p:p + 8])[0]
                fn.update(state="slack (deleted/old entry)", mft_ref=mref & 0xFFFFFFFFFFFF,
                          mft_seq=mref >> 48, record_vcn=vcn, offset=base + p)
                out["entries"].append(fn)
                seen.add((fn["name"], fn["_raw_times"]))
            p += 8
    for e in out["entries"]:
        e.pop("_raw_times", None)
    return out
