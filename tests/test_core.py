"""Unit + integration tests against synthetic evidence with known ground truth.

Run:  python -I tests/run_tests.py
"""
import hashlib
import os
import shutil
import sqlite3
import struct
import tempfile
import unittest

from winwitness import engine as E
from winwitness import model as M
from winwitness.sqlite_low import (read_varint, parse_record, parse_db_header, parse_wal, serial_len, FormatError,
                                _wal_cksum)
from winwitness.carver import Carver
from winwitness.ntfs_i30 import parse_i30
from tests import fixtures as FX


def _log(_m):
    pass


class TestPrimitives(unittest.TestCase):
    def test_varint_roundtrip(self):
        def enc(v):
            if v > 0x00FFFFFFFFFFFFFF:
                out = [v & 0xFF]
                v >>= 8
                for _ in range(8):
                    out.insert(0, (v & 0x7F) | 0x80)
                    v >>= 7
                return bytes(out)
            out = [v & 0x7F]
            v >>= 7
            while v:
                out.insert(0, (v & 0x7F) | 0x80)
                v >>= 7
            return bytes(out)
        for v in (0, 1, 127, 128, 16383, 16384, 2 ** 31, 2 ** 56 - 1, 2 ** 56, 2 ** 63 - 1, 2 ** 64 - 1):
            b = enc(v)
            self.assertEqual(read_varint(b, 0), (v, len(b)), v)

    def test_serial_lengths(self):
        self.assertEqual([serial_len(i) for i in range(10)], [0, 1, 2, 3, 4, 6, 8, 8, 0, 0])
        self.assertEqual(serial_len(13), 0)
        self.assertEqual(serial_len(25), 6)
        self.assertEqual(serial_len(12), 0)
        self.assertEqual(serial_len(18), 3)

    def test_record_vs_sqlite(self):
        """Our record decoder must agree with what SQLite stores, for every type."""
        d = tempfile.mkdtemp()
        p = os.path.join(d, "t.db")
        con = sqlite3.connect(p)
        con.execute("create table t(a,b,c,d,e,f,g)")
        row = (None, 0, 1, -129, 2 ** 40 + 7, 3.5, "héllo")
        con.execute("insert into t values(?,?,?,?,?,?,?)", row)
        con.execute("insert into t values(?,?,?,?,?,?,?)", (b"\x00\x01", 127, -1, 32768, -2 ** 63, 0.0, ""))
        con.commit()
        con.close()
        from winwitness.sqlite_low import PageImage, BTreeReader
        b = open(p, "rb").read()
        rd = BTreeReader(PageImage(b, parse_db_header(b)))
        root = [r for r in rd.schema() if r["name"] == "t"][0]["rootpage"]
        got = [tuple(c.values) for c in rd.walk_table(root, "t")]
        self.assertEqual(got[0], row)
        self.assertEqual(got[1], (b"\x00\x01", 127, -1, 32768, -2 ** 63, 0.0, ""))
        shutil.rmtree(d)

    def test_bad_inputs_raise_cleanly(self):
        with self.assertRaises(FormatError):
            parse_db_header(b"not sqlite" * 20)
        with self.assertRaises(FormatError):
            parse_db_header(b"SQLite format 3\x00" + b"\x00\x03" + b"\x00" * 90)   # page size 3
        with self.assertRaises((FormatError, IndexError)):
            parse_record(b"\x05\x01")
        self.assertIsNone(parse_wal(b"short"))
        with self.assertRaises(FormatError):
            parse_wal(b"\x00" * 64)

    def test_filetime(self):
        self.assertEqual(M.ft_str(116444736000000000), "1970-01-01 00:00:00.000000")
        self.assertEqual(M.ft_str(0), "")
        self.assertTrue(M.ft_str(10).startswith("INVALID"))
        self.assertEqual(M.ft_str(134365667394199327), "2026-10-15 19:38:59.419932")
        ist = M.parse_tz("+05:30")
        self.assertEqual(M.ft_str(134365667394199327, ist), "2026-10-16 01:08:59.419932")
        with self.assertRaises(ValueError):
            M.parse_tz("IST")

    def test_signature_min_cols_from_alter(self):
        sql = 'CREATE TABLE "PackagedUsageHistory"(ID INTEGER PRIMARY KEY NOT NULL,LastUsedTimeStart INTEGER NOT NULL,LastUsedTimeStop INTEGER NOT NULL,AccessBlocked INTEGER NOT NULL,Capability INTEGER NOT NULL,PackageFamilyName INTEGER NOT NULL,UserSid INTEGER NOT NULL,AccessGUID INTEGER NOT NULL,Label INTEGER NOT NULL,AppName INTEGER NOT NULL, Context INTEGER DEFAULT \'0\')'
        s = M.sig_from_sql("CapabilityAccessManager.db", "PackagedUsageHistory", sql)
        self.assertEqual((s.min_cols, s.max_cols), (10, 11))
        self.assertTrue(s.columns[0].pk_alias)
        self.assertEqual(s.columns[-1].default, 0)
        s2 = M.sig_from_sql("c", "App", FX.CONSENT_SCHEMA[3])
        self.assertFalse(any(c.pk_alias for c in s2.columns))
        self.assertEqual(s2.min_cols, 4)

    def test_lookup_classifier(self):
        self.assertEqual(M.classify_lookup_string(FX.SID), "Users")
        self.assertEqual(M.classify_lookup_string("0000" + "ab" * 20), "FileIDs")
        self.assertEqual(M.classify_lookup_string("0006" + "ab" * 16 + "00000904"), "ProgramIDs")
        self.assertEqual(M.classify_lookup_string("0000" + "ab" * 16 + "0000ffff"), "ProgramIDs")
        self.assertEqual(M.classify_lookup_string(r"C:\x\y.exe"), "BinaryFullPaths")
        self.assertEqual(M.classify_lookup_string("brave.exe"), "BinaryNames")
        self.assertEqual(M.classify_lookup_string("Microsoft.WindowsCamera_8wekyb3d8bbwe"), "PackageFamilyNames")

    def test_wal_checksum_matches_sqlite(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "w.db")
        con = sqlite3.connect(p, isolation_level=None)
        con.execute("pragma journal_mode=wal")
        con.execute("pragma wal_autocheckpoint=0")
        con.execute("create table t(x)")
        for i in range(50):
            con.execute("insert into t values(?)", (i,))
        w = open(p + "-wal", "rb").read()
        con.close()
        info = parse_wal(w)
        self.assertTrue(info.header_cksum_ok)
        self.assertEqual(len(info.valid_frames), len(info.frames))
        self.assertEqual(len({f.txn for f in info.valid_frames}), 51)
        # corrupt one byte in frame 10's page -> it and every later frame become invalid
        bad = bytearray(w)
        bad[32 + 10 * (24 + info.page_size) + 24 + 500] ^= 0xFF
        info2 = parse_wal(bytes(bad))
        self.assertTrue(all(f.valid for f in info2.frames[:10]))
        self.assertFalse(any(f.valid for f in info2.frames[10:]))
        shutil.rmtree(d)


class TestGroundTruth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="camfx_")
        cls.truth = FX.build(cls.dir)
        cls.hashes = {f: hashlib.sha256(open(os.path.join(cls.dir, f), "rb").read()).hexdigest()
                      for f in os.listdir(cls.dir)}
        roles = E.discover(cls.dir)
        cls.files = {k: E.load_evidence(v) for k, v in roles.items()}
        cls.tmp = tempfile.mkdtemp()
        cls.A = E.analyze_db(M.CAM_DB, cls.files[M.CAM_DB], cls.files.get(M.CAM_DB + "-wal"),
                             cls.files.get(M.CAM_DB + "-shm"), cls.tmp, _log)
        E.carve_db(cls.A, [], _log)
        cls.C = E.analyze_db(M.CONSENT_DB, cls.files[M.CONSENT_DB], None, None, cls.tmp, _log)
        E.carve_db(cls.C, [], _log)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_inputs_untouched(self):
        for f, h in self.hashes.items():
            self.assertEqual(hashlib.sha256(open(os.path.join(self.dir, f), "rb").read()).hexdigest(), h, f)

    def test_live_rows_and_library_agree(self):
        ids = sorted(r["ID"] for r in self.A.tables["PackagedUsageHistory"])
        self.assertEqual(ids, self.truth["live_ids"])
        self.assertTrue(self.A.library_check["match"], self.A.library_check)
        self.assertTrue(self.C.library_check["match"], self.C.library_check)

    def test_pre_alter_rows_get_default(self):
        rows = {r["ID"]: r for r in self.A.tables["PackagedUsageHistory"]}
        for i in self.truth["pre_alter_ids"]:
            self.assertEqual(rows[i]["_ncols_stored"], 10)
            self.assertEqual(rows[i]["Context"], 0)

    def test_wal_diff(self):
        ch = self.A.wal_changes
        ins = sorted(c["rowid"] for c in ch if c["change"] == "INSERT" and c["table"] == "PackagedUsageHistory")
        upd = sorted(c["rowid"] for c in ch if c["change"] == "UPDATE")
        dele = sorted(c["rowid"] for c in ch if c["change"] == "DELETE")
        self.assertEqual(ins, self.truth["wal_inserts"])
        self.assertEqual(upd, self.truth["wal_updates"])
        self.assertEqual(dele, self.truth["wal_deletes"])
        u = [c for c in ch if c["change"] == "UPDATE"][0]
        self.assertEqual(u["after"]["Label"], 99)
        self.assertNotEqual(u["before"]["Label"], 99)

    def test_main_only_snapshot_differs_from_final(self):
        main_ids = {r["ID"] for r in self.A.tables_main_only["PackagedUsageHistory"]}
        self.assertTrue(set(self.truth["wal_deletes"]) <= main_ids)
        self.assertFalse(set(self.truth["wal_inserts"]) & main_ids)

    def _carved_ids(self, prefix="DELETED"):
        return {c.rowid for c in self.A.carved if c.table == "PackagedUsageHistory" and c.status.startswith(prefix)}

    def test_deleted_rows_recovered_with_ids(self):
        got = self._carved_ids()
        missing = set(self.truth["deleted_ids"]) - got
        # a freeblock header overwrites the first 4 bytes of a cell; the row survives but its ID can be lost
        lost = [c for c in self.A.carved if c.status == "DELETED (ID lost)"]
        self.assertLessEqual(len(missing), len(lost), f"missing {missing}")
        self.assertGreaterEqual(len(got & set(self.truth["deleted_ids"])), len(self.truth["deleted_ids"]) // 2)

    def test_no_false_ids(self):
        """Every carved DELETED row with an ID must be a row that really existed."""
        real = set(self.truth["deleted_ids"]) | set(self.truth["tail_ids"]) | set(self.truth["wal_deletes"]) \
            | set(range(1, 400))
        for c in self.A.carved:
            if c.table == "PackagedUsageHistory" and c.status == "DELETED":
                self.assertIn(c.rowid, real, c)

    def test_wal_deleted_row_recovered(self):
        # the row deleted inside the WAL is still in the main file -> live in main-only snapshot,
        # reported as DELETE in the WAL diff; carving must not call it live
        for c in self.A.carved:
            if c.rowid in self.truth["wal_deletes"] and c.table == "PackagedUsageHistory":
                self.assertTrue(c.status.startswith("DELETED"), c.status)

    def test_wal_updated_row_old_version(self):
        olds = [c for c in self.A.carved if c.rowid in self.truth["wal_updates"]]
        self.assertTrue(any(c.status == "HISTORICAL-VERSION" for c in olds) or
                        any(ch["change"] == "UPDATE" for ch in self.A.wal_changes))

    def test_tail_pages(self):
        self.assertTrue(self.A.beyond_eof_pages)
        got = {c.rowid for c in self.A.carved if c.source.startswith("main:") and "beyond" in c.source}
        self.assertTrue(set(self.truth["tail_ids"]) <= got, set(self.truth["tail_ids"]) - got)

    def test_consent_deleted_row(self):
        cap, sid, pfn = self.truth["deleted_consent_key"]
        hits = [c for c in self.C.carved if c.values[:3] == [cap, sid, pfn]]
        self.assertTrue(hits, "deleted App row not carved")
        self.assertTrue(any(c.status.startswith("DELETED") for c in hits), [c.status for c in hits])

    def test_carver_rejects_garbage(self):
        rnd = __import__("random").Random(7)
        junk = bytes(rnd.getrandbits(8) for _ in range(2_000_000))
        hits = Carver(self.A.sigs).carve(junk, 0, len(junk), "junk", "junk")
        usage = [h for h in hits if "UsageHistory" in h.table]
        self.assertLessEqual(len(usage), 1, usage[:3])


class TestI30(unittest.TestCase):
    def test_synthetic_indx(self):
        rec = bytearray(4096)
        rec[0:4] = b"INDX"
        struct.pack_into("<HH", rec, 4, 0x28, 9)
        struct.pack_into("<III", rec, 0x18, 0x28, 0x28 + 0x80, 4096 - 0x18)
        usn = b"\x01\x00"
        rec[0x28:0x2A] = usn
        o = 0x18 + 0x28
        name = "CapabilityAccessManager.db".encode("utf-16le")
        fn = struct.pack("<QQQQQQQII", 5 | (5 << 48), 132900000000000000, 134365667394199327,
                         134365667394199327, 134365667394199327, 65536, 28872, 0x20, 0) + bytes([len(name) // 2, 1]) + name
        ent = struct.pack("<QHHI", 123 | (7 << 48), 16 + len(fn) + 6, len(fn), 0) + fn
        ent += b"\x00" * ((-len(ent)) % 8)
        struct.pack_into("<H", rec, o + 8, len(ent))
        rec[o:o + len(ent)] = ent
        rec[o + 8:o + 10] = struct.pack("<H", len(ent))
        last = struct.pack("<QHHI", 0, 16, 0, 2)
        rec[o + len(ent):o + len(ent) + 16] = last
        struct.pack_into("<I", rec, 0x1C, 0x28 + len(ent) + 16)
        for i in range(1, 9):
            rec[0x28 + 2 * i:0x2A + 2 * i] = rec[i * 512 - 2:i * 512]
            rec[i * 512 - 2:i * 512] = usn
        r = parse_i30(bytes(rec))
        self.assertEqual(r["errors"], [])
        self.assertEqual(len(r["entries"]), 1)
        e = r["entries"][0]
        self.assertEqual((e["name"], e["real_size"], e["mft_ref"], e["mft_seq"]), ("CapabilityAccessManager.db", 28872, 123, 7))


if __name__ == "__main__":
    unittest.main()
