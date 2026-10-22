"""Robustness: corrupted / truncated / empty / wrong inputs, CLI contract, determinism."""
import hashlib
import io
import os
import random
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

from camtool import cli
from camtool import engine as E
from camtool import model as M
from tests import fixtures as FX

FUZZ_ROUNDS = int(os.environ.get("CAMTOOL_FUZZ_ROUNDS", "150"))


def run_cli(args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            rc = cli.main(args)
        except SystemExit as ex:
            rc = ex.code
    return rc, out.getvalue(), err.getvalue()


def sha_dir(d):
    return {f: hashlib.sha256(open(os.path.join(d, f), "rb").read()).hexdigest()
            for f in sorted(os.listdir(d)) if os.path.isfile(os.path.join(d, f))}


class TestCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix="cam rob ü_")      # space + non-ASCII in path on purpose
        cls.ev = os.path.join(cls.base, "evidence dir")
        cls.truth = FX.build(cls.ev)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base, ignore_errors=True)

    def test_full_run_outputs_and_integrity(self):
        before = sha_dir(self.ev)
        out = os.path.join(self.base, "out1")
        rc, so, se = run_cli([self.ev, "-o", out, "-q", "--tz", "+05:30"])
        self.assertEqual(rc, 0, se)
        self.assertEqual(before, sha_dir(self.ev))
        for f in ("CAM_report.html", "camtool_results.json", "camtool_results.sqlite", "run_log.txt", "MANIFEST.sha256",
                  os.path.join("csv", "technical", "usage.csv"), os.path.join("csv", "technical", "timeline.csv"),
                  "activity_timeline.csv", "findings.csv", "CAM_activity.xlsx", "CAM_technical_report.html"):
            self.assertTrue(os.path.isfile(os.path.join(out, f)), f)
        # manifest verifies
        for line in open(os.path.join(out, "MANIFEST.sha256"), encoding="utf-8"):
            h, name = line.strip().split(" *", 1)
            self.assertEqual(hashlib.sha256(open(os.path.join(out, name), "rb").read()).hexdigest(), h, name)
        # results DB is queryable
        con = sqlite3.connect(os.path.join(out, "camtool_results.sqlite"))
        n = con.execute("select count(*) from usage").fetchone()[0]
        con.close()
        self.assertEqual(n, len(self.truth["live_ids"]) + 1)   # + 1 NonPackaged row

    def test_deterministic(self):
        a, b = os.path.join(self.base, "d1"), os.path.join(self.base, "d2")
        run_cli([self.ev, "-o", a, "-q"])
        run_cli([self.ev, "-o", b, "-q"])
        for f in [os.path.join("csv", "technical", x) for x in ("usage.csv", "carved_all.csv", "wal_changes.csv",
                                                                 "timeline.csv", "findings.csv")] +                 ["activity_timeline.csv", "apps.csv", "services.csv", "permissions.csv", "programs.csv"]:
            self.assertEqual(open(os.path.join(a, f), "rb").read(), open(os.path.join(b, f), "rb").read(), f)

    def test_missing_folder(self):
        rc, _, se = run_cli([os.path.join(self.base, "nope"), "-q"])
        self.assertEqual(rc, 2)

    def test_folder_without_dbs(self):
        d = tempfile.mkdtemp(dir=self.base)
        open(os.path.join(d, "readme.txt"), "w").write("x")
        rc, _, se = run_cli([d, "-q", "-o", os.path.join(d, "o")])
        self.assertEqual(rc, 2)

    def test_single_file_argument(self):
        out = os.path.join(self.base, "single")
        rc, _, se = run_cli([os.path.join(self.ev, M.CAM_DB), "-o", out, "-q"])
        self.assertEqual(rc, 0, se)

    def test_bad_tz(self):
        rc, _, se = run_cli([self.ev, "--tz", "IST", "-q"])
        self.assertEqual(rc, 2)

    def test_output_inside_evidence_refused(self):
        rc, _, se = run_cli([self.ev, "-o", self.ev, "-q"])
        self.assertEqual(rc, 2)

    def test_only_consent_db(self):
        d = tempfile.mkdtemp(dir=self.base)
        shutil.copy(os.path.join(self.ev, M.CONSENT_DB), d)
        rc, _, se = run_cli([d, "-o", os.path.join(self.base, "oc"), "-q"])
        self.assertEqual(rc, 0, se)

    def test_db_without_wal_and_shm(self):
        d = tempfile.mkdtemp(dir=self.base)
        shutil.copy(os.path.join(self.ev, M.CAM_DB), d)
        rc, _, se = run_cli([d, "-o", os.path.join(self.base, "nowal"), "-q"])
        self.assertEqual(rc, 0, se)

    def test_reg_export_parsing(self):
        reg = os.path.join(self.base, "cs.reg")
        txt = ("Windows Registry Editor Version 5.00\r\n\r\n"
               "[HKEY_USERS\\" + FX.SID + "\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam]\r\n"
               "\"Value\"=\"Allow\"\r\n\r\n"
               "[HKEY_USERS\\" + FX.SID + "\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam\\Vendor.App01_abcdefghijklm]\r\n"
               "\"Value\"=\"Deny\"\r\n\"LastUsedTimeStart\"=hex(b):00,00,00,00,00,00,00,00\r\n\r\n"
               "[HKEY_USERS\\" + FX.SID + "\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam\\Vendor.App02_abcdefghijklm]\r\n"
               "\"Value\"=\"Prompt\"\r\n")
        open(reg, "w", encoding="utf-16").write(txt)
        out = os.path.join(self.base, "regout")
        rc, so, se = run_cli([self.ev, "-o", out, "--registry", reg])
        self.assertEqual(rc, 0, se)
        self.assertIn("Value matches 3/3", so)


class TestFuzz(unittest.TestCase):
    """Random corruption must never crash the engine (errors are reported, not raised)."""

    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix="camfuzz_")
        FX.build(cls.base)
        cls.orig = {f: open(os.path.join(cls.base, f), "rb").read() for f in os.listdir(cls.base)
                    if os.path.isfile(os.path.join(cls.base, f))}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base, ignore_errors=True)

    def _analyze(self, files: dict):
        d = tempfile.mkdtemp(dir=self.base)
        try:
            for n, b in files.items():
                open(os.path.join(d, n), "wb").write(b)
            ev = {k: E.load_evidence(v) for k, v in E.discover(d).items()}
            tmp = tempfile.mkdtemp(dir=d)
            for db in (M.CAM_DB, M.CONSENT_DB):
                if db not in ev:
                    continue
                try:
                    A = E.analyze_db(db, ev[db], ev.get(db + "-wal"), ev.get(db + "-shm"), tmp, lambda m: None)
                except Exception as ex:   # only clean, documented failures are allowed
                    self.assertIsInstance(ex, (E.FormatError,), f"{type(ex).__name__}: {ex}")
                    continue
                E.carve_db(A, [], lambda m: None)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_random_byte_flips(self):
        rnd = random.Random(int(os.environ.get("CAMTOOL_FUZZ_SEED", "1234")))
        for i in range(FUZZ_ROUNDS):
            files = dict(self.orig)
            target = rnd.choice([M.CAM_DB, M.CAM_DB + "-wal", M.CONSENT_DB])
            b = bytearray(files[target])
            for _ in range(rnd.randint(1, 40)):
                pos = rnd.randrange(100 if target.endswith(".db") else 32, len(b))
                b[pos] = rnd.getrandbits(8)
            files[target] = bytes(b)
            with self.subTest(round=i, target=target):
                self._analyze(files)

    def test_page_level_garbage(self):
        rnd = random.Random(99)
        for i in range(max(10, FUZZ_ROUNDS // 5)):
            files = dict(self.orig)
            b = bytearray(files[M.CAM_DB])
            pg = rnd.randrange(1, len(b) // 4096)
            b[pg * 4096:(pg + 1) * 4096] = bytes(rnd.getrandbits(8) for _ in range(4096))
            files[M.CAM_DB] = bytes(b)
            with self.subTest(round=i, page=pg + 1):
                self._analyze(files)

    def test_truncations(self):
        for target in (M.CAM_DB, M.CAM_DB + "-wal", M.CONSENT_DB):
            n = len(self.orig[target])
            for cut in sorted({0, 1, 50, 99, 100, 101, 4095, 4096, 4097, n // 2, n - 1}):
                files = dict(self.orig)
                files[target] = self.orig[target][:cut]
                with self.subTest(target=target, cut=cut):
                    self._analyze(files)

    def test_wrong_file_types(self):
        for payload in (b"", b"MZ" + os.urandom(5000), b"SQLite format 3\x00" + b"\xff" * 200, b"\x00" * 8192):
            files = dict(self.orig)
            files[M.CAM_DB] = payload
            with self.subTest(payload=payload[:8]):
                self._analyze(files)


class TestMergedFreeblocks(unittest.TestCase):
    """Two neighbouring rows deleted one after the other: SQLite writes a freeblock header into each cell
    and then merges them, so every cell in the merged block has lost its first 4 bytes."""

    def test_adjacent_deleted_rows_all_recovered(self):
        d = tempfile.mkdtemp(prefix="cammerge_")
        try:
            p = os.path.join(d, M.CAM_DB)
            con = sqlite3.connect(p, isolation_level=None)
            con.execute("PRAGMA secure_delete=OFF")
            for s in FX.CAM_SCHEMA:
                con.execute(s)
            for s in FX.CAM_ALTERS:
                con.execute(s)
            con.execute("INSERT INTO Capabilities VALUES(10,'contacts')")
            for i in range(1001, 1061):
                con.execute("INSERT INTO PackagedUsageHistory VALUES(?,?,?,0,10,25,1,0,2,10,0)",
                            (i, FX.FT0 + i * 10**9, FX.FT0 + i * 10**9))
            gone = [1020, 1021, 1022, 1040, 1041]
            want = {}
            for i in gone:                      # separate statements -> separate freeblock headers, then merged
                want[i] = con.execute("select LastUsedTimeStart from PackagedUsageHistory where ID=?", (i,)).fetchone()[0]
                con.execute("DELETE FROM PackagedUsageHistory WHERE ID=?", (i,))
            con.close()
            ev = E.load_evidence(p)
            A = E.analyze_db(M.CAM_DB, ev, None, None, d, lambda m: None)
            E.carve_db(A, [], lambda m: None)
            got = {c.values[1] for c in A.carved if c.table == "PackagedUsageHistory" and c.status.startswith("DELETED")}
            self.assertEqual(set(want.values()) - got, set(), f"not recovered: {sorted(set(want.values()) - got)}")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestHeaderRepairSmallIds(unittest.TestCase):
    """Rows with ID < 128 lose header-length AND first serial to the freeblock header."""

    def test_small_id_rows(self):
        d = tempfile.mkdtemp(prefix="camsmall_")
        try:
            p = os.path.join(d, M.CAM_DB)
            con = sqlite3.connect(p, isolation_level=None)
            con.execute("PRAGMA secure_delete=OFF")
            for s in FX.CAM_SCHEMA:
                con.execute(s)
            for s in FX.CAM_ALTERS:
                con.execute(s)
            con.execute("INSERT INTO Capabilities VALUES(2,'webcam')")
            for i in range(1, 60):
                con.execute("INSERT INTO PackagedUsageHistory VALUES(?,?,?,0,2,25,1,0,2,10,0)",
                            (i, FX.FT0 + i * 10**9, FX.FT0 + i * 10**9 + 5))
            gone = [10, 20, 30, 40]
            vals = {}
            for i in gone:
                vals[i] = con.execute("select LastUsedTimeStart from PackagedUsageHistory where ID=?", (i,)).fetchone()[0]
                con.execute("DELETE FROM PackagedUsageHistory WHERE ID=?", (i,))
            con.close()
            ev = E.load_evidence(p)
            A = E.analyze_db(M.CAM_DB, ev, None, None, d, lambda m: None)
            E.carve_db(A, [], lambda m: None)
            got = {c.values[1] for c in A.carved if c.table == "PackagedUsageHistory" and c.status.startswith("DELETED")}
            self.assertTrue(set(vals.values()) <= got, (vals, got))
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
