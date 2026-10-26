"""Oracle equivalence + stress / scale tests.

APP_ACCESS_HISTORY_STRESS=big enables the large run (~1M rows, ~20k WAL transactions, 64 MiB slack).
"""
import os
import random
import shutil
import sqlite3
import tempfile
import time
import unittest

from app_access_history import engine as E
from app_access_history import model as M
from app_access_history.sqlite_low import PageImage, parse_db_header, parse_wal
from tests import fixtures as FX

BIG = os.environ.get("APP_ACCESS_HISTORY_STRESS") == "big"


def make_wal_db(d, n_rows, n_txn, seed=3, big_rows=False):
    """DB in WAL mode; returns paths after `n_txn` random insert/update/delete transactions."""
    rnd = random.Random(seed)
    p = os.path.join(d, M.CAM_DB)
    con = sqlite3.connect(p, isolation_level=None)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=0")
    con.execute("PRAGMA secure_delete=OFF")
    for s in FX.CAM_SCHEMA:
        con.execute(s)
    for s in FX.CAM_ALTERS:
        con.execute(s)
    con.execute("INSERT INTO Capabilities VALUES(2,'webcam')")
    con.execute("BEGIN")
    for i in range(1, n_rows + 1):
        con.execute("INSERT INTO PackagedUsageHistory VALUES(?,?,?,0,2,25,1,0,2,10,0)",
                    (i, FX.FT0 + i * 10**7, FX.FT0 + i * 10**7 + 5))
    con.execute("COMMIT")
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    nxt = n_rows + 1
    for _ in range(n_txn):
        con.execute("BEGIN")
        for _ in range(rnd.randint(1, 40 if big_rows else 6)):
            op = rnd.random()
            if op < 0.5:
                con.execute("INSERT INTO PackagedUsageHistory VALUES(?,?,?,0,2,25,1,0,2,10,0)",
                            (nxt, FX.FT0 + nxt * 10**7, FX.FT0 + nxt * 10**7 + 5))
                nxt += 1
            elif op < 0.75:
                con.execute("UPDATE PackagedUsageHistory SET Label=? WHERE ID=?", (rnd.randint(0, 9), rnd.randint(1, nxt)))
            else:
                lo = rnd.randint(1, nxt)
                con.execute("DELETE FROM PackagedUsageHistory WHERE ID BETWEEN ? AND ?", (lo, lo + rnd.randint(0, 30)))
        con.execute("COMMIT")
    out = os.path.join(d, "ev")
    os.makedirs(out)
    for suf in ("", "-wal", "-shm"):
        shutil.copyfile(p + suf, os.path.join(out, M.CAM_DB + suf))
    con.close()
    return out


class TestOracle(unittest.TestCase):
    def test_incremental_equals_full_rebuild(self):
        for seed, rows, txns in ((3, 2000, 120), (4, 300, 400), (5, 20000, 60), (6, 50, 600), (7, 5000, 300), (8, 900, 250)):
            with self.subTest(seed=seed):
                d = tempfile.mkdtemp(prefix="camorc_")
                try:
                    ev = make_wal_db(d, rows, txns, seed, big_rows=True)
                    main = open(os.path.join(ev, M.CAM_DB), "rb").read()
                    wal = open(os.path.join(ev, M.CAM_DB + "-wal"), "rb").read()
                    h = parse_db_header(main)
                    w = parse_wal(wal)
                    base = PageImage(main, h)
                    from app_access_history.sqlite_low import BTreeReader
                    sch = BTreeReader(base).schema()
                    sigs = {s.table: s for s in (M.sig_from_sql(M.CAM_DB, x["name"], x["sql"]) for x in sch) if s}
                    errs = []
                    inc = E.wal_history(main, h, base, w.valid_frames, sch, sigs, errs)
                    inc_t = sorted((int(c["step"].split()[2]), c["table"], c["rowid"], c["change"]) for c in inc)
                    full = sorted(E.full_snapshot_history(main, h, base, w.valid_frames, sigs))
                    self.assertEqual(inc_t, full)
                    self.assertGreater(len(full), txns)
                    self.assertEqual(errs, [])
                finally:
                    shutil.rmtree(d, ignore_errors=True)


class TestStress(unittest.TestCase):
    def test_scale(self):
        rows, txns, slack_mb = (1_000_000, 20_000, 64) if BIG else (150_000, 3_000, 16)
        d = tempfile.mkdtemp(prefix="camstress_")
        try:
            t = time.time()
            ev = make_wal_db(d, rows, txns, seed=11)
            with open(os.path.join(ev, M.CAM_DB + ".FileSlack"), "wb") as f:
                f.write(os.urandom(slack_mb << 20))
            gen = time.time() - t
            sizes = {f: os.path.getsize(os.path.join(ev, f)) for f in os.listdir(ev)}
            out = os.path.join(d, "out")
            from tests.test_robustness import run_cli
            t = time.time()
            rc, so, se = run_cli([ev, "-o", out, "-q"])
            el = time.time() - t
            self.assertEqual(rc, 0, se)
            con = sqlite3.connect(os.path.join(out, "app_access_history_results.sqlite"))
            n_use = con.execute("select count(*) from usage").fetchone()[0]
            n_wal = con.execute("select count(*) from wal_changes").fetchone()[0]
            con.close()
            ref = sqlite3.connect(os.path.join(d, M.CAM_DB))     # the still-existing original (checkpointed)
            n_ref = ref.execute("select count(*) from PackagedUsageHistory").fetchone()[0]
            ref.close()
            self.assertEqual(n_use, n_ref)
            print(f"\n    stress: rows={rows:,} txns={txns:,} files={ {k: f'{v/2**20:.1f}MiB' for k, v in sizes.items()} } "
                  f"gen={gen:.1f}s analyse={el:.1f}s live_rows={n_use:,} wal_changes={n_wal:,}")
            self.assertLess(el, 1800)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
