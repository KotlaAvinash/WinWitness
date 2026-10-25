"""Build synthetic CAM evidence with KNOWN ground truth (schemas copied from a real 26200 build)."""
from __future__ import annotations

import os
import random
import shutil
import sqlite3

CAM_SCHEMA = [
    "CREATE TABLE NonPackagedIdentityRelationship(ID INTEGER PRIMARY KEY NOT NULL,BinaryFullPath INTEGER NOT NULL,FileID INTEGER NOT NULL,ProgramID INTEGER NOT NULL,LastObservedTime INTEGER NOT NULL)",
    "CREATE TABLE Capabilities(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT COLLATE NOCASE NOT NULL)",
    "CREATE TABLE PackageFamilyNames(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT COLLATE NOCASE NOT NULL)",
    "CREATE TABLE BinaryFullPaths(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT COLLATE NOCASE NOT NULL)",
    "CREATE TABLE Users(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT COLLATE NOCASE NOT NULL)",
    "CREATE TABLE FileIDs(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT COLLATE NOCASE NOT NULL)",
    "CREATE TABLE ProgramIDs(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT COLLATE NOCASE NOT NULL)",
    'CREATE TABLE "NonPackagedUsageHistory"(ID INTEGER PRIMARY KEY NOT NULL,LastUsedTimeStart INTEGER NOT NULL,LastUsedTimeStop INTEGER NOT NULL,AccessBlocked INTEGER NOT NULL,Capability INTEGER NOT NULL,FileID INTEGER NOT NULL,ProgramID INTEGER NOT NULL,BinaryFullPath INTEGER NOT NULL,UserSid INTEGER NOT NULL,AppName INTEGER NOT NULL,ServiceName INTEGER NOT NULL DEFAULT \'0\',AccessGUID INTEGER NOT NULL,Label INTEGER NOT NULL)',
    "CREATE TABLE NonPackagedGlobalPromptHistory(ID INTEGER PRIMARY KEY NOT NULL,ShownTime INTEGER NOT NULL,Capability INTEGER NOT NULL,FileID INTEGER NOT NULL,ProgramID INTEGER NOT NULL,UserSid INTEGER NOT NULL)",
    'CREATE TABLE "PackagedUsageHistory"(ID INTEGER PRIMARY KEY NOT NULL,LastUsedTimeStart INTEGER NOT NULL,LastUsedTimeStop INTEGER NOT NULL,AccessBlocked INTEGER NOT NULL,Capability INTEGER NOT NULL,PackageFamilyName INTEGER NOT NULL,UserSid INTEGER NOT NULL,AccessGUID INTEGER NOT NULL,Label INTEGER NOT NULL,AppName INTEGER NOT NULL)',
    "CREATE TABLE AccessGUIDs(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT COLLATE NOCASE NOT NULL)",
    "CREATE TABLE AppNames(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT COLLATE NOCASE NOT NULL)",
    "CREATE TABLE ServiceNames(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT COLLATE NOCASE NOT NULL)",
    "CREATE TABLE PackagedGlobalPromptHistory(ID INTEGER PRIMARY KEY NOT NULL,Capability INTEGER NOT NULL,UserSid INTEGER NOT NULL,PackageFamilyName INTEGER NOT NULL)",
    "CREATE TABLE BinaryNames(ID INTEGER PRIMARY KEY NOT NULL,StringValue TEXT COLLATE NOCASE NOT NULL)",
]
# Columns Windows added later with ALTER TABLE (rows written before have fewer columns)
CAM_ALTERS = [
    "ALTER TABLE NonPackagedUsageHistory ADD Context INTEGER DEFAULT '0'",
    "ALTER TABLE PackagedUsageHistory ADD Context INTEGER DEFAULT '0'",
    "ALTER TABLE NonPackagedGlobalPromptHistory ADD BinaryName INTEGER DEFAULT '0'",
]
CONSENT_SCHEMA = [
    "CREATE TABLE MigratedUsers(User TEXT COLLATE NOCASE NOT NULL,Value INTEGER NOT NULL,PRIMARY KEY(User))",
    "CREATE TABLE SystemGlobal(Capability TEXT COLLATE NOCASE NOT NULL,Value INTEGER NOT NULL,PRIMARY KEY(Capability))",
    "CREATE TABLE UserGlobal(Capability TEXT COLLATE NOCASE NOT NULL,User TEXT COLLATE NOCASE NOT NULL,Value INTEGER NOT NULL,PRIMARY KEY(Capability, User))",
    "CREATE TABLE App(Capability TEXT COLLATE NOCASE NOT NULL,User TEXT COLLATE NOCASE NOT NULL,PackageFamily TEXT COLLATE NOCASE NOT NULL,Value INTEGER NOT NULL,PRIMARY KEY(Capability, User, PackageFamily))",
    "CREATE TABLE UserGlobalWithConsentID(Capability TEXT COLLATE NOCASE NOT NULL,User TEXT COLLATE NOCASE NOT NULL,ConsentID TEXT COLLATE NOCASE NOT NULL,Value INTEGER NOT NULL,PRIMARY KEY(Capability, User, ConsentID))",
]

SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
FT0 = 134300000000000000      # 2026-08-xx
CAPS = {1: "location", 2: "webcam", 3: "microphone", 17: "graphicsCaptureWithoutBorder"}
PFNS = {25: "Microsoft.WindowsCamera_8wekyb3d8bbwe", 26: "Microsoft.ScreenSketch_8wekyb3d8bbwe"}
APPN = {10: "Camera", 18: "Snipping Tool"}


def _con(path):
    con = sqlite3.connect(path, isolation_level=None)
    con.execute("PRAGMA secure_delete=OFF")
    return con


def _lookups(con):
    for i, v in CAPS.items():
        con.execute("INSERT INTO Capabilities VALUES(?,?)", (i, v))
    for i, v in PFNS.items():
        con.execute("INSERT INTO PackageFamilyNames VALUES(?,?)", (i, v))
    for i, v in APPN.items():
        con.execute("INSERT INTO AppNames VALUES(?,?)", (i, v))
    con.execute("INSERT INTO Users VALUES(1,?)", (SID,))
    con.execute("INSERT INTO BinaryFullPaths VALUES(5,'C:\\Program Files\\App\\app.exe')")
    con.execute("INSERT INTO FileIDs VALUES(7,'0000' || ?)", ("a" * 40,))
    con.execute("INSERT INTO ProgramIDs VALUES(9,'0006' || ? || '00000904')", ("b" * 32,))


def usage_row(i, t, cap=2, pfn=25, app=10, label=2, dur=50_000_000, ctx=True):
    r = (i, t, t + dur, 0, cap, pfn, 1, 0, label, app)
    return r + (0,) if ctx else r


def build(dirpath: str, n_old=300, n_live=120, n_wal=6, wal_update=True, wal_delete=True,
          with_tail=True, seed=1) -> dict:
    """Create CapabilityAccessManager.db (+wal/shm) and CapabilityConsentStorage.db in dirpath.

    Ground truth returned:
      deleted_ids   rows deleted inside the main file (freeblocks)  -> must be carved WITH ID
      tail_ids      rows only present in pages past logical EOF     -> must be carved
      wal_inserts / wal_updates / wal_deletes                       -> must appear in WAL diff
      live_ids      final live PackagedUsageHistory IDs
    """
    rnd = random.Random(seed)
    os.makedirs(dirpath, exist_ok=True)
    truth = {}
    work = os.path.join(dirpath, "_work")
    os.makedirs(work, exist_ok=True)

    # ---- 1. "big" historic database: provides the tail beyond logical EOF
    big = os.path.join(work, "big.db")
    con = _con(big)
    for s in CAM_SCHEMA:
        con.execute(s)
    _lookups(con)
    con.execute("BEGIN")
    for i in range(1, n_old + 1):
        con.execute("INSERT INTO PackagedUsageHistory VALUES(?,?,?,?,?,?,?,?,?,?)",
                    usage_row(i, FT0 + i * 10_000_000_000, ctx=False))
    con.execute("COMMIT")
    for s in CAM_ALTERS:
        con.execute(s)
    con.close()
    big_bytes = open(big, "rb").read()

    # ---- 2. the current database
    p = os.path.join(work, "CapabilityAccessManager.db")
    con = _con(p)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=0")
    for s in CAM_SCHEMA:
        con.execute(s)
    _lookups(con)
    con.execute("BEGIN")
    base = n_old + 1000
    pre_alter = list(range(base, base + 10))
    for i in pre_alter:        # rows written before the ALTER (10 columns)
        con.execute("INSERT INTO PackagedUsageHistory VALUES(?,?,?,?,?,?,?,?,?,?)", usage_row(i, FT0 + i * 10_000_000_000, ctx=False))
    con.execute("COMMIT")
    for s in CAM_ALTERS:
        con.execute(s)
    con.execute("BEGIN")
    ids = list(range(base + 10, base + n_live))
    for i in ids:
        con.execute("INSERT INTO PackagedUsageHistory VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    usage_row(i, FT0 + i * 10_000_000_000, cap=rnd.choice([2, 3, 17]), label=rnd.choice([0, 2])))
    con.execute("INSERT INTO NonPackagedUsageHistory VALUES(1,?,?,0,1,7,9,5,1,0,0,0,2,0)", (FT0, FT0 + 1))
    con.execute("INSERT INTO NonPackagedIdentityRelationship VALUES(1,5,7,9,?)", (FT0 - 5,))
    con.execute("INSERT INTO NonPackagedGlobalPromptHistory VALUES(1,?,1,7,9,1,0)", (FT0 - 3,))
    con.execute("COMMIT")
    # deletions inside the main file -> freeblocks
    deleted = sorted(rnd.sample(ids[5:-5], 12))
    con.execute("BEGIN")
    for i in deleted:
        con.execute("DELETE FROM PackagedUsageHistory WHERE ID=?", (i,))
    con.execute("COMMIT")
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    # ---- 3. WAL-only changes
    wal_ins = list(range(base + n_live, base + n_live + n_wal))
    for i in wal_ins:
        con.execute("INSERT INTO PackagedUsageHistory VALUES(?,?,?,?,?,?,?,?,?,?,?)", usage_row(i, FT0 + i * 10_000_000_000))
    wal_upd, wal_del = [], []
    live_now = [i for i in ids if i not in deleted]
    if wal_update:
        wal_upd = [live_now[3]]
        con.execute("UPDATE PackagedUsageHistory SET Label=99 WHERE ID=?", (wal_upd[0],))
    if wal_delete:
        wal_del = [live_now[7]]
        con.execute("DELETE FROM PackagedUsageHistory WHERE ID=?", (wal_del[0],))
    # snapshot while open (closing would checkpoint)
    for suf in ("", "-wal", "-shm"):
        shutil.copyfile(p + suf, os.path.join(dirpath, "CapabilityAccessManager.db" + suf))
    con.close()

    main = bytearray(open(os.path.join(dirpath, "CapabilityAccessManager.db"), "rb").read())
    tail_ids = []
    if with_tail and len(big_bytes) > len(main):
        # emulate SQLite chunk-size behaviour: file keeps old pages beyond the logical end
        main += big_bytes[len(main):]
        con = sqlite3.connect(big)
        n_main_pages = len(open(os.path.join(dirpath, "CapabilityAccessManager.db"), "rb").read()) // 4096
        # rows whose leaf page lies in the tail
        tail_ids = []
        from winwitness.sqlite_low import parse_db_header, PageImage, BTreeReader
        img = PageImage(big_bytes, parse_db_header(big_bytes))
        rd = BTreeReader(img)
        root = [r for r in rd.schema() if r["name"] == "PackagedUsageHistory"][0]["rootpage"]
        for c in rd.walk_table(root, "x"):
            if c.page > n_main_pages:
                tail_ids.append(c.rowid)
        con.close()
        open(os.path.join(dirpath, "CapabilityAccessManager.db"), "wb").write(main)

    # ---- 4. consent DB (no WAL content) with a deleted App row
    cp = os.path.join(dirpath, "CapabilityConsentStorage.db")
    con = _con(cp)
    for s in CONSENT_SCHEMA:
        con.execute(s)
    con.execute("INSERT INTO MigratedUsers VALUES(?,1)", (SID,))
    con.execute("INSERT INTO SystemGlobal VALUES('webcam',1)")
    con.execute("INSERT INTO UserGlobal VALUES('webcam',?,1)", (SID,))
    for j in range(40):
        con.execute("INSERT INTO App VALUES('webcam',?,?,?)", (SID, f"Vendor.App{j:02d}_abcdefghijklm", 1 + j % 3))
    con.execute("DELETE FROM App WHERE PackageFamily='Vendor.App07_abcdefghijklm'")
    con.close()
    shutil.rmtree(work, ignore_errors=True)
    truth.update(deleted_ids=deleted, tail_ids=sorted(tail_ids), wal_inserts=wal_ins, wal_updates=wal_upd,
                 wal_deletes=wal_del, pre_alter_ids=pre_alter,
                 live_ids=sorted([i for i in live_now if i not in wal_del] + wal_ins + pre_alter),
                 deleted_consent_key=("webcam", SID, "Vendor.App07_abcdefghijklm"))
    return truth
