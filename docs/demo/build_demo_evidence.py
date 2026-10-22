#!/usr/bin/env python3
"""Build a FAKE but realistic Capability Access Manager evidence folder for demos and screenshots.

    python docs/demo/build_demo_evidence.py <output folder>
    python camtool_cli.py <output folder> -o <report folder> --tz +05:30

Everything here is invented: a made-up account (S-1-5-21-1111111111-2222222222-3333333333-1001,
user folder "analyst"), random hashes, and a short story: video calls in Teams and Zoom, Mail reading
contacts, Snipping Tool captures, browser passkeys, and an unknown "recorder.exe" run from Downloads
that used the microphone at night. Some rows are deleted (recoverable) and the newest rows are left
in the -wal file, so every feature of the report has something to show.
"""
import hashlib
import os
import random
import shutil
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
from tests.fixtures import CAM_ALTERS, CAM_SCHEMA  # noqa: E402

SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
SID2 = "S-1-5-21-1111111111-2222222222-3333333333-1002"
EPOCH_DIFF = 11644473600
BASE = 1791072000            # 2026-10-04 00:00:00 UTC
rnd = random.Random(2026)


def ft(day, hh, mm, ss=0):
    """FILETIME for BASE + day days + hh:mm:ss local (IST, UTC+05:30)."""
    t = BASE + day * 86400 + hh * 3600 + mm * 60 + ss - 19800
    return int((t + EPOCH_DIFF) * 10_000_000) + rnd.randrange(0, 9_999_999)


def sha():
    return hashlib.sha1(str(rnd.random()).encode()).hexdigest()


CAPS = {1: "location", 2: "webcam", 3: "microphone", 10: "contacts", 17: "graphicsCaptureWithoutBorder",
        20: "passkeysEnumeration", 21: "passkeys"}
PFNS = {25: ("microsoft.windowscommunicationsapps_8wekyb3d8bbwe", 10, "Mail and Calendar"),
        26: ("Microsoft.ScreenSketch_8wekyb3d8bbwe", 18, "Snipping Tool"),
        27: ("MSTeams_8wekyb3d8bbwe", 30, "Microsoft Teams"),
        28: ("Microsoft.WindowsCamera_8wekyb3d8bbwe", 31, "Camera")}
BINS = {5: r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        6: r"C:\Users\analyst\AppData\Roaming\Zoom\bin\Zoom.exe",
        7: r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
        8: r"C:\Users\analyst\Downloads\tools\recorder.exe",
        9: r"D:\portable\obs-studio\bin\64bit\obs64.exe"}
APPNAMES = {10: "Mail and Calendar", 18: "Snipping Tool", 30: "Microsoft Teams", 31: "Camera", 40: "Zoom",
            41: "Brave Browser"}

CONSENT_SCHEMA = [
    "CREATE TABLE MigratedUsers(User TEXT COLLATE NOCASE NOT NULL,Value INTEGER NOT NULL,PRIMARY KEY(User))",
    "CREATE TABLE SystemGlobal(Capability TEXT COLLATE NOCASE NOT NULL,Value INTEGER NOT NULL,PRIMARY KEY(Capability))",
    "CREATE TABLE UserGlobal(Capability TEXT COLLATE NOCASE NOT NULL,User TEXT COLLATE NOCASE NOT NULL,Value INTEGER NOT NULL,PRIMARY KEY(Capability, User))",
    "CREATE TABLE ClassicGlobal(Capability TEXT COLLATE NOCASE NOT NULL,User TEXT COLLATE NOCASE NOT NULL,Value INTEGER NOT NULL,PRIMARY KEY(Capability, User))",
    "CREATE TABLE App(Capability TEXT COLLATE NOCASE NOT NULL,User TEXT COLLATE NOCASE NOT NULL,PackageFamily TEXT COLLATE NOCASE NOT NULL,Value INTEGER NOT NULL,PRIMARY KEY(Capability, User, PackageFamily))",
    "CREATE TABLE UserGlobalWithConsentID(Capability TEXT COLLATE NOCASE NOT NULL,User TEXT COLLATE NOCASE NOT NULL,ConsentID TEXT COLLATE NOCASE NOT NULL,Value INTEGER NOT NULL,PRIMARY KEY(Capability, User, ConsentID))",
    "CREATE TABLE ShowGlobalPrompts(Capability TEXT COLLATE NOCASE NOT NULL,User TEXT COLLATE NOCASE NOT NULL,Value INTEGER NOT NULL,PRIMARY KEY(User, Capability))",
]


def build(out: str):
    os.makedirs(out, exist_ok=True)
    work = os.path.join(out, "_work")
    os.makedirs(work, exist_ok=True)
    p = os.path.join(work, "CapabilityAccessManager.db")
    con = sqlite3.connect(p, isolation_level=None)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=0")
    con.execute("PRAGMA secure_delete=OFF")
    for s in CAM_SCHEMA:
        con.execute(s)
    for s in CAM_ALTERS:
        con.execute(s)
    ins = lambda t, *v: con.execute(f"INSERT INTO {t} VALUES({','.join('?' * len(v))})", v)  # noqa: E731
    for i, c in CAPS.items():
        ins("Capabilities", i, c)
    for i, (pfn, _a, _n) in PFNS.items():
        ins("PackageFamilyNames", i, pfn)
    for i, n in APPNAMES.items():
        ins("AppNames", i, n)
    ins("Users", 1, SID)
    ins("BinaryNames", 1, "recorder.exe")
    fid, pid = {}, {}
    for i, path in BINS.items():
        fid[i], pid[i] = 300 + i, 200 + i
        ins("BinaryFullPaths", i, path)
        ins("FileIDs", fid[i], "0000" + sha())
        ins("ProgramIDs", pid[i], "0006" + sha()[:32] + "00000904")
    # ---- packaged (Store/MSIX) usage
    rows, rid = [], [1000]

    def pk(pfn_id, cap, s, e, blocked=0):
        rid[0] += 1
        rows.append(("P", rid[0], s, e, blocked, cap, pfn_id))

    def np_(bin_id, cap, s, e, app=0, blocked=0):
        rid[0] += 1
        rows.append(("N", rid[0], s, e, blocked, cap, bin_id, app))

    for d in range(0, 10):
        for hh in (9, 13, 18):                      # Mail reads contacts in instant pairs
            t = ft(d, hh, rnd.randrange(0, 59))
            pk(25, 10, t, t)
            pk(25, 10, t + 3_000_000, t + 3_000_000)
        if d % 2 == 0:                              # Snipping Tool captures (~5 s)
            for _ in range(rnd.randrange(1, 4)):
                t = ft(d, rnd.randrange(10, 20), rnd.randrange(0, 59))
                pk(26, 17, t, t + 50_000_000)
        if d in (1, 2, 4, 7, 8):                    # Teams meetings: camera + microphone
            s = ft(d, 10, 30)
            dur = rnd.randrange(25, 55) * 60 * 10_000_000
            pk(27, 3, s, s + dur)
            pk(27, 2, s + 600_000_000, s + dur - 1_200_000_000)
        if d in (3, 6, 9):                          # Zoom calls (desktop program)
            s = ft(d, 16, 0)
            dur = rnd.randrange(20, 70) * 60 * 10_000_000
            np_(6, 3, s, s + dur, 40)
            np_(6, 2, s + 300_000_000, s + dur, 40)
    t = ft(5, 12, 5)
    pk(28, 2, t, t + 90 * 10_000_000)               # Camera app photo
    np_(7, 21, ft(2, 21, 14), ft(2, 21, 14) + 50_000_000, 41)     # Brave passkey sign-in
    np_(7, 20, ft(6, 20, 2), ft(6, 20, 2) + 50_000_000, 41)
    np_(5, 20, ft(8, 11, 47), ft(8, 11, 47) + 50_000_000)
    s = ft(7, 2, 13)                                # unknown recorder.exe at night
    np_(8, 3, s, s + 2 * 3600 * 10_000_000 + 7 * 60 * 10_000_000)
    np_(8, 2, ft(7, 2, 14), ft(7, 2, 14), blocked=1)
    np_(9, 3, ft(8, 22, 40), ft(8, 22, 40) + 47 * 60 * 10_000_000)  # OBS from another drive
    rows.sort(key=lambda r: r[2])
    split = len(rows) - 6                           # last rows stay in the WAL
    deleted = set()

    def write(rs):
        con.execute("BEGIN")
        for r in rs:
            if r[0] == "P":
                _, i, s, e, b, cap, pfn = r
                ins("PackagedUsageHistory", i, s, e, b, cap, pfn, 1, 0, 2, PFNS[pfn][1], 0)
            else:
                _, i, s, e, b, cap, bid, app = r
                ins("NonPackagedUsageHistory", i, s, e, b, cap, fid[bid], pid[bid], bid, 1, app, 0, 0, 2, 0)
        con.execute("COMMIT")

    for i in range(len(rows[:split])):
        rows[i] = rows[i][:1] + (i + 1001,) + rows[i][2:]
    for i in range(split, len(rows)):
        rows[i] = rows[i][:1] + (i + 1001,) + rows[i][2:]
    write(rows[:split])
    # identities, location prompts
    for n, (b, d, hh) in enumerate(((5, 0, 9), (6, 1, 11), (7, 2, 21), (8, 7, 2), (9, 8, 22)), start=1):
        ins("NonPackagedIdentityRelationship", 400 + n, b, fid[b], pid[b], ft(d, hh, 1))
        ins("NonPackagedGlobalPromptHistory", n, ft(d, hh, 0, 30), 1, fid[b], pid[b], 1, 1 if b == 8 else 0)
    # delete a few Mail rows -> recoverable deleted records
    mail = [r[1] for r in rows[:split] if r[0] == "P" and r[5] == 10][4:10]
    con.execute("BEGIN")
    for i in mail:
        con.execute("DELETE FROM PackagedUsageHistory WHERE ID=?", (i,))
        deleted.add(i)
    con.execute("COMMIT")
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    write(rows[split:])                            # newest rows: only in the WAL
    for suf in ("", "-wal", "-shm"):
        shutil.copyfile(p + suf, os.path.join(out, "CapabilityAccessManager.db" + suf))
    con.close()

    c = sqlite3.connect(os.path.join(out, "CapabilityConsentStorage.db"))
    for s in CONSENT_SCHEMA:
        c.execute(s)
    for u in (SID, SID2, "S-1-5-18"):
        c.execute("INSERT INTO MigratedUsers VALUES(?,1)", (u,))
    for cap in ("webcam", "microphone", "location", "contacts", "graphicsCaptureWithoutBorder", "passkeys",
                "passkeysEnumeration"):
        c.execute("INSERT INTO SystemGlobal VALUES(?,1)", (cap,))
        c.execute("INSERT INTO UserGlobal VALUES(?,?,1)", (cap, SID))
    for cap, v in (("webcam", 1), ("microphone", 1), ("location", 2)):
        c.execute("INSERT INTO ClassicGlobal VALUES(?,?,?)", (cap, SID, v))
    for cap, pfn, v in (("contacts", 25, 1), ("graphicsCaptureWithoutBorder", 26, 1), ("webcam", 27, 1),
                        ("microphone", 27, 1), ("webcam", 28, 2), ("microphone", 28, 3)):
        c.execute("INSERT INTO App VALUES(?,?,?,?)", (cap, SID, PFNS[pfn][0], v))
    for site in ("example-bank.test", "mail.example.test"):
        c.execute("INSERT INTO UserGlobalWithConsentID VALUES('passkeys',?,?,1)", (SID, site))
    c.execute("INSERT INTO ShowGlobalPrompts VALUES('location',?,1)", (SID,))
    c.commit()
    c.close()
    shutil.rmtree(work, ignore_errors=True)
    return dict(rows=len(rows), wal_rows=len(rows) - split, deleted=sorted(deleted))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    print(build(sys.argv[1]))
