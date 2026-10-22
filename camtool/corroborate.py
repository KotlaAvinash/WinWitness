"""Decode rows, build the timeline, run consistency checks and external corroboration."""
from __future__ import annotations

import csv
import hashlib
import os
import re
from collections import Counter, defaultdict

from . import model as M

AMCACHE_HASH_LIMIT = 31_457_280   # [published] Amcache/CAM FileID = SHA-1 of first 30 MiB


# --------------------------------------------------------------------------- decoding
def lookups(A) -> dict:
    """{lookup_table: {id: string}} from live rows, plus carved lookup records as fallback."""
    out = {t: {} for t in M.LOOKUP_TABLES}
    for t in M.LOOKUP_TABLES:
        for r in A.tables.get(t, []):
            out[t][r["ID"]] = r["StringValue"]
    out["_carved"] = {}
    for c in getattr(A, "carved", []):
        if c.table in M.LOOKUP_TABLES and c.rowid is not None and c.status.startswith("DELETED"):
            out["_carved"].setdefault(c.table, {})[c.rowid] = c.values[1]
    return out


def resolve(L: dict, col: str, v):
    t = M.FK_MAP.get(col)
    if t is None or v in (None, 0):
        return ""
    if v in L[t]:
        return L[t][v]
    if v in L["_carved"].get(t, {}):
        return L["_carved"][t][v] + "  [carved]"
    return f"<unresolved {t} ID {v}: purged>"


def decode_usage(table: str, raw: dict, L: dict, tz, source: str) -> dict:
    s, e = raw.get("LastUsedTimeStart"), raw.get("LastUsedTimeStop")
    d = dict(source=source, table=table, ID=raw.get("ID"),
             start_utc=M.ft_str(s), stop_utc=M.ft_str(e),
             start_local=M.ft_str(s, tz), stop_local=M.ft_str(e, tz),
             duration_s=round((e - s) / 1e7, 3) if isinstance(s, int) and isinstance(e, int) and s and e else "",
             access=M.ACCESS_BLOCKED.get(raw.get("AccessBlocked"), raw.get("AccessBlocked")),
             capability=resolve(L, "Capability", raw.get("Capability")),
             app_name=resolve(L, "AppName", raw.get("AppName")),
             user_sid=resolve(L, "UserSid", raw.get("UserSid")))
    if table == "PackagedUsageHistory":
        d["app"] = resolve(L, "PackageFamilyName", raw.get("PackageFamilyName"))
        d["kind"] = "packaged"
    else:
        d["app"] = resolve(L, "BinaryFullPath", raw.get("BinaryFullPath"))
        fid = resolve(L, "FileID", raw.get("FileID"))
        d.update(kind="nonpackaged", file_id=fid, sha1=M.sha1_from_fileid(fid.split()[0] if fid else None) or "",
                 program_id=resolve(L, "ProgramID", raw.get("ProgramID")),
                 service=resolve(L, "ServiceName", raw.get("ServiceName")))
    d["access_guid"] = resolve(L, "AccessGUID", raw.get("AccessGUID"))
    d["Label"] = raw.get("Label")
    d["Context"] = raw.get("Context")
    d["raw"] = {k: v for k, v in raw.items() if not k.startswith("_")}
    return d


def decode_cam(A, tz) -> dict:
    L = lookups(A)
    out = dict(usage=[], identity=[], prompts=[], packaged_prompts=[], lookups=L)
    for t in ("PackagedUsageHistory", "NonPackagedUsageHistory"):
        for r in A.tables.get(t, []):
            out["usage"].append(decode_usage(t, r, L, tz, "live"))
    for r in A.tables.get("NonPackagedIdentityRelationship", []):
        fid = resolve(L, "FileID", r["FileID"])
        out["identity"].append(dict(ID=r["ID"], binary=resolve(L, "BinaryFullPath", r["BinaryFullPath"]),
                                    file_id=fid, sha1=M.sha1_from_fileid(fid) or "",
                                    program_id=resolve(L, "ProgramID", r["ProgramID"]),
                                    first_observed_utc=M.ft_str(r["LastObservedTime"]),
                                    first_observed_local=M.ft_str(r["LastObservedTime"], tz),
                                    raw={k: v for k, v in r.items() if not k.startswith("_")}))
    rel_by_fid = {r["FileID"]: r for r in A.tables.get("NonPackagedIdentityRelationship", [])}
    for r in A.tables.get("NonPackagedGlobalPromptHistory", []):
        fid = resolve(L, "FileID", r["FileID"])
        rel = rel_by_fid.get(r["FileID"])
        out["prompts"].append(dict(ID=r["ID"], shown_utc=M.ft_str(r["ShownTime"]),
                                   shown_local=M.ft_str(r["ShownTime"], tz),
                                   capability=resolve(L, "Capability", r["Capability"]),
                                   binary=resolve(L, "BinaryFullPath", rel["BinaryFullPath"]) if rel else "",
                                   binary_name=resolve(L, "BinaryName", r.get("BinaryName")),
                                   file_id=fid, sha1=M.sha1_from_fileid(fid) or "",
                                   program_id=resolve(L, "ProgramID", r["ProgramID"]),
                                   user_sid=resolve(L, "UserSid", r["UserSid"]),
                                   raw={k: v for k, v in r.items() if not k.startswith("_")}))
    for r in A.tables.get("PackagedGlobalPromptHistory", []):
        out["packaged_prompts"].append(dict(ID=r["ID"], capability=resolve(L, "Capability", r["Capability"]),
                                            app=resolve(L, "PackageFamilyName", r["PackageFamilyName"]),
                                            user_sid=resolve(L, "UserSid", r["UserSid"]),
                                            raw={k: v for k, v in r.items() if not k.startswith("_")}))
    # carved usage rows decoded with the same lookups
    out["carved_usage"] = []
    for c in A.carved:
        if c.table in ("PackagedUsageHistory", "NonPackagedUsageHistory") and not c.status.startswith("LIVE"):
            raw = dict(zip(c.columns, c.values))
            raw["ID"] = c.rowid
            d = decode_usage(c.table, raw, L, tz, "carved")
            d.update(status=c.status, found_at=c.source, offset=c.offset, file=c.file,
                     id_basis=c.rowid_basis, seen_at="; ".join(c.extra.get("seen_at", [])))
            out["carved_usage"].append(d)
    out["carved_usage"].sort(key=lambda d: (d["start_utc"] or "", d["ID"] or 0))
    return out


def decode_consent(C) -> dict:
    out = {}
    for t, rows in C.tables.items():
        dec = []
        for r in rows:
            d = {k: v for k, v in r.items() if not k.startswith("_")}
            d["rowid"] = r["_rowid"]
            if "Value" in d and t not in ("MigratedUsers", "ShowGlobalPrompts"):
                d["Value_meaning"] = M.CONSENT_VALUE.get(d["Value"], f"unknown({d['Value']})")
            if t == "UserGlobalWithConsentID" and str(d.get("ConsentID", "")).startswith("Bluetooth"):
                m = re.search(r"([0-9a-f:]{17})-([0-9a-f:]{17})", d["ConsentID"], re.I)
                if m:
                    d["local_adapter_mac"], d["remote_device_mac"] = m.group(1), m.group(2)
            dec.append(d)
        out[t] = dec
    return out


# --------------------------------------------------------------------------- timeline
def build_timeline(cam: dict | None, consent: dict | None, i30: dict | None, A=None, reg=None, tz=None) -> list[dict]:
    ev = []

    def add(ts, tsl, kind, what, detail, source, ref=""):
        if ts:
            ev.append(dict(time_utc=ts, time_local=tsl, event=kind, subject=what, detail=detail,
                           source=source, ref=ref))
    if cam:
        for u in cam["usage"] + cam.get("carved_usage", []):
            src = u["table"] + (" [" + u["status"] + "]" if u.get("source") == "carved" else "")
            add(u["start_utc"], u["start_local"], f"{u['capability'] or '?'} use START", u["app"],
                f"access={u['access']} dur={u['duration_s']}s app_name={u['app_name']}", src, f"ID {u['ID']}")
            if u["stop_utc"] and u["stop_utc"] != u["start_utc"]:
                add(u["stop_utc"], u["stop_local"], f"{u['capability'] or '?'} use STOP", u["app"], "", src, f"ID {u['ID']}")
        for p in cam["prompts"]:
            add(p["shown_utc"], p["shown_local"], f"{p['capability']} global prompt shown",
                p["binary"] or p["binary_name"], f"FileID {p['file_id']}", "NonPackagedGlobalPromptHistory", f"ID {p['ID']}")
        for r in cam["identity"]:
            add(r["first_observed_utc"], r["first_observed_local"], "binary identity first observed",
                r["binary"], f"SHA-1 {r['sha1']}", "NonPackagedIdentityRelationship", f"ID {r['ID']}")
    if i30:
        for e in i30.get("entries", []):
            if e["namespace"] == "DOS":
                continue
            for k, lab in (("created", "$FN created"), ("modified", "$FN modified"), ("mft_modified", "$FN MFT changed")):
                add(e[k], M.fmt_dt(_parse(e[k]), tz) if tz else e[k], lab, e["name"],
                    f"real={e['real_size']} alloc={e['alloc_size']} ({e['state']})", "$I30", f"MFT {e['mft_ref']}-{e['mft_seq']}")
    if reg:
        for r in reg.get("entries", []):
            for k in ("LastUsedTimeStart", "LastUsedTimeStop"):
                v = r.get(k)
                if v:
                    add(M.ft_str(v), M.ft_str(v, tz), f"{r['capability']} {k} (registry)", r["app"],
                        f"Value={r.get('Value')}", "ConsentStore registry", r["hive"])
    ev.sort(key=lambda e: (e["time_utc"], e["source"]))
    return ev


def _parse(s):
    from datetime import datetime, timezone
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------- findings
def F(sev, cat, title, detail, basis="observed", evidence=""):
    return dict(severity=sev, category=cat, title=title, detail=detail, basis=basis, evidence=evidence)


def run_checks(A, C, cam, consent, i30, ev_files) -> list[dict]:
    out = []
    # ---- container / acquisition
    for D in (A, C):
        if D is None:
            continue
        h = D.header
        if D.beyond_eof_pages:
            out.append(F("HIGH", "recovery", f"{D.name}: {len(D.beyond_eof_pages)} page(s) of old data past the logical end",
                         f"Header says {h.page_count} pages ({h.page_count * h.page_size:,} bytes) but the file is "
                         f"{len(D.main.data):,} bytes. Pages {D.beyond_eof_pages} still hold b-tree data from before the "
                         f"database shrank. Any tool that checkpoints or VACUUMs the file truncates these pages away.",
                         "measured"))
        if D.wal_info:
            w = D.wal_info
            live = w.valid_frames
            sl = [f for f in w.frames if f.in_slack and f.valid]
            out.append(F("INFO", "wal", f"{D.name}: WAL holds {len(live)} committed frame(s) not yet in the main file",
                         f"{len({f.txn for f in live})} transaction(s), checkpoint seq {w.checkpoint_seq}, salts "
                         f"{w.salt1:#010x}/{w.salt2:#010x}, header checksum ok={w.header_cksum_ok}. These rows are "
                         "invisible to tools that read the .db without its -wal.", "measured"))
            if sl:
                out.append(F("HIGH", "acquisition", f"{D.name}: {len(sl)} checksum-valid WAL frame(s) found in WAL file SLACK",
                             "The frame(s) continue the live WAL's salt and checksum chain but sit past the WAL's logical "
                             "size. Most likely the collection read the file size before SQLite appended them (live, "
                             "non-atomic acquisition). Their rows are reported as 'RECOVERED (WAL slack txn)' and are NOT "
                             "merged into the live tables.", "measured"))
            if D.shm_info:
                sh = D.shm_info["header"]
                same = tuple(sh["aSalt"]) == (w.salt1, w.salt2)
                out.append(F("INFO" if same else "MEDIUM", "wal",
                             f"{D.name}: -shm {'matches' if same else 'does NOT match'} the WAL generation",
                             f"shm mxFrame={sh['mxFrame']} nBackfill={D.shm_info['nBackfill']} salts "
                             f"{sh['aSalt'][0]:#010x}/{sh['aSalt'][1]:#010x}; WAL valid frames={len(live)}. "
                             + ("" if same else f"The -shm describes an EARLIER WAL generation that held at least "
                                f"{sh['mxFrame']} frame(s) before a checkpoint restarted the WAL with new salts. -shm is "
                                "rebuilt by SQLite, so this does not affect the data, but it shows prior write activity."),
                             "measured"))
        lc = D.library_check
        out.append(F("INFO" if lc.get("match") else "HIGH", "validation",
                     f"{D.name}: independent b-tree reader vs sqlite3 library: {'IDENTICAL' if lc.get('match') else 'MISMATCH'}",
                     f"tables compared={lc.get('tables_compared')}, mismatched={lc.get('mismatched_tables')}, "
                     f"PRAGMA integrity_check={lc.get('integrity_check')}", "measured"))
    # ---- CAM content
    if cam:
        usage = cam["usage"]
        # ID gaps (purged history)
        for t in ("PackagedUsageHistory", "NonPackagedUsageHistory", "NonPackagedGlobalPromptHistory",
                  "NonPackagedIdentityRelationship"):
            ids = sorted(r["_rowid"] for r in A.tables.get(t, []))
            if ids:
                missing = (ids[-1] - ids[0] + 1) - len(ids)
                out.append(F("INFO", "retention", f"{t}: IDs {ids[0]}..{ids[-1]} ({len(ids)} rows)",
                             f"{ids[0] - 1:,} earlier ID(s) were used and later removed; {missing} gap(s) inside the live "
                             f"range. IDs are never reused [published], so a gap means a row existed.",
                             "published+measured"))
        # orphaned lookup values
        refs = defaultdict(set)
        for t in ("PackagedUsageHistory", "NonPackagedUsageHistory", "NonPackagedIdentityRelationship",
                  "NonPackagedGlobalPromptHistory", "PackagedGlobalPromptHistory"):
            for r in A.tables.get(t, []):
                for col, lt in M.FK_MAP.items():
                    if col in r and r[col]:
                        refs[lt].add(r[col])
        wal_ins = {(w["table"], w["rowid"]): w["step"] for w in A.wal_changes if w["change"] == "INSERT"}
        for lt in M.LOOKUP_TABLES:
            ids = {r["ID"] for r in A.tables.get(lt, [])}
            orph = sorted(ids - refs[lt])
            dang = sorted(refs[lt] - ids)
            if orph:
                fresh = [i for i in orph if (lt, i) in wal_ins]
                old = [i for i in orph if (lt, i) not in wal_ins]
                parts = []
                if old:
                    parts.append(f"IDs {old[:15]}{'...' if len(old) > 15 else ''} "
                                 f"({[cam['lookups'][lt][i] for i in old][:6]}): the rows that used them were purged; "
                                 "lookup values outlive history rows, so they prove past activity.")
                if fresh:
                    parts.append(f"IDs {fresh} ({[cam['lookups'][lt][i] for i in fresh]}) were inserted in the WAL "
                                 f"({', '.join(wal_ins[(lt, i)] for i in fresh)}) but no row references them yet: "
                                 "the referencing event had not been written when the files were collected.")
                out.append(F("MEDIUM", "retention", f"{lt}: {len(orph)} value(s) no live row references",
                             " ".join(parts), "measured", ", ".join(map(str, orph))))
            if dang:
                out.append(F("MEDIUM", "integrity", f"{lt}: {len(dang)} referenced ID(s) missing", f"IDs {dang}", "measured"))
        # time sanity
        bad = [u for u in usage if u["raw"].get("LastUsedTimeStop") and u["raw"]["LastUsedTimeStop"] < u["raw"]["LastUsedTimeStart"]]
        if bad:
            out.append(F("HIGH", "time", f"{len(bad)} usage row(s) stop before they start", str([u['ID'] for u in bad][:20]), "measured"))
        zero = [u for u in usage if not u["raw"].get("LastUsedTimeStart")]
        if zero:
            out.append(F("MEDIUM", "time", f"{len(zero)} usage row(s) with start time 0",
                         "Published research associates start=0 with blocked access.", "published"))
        inst = [u for u in usage if u["raw"].get("LastUsedTimeStart") and u["raw"]["LastUsedTimeStart"] == u["raw"]["LastUsedTimeStop"]]
        if inst:
            c = Counter((u["capability"], u["app"]) for u in inst)
            out.append(F("INFO", "pattern", f"{len(inst)} usage row(s) have start == stop (instant access)",
                         "; ".join(f"{k[0]} by {k[1]}: {v}" for k, v in c.most_common(5)), "measured"))
        # anchors in relative time: ID order vs time order per (table, cap, app, user)
        grp = defaultdict(list)
        for u in usage + [c for c in cam.get("carved_usage", []) if c["ID"] is not None]:
            grp[(u["table"], u["capability"], u["app"], u["user_sid"])].append(u)
        inv = []
        for k, rows in grp.items():
            rows.sort(key=lambda u: u["ID"])
            for a, b in zip(rows, rows[1:]):
                if a["raw"]["LastUsedTimeStart"] and b["raw"]["LastUsedTimeStart"] and \
                        b["raw"]["LastUsedTimeStart"] < a["raw"]["LastUsedTimeStart"]:
                    inv.append((k, a["ID"], b["ID"]))
        out.append(F("HIGH" if inv else "INFO", "time",
                     f"ID-vs-time order per (capability, app, user): {len(inv)} inversion(s)",
                     ("Inversions within one capability/app/user stream suggest a clock change: " + str(inv[:10]))
                     if inv else f"All {len(grp)} streams (live + recovered rows with a known ID) are monotonic: "
                     "no sign of clock manipulation.",
                     "published method (Cyber Sundae Pt2) + measured"))
        # retention / age per table
        newest = max([u["raw"]["LastUsedTimeStart"] or 0 for u in usage] +
                     [p["ShownTime"] for p in A.tables.get("NonPackagedGlobalPromptHistory", [])] + [0])
        rows = []
        for t, col in (("PackagedUsageHistory", "LastUsedTimeStart"), ("NonPackagedUsageHistory", "LastUsedTimeStart"),
                       ("NonPackagedGlobalPromptHistory", "ShownTime"), ("NonPackagedIdentityRelationship", "LastObservedTime")):
            ts = [r[col] for r in A.tables.get(t, []) if r.get(col)]
            if ts:
                rows.append(f"{t}: {len(ts)} rows, {M.ft_str(min(ts))[:10]} .. {M.ft_str(max(ts))[:10]} "
                            f"(oldest {round((newest - min(ts)) / 864e9)} d before newest event)")
        out.append(F("INFO", "retention", "Time span kept per table",
                     "; ".join(rows) + ". Rows older than ExpirationPolicyInDays (default 30) are expected to be purged "
                     "[published]; tables that keep far older rows are evidently not purged by age on this build.",
                     "measured"))

        # Label transitions
        lab = [(u["ID"], u["Label"], u["start_utc"]) for u in sorted(usage, key=lambda u: u["ID"])
               if u["table"] == "PackagedUsageHistory"]
        trans = [(a, b) for a, b in zip(lab, lab[1:]) if a[1] != b[1]]
        if trans:
            out.append(F("INFO", "unknown-field", f"Label changes value {len(trans)} time(s) in PackagedUsageHistory",
                         "; ".join(f"ID {a[0]} Label={a[1]} -> ID {b[0]} Label={b[1]} at {b[2]} UTC" for a, b in trans) +
                         ". Meaning of Label is not documented; a single global switch at one moment suggests a "
                         "service/OS change rather than per-app behaviour.", "observed"))
        # Identity first-seen vs first prompt
        pr = defaultdict(list)
        for p in A.tables.get("NonPackagedGlobalPromptHistory", []):
            if p["ShownTime"]:
                pr[p["FileID"]].append(p["ShownTime"])
        far = []
        for r in A.tables.get("NonPackagedIdentityRelationship", []):
            if r["FileID"] in pr:
                d = (r["LastObservedTime"] - min(pr[r["FileID"]])) / 1e7
                if abs(d) > 86400:
                    far.append((r["ID"], cam["lookups"]["BinaryFullPaths"].get(r["BinaryFullPath"]), round(d / 86400, 1)))
        close = sum(1 for r in A.tables.get("NonPackagedIdentityRelationship", []) if r["FileID"] in pr) - len(far)
        out.append(F("MEDIUM" if far else "INFO", "consistency",
                     f"IdentityRelationship.LastObservedTime vs first prompt for the same FileID: {close} agree (<1 day), {len(far)} differ",
                     ("Differences (rel ID, binary, days): " + str(far)) if far else "", "measured"))
        zero_prompt = [p for p in A.tables.get("NonPackagedGlobalPromptHistory", []) if not p["ShownTime"]]
        if zero_prompt:
            out.append(F("MEDIUM", "consistency", f"{len(zero_prompt)} prompt row(s) with ShownTime = 0",
                         str([{k: v for k, v in p.items() if not k.startswith('_')} for p in zero_prompt]), "measured"))
        # binaries run from unusual places
        odd = [v for v in cam["lookups"]["BinaryFullPaths"].values()
               if re.search(r"\\(Temp|Downloads|AppData\\Local\\Temp)\\", v, re.I) or not v.upper().startswith("C:")]
        if odd:
            out.append(F("MEDIUM", "triage", f"{len(odd)} binary path(s) outside C: or in Temp/Downloads", "; ".join(odd), "measured"))
        multi = defaultdict(set)
        for r in A.tables.get("NonPackagedIdentityRelationship", []):
            multi[cam["lookups"]["BinaryFullPaths"].get(r["BinaryFullPath"])].add(r["FileID"])
        m2 = {k: len(v) for k, v in multi.items() if len(v) > 1}
        if m2:
            out.append(F("INFO", "triage", "Same path seen with several FileIDs (binary was updated/replaced)",
                         "; ".join(f"{k}: {v} hashes" for k, v in m2.items()), "measured"))
        # usage vs current consent
        if consent:
            app_cons = {(r["Capability"].lower(), r["PackageFamily"].lower()): r for r in consent.get("App", [])}
            for u in usage:
                if u["kind"] != "packaged":
                    continue
                k = (u["capability"].lower(), u["app"].lower())
                cr = app_cons.get(k)
                if cr and cr["Value"] == 2 and u["access"] == "Allowed":
                    out.append(F("MEDIUM", "consistency", f"Allowed use while consent is now Deny: {u['app']} {u['capability']}",
                                 f"usage ID {u['ID']} at {u['start_utc']}; consent may have been changed afterwards", "measured"))
            pairs = {(u["capability"], u["app"]) for u in usage if u["kind"] == "packaged"}
            rows = []
            for cap, app in sorted(pairs):
                cr = app_cons.get((cap.lower(), app.lower()))
                rows.append(f"{app} / {cap}: consent={cr['Value_meaning'] if cr else 'no App row'}")
            out.append(F("INFO", "corroboration", "Packaged usage vs CapabilityConsentStorage.App", "; ".join(rows), "measured"))
            # passkeys
            pk = [u for u in usage if u["capability"].startswith("passkeys")]
            if pk:
                rps = sorted({r["ConsentID"] for r in consent.get("UserGlobalWithConsentID", []) if r["Capability"].startswith("passkeys")})
                out.append(F("INFO", "corroboration", f"{len(pk)} passkey access(es) by "
                             f"{', '.join(sorted({u['app'].split(chr(92))[-1] for u in pk}))}",
                             f"Times: {[u['start_utc'] for u in pk]}. Consent DB lists passkey relying parties with a "
                             f"stored per-site decision: {rps}. CAM records THAT passkeys were enumerated/used, "
                             "not which site.", "measured"))
        # SIDs
        if consent:
            usids = set(cam["lookups"]["Users"].values())
            csids = {r["User"] for r in consent.get("MigratedUsers", [])}
            other = sorted(s for s in csids - usids if s.startswith("S-1-5-21"))
            out.append(F("INFO", "corroboration", f"User SIDs: usage history has {len(usids)}, consent DB knows {len(csids)}",
                         f"usage: {sorted(usids)}; consent only: {sorted(csids - usids)}"
                         + (f". Local account(s) {other} exist on the host but have no retained usage." if other else ""),
                         "measured"))
        # carved summary
        cu = cam.get("carved_usage", [])
        if cu:
            st = Counter(c["status"] for c in cu)
            t0 = min((c["start_utc"] for c in cu if c["start_utc"]), default="")
            t1 = max((c["start_utc"] for c in cu if c["start_utc"]), default="")
            unresolved = Counter(v for c in cu for v in (c["capability"], c["app"], c["app_name"], c["user_sid"])
                                 if isinstance(v, str) and v.startswith("<unresolved"))
            out.append(F("HIGH", "recovery", f"{len(cu)} usage record(s) recovered that are not in the live tables",
                         f"{dict(st)}; span {t0} .. {t1} UTC. "
                         + (f"Unresolvable lookup IDs (lookup row was purged): {dict(unresolved)}." if unresolved else ""),
                         "measured"))
    if i30:
        out.append(F("INFO", "corroboration", f"$I30: {len([e for e in i30['entries'] if e['namespace'] != 'DOS'])} Win32 entries, "
                     f"{len([e for e in i30['entries'] if e['state'] != 'live'])} slack entries",
                     "$FILE_NAME sizes/times are a copy from the last index update and are usually older than $SI.",
                     "published"))
        names = {e["name"].lower(): e for e in i30["entries"]}
        for f in ev_files:
            e = names.get(f.name.lower())
            if e and not f.name.lower().endswith("fileslack"):
                same = e["real_size"] == f.size
                out.append(F("INFO" if same else "MEDIUM", "corroboration",
                             f"$I30 size for {f.name}: {e['real_size']:,} vs collected {f.size:,} ({'match' if same else 'differs'})",
                             f"allocated {e['alloc_size']:,}; $FN modified {e['modified']} UTC", "measured"))
    return out


# --------------------------------------------------------------------------- registry
REG_BASE = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"


def read_live_registry() -> dict:
    """Read HKCU (+ HKLM) ConsentStore of the CURRENT user on THIS machine (read-only)."""
    import winreg
    out = dict(source="live registry (HKCU/HKLM of the analysing account)", entries=[], sid=None)
    try:
        import subprocess
        r = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=10)
        out["sid"] = r.stdout.strip().split(",")[-1].strip('"') or None
    except Exception:
        pass
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\CapabilityUsageHistory")
        out["usage_history_settings"] = _vals(k)
    except OSError:
        out["usage_history_settings"] = {}
    for hive, hname in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
        try:
            base = winreg.OpenKey(hive, REG_BASE, 0, winreg.KEY_READ)
        except OSError:
            continue
        i = 0
        while True:
            try:
                cap = winreg.EnumKey(base, i)
            except OSError:
                break
            i += 1
            ck = winreg.OpenKey(base, cap)
            out["entries"].append(dict(hive=hname, capability=cap, app="(global)", **_vals(ck)))
            _walk_apps(ck, cap, hname, "", out["entries"])
    return out


def _vals(k) -> dict:
    import winreg
    d, j = {}, 0
    while True:
        try:
            n, v, _t = winreg.EnumValue(k, j)
        except OSError:
            break
        d[n] = v
        j += 1
    return d


def _walk_apps(ck, cap, hname, prefix, out):
    import winreg
    j = 0
    while True:
        try:
            app = winreg.EnumKey(ck, j)
        except OSError:
            break
        j += 1
        ak = winreg.OpenKey(ck, app)
        if app == "NonPackaged" and not prefix:
            out.append(dict(hive=hname, capability=cap, app="NonPackaged (default)", **_vals(ak)))
            _walk_apps(ak, cap, hname, "NonPackaged\\", out)
        else:
            name = app.replace("#", "\\") if prefix else app
            out.append(dict(hive=hname, capability=cap, app=name, nonpackaged=bool(prefix), **_vals(ak)))


CS_USER = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
CS_MACHINE = r"Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"


def _hive_consent_entries(cs_key, hive_label: str) -> list[dict]:
    """Walk a ConsentStore key of an offline hive into read_live_registry()-shaped entries.

    Registry values are merged first and our own fields set afterwards, so a value that happens to be
    named 'app' or 'hive' can never overwrite them (or raise on a duplicate keyword)."""
    out = []
    if cs_key is None:
        return out

    def entry(key, cap, app, nonpackaged):
        e = dict(key.values())
        e.update(hive=hive_label, capability=cap, app=app, nonpackaged=nonpackaged, key_last_write=key.last_write)
        return e

    for cap in cs_key.subkeys():
        out.append(entry(cap, cap.name, "(global)", False))
        for app in cap.subkeys():
            if app.name == "NonPackaged":
                out.append(entry(app, cap.name, "NonPackaged (default)", False))
                for np_ in app.subkeys():
                    out.append(entry(np_, cap.name, np_.name.replace("#", "\\"), True))
            else:
                out.append(entry(app, cap.name, app.name, False))
    return out


def read_hive_consentstore(hive, label: str) -> dict:
    """ConsentStore (per-user decisions + last-use times) from an offline NTUSER.DAT."""
    return dict(source=f"offline hive {label}", sid=None,
                entries=_hive_consent_entries(hive.key(CS_USER), f"HKCU({label})"))


def read_software_hive(hive) -> dict:
    """OS version, ProfileList (SID -> profile path), CAM settings, HKLM ConsentStore, Uninstall entries."""
    cv = hive.key(r"Microsoft\Windows NT\CurrentVersion")
    v = cv.values() if cv else {}
    os_info = dict(product=v.get("ProductName", ""), display_version=v.get("DisplayVersion", ""),
                   build=str(v.get("CurrentBuild", "")), ubr=v.get("UBR", ""),
                   registered_owner=v.get("RegisteredOwner", ""))
    profiles = {}
    pl = hive.key(r"Microsoft\Windows NT\CurrentVersion\ProfileList")
    for k in pl.subkeys() if pl else []:
        path = k.values().get("ProfileImagePath")
        if isinstance(path, str):
            profiles[k.name] = path
    uh = hive.key(r"Microsoft\Windows\CurrentVersion\CapabilityAccessManager\CapabilityUsageHistory")
    uninstall = []
    for base in (r"Microsoft\Windows\CurrentVersion\Uninstall",
                 r"WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"):
        u = hive.key(base)
        for k in u.subkeys() if u else []:
            x = k.values()
            name = x.get("DisplayName")
            if not isinstance(name, str) or not name:
                continue
            uninstall.append(dict(name=name, key=k.name, install_location=x.get("InstallLocation", "") or "",
                                  install_source=x.get("InstallSource", "") or "",
                                  display_icon=x.get("DisplayIcon", "") or "",
                                  uninstall_string=x.get("UninstallString", "") or "",
                                  publisher=x.get("Publisher", "") or "", version=x.get("DisplayVersion", "") or "",
                                  install_date=x.get("InstallDate", "") or "", key_last_write=k.last_write_utc))
    return dict(os=os_info, profiles=profiles, usage_history_settings=uh.values() if uh else {},
                uninstall=uninstall, consent_entries=_hive_consent_entries(hive.key(CS_MACHINE), "HKLM(SOFTWARE)"))


def parse_reg_export(path: str) -> dict:
    """Parse a regedit .reg export (UTF-16 or UTF-8) of a ConsentStore key (any hive)."""
    raw = open(path, "rb").read()
    txt = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8", "replace")
    out = dict(source=f".reg file {os.path.basename(path)}", entries=[], sid=None, usage_history_settings={})
    cur = None
    for line in txt.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            key = line[1:-1]
            if key.lower().endswith(r"capabilityaccessmanager\capabilityusagehistory"):
                cur = out["usage_history_settings"]
                continue
            m = re.search(r"ConsentStore\\([^\\]+)(?:\\(.+))?$", key, re.I)
            cur = None
            if m:
                hive = key.split("\\")[0]
                sidm = re.search(r"(S-1-5-21-[\d-]+)", key)
                if sidm:
                    out["sid"] = sidm.group(1)
                app = m.group(2) or "(global)"
                np_ = app.startswith("NonPackaged\\")
                if np_:
                    app = app[len("NonPackaged\\"):].replace("#", "\\")
                elif app == "NonPackaged":
                    app = "NonPackaged (default)"
                cur = dict(hive=hive, capability=m.group(1), app=app, nonpackaged=np_)
                out["entries"].append(cur)
        elif cur is not None and "=" in line:
            n, v = line.split("=", 1)
            n = n.strip('"')
            if v.startswith('"'):
                cur[n] = v.strip('"')
            elif v.lower().startswith("hex(b):"):
                b = bytes(int(x, 16) for x in v[7:].replace("\\", "").split(",") if x.strip())
                cur[n] = int.from_bytes(b, "little")
            elif v.lower().startswith("dword:"):
                cur[n] = int(v[6:], 16)
    return out


def compare_registry(reg: dict, consent: dict | None, cam: dict | None, cam_sid: str | None) -> dict:
    res = dict(source=reg["source"], sid=reg.get("sid"), same_user=None, value_checks=[], time_checks=[], summary={})
    if cam_sid and reg.get("sid"):
        res["same_user"] = cam_sid.upper() == reg["sid"].upper()
    rev = {v: k for k, v in M.CONSENT_VALUE.items()}
    if consent:
        apps = {(r["Capability"].lower(), r["PackageFamily"].lower()): r for r in consent.get("App", [])}
        ug = {r["Capability"].lower(): r for r in consent.get("UserGlobal", []) if r["User"] == cam_sid}
        sg = {r["Capability"].lower(): r for r in consent.get("SystemGlobal", [])}
        for e in reg["entries"]:
            v = e.get("Value")
            if v is None:
                continue
            k = (e["capability"].lower(), e["app"].lower())
            db = None
            if e["app"] == "(global)":
                db = (ug if e["hive"].upper().startswith(("HKCU", "HKEY_CURRENT_USER", "HKEY_USERS")) else sg).get(k[0])
            elif not e.get("nonpackaged"):
                db = apps.get(k)
            if db is None:
                res["value_checks"].append(dict(capability=e["capability"], app=e["app"], hive=e["hive"],
                                                registry=v, database="(no row)", match=None))
                continue
            res["value_checks"].append(dict(capability=e["capability"], app=e["app"], hive=e["hive"], registry=v,
                                            database=f"{db['Value']} ({M.CONSENT_VALUE.get(db['Value'], '?')})",
                                            match=rev.get(v) == db["Value"]))
    if cam:
        last = defaultdict(int)
        starts = defaultdict(set)
        for u in cam["usage"] + cam.get("carved_usage", []):
            k = (u["capability"].lower(), u["app"].lower())
            st = u["raw"].get("LastUsedTimeStart") or 0
            starts[k].add(st)
            if u.get("source") == "live":
                last[k] = max(last[k], st)
        for e in reg["entries"]:
            s = e.get("LastUsedTimeStart")
            if not s:
                continue
            k = (e["capability"].lower(), e["app"].lower())
            if k in last:
                res["time_checks"].append(dict(capability=e["capability"], app=e["app"],
                                               registry_last_start=M.ft_str(s), db_latest_start=M.ft_str(last[k]),
                                               registry_is_newer=s >= last[k],
                                               same_event_in_db=s in starts[k]))
    vc = [c for c in res["value_checks"] if c["match"] is not None]
    res["summary"] = dict(value_pairs=len(vc), value_matches=sum(c["match"] for c in vc),
                          time_pairs=len(res["time_checks"]),
                          registry_newer=sum(c["registry_is_newer"] for c in res["time_checks"]),
                          registry_event_also_in_db=sum(c["same_event_in_db"] for c in res["time_checks"]))
    return res


# --------------------------------------------------------------------------- binaries / Amcache
def hash_binaries(cam: dict, path_map: list[tuple[str, str]] | None = None) -> list[dict]:
    """SHA-1 of the first 31,457,280 bytes of each BinaryFullPath (as Amcache computes FileID)."""
    out = []
    seen = set()
    for r in cam["identity"]:
        p = r["binary"]
        if not p or (p, r["sha1"]) in seen:
            continue
        seen.add((p, r["sha1"]))
        local = p
        for a, b in path_map or []:
            if local.lower().startswith(a.lower()):
                local = b + local[len(a):]
        d = dict(binary=p, checked_path=local, fileid_sha1=r["sha1"], exists=os.path.isfile(local))
        if d["exists"]:
            try:
                h = hashlib.sha1()
                with open(local, "rb") as f:
                    h.update(f.read(AMCACHE_HASH_LIMIT))
                d["sha1_first_30MiB"] = h.hexdigest()
                d["size"] = os.path.getsize(local)
                d["match"] = d["sha1_first_30MiB"] == r["sha1"]
                mt = os.path.getmtime(local)
                ft = int((mt + 11644473600) * 1e7)
                d["file_mtime_utc"] = M.ft_str(ft)
                d["first_observed_utc"] = r["first_observed_utc"]
                fo = r["raw"].get("LastObservedTime") or 0
                d["file_modified_after_fileid_recorded"] = ft > fo
                if not d["match"]:
                    d["interpretation"] = ("binary replaced/updated after the FileID was recorded: mismatch expected"
                                           if ft > fo else "binary NOT modified since, yet hash differs: investigate")
            except OSError as e:
                d["error"] = str(e)
        out.append(d)
    return out


def amcache_compare(cam: dict, csv_path: str) -> dict:
    """Compare FileIDs/ProgramIDs with an AmcacheParser (or similar) CSV export."""
    with open(csv_path, newline="", encoding="utf-8-sig", errors="replace") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        return dict(rows=0, matches=[])
    cols = {c.lower().replace(" ", ""): c for c in rows[0].keys()}
    sha_c = next((cols[c] for c in ("sha1", "fileid", "hash") if c in cols), None)
    path_c = next((cols[c] for c in ("fullpath", "lowercaselongpath", "path") if c in cols), None)
    prog_c = next((cols[c] for c in ("programid",) if c in cols), None)
    idx = defaultdict(list)
    for r in rows:
        v = (r.get(sha_c) or "").strip().lower()
        if v.startswith("0000") and len(v) == 44:
            v = v[4:]
        if v:
            idx[v].append(r)
    res = []
    for r in cam["identity"]:
        hits = idx.get(r["sha1"], [])
        res.append(dict(binary=r["binary"], sha1=r["sha1"], amcache_hits=len(hits),
                        amcache_path=hits[0].get(path_c, "") if hits else "",
                        amcache_programid=hits[0].get(prog_c, "") if hits and prog_c else "",
                        programid_match=(hits[0].get(prog_c, "").lower() == r["program_id"].lower()) if hits and prog_c else None))
    return dict(rows=len(rows), sha_column=sha_c, matches=res)
