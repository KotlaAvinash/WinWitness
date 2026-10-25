"""WinWitness command line. Run:  python winwitness_cli.py <evidence folder> -o <output folder>"""
from __future__ import annotations

import argparse
import json
import ntpath
import os
import shutil
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone

from . import corroborate as X
from . import engine as E
from . import model as M
from . import report as R
from . import views as V
from . import xlsx as XL
from .ntfs_i30 import parse_i30

METHOD_HTML = """
<ol>
<li><b>Intake.</b> Every input is hashed (SHA-256, MD5) and read once into memory. Inputs are never opened for writing.
After the run they are hashed again and the report states whether anything changed.</li>
<li><b>Two independent readers.</b> WinWitness walks the SQLite b-trees itself (main file + valid WAL frames) and, separately,
lets the <code>sqlite3</code> library read a <i>temporary copy</i>. Both results are compared table by table.
(Opening the original with any SQLite tool checkpoints the WAL and can truncate the file, destroying recoverable pages.)</li>
<li><b>WAL history.</b> Frames are checksum-verified. The database is rebuilt at the last checkpoint and after every committed
transaction; consecutive states are diffed row by row (INSERT / UPDATE / DELETE). WAL file slack is checked for frames that
continue the same salt + checksum chain; such rows are reported separately, never merged into the live data.</li>
<li><b>Carving.</b> Record signatures are generated from the evidence's own CREATE TABLE statements (so rows written before
an ALTER TABLE, which have fewer columns, are found too). Searched areas: freeblocks and unallocated space in every b-tree
page, freelist/orphan pages, pages past the logical end of file, superseded and invalid WAL frames, WAL tail, and *.FileSlack.
The row ID is recovered only when the cell's payload-length varint matches the record length exactly; otherwise it is
reported as lost. Index-page residue is interpreted as (key, rowid), not as table rows.</li>
<li><b>Classification.</b> Each carved record is compared with the live data: LIVE-DUPLICATE, HISTORICAL-VERSION (same ID,
different values), DELETED, DELETED (ID lost), RECOVERED (WAL slack txn), INDEX-RESIDUE.</li>
<li><b>Decoding.</b> FILETIME → UTC (and the chosen local offset). Foreign keys resolved through the lookup tables;
a key whose lookup row was purged is shown as <code>&lt;unresolved … purged&gt;</code>, never guessed.
Consent Value 1/2/3 = Allow/Deny/Prompt was <i>measured</i> against a live ConsentStore registry (186/186 values, build 26200).</li>
<li><b>Checks &amp; corroboration.</b> ID gaps, orphaned lookup values, time sanity, ID-vs-time order per stream
(clock-change test), Label transitions, identity-vs-prompt times, usage vs consent, $I30 sizes/times, and optionally the
ConsentStore registry (live or .reg), SHA-1 of the binaries (first 31,457,280 bytes, as Amcache) and an Amcache CSV.</li>
</ol>
<h3>Limits</h3>
<ul>
<li>The most recent access per app/capability lives in the ConsentStore <b>registry</b>, not the database: it is moved to the
database only when the same app uses the same capability again [published]. Use <code>--registry</code> to see it.</li>
<li>History is purged after ExpirationPolicyInDays (default 30) [published]; absence of a row is not absence of activity.</li>
<li>Location rows record use of the Windows location API only; an app can learn location by other means.</li>
<li>FileID is taken from Amcache when the row is written, so it can reflect the binary at that later moment [published].</li>
<li>Carved records whose first bytes were overwritten (freeblock header) keep their values but lose their ID.</li>
<li>Meaning of <code>Label</code>, <code>Context</code> and <code>AccessGUID</code> is undocumented; they are shown raw.</li>
<li>*.FileSlack with ~8 bits/byte entropy carries no SQLite structure; it is still scanned.</li>
</ul>
"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="winwitness", description="WinWitness: forensic parser for Windows CapabilityAccessManager.db "
                                 "and CapabilityConsentStorage.db (with WAL, slack and carving).")
    ap.add_argument("evidence", help="folder holding the databases (or the path of one .db file)")
    ap.add_argument("-o", "--out", help="output folder (default: ./winwitness_output_<UTC time>)")
    ap.add_argument("--tz", default="+00:00", help="offset for the local-time column, e.g. +05:30 (default UTC)")
    ap.add_argument("--registry", help="'live' to read this machine's HKCU/HKLM ConsentStore, or a .reg export file")
    ap.add_argument("--hash-binaries", action="store_true",
                    help="hash binaries named in BinaryFullPaths on this machine (SHA-1 of first 30 MiB)")
    ap.add_argument("--path-map", action="append", default=[], metavar="FROM=TO",
                    help="rewrite a path prefix before hashing, e.g. C:\\=E:\\mounted\\ (repeatable)")
    ap.add_argument("--amcache-csv", help="AmcacheParser CSV to compare FileIDs/ProgramIDs with")
    ap.add_argument("--no-carve", action="store_true", help="skip carving (faster)")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("--version", action="version", version=f"{E.TOOL_NAME} {E.TOOL_VERSION}")
    a = ap.parse_args(argv)
    try:
        tz = M.parse_tz(a.tz)
    except ValueError as ex:
        ap.error(str(ex))
    return run(a, tz)


def run(a, tz) -> int:
    t0 = time.time()
    ev = os.path.abspath(a.evidence)
    if os.path.isfile(ev):
        roles = {}
        base = os.path.basename(ev)
        for r in (M.CAM_DB, M.CONSENT_DB):
            if base.lower() == r.lower():
                for suf in ("", "-wal", "-shm", ".FileSlack", "-wal.FileSlack", "-shm.FileSlack"):
                    if os.path.exists(ev + suf):
                        roles[r + suf] = ev + suf
        if not roles:
            print(f"error: {ev} is not named {M.CAM_DB} or {M.CONSENT_DB}", file=sys.stderr)
            return 2
        ev_dir = os.path.dirname(ev)
    elif os.path.isdir(ev):
        roles = E.discover(ev)
        ev_dir = ev
    else:
        print(f"error: {ev} not found", file=sys.stderr)
        return 2
    if M.CAM_DB not in roles and M.CONSENT_DB not in roles:
        print(f"error: no {M.CAM_DB} or {M.CONSENT_DB} in {ev}", file=sys.stderr)
        return 2

    out = os.path.abspath(a.out or os.path.join(os.getcwd(), "winwitness_output_" +
                                                 datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")))
    for p in roles.values():
        if os.path.abspath(p).startswith(out + os.sep):
            print("error: output folder must not contain the evidence", file=sys.stderr)
            return 2
    os.makedirs(out, exist_ok=True)
    os.makedirs(os.path.join(out, "csv"), exist_ok=True)
    logf = open(os.path.join(out, "run_log.txt"), "w", encoding="utf-8")

    def log(msg):
        line = f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}Z  {msg}"
        logf.write(line + "\n")
        logf.flush()
        if not a.quiet:
            print(line)

    log(f"{E.TOOL_NAME} {E.TOOL_VERSION}  evidence={ev}  out={out}  tz={a.tz}")
    files = {}
    for role, p in sorted(roles.items()):
        files[role] = E.load_evidence(p)
        f = files[role]
        log(f"intake {role:42s} {f.size:>10,} bytes sha256={f.sha256}")

    tmp = tempfile.mkdtemp(prefix="winwitness_")
    A = C = None
    try:
        if M.CAM_DB in files:
            try:
                A = E.analyze_db(M.CAM_DB, files[M.CAM_DB], files.get(M.CAM_DB + "-wal"), files.get(M.CAM_DB + "-shm"),
                                 tmp, log, files.get(M.CAM_DB + "-wal.FileSlack"))
            except Exception as ex:
                log(f"ERROR {M.CAM_DB}: {type(ex).__name__}: {ex}")
        if M.CONSENT_DB in files:
            try:
                C = E.analyze_db(M.CONSENT_DB, files[M.CONSENT_DB], files.get(M.CONSENT_DB + "-wal"),
                                 files.get(M.CONSENT_DB + "-shm"), tmp, log, files.get(M.CONSENT_DB + "-wal.FileSlack"))
            except Exception as ex:
                log(f"ERROR {M.CONSENT_DB}: {type(ex).__name__}: {ex}")
        if A is None and C is None:
            log("nothing could be parsed")
            return 1
        if not a.no_carve:
            for D in (A, C):
                if D:
                    slack = [files[k] for k in files if k.startswith(D.name) and k.endswith("FileSlack")]
                    E.carve_db(D, slack, log)
        i30 = parse_i30(files["$I30"].data) if "$I30" in files else None
        if i30:
            log(f"$I30: {i30['records']} INDX record(s), {len(i30['entries'])} entries, errors={i30['errors']}")
        cam = X.decode_cam(A, tz) if A else None
        consent = X.decode_consent(C) if C else None
        cam_sid = None
        if cam and cam["lookups"]["Users"]:
            cam_sid = sorted(cam["lookups"]["Users"].values())[0]

        corr = []
        # ---- optional registry sources: offline hives in the evidence folder, then --registry
        from .regf import Hive
        software = None
        if "SOFTWARE" in files:
            try:
                software = X.read_software_hive(Hive(files["SOFTWARE"].data))
                log(f"SOFTWARE hive: {len(software['profiles'])} profiles, {len(software['uninstall'])} installed "
                    f"programs, OS {software['os'].get('product')} {software['os'].get('display_version')} "
                    f"build {software['os'].get('build')}")
                if software["usage_history_settings"]:
                    corr.append(("CapabilityUsageHistory settings (SOFTWARE hive)", [software["usage_history_settings"]]))
            except Exception as ex:          # a damaged hive must never stop the run
                log(f"SOFTWARE: skipped ({type(ex).__name__}: {ex})")
                software = None
        reg_sources = []
        for role in sorted(k for k in files if k.startswith("NTUSER.DAT:")):
            try:
                r = X.read_hive_consentstore(Hive(files[role].data), role)
            except Exception as ex:
                log(f"{role}: skipped ({type(ex).__name__}: {ex})")
                continue
            parent = os.path.basename(os.path.dirname(files[role].path)).lower()
            for sid, prof in (software or {}).get("profiles", {}).items():
                if parent and ntpath.basename(prof.rstrip("\\/")).lower() == parent:
                    r["sid"] = sid
            for e in r["entries"]:
                e["sid"] = r["sid"]
            log(f"{role}: {len(r['entries'])} ConsentStore keys (account {r['sid'] or 'not identified'})")
            reg_sources.append(r)
        if software and software["consent_entries"]:
            reg_sources.append(dict(source="offline hive SOFTWARE", sid=None, entries=software["consent_entries"]))
        if a.registry:
            try:
                reg_sources.append(X.read_live_registry() if a.registry.lower() == "live"
                                   else X.parse_reg_export(a.registry))
            except Exception as ex:
                log(f"registry input failed: {type(ex).__name__}: {ex}")
        reg = None
        if reg_sources:
            reg = dict(source=" + ".join(r["source"] for r in reg_sources),
                       sid=next((r["sid"] for r in reg_sources if r.get("sid")), None),
                       entries=[e for r in reg_sources for e in r["entries"]],
                       usage_history_settings=next((r.get("usage_history_settings") for r in reg_sources
                                                    if r.get("usage_history_settings")), None))
            for r in reg_sources:
                rc = X.compare_registry(r, consent, cam, cam_sid)
                s_ = rc["summary"]
                log(f"registry: {len(r['entries'])} keys from {r['source']}; same user as evidence={rc['same_user']}; "
                    f"Value matches {s_['value_matches']}/{s_['value_pairs']}; registry newer than DB "
                    f"{s_['registry_newer']}/{s_['time_pairs']}")
                corr.append((f"ConsentStore registry vs consent DB ({r['source']}; registry SID {rc['sid']}; "
                             f"same user as evidence: {rc['same_user']})", rc["value_checks"]))
                corr.append((f"Registry last-use vs newest DB row ({r['source']})", rc["time_checks"]))
                if r.get("usage_history_settings"):
                    corr.append(("CapabilityUsageHistory settings (HKLM; DatabaseRoot / retention)",
                                 [r["usage_history_settings"]]))
        if a.hash_binaries and cam:
            pm = [tuple(x.split("=", 1)) for x in a.path_map if "=" in x]
            hb = X.hash_binaries(cam, pm)
            log(f"binary hashing: {sum(1 for h in hb if h['exists'])}/{len(hb)} present, "
                f"{sum(1 for h in hb if h.get('match'))} FileID matches")
            corr.append(("FileID vs SHA-1 (first 31,457,280 bytes) of the binary on disk", hb))
        if a.amcache_csv and cam:
            am = X.amcache_compare(cam, a.amcache_csv)
            corr.append((f"Amcache CSV ({am['rows']} rows, hash column {am.get('sha_column')})", am["matches"]))
        if i30:
            corr.append(("$I30 directory index entries", i30["entries"]))

        findings = X.run_checks(A, C, cam, consent, i30, list(files.values()))
        sev_order = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
        findings.sort(key=lambda f: sev_order.get(f["severity"], 3))
        timeline = X.build_timeline(cam, consent, i30, A, reg, tz)

        # ------------------------------------------------------------- integrity re-check
        changed = []
        for role, f in files.items():
            sha, _md5, _n = E.hash_file(f.path)
            if sha != f.sha256:
                changed.append(role)
        integrity_ok = not changed
        log("integrity: all inputs unchanged" if integrity_ok else f"INTEGRITY FAILURE: {changed}")

        # ------------------------------------------------------------- outputs
        ev_rows = [dict(role=k, name=f.name, size=f.size, sha256=f.sha256, md5=f.md5, mtime_utc=f.mtime_utc,
                        path=f.path, unchanged_after_run=k not in changed) for k, f in files.items()]
        usage = sorted(cam["usage"], key=lambda u: u["start_utc"] or "") if cam else []
        carved_all = []
        wal_changes = []
        raw = {}
        structure = []
        for D in (A, C):
            if not D:
                continue
            for c in D.carved:
                carved_all.append(dict(db=D.name, status=c.status, table=c.table, rowid=c.rowid, id_basis=c.rowid_basis,
                                       columns=c.columns, values=c.values, source=c.source, file=c.file, offset=c.offset,
                                       note=c.note, seen_at=c.extra.get("seen_at")))
            for w in D.wal_changes:
                wal_changes.append(dict(db=D.name, **w))
            for t, rows in D.tables.items():
                raw[f"{D.name}:{t}"] = [{k: v for k, v in r.items() if k not in ("_page",)} for r in rows]
            h = D.header
            structure.append((f"{D.name}: header", [dict(page_size=h.page_size, page_count_header=h.page_count,
                              file_pages=len(D.main.data) // h.page_size, change_counter=h.change_counter,
                              freelist_trunk=h.freelist_trunk, freelist_pages=h.freelist_count,
                              schema_cookie=h.schema_cookie, user_version=h.user_version, text_encoding=h.text_encoding,
                              auto_vacuum=bool(h.auto_vacuum_root), sqlite_version=h.sqlite_version_str,
                              journal_mode="WAL" if h.write_version == 2 else "rollback")]))
            structure.append((f"{D.name}: page map", D.page_map))
            if D.wal_info:
                w = D.wal_info
                structure.append((f"{D.name}-wal: frames", [dict(frame=f.index, offset=f.offset, page=f.pgno,
                                  commit_size=f.commit_size, salt_ok=f.salt_ok, checksum_ok=f.cksum_ok, valid=f.valid,
                                  txn=f.txn, in_slack=f.in_slack, page_type=f.data[100 if f.pgno == 1 else 0])
                                  for f in w.frames if f.pgno and f.salt_ok]))
                structure.append((f"{D.name}-wal: header", dict(magic=hex(w.magic), version=w.version, page_size=w.page_size,
                                  checkpoint_seq=w.checkpoint_seq, salt1=hex(w.salt1), salt2=hex(w.salt2),
                                  header_checksum_ok=w.header_cksum_ok, frames_in_file=sum(1 for f in w.frames if not f.in_slack),
                                  frames_scanned_in_slack=sum(1 for f in w.frames if f.in_slack))))
            if D.shm_info:
                structure.append((f"{D.name}-shm: wal-index header", D.shm_info))
            structure.append((f"{D.name}: schema", [dict(type=s["type"], name=s["name"], rootpage=s["rootpage"], sql=s["sql"])
                                                   for s in D.schema]))
            if D.errors:
                structure.append((f"{D.name}: parser notes", [dict(note=x) for x in D.errors]))
        carved_usage = cam["carved_usage"] if cam else []
        n_del = sum(1 for c in carved_all if c["status"].startswith(("DELETED", "RECOVERED", "HISTORICAL")))
        cards = [("live usage rows", len(usage)), ("recovered usage rows", len(carved_usage)),
                 ("all non-live carved records", n_del), ("WAL row changes", len(wal_changes)),
                 ("location prompts", len(cam["prompts"]) if cam else 0),
                 ("binaries (identities)", len(cam["identity"]) if cam else 0),
                 ("consent rows", sum(len(v) for v in consent.values()) if consent else 0),
                 ("HIGH findings", sum(1 for f in findings if f["severity"] == "HIGH")),
                 ("inputs unchanged", "yes" if integrity_ok else "NO")]
        if usage:
            cards.insert(0, ("live usage span (UTC)", f"{usage[0]['start_utc'][:10]} → {usage[-1]['start_utc'][:10]}"))

        csvd = os.path.join(out, "csv", "technical")
        os.makedirs(csvd, exist_ok=True)
        outputs = dict(findings=findings, timeline=timeline, usage=usage, carved_usage=carved_usage,
                       carved_all=carved_all, wal_changes=wal_changes, evidence=ev_rows)
        if cam:
            outputs.update(prompts=cam["prompts"], identity=cam["identity"], packaged_prompts=cam["packaged_prompts"])
        if consent:
            for t, rows in consent.items():
                outputs[f"consent_{t}"] = rows
        for t, rows in raw.items():
            outputs["raw_" + t.split(".db:")[0].replace("Capability", "") + "_" + t.split(":")[1]] = rows
        for name, rows in outputs.items():
            R.write_csv(os.path.join(csvd, name + ".csv"), rows)
        for title, rows in corr:
            if isinstance(rows, list):
                safe = "".join(ch if ch.isalnum() else "_" for ch in title)[:60].strip("_")
                R.write_csv(os.path.join(csvd, "corroboration_" + safe + ".csv"), rows)

        # ------------------------------------------------------------- analyst views (v2)
        names = {}
        for sid, prof in (software or {}).get("profiles", {}).items():
            names[sid] = ntpath.basename(prof.rstrip("\\/"))
        empty_cam = dict(usage=[], carved_usage=[], prompts=[], identity=[], packaged_prompts=[], lookups={})
        activity = V.build_activity(cam or empty_cam, A.wal_changes if A else [], reg, names, tz,
                                    consent=consent, software=software)
        apps = V.app_summary(activity)
        services = V.feature_view(activity)
        perms = V.permission_view(consent, reg, activity, names)
        programs = V.program_view(cam or empty_cam, activity, software)
        recovered = [r for r in activity if r["source"].startswith("Recovered")]
        for tname, (cols, rows) in V.analyst_tables(activity, apps, services, perms, programs, recovered,
                                                    findings).items():
            R.write_table_csv(os.path.join(out, tname + ".csv"), cols, rows)
        XL.write_xlsx(os.path.join(out, "WinWitness_activity.xlsx"),
                      [(title, [c[0] for c in cols], [[r.get(c[1], "") for c in cols] for r in rows])
                       for title, (cols, rows) in zip(V.SHEET_TITLES, V.analyst_tables(
                           activity, apps, services, perms, programs, recovered, findings).values())])
        outputs.update(activity=activity, apps=apps, services=services, permissions=perms, programs=programs)
        R.write_sqlite(os.path.join(out, "winwitness_results.sqlite"), {k: v for k, v in outputs.items()})
        with open(os.path.join(out, "winwitness_results.json"), "w", encoding="utf-8") as jf:
            json.dump(dict(tool=f"{E.TOOL_NAME} {E.TOOL_VERSION}", evidence=ev_rows, findings=findings,
                           activity=activity, apps=apps, services=services, permissions=perms, programs=programs,
                           usage=usage, carved=carved_all, wal_changes=wal_changes,
                           consent=consent, prompts=cam["prompts"] if cam else [],
                           identity=cam["identity"] if cam else [], timeline=timeline,
                           corroboration={t: r for t, r in corr}), jf, indent=1, default=str, ensure_ascii=False)
        tzlabel = a.tz if a.tz not in ("+00:00", "UTC") else "+00:00"
        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        R.write_html(os.path.join(out, "WinWitness_technical_report.html"), dict(
            tool=f"{E.TOOL_NAME} {E.TOOL_VERSION}", generated_utc=generated,
            evidence_dir=ev_dir, tz_label=tzlabel, cards=cards, findings=findings, evidence=ev_rows,
            integrity_ok=integrity_ok, timeline=timeline, usage=usage, carved_usage=carved_usage, carved_all=carved_all,
            wal_changes=wal_changes, prompts=cam["prompts"] if cam else [], identity=cam["identity"] if cam else [],
            consent=consent or {}, corroboration=corr, structure=structure, raw=raw, method_html=METHOD_HTML))
        R.write_html_v2(os.path.join(out, "WinWitness_report.html"), dict(
            tool=f"{E.TOOL_NAME} {E.TOOL_VERSION}", generated_utc=generated, evidence_dir=ev_dir, tz_label=tzlabel,
            summary=V.summary(activity, software, names), activity=activity, apps=apps, features=services,
            permissions=perms, programs=programs, findings=findings, evidence=ev_rows, integrity_ok=integrity_ok,
            technical_report="WinWitness_technical_report.html", method_html=METHOD_HTML))
        log(f"wrote WinWitness_report.html, WinWitness_activity.xlsx, {len(V.SHEET_TITLES)} analyst CSVs, {len(outputs)} technical "
            f"CSVs, SQLite and JSON in {time.time() - t0:.2f}s ({len(activity)} timeline events)")
        log("findings: " + ", ".join(f"{k}={v}" for k, v in Counter(f['severity'] for f in findings).items()))
        logf.close()
        R.manifest(out)
        if not a.quiet:
            print(f"\nReport: {os.path.join(out, 'WinWitness_report.html')}")
        return 0 if integrity_ok else 3
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        if not logf.closed:
            logf.close()


if __name__ == "__main__":
    sys.exit(main())
