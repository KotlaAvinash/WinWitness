"""Analyst views: turn decoded CAM data into "which app used which service, when, for how long".

Inputs are the outputs of corroborate.decode_cam() / decode_consent(), the engine's WAL diff,
an optional merged registry dict (offline hives, live registry or .reg) and an optional parsed
SOFTWARE hive. Nothing here guesses: unknown values are labelled as unknown.
"""
from __future__ import annotations

import ntpath
import re
from collections import Counter, defaultdict

from . import model as M

# id -> (label, plain-language description, icon key used by the report)
SERVICES = {
    "webcam": ("Camera", "Captured video from a camera (built-in or USB webcam)", "camera"),
    "microphone": ("Microphone", "Recorded or listened to audio from a microphone", "mic"),
    "location": ("Location", "Asked Windows for the device's location", "pin"),
    "contacts": ("Contacts", "Read the user's contacts (People)", "people"),
    "appointments": ("Calendar", "Read or changed calendar appointments", "calendar"),
    "email": ("Email", "Read or sent email through Windows email accounts", "mail"),
    "chat": ("Messages", "Read or sent text messages (SMS/MMS)", "chat"),
    "phoneCall": ("Phone calls", "Placed phone calls", "phone"),
    "phoneCallHistory": ("Call history", "Read phone call history", "phone"),
    "userAccountInformation": ("Account info", "Read the user's name, picture and account info", "user"),
    "userDataTasks": ("Tasks", "Read or changed the user's tasks", "check"),
    "userNotificationListener": ("Notifications", "Read the user's notifications", "bell"),
    "radios": ("Radios", "Turned radios (Bluetooth, Wi-Fi) on or off", "radio"),
    "bluetooth": ("Bluetooth", "Communicated with Bluetooth devices", "radio"),
    "bluetoothSync": ("Bluetooth sync", "Synced with unpaired Bluetooth devices", "radio"),
    "wifiData": ("Wi-Fi data", "Used Wi-Fi network data", "wifi"),
    "wiFiDirect": ("Wi-Fi Direct", "Connected directly to Wi-Fi Direct devices", "wifi"),
    "cellularData": ("Cellular data", "Used mobile (cellular) data", "wifi"),
    "documentsLibrary": ("Documents", "Accessed the Documents library", "file"),
    "picturesLibrary": ("Pictures", "Accessed the Pictures library", "image"),
    "videosLibrary": ("Videos", "Accessed the Videos library", "film"),
    "musicLibrary": ("Music", "Accessed the Music library", "music"),
    "broadFileSystemAccess": ("File system", "Accessed the whole file system", "file"),
    "activity": ("Activity history", "Read the user's activity history", "clock"),
    "appDiagnostics": ("App diagnostics", "Read diagnostic info about other apps", "chip"),
    "gazeInput": ("Eye tracker", "Used an eye-tracking device", "eye"),
    "humanInterfaceDevice": ("HID devices", "Talked to human-interface devices", "chip"),
    "serialCommunication": ("Serial ports", "Talked to serial-port devices", "chip"),
    "usb": ("USB devices", "Talked to USB devices directly", "chip"),
    "sensors.custom": ("Custom sensors", "Read custom sensors", "chip"),
    "graphicsCaptureWithoutBorder": ("Screen capture (no border)",
                                     "Captured the screen or a window without the yellow capture border "
                                     "(e.g. Snipping Tool)", "screen"),
    "graphicsCaptureProgrammatic": ("Screen capture (programmatic)",
                                    "Captured the screen or a window programmatically", "screen"),
    "passkeys": ("Passkey use", "Used a passkey stored in Windows to sign in to a website", "key"),
    "passkeysEnumeration": ("Passkey list", "Listed the passkeys stored in Windows", "key"),
    "systemAIModels": ("On-device AI", "Used Windows on-device AI models", "chip"),
}

KNOWN_PACKAGES = {
    "microsoft.windowscommunicationsapps": "Mail and Calendar", "microsoft.screensketch": "Snipping Tool",
    "microsoft.windowscamera": "Camera", "msteams": "Microsoft Teams", "microsoft.windowssoundrecorder": "Sound Recorder",
    "microsoft.windowsmaps": "Maps", "microsoft.bingweather": "Weather", "microsoft.bingnews": "News",
    "microsoft.people": "People", "microsoft.xboxgamingoverlay": "Xbox Game Bar", "microsoft.gamingapp": "Xbox",
    "microsoft.windows.photos": "Photos", "microsoft.windowsnotepad": "Notepad", "microsoft.office.onenote": "OneNote",
    "microsoft.microsoftofficehub": "Microsoft 365 (Office)", "microsoft.startexperiencesapp": "Start / Widgets experiences",
    "microsoftwindows.client.webexperience": "Widgets", "microsoftwindows.client.cbs": "Windows shell (Start, Search)",
    "microsoftwindows.crossdevice": "Cross-device experience (Phone Link)", "microsoft.yourphone": "Phone Link",
    "windows.immersivecontrolpanel": "Settings", "telegrammessengerllp.telegramdesktop": "Telegram",
    "clipchamp.clipchamp": "Clipchamp", "appleinc.applemusicwin": "Apple Music", "openai.codex": "OpenAI Codex",
    "claude": "Claude", "microsoft.mixedreality.portal": "Mixed Reality Portal", "5319275a.whatsappdesktop": "WhatsApp",
    "microsoft.skypeapp": "Skype", "microsoft.windowsstore": "Microsoft Store", "microsoft.zunemusic": "Media Player",
    "microsoft.zunevideo": "Movies & TV", "microsoft.windowsfeedbackhub": "Feedback Hub",
    "microsoft.windowsalarms": "Clock", "microsoft.windowscalculator": "Calculator", "microsoft.todos": "Microsoft To Do",
    "microsoft.mspaint": "Paint", "microsoft.gethelp": "Get Help", "microsoft.secHealthUI".lower(): "Windows Security",
    "e046963f.lenovocompanion": "Lenovo Vantage", "samsungelectronicscoltd.samsungflux": "Samsung Flow",
    "samsungelectronicsco.ltd.samsungaccount": "Samsung Account", "a-volute.nahimic": "Nahimic",
}
KNOWN_EXES = {
    "brave.exe": "Brave", "chrome.exe": "Google Chrome", "msedge.exe": "Microsoft Edge", "firefox.exe": "Firefox",
    "teams.exe": "Microsoft Teams (classic)", "ms-teams.exe": "Microsoft Teams", "zoom.exe": "Zoom",
    "discord.exe": "Discord", "code.exe": "Visual Studio Code", "steamwebhelper.exe": "Steam",
    "protonvpn.exe": "Proton VPN", "protonvpn.client.exe": "Proton VPN", "dllhost.exe": "COM Surrogate (dllhost)",
    "obs64.exe": "OBS Studio", "slack.exe": "Slack", "whatsapp.exe": "WhatsApp", "skype.exe": "Skype",
    "nvidia app.exe": "NVIDIA app", "nvidia overlay.exe": "NVIDIA Overlay",
    "nvidia geforce experience.exe": "NVIDIA GeForce Experience", "balenaetcher.exe": "balenaEtcher",
    "lenovovantage-(lenovosecurityaddin).exe": "Lenovo Vantage (Security add-in)", "telegram.exe": "Telegram",
    "opera.exe": "Opera", "vivaldi.exe": "Vivaldi", "webex.exe": "Webex", "anydesk.exe": "AnyDesk",
    "teamviewer.exe": "TeamViewer",
}
WELL_KNOWN_SIDS = {"S-1-5-18": "SYSTEM", "S-1-5-19": "LOCAL SERVICE", "S-1-5-20": "NETWORK SERVICE", "SYSTEM": "SYSTEM"}
_PURGED = re.compile(r"^<unresolved \w+ ID (\d+): purged>")
INSTALLER_STORE = "Microsoft Store / Windows package (no installer path recorded)"
INSTALLER_NONE = "not recorded in CAM (add the SOFTWARE hive)"
SOURCE_DB, SOURCE_WAL = "Database", "Database (WAL, not yet in .db)"
SOURCE_DEL, SOURCE_SLACK = "Recovered (deleted)", "Recovered (WAL slack)"
SOURCE_REG, SOURCE_BOTH, SOURCE_PROMPT = "Registry (last use)", "Database + Registry", "Location prompt"


# --------------------------------------------------------------------------- labels
def feature_label(cap: str) -> str:
    m = _PURGED.match(cap or "")
    if m:
        return f"unknown service (purged, ID {m.group(1)})"
    return SERVICES.get(cap, (cap,))[0] if cap else ""


def service_desc(cap: str) -> str:
    return SERVICES[cap][1] if cap in SERVICES else ""


def service_icon(cap: str) -> str:
    return SERVICES[cap][2] if cap in SERVICES else "dot"


def app_label(app_id: str, app_name: str = "") -> str:
    if app_name and not app_name.startswith("<"):
        return app_name.replace("  [carved]", "")
    if not app_id:
        return "unknown app"
    if app_id.startswith("sha1:"):
        return f"unknown program (SHA-1 {app_id[5:15]}…)"
    m = _PURGED.match(app_id)
    if m:
        return f"unknown app (purged, ID {m.group(1)})"
    if "\\" in app_id or app_id.lower().endswith(".exe"):
        exe = ntpath.basename(app_id)
        return KNOWN_EXES.get(exe.lower(), exe[:-4] if exe.lower().endswith(".exe") else exe)
    name = app_id.split("_")[0] if "_" in app_id else app_id
    if name.lower() in KNOWN_PACKAGES:
        return KNOWN_PACKAGES[name.lower()]
    return name.split(".")[-1] or name


def user_label(sid: str, names: dict) -> str:
    if not sid:
        return ""
    if sid in names:
        return f"{names[sid]} ({sid})"
    if sid.upper() in WELL_KNOWN_SIDS:
        return f"{WELL_KNOWN_SIDS[sid.upper()]} ({sid})"
    return sid


def duration_text(s) -> str:
    if s in ("", None):
        return ""
    s = float(s)
    if s <= 0:
        return "instant"
    if s < 60:
        return f"{s:.1f} s"
    if s < 3600:
        m, sec = divmod(int(round(s)), 60)
        return f"{m} min {sec} s" if sec else f"{m} min"
    h, rem = divmod(int(round(s)), 3600)
    return f"{h} h {rem // 60} min"


def app_location(app_id: str, kind: str) -> tuple[str, bool]:
    """(location, derived?) - Store apps only have a package name in CAM, so the folder is derived."""
    if kind == "nonpackaged" or "\\" in (app_id or ""):
        return app_id, False
    if not app_id or app_id.startswith("<"):
        return "", False
    if "_" not in app_id:
        return "", False
    name, pub = app_id.rsplit("_", 1)
    if pub.lower() == "cw5n1h2txyewy":
        return rf"C:\Windows\SystemApps\{name}_{pub}", True
    return rf"C:\Program Files\WindowsApps\{name}_<version>_<arch>__{pub}", True


def location_flag(path: str) -> str:
    p = (path or "").lower()
    if not p or "\\" not in p:
        return ""
    if "\\temp\\" in p or "\\tmp\\" in p:
        return "Temp folder"
    if "\\downloads\\" in p:
        return "Downloads"
    if re.match(r"^[a-z]:", p) and not p.startswith("c:"):
        return f"Other drive ({p[0].upper()}:)"
    return ""


# --------------------------------------------------------------------------- consent lookup
class _Consent:
    def __init__(self, consent: dict | None, reg: dict | None):
        c = consent or {}
        low = lambda *x: tuple(str(v).lower() for v in x)  # noqa: E731
        self.app = {low(r["Capability"], r["User"], r["PackageFamily"]): r for r in c.get("App", [])}
        self.classic = {low(r["Capability"], r["User"]): r for r in c.get("ClassicGlobal", [])}
        self.user = {low(r["Capability"], r["User"]): r for r in c.get("UserGlobal", [])}
        self.system = {low(r["Capability"]): r for r in c.get("SystemGlobal", [])}
        self.reg = {}
        for e in (reg or {}).get("entries", []):
            if e.get("app") not in ("(global)", "NonPackaged (default)"):
                self.reg[low(e["capability"], e["app"])] = e

    def allowed_by(self, cap: str, sid: str, app_id: str, kind: str) -> str:
        cap_, sid_, app_ = str(cap).lower(), str(sid).lower(), str(app_id).lower()
        meaning = lambda r: r.get("Value_meaning") or M.CONSENT_VALUE.get(r.get("Value"), str(r.get("Value")))  # noqa
        if kind == "packaged" and (cap_, sid_, app_) in self.app:
            return f"App setting (this account): {meaning(self.app[(cap_, sid_, app_)])}"
        r = self.reg.get((cap_, app_))
        if r is not None and r.get("Value"):
            return f"Registry app setting: {r['Value']}"
        if kind == "nonpackaged" and (cap_, sid_) in self.classic:
            return f"Desktop-apps switch (this account): {meaning(self.classic[(cap_, sid_)])}"
        if (cap_, sid_) in self.user:
            return f"User default (this account): {meaning(self.user[(cap_, sid_)])}"
        if (cap_,) in self.system:
            return f"System default: {meaning(self.system[(cap_,)])}"
        return "not recorded"

    def reg_entry(self, cap: str, app_id: str):
        return self.reg.get((str(cap).lower(), str(app_id).lower()))


def _installer(app_id: str, kind: str, software: dict | None) -> str:
    if kind == "packaged":
        return INSTALLER_STORE
    if not software:
        return INSTALLER_NONE
    exe = (app_id or "").lower()
    for u in software.get("uninstall", []):
        loc = (u.get("install_location") or "").strip('"').rstrip("\\").lower()
        icon = (u.get("display_icon") or "").split(",")[0].strip('"').lower()
        if (loc and exe.startswith(loc + "\\")) or (icon and icon == exe):
            src = u.get("install_source") or "(install source not recorded)"
            bits = [b for b in (u.get("name"), u.get("version")) if b]
            extra = " ".join(bits)
            if u.get("publisher"):
                extra += f" by {u['publisher']}"
            if u.get("install_date"):
                extra += f", installed {u['install_date']}"
            return f"{src} — {extra}"
    return "no matching installed-program entry in SOFTWARE"


# --------------------------------------------------------------------------- activity timeline
def build_activity(cam: dict, wal_changes: list, reg: dict | None, names: dict, tz, consent: dict | None = None,
                   software: dict | None = None) -> list[dict]:
    cons = _Consent(consent, reg)
    wal_ins = {(w["table"], w["rowid"]) for w in wal_changes or []
               if w.get("change") == "INSERT" and not w.get("from_slack")}
    rows = []

    def base(app_id, kind, cap, sid, start, stop, access, source, ref, sha1="", app_name="", event="use"):
        loc, derived = app_location(app_id, kind)
        when_utc, end_utc = M.ft_str(start) if start else "", M.ft_str(stop) if stop else ""
        dur = round((stop - start) / 1e7, 3) if start and stop and stop >= start else ""
        r = dict(event=event, when_utc=when_utc, end_utc=end_utc if event == "use" else "",
                 when_local=M.ft_str(start, tz) if start else "", end_local=M.ft_str(stop, tz) if stop and event == "use" else "",
                 duration_s=dur, duration_text=duration_text(dur) if event == "use" else "",
                 app=app_label(app_id, app_name), app_id=app_id, app_kind="Store app" if kind == "packaged" else "Desktop program",
                 feature=feature_label(cap), feature_id=cap, service_desc=service_desc(cap), access=access,
                 user=user_label(sid, names), sid=sid, allowed_by=cons.allowed_by(cap, sid, app_id, kind) if event == "use" else "",
                 source=source, app_location=loc + ("  (derived)" if derived else ""), installer=_installer(app_id, kind, software),
                 sha1=sha1, ref=ref, note="", use_no="", _start=start or 0, _stop=stop or 0, _kind=kind)
        r["date"] = (r["when_local"] or r["when_utc"])[:10]
        e = cons.reg_entry(cap, app_id) if event == "use" else None
        if e is not None and e.get("key_last_write") and stop and e["key_last_write"] > stop:
            r["note"] = (f"setting changed after this use (registry key last written "
                         f"{M.ft_str(e['key_last_write'])} UTC)")
        return r

    for u in cam.get("usage", []) + cam.get("carved_usage", []):
        st = u.get("status", "")
        if u.get("source") == "carved":
            source = SOURCE_SLACK if st.startswith("RECOVERED") else SOURCE_DEL
        else:
            source = SOURCE_WAL if (u["table"], u["ID"]) in wal_ins else SOURCE_DB
        raw = u.get("raw", {})
        rows.append(base(u["app"], u["kind"], u["capability"], u.get("user_sid", ""), raw.get("LastUsedTimeStart"),
                         raw.get("LastUsedTimeStop"), u.get("access", ""), source, f"{u['table']} ID {u['ID']}",
                         u.get("sha1", ""), u.get("app_name", "")))
    # registry last-use events: merge with identical DB events, add the rest
    index = {(r["feature_id"].lower(), r["app_id"].lower(), r["_start"]): r for r in rows}
    for e in (reg or {}).get("entries", []):
        start = e.get("LastUsedTimeStart")
        if not isinstance(start, int) or not start or e.get("app") in ("(global)", "NonPackaged (default)"):
            continue
        k = (e["capability"].lower(), e["app"].lower(), start)
        if k in index:
            index[k]["source"] = SOURCE_BOTH
            continue
        stop = e.get("LastUsedTimeStop") if isinstance(e.get("LastUsedTimeStop"), int) else 0
        sid = e.get("sid") or ""
        r = base(e["app"], "nonpackaged" if e.get("nonpackaged") else "packaged", e["capability"], sid, start, stop,
                 "Allowed", SOURCE_REG, f"Registry {e.get('hive', '')}")
        if not sid:
            r["user"] = f"account of {e.get('hive', 'registry')}"
        rows.append(r)
        index[k] = r
    # prompts whose identity row was purged have no path: link through ProgramID or exe name
    # (only when exactly one known path matches), otherwise identify them by their SHA-1
    by_prog, by_name = defaultdict(set), defaultdict(set)
    for r in cam.get("identity", []):
        if r.get("binary"):
            by_prog[r.get("program_id", "")].add(r["binary"])
            by_name[ntpath.basename(r["binary"]).lower()].add(r["binary"])
    for p in cam.get("prompts", []):
        start = p.get("raw", {}).get("ShownTime")
        if not start and p.get("shown_utc"):
            start = _ft_from_str(p["shown_utc"])
        app, note = p.get("binary") or "", ""
        if not app:
            prog = by_prog.get(p.get("program_id", "")) or set()
            name = by_name.get((p.get("binary_name") or "").lower()) or set()
            if len(prog) == 1:
                app, note = next(iter(prog)), ("path matched by ProgramID (same program, a different file version; "
                                              "this file's own path was purged)")
            elif len(name) == 1:
                app, note = next(iter(name)), "path matched by file name (this file's own path was purged)"
            elif p.get("binary_name"):
                app, note = p["binary_name"], "only the file name is recorded"
            elif p.get("sha1"):
                app, note = "sha1:" + p["sha1"], "path purged; look up this SHA-1 in Amcache"
        r = base(app, "nonpackaged", p.get("capability", "location"), p.get("user_sid", ""), start, 0, "Prompt shown",
                 SOURCE_PROMPT, f"NonPackagedGlobalPromptHistory ID {p['ID']}", p.get("sha1", ""), event="prompt")
        if app.startswith("sha1:"):
            r["app_location"] = ""
        r["note"] = note if start else ("ShownTime is 0 in the database. " + note).strip()
        rows.append(r)
    rows.sort(key=lambda r: (r["when_utc"] or "9999", r["app"], r["ref"]))
    totals = Counter((r["app_id"].lower(), r["feature_id"]) for r in rows if r["event"] == "use")
    seen = Counter()
    for r in rows:
        if r["event"] == "use":
            k = (r["app_id"].lower(), r["feature_id"])
            seen[k] += 1
            r["use_no"] = f"#{seen[k]} of {totals[k]}"
    for r in rows:
        for k in ("_start", "_stop", "_kind"):
            r.pop(k, None)
    return rows


def _ft_from_str(s: str) -> int:
    from datetime import datetime, timezone
    try:
        dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    except ValueError:
        return 0
    return int((dt.timestamp() + 11644473600) * 1e7)


# --------------------------------------------------------------------------- summaries
def _uses(activity):
    return [r for r in activity if r["event"] == "use"]


def app_summary(activity: list[dict]) -> list[dict]:
    g = defaultdict(list)
    for r in activity:
        g[r["app_id"].lower()].append(r)
    out = []
    for _, rows in g.items():
        uses = _uses(rows)
        times = [r["when_utc"] for r in uses if r["when_utc"]]
        loc = [r["when_local"] for r in uses if r["when_local"]]
        seen = [r["when_utc"] for r in rows if r["when_utc"]]
        seen_l = [r["when_local"] for r in rows if r["when_local"]]
        out.append(dict(app=rows[0]["app"], app_id=rows[0]["app_id"], app_kind=rows[0]["app_kind"],
                        app_location=rows[0]["app_location"],
                        services=", ".join(sorted({r["feature"] for r in uses})), uses=len(uses),
                        blocked=sum(1 for r in uses if r["access"] == "Blocked"),
                        prompts=sum(1 for r in rows if r["event"] == "prompt"),
                        first_utc=min(times) if times else "", last_utc=max(times) if times else "",
                        first_local=min(loc) if loc else "", last_local=max(loc) if loc else "",
                        first_seen_utc=min(seen) if seen else "", first_seen_local=min(seen_l) if seen_l else "",
                        total_duration=duration_text(sum(float(r["duration_s"] or 0) for r in uses)) if uses else "",
                        sources=", ".join(sorted({r["source"] for r in rows}))))
    out.sort(key=lambda r: (-r["uses"], r["app"]))
    return out


def feature_view(activity: list[dict]) -> list[dict]:
    g = defaultdict(list)
    for r in _uses(activity):
        g[(r["feature"], r["app_id"].lower())].append(r)
    out = []
    for (feat, _), rows in g.items():
        out.append(dict(feature=feat, feature_id=rows[0]["feature_id"], service_desc=rows[0]["service_desc"],
                        app=rows[0]["app"], app_id=rows[0]["app_id"], uses=len(rows),
                        blocked=sum(1 for r in rows if r["access"] == "Blocked"),
                        first_utc=min(r["when_utc"] for r in rows), last_utc=max(r["when_utc"] for r in rows),
                        first_local=min(r["when_local"] for r in rows), last_local=max(r["when_local"] for r in rows),
                        total_duration=duration_text(sum(float(r["duration_s"] or 0) for r in rows))))
    out.sort(key=lambda r: (r["feature"], -r["uses"], r["app"]))
    return out


def permission_view(consent: dict | None, reg: dict | None, activity: list[dict], names: dict) -> list[dict]:
    if not consent and not reg:
        return [{"note": "no consent data"}]
    used = defaultdict(list)
    for r in _uses(activity):
        used[(r["app_id"].lower(), r["feature_id"].lower())].append(r)
    out = []

    def row(app_id, cap, setting, scope, sid, per_app):
        u = used.get((str(app_id).lower(), str(cap).lower()), [])
        flag = ""
        if per_app:
            if u and setting == "Deny":
                flag = "Used while now Deny"
            elif not u:
                flag = "Never used"
        out.append(dict(app=app_label(app_id) if app_id else "(all apps)", app_id=app_id, feature=feature_label(cap),
                        feature_id=cap, setting=setting, scope=scope, user=user_label(sid, names) if sid else "",
                        used_count=len(u), last_used_local=max((x["when_local"] for x in u), default=""), flag=flag))
    c = consent or {}
    for r in c.get("App", []):
        row(r["PackageFamily"], r["Capability"], r.get("Value_meaning", ""), "App setting", r["User"], True)
    for r in c.get("ClassicGlobal", []):
        row("", r["Capability"], r.get("Value_meaning", ""), "Desktop-apps switch", r["User"], False)
    for r in c.get("UserGlobal", []):
        row("", r["Capability"], r.get("Value_meaning", ""), "User default", r["User"], False)
    for r in c.get("SystemGlobal", []):
        row("", r["Capability"], r.get("Value_meaning", ""), "System default", "", False)
    for e in (reg or {}).get("entries", []):
        if e.get("nonpackaged") and e.get("Value"):
            row(e["app"], e["capability"], e["Value"], f"Registry ({e.get('hive', '')})", e.get("sid") or "", True)
    flag_order = {"Used while now Deny": 0, "": 1, "Never used": 2}
    out.sort(key=lambda r: (flag_order.get(r["flag"], 3), r["feature"], r["app"]))
    return out


def program_view(cam: dict, activity: list[dict], software: dict | None = None) -> list[dict]:
    uses = Counter(r["app_id"].lower() for r in _uses(activity))
    prompts = Counter((r["app_id"].lower(), r["sha1"]) for r in activity if r["event"] == "prompt")
    out = []
    for r in cam.get("identity", []):
        path = r.get("binary") or ""
        out.append(dict(program=app_label(path), exe_path=path, sha1=r.get("sha1", ""), program_id=r.get("program_id", ""),
                        first_seen_utc=r.get("first_observed_utc", ""), first_seen_local=r.get("first_observed_local", ""),
                        location_flag=location_flag(path), uses=uses.get(path.lower(), 0),
                        prompts=prompts.get((path.lower(), r.get("sha1", "")), 0),
                        installer=_installer(path, "nonpackaged", software)))
    out.sort(key=lambda r: (r["first_seen_utc"] or "", r["program"]))
    return out


def day_counts(activity: list[dict]) -> list[dict]:
    c = Counter((r["date"], r["feature"]) for r in _uses(activity) if r["date"])
    return [dict(day=d, feature=f, count=n) for (d, f), n in sorted(c.items())]
