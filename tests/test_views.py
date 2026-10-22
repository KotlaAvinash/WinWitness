"""Analyst views (Task 3): activity timeline, apps, services, permissions, programs."""
import unittest

from camtool import model as M
from camtool import views as V

SID = "S-1-5-21-1-2-3-1001"
MAIL = "microsoft.windowscommunicationsapps_8wekyb3d8bbwe"
BRAVE = r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"
TEMP_EXE = r"C:\Users\alice\AppData\Local\Temp\x\tool.exe"
IST = M.parse_tz("+05:30")


def ft(sec_after_2026):           # FILETIME for 2026-01-01 00:00:00 UTC + n seconds
    return 134116992000000000 + int(sec_after_2026 * 1e7)


def usage(ID, start, stop, cap, app, kind="packaged", app_name="", source="live", table=None, access="Allowed",
          sha1="", status=None, sid=SID):
    d = dict(source=source, table=table or ("PackagedUsageHistory" if kind == "packaged" else "NonPackagedUsageHistory"),
             ID=ID, start_utc=M.ft_str(start), stop_utc=M.ft_str(stop), start_local=M.ft_str(start, IST),
             stop_local=M.ft_str(stop, IST), duration_s=round((stop - start) / 1e7, 3) if start and stop else "",
             access=access, capability=cap, app_name=app_name, user_sid=sid, app=app, kind=kind, sha1=sha1,
             file_id=("0000" + sha1) if sha1 else "", program_id="", raw=dict(LastUsedTimeStart=start, LastUsedTimeStop=stop))
    if status:
        d.update(status=status)
    return d


def cam(usage_rows=(), carved=(), prompts=(), identity=()):
    return dict(usage=list(usage_rows), carved_usage=list(carved), prompts=list(prompts), identity=list(identity),
                packaged_prompts=[], lookups={})


class TestLabels(unittest.TestCase):
    def test_feature_and_app_labels(self):
        self.assertEqual(V.feature_label("webcam"), "Camera")
        self.assertEqual(V.feature_label("graphicsCaptureWithoutBorder"), "Screen capture (no border)")
        self.assertEqual(V.feature_label("someNewCap"), "someNewCap")
        self.assertTrue(V.service_desc("microphone"))
        self.assertEqual(V.app_label(MAIL), "Mail and Calendar")
        self.assertEqual(V.app_label(BRAVE), "Brave")
        self.assertEqual(V.app_label("Contoso.SuperNotes_abcdefghijklm"), "SuperNotes")
        self.assertEqual(V.app_label(MAIL, "Mail and Calendar"), "Mail and Calendar")

    def test_purged_lookup_label(self):
        self.assertEqual(V.app_label("<unresolved PackageFamilyNames ID 28: purged>"), "unknown app (purged, ID 28)")
        self.assertEqual(V.feature_label("<unresolved Capabilities ID 12: purged>"), "unknown service (purged, ID 12)")

    def test_user_label(self):
        self.assertEqual(V.user_label(SID, {SID: "alice"}), f"alice ({SID})")
        self.assertEqual(V.user_label("S-1-5-18", {}), "SYSTEM (S-1-5-18)")
        self.assertEqual(V.user_label(SID, {}), SID)

    def test_duration_text(self):
        self.assertEqual(V.duration_text(5.0), "5.0 s")
        self.assertEqual(V.duration_text(754), "12 min 34 s")
        self.assertEqual(V.duration_text(0), "instant")
        self.assertEqual(V.duration_text(3725), "1 h 2 min")
        self.assertEqual(V.duration_text(""), "")

    def test_store_app_location_is_derived(self):
        loc, derived = V.app_location(MAIL, "packaged")
        self.assertTrue(derived)
        self.assertIn("WindowsApps", loc)
        self.assertIn("microsoft.windowscommunicationsapps_", loc)
        self.assertEqual(V.app_location(BRAVE, "nonpackaged"), (BRAVE, False))


class TestActivity(unittest.TestCase):
    def test_activity_sorted_and_fields(self):
        c = cam([usage(2, ft(200), ft(205), "graphicsCaptureWithoutBorder", "Microsoft.ScreenSketch_8wekyb3d8bbwe",
                       app_name="Snipping Tool"),
                 usage(1, ft(100), ft(100), "contacts", MAIL, app_name="Mail and Calendar"),
                 usage(3, ft(300), ft(305), "contacts", MAIL)])
        a = V.build_activity(c, [], None, {}, IST)
        self.assertEqual([r["app"] for r in a], ["Mail and Calendar", "Snipping Tool", "Mail and Calendar"])
        r = a[1]
        for k in ("date", "when_utc", "when_local", "end_utc", "end_local", "duration_text", "app", "app_id", "app_kind",
                  "feature", "feature_id", "service_desc", "access", "user", "sid", "allowed_by", "source",
                  "app_location", "installer", "use_no", "event"):
            self.assertIn(k, r)
        self.assertEqual(r["duration_text"], "5.0 s")
        self.assertEqual(r["feature"], "Screen capture (no border)")
        self.assertEqual(a[0]["use_no"], "#1 of 2")
        self.assertEqual(a[2]["use_no"], "#2 of 2")
        self.assertEqual(a[0]["installer"], "Microsoft Store / Windows package (no installer path recorded)")

    def test_wal_row_labelled(self):
        c = cam([usage(10, ft(1), ft(2), "contacts", MAIL), usage(11, ft(3), ft(4), "contacts", MAIL)])
        wal = [dict(step="WAL txn 0", table="PackagedUsageHistory", rowid=11, change="INSERT", from_slack=False)]
        a = V.build_activity(c, wal, None, {}, IST)
        self.assertEqual([r["source"] for r in a], ["Database", "Database (WAL, not yet in .db)"])

    def test_recovered_rows_labelled(self):
        c = cam([], carved=[usage(5, ft(1), ft(2), "contacts", MAIL, source="carved", status="DELETED"),
                            usage(6, ft(3), ft(4), "<unresolved Capabilities ID 12: purged>",
                                  "<unresolved PackageFamilyNames ID 28: purged>", source="carved",
                                  status="RECOVERED (WAL slack txn)")])
        a = V.build_activity(c, [], None, {}, IST)
        self.assertEqual([r["source"] for r in a], ["Recovered (deleted)", "Recovered (WAL slack)"])
        self.assertEqual(a[1]["app"], "unknown app (purged, ID 28)")

    def test_db_and_registry_same_event_merged(self):
        c = cam([usage(1, ft(100), ft(160), "webcam", "Contoso.Cam_abcdefghijklm")])
        reg = dict(source="hive", entries=[
            dict(hive="HKCU(x)", capability="webcam", app="Contoso.Cam_abcdefghijklm", nonpackaged=False,
                 Value="Allow", LastUsedTimeStart=ft(100), LastUsedTimeStop=ft(160), key_last_write=ft(50), sid=SID),
            dict(hive="HKCU(x)", capability="microphone", app=BRAVE, nonpackaged=True, Value="Allow",
                 LastUsedTimeStart=ft(500), LastUsedTimeStop=ft(560), key_last_write=ft(600), sid=SID)])
        a = V.build_activity(c, [], reg, {}, IST)
        self.assertEqual(len(a), 2)
        self.assertEqual(a[0]["source"], "Database + Registry")
        self.assertEqual(a[1]["source"], "Registry (last use)")
        self.assertEqual(a[1]["app"], "Brave")
        self.assertEqual(a[1]["feature"], "Microphone")
        self.assertIn("changed after this use", a[1]["note"])

    def test_prompts_in_timeline(self):
        c = cam(prompts=[dict(ID=1, shown_utc=M.ft_str(ft(10)), shown_local=M.ft_str(ft(10), IST), capability="location",
                              binary=BRAVE, binary_name="", sha1="ab" * 20, user_sid=SID, raw={})])
        a = V.build_activity(c, [], None, {}, IST)
        self.assertEqual((a[0]["event"], a[0]["access"], a[0]["source"]), ("prompt", "Prompt shown", "Location prompt"))

    def test_prompt_path_linked_by_programid_or_name(self):
        ident = [dict(ID=1, binary=BRAVE, sha1="aa" * 20, program_id="0006pp", first_observed_utc="", raw={}),
                 dict(ID=2, binary=r"C:\Windows\System32\dllhost.exe", sha1="bb" * 20, program_id="0000q",
                      first_observed_utc="", raw={})]
        pr = [dict(ID=5, shown_utc=M.ft_str(ft(10)), capability="location", binary="", binary_name="",
                   sha1="cc" * 20, program_id="0006pp", user_sid=SID, raw={"ShownTime": ft(10)}),
              dict(ID=6, shown_utc=M.ft_str(ft(20)), capability="location", binary="", binary_name="dllhost.exe",
                   sha1="dd" * 20, program_id="0000zz", user_sid=SID, raw={"ShownTime": ft(20)}),
              dict(ID=7, shown_utc=M.ft_str(ft(30)), capability="location", binary="", binary_name="",
                   sha1="ee" * 20, program_id="0000zz", user_sid=SID, raw={"ShownTime": ft(30)})]
        a = V.build_activity(cam(prompts=pr, identity=ident), [], None, {}, IST)
        self.assertEqual(a[0]["app_id"], BRAVE)
        self.assertIn("matched by ProgramID", a[0]["note"])
        self.assertEqual(a[1]["app_id"], r"C:\Windows\System32\dllhost.exe")
        self.assertIn("matched by file name", a[1]["note"])
        self.assertEqual(a[2]["app"], "unknown program (SHA-1 eeeeeeeeee…)")

    def test_allowed_by_from_consent(self):
        consent = {"App": [dict(Capability="webcam", User=SID, PackageFamily="Contoso.Cam_abcdefghijklm", Value=2,
                                Value_meaning="Deny")],
                   "ClassicGlobal": [dict(Capability="microphone", User=SID, Value=1, Value_meaning="Allow")],
                   "UserGlobal": [], "SystemGlobal": [dict(Capability="contacts", Value=1, Value_meaning="Allow")]}
        c = cam([usage(1, ft(1), ft(2), "webcam", "Contoso.Cam_abcdefghijklm"),
                 usage(2, ft(3), ft(4), "microphone", BRAVE, kind="nonpackaged"),
                 usage(3, ft(5), ft(6), "contacts", MAIL)])
        a = V.build_activity(c, [], None, {}, IST, consent=consent)
        self.assertEqual(a[0]["allowed_by"], "App setting (this account): Deny")
        self.assertEqual(a[1]["allowed_by"], "Desktop-apps switch (this account): Allow")
        self.assertEqual(a[2]["allowed_by"], "System default: Allow")

    def test_installer_from_software_hive(self):
        sw = dict(uninstall=[dict(name="Brave", install_location=r"C:\Program Files\BraveSoftware\Brave-Browser\Application",
                                  install_source=r"C:\Users\alice\Downloads", display_icon="", publisher="Brave Software",
                                  version="1.80", install_date="20261001", uninstall_string="")])
        c = cam([usage(1, ft(1), ft(2), "passkeys", BRAVE, kind="nonpackaged")])
        a = V.build_activity(c, [], None, {}, IST, software=sw)
        self.assertIn(r"C:\Users\alice\Downloads", a[0]["installer"])
        a2 = V.build_activity(c, [], None, {}, IST)
        self.assertEqual(a2[0]["installer"], "not recorded in CAM (add the SOFTWARE hive)")


class TestOtherViews(unittest.TestCase):
    def setUp(self):
        self.c = cam([usage(1, ft(100), ft(130), "webcam", "Contoso.Cam_abcdefghijklm"),
                      usage(2, ft(86400 + 5), ft(86400 + 65), "webcam", "Contoso.Cam_abcdefghijklm"),
                      usage(3, ft(86400 + 100), ft(86400 + 100), "contacts", MAIL),
                      usage(4, ft(200), ft(205), "microphone", TEMP_EXE, kind="nonpackaged", sha1="cd" * 20)],
                     identity=[dict(ID=1, binary=TEMP_EXE, sha1="cd" * 20, program_id="0006aa",
                                    first_observed_utc=M.ft_str(ft(50)), first_observed_local="", raw={})])
        self.a = V.build_activity(self.c, [], None, {}, IST)

    def test_app_summary(self):
        s = {r["app"]: r for r in V.app_summary(self.a)}
        cam_ = s["Cam"]
        self.assertEqual(cam_["uses"], 2)
        self.assertEqual(cam_["services"], "Camera")
        self.assertEqual(cam_["total_duration"], "1 min 30 s")
        self.assertTrue(cam_["first_utc"] < cam_["last_utc"])

    def test_summary_use_times_exclude_prompts(self):
        a = self.a + [dict(event="prompt", when_utc="2020-01-01 00:00:00.000000", when_local="2020-01-01 05:30:00.000000",
                           app="Cam", app_id="Contoso.Cam_abcdefghijklm", app_kind="Store app", app_location="",
                           feature="Location", feature_id="location", access="Prompt shown", duration_s="",
                           source="Location prompt", sha1="", date="2020-01-01")]
        cam_ = {r["app"]: r for r in V.app_summary(a)}["Cam"]
        self.assertFalse(cam_["first_utc"].startswith("2020"))
        self.assertTrue(cam_["first_seen_utc"].startswith("2020"))

    def test_feature_view(self):
        f = V.feature_view(self.a)
        cams = [r for r in f if r["feature"] == "Camera"]
        self.assertEqual(len(cams), 1)
        self.assertEqual(cams[0]["uses"], 2)

    def test_permission_mismatch_flag(self):
        consent = {"App": [dict(Capability="webcam", User=SID, PackageFamily="Contoso.Cam_abcdefghijklm", Value=2,
                                Value_meaning="Deny"),
                           dict(Capability="microphone", User=SID, PackageFamily="Never.Used_abcdefghijklm", Value=1,
                                Value_meaning="Allow")]}
        p = {(r["app_id"], r["feature_id"]): r for r in V.permission_view(consent, None, self.a, {})}
        self.assertEqual(p[("Contoso.Cam_abcdefghijklm", "webcam")]["flag"], "Used while now Deny")
        self.assertEqual(p[("Never.Used_abcdefghijklm", "microphone")]["flag"], "Never used")

    def test_permission_order_app_rows_before_global(self):
        consent = {"SystemGlobal": [dict(Capability="webcam", Value=1, Value_meaning="Allow")],
                   "UserGlobal": [dict(Capability="webcam", User=SID, Value=1, Value_meaning="Allow")],
                   "App": [dict(Capability="webcam", User=SID, PackageFamily="Contoso.Cam_abcdefghijklm", Value=1,
                                Value_meaning="Allow")]}
        p = V.permission_view(consent, None, self.a, {})
        self.assertEqual([r["scope"] for r in p], ["App setting", "User default", "System default"])

    def test_views_without_consent_or_registry(self):
        self.assertEqual(V.permission_view(None, None, self.a, {}), [{"note": "no consent data"}])
        self.assertTrue(V.app_summary(self.a))
        self.assertTrue(V.feature_view(self.a))

    def test_program_view_flags(self):
        p = V.program_view(self.c, self.a)
        self.assertEqual(p[0]["location_flag"], "Temp folder")
        self.assertEqual(p[0]["uses"], 1)

    def test_day_counts(self):
        d = V.day_counts(self.a)
        self.assertEqual(sum(x["count"] for x in d), 4)
        self.assertEqual(len({x["day"] for x in d}), 2)


if __name__ == "__main__":
    unittest.main()
