"""Regression tests for the final whole-branch review findings (one test per finding)."""
import json
import os
import re
import tempfile
import unittest
import zipfile

from winwitness import model as M
from winwitness import report as R
from winwitness import views as V
from winwitness.xlsx import write_xlsx
from tests import hivegen
from tests.test_views import BRAVE, IST, MAIL, SID, cam, ft, usage
from tests.test_report import ctx

SID_B = "S-1-5-21-1-2-3-1002"
CAMAPP = "Contoso.Cam_abcdefghijklm"
BS = chr(92)
CS = BS.join(["Software", "Microsoft", "Windows", "CurrentVersion", "CapabilityAccessManager", "ConsentStore"])


def reg_entry(cap, app, start=None, stop=None, value=None, sid=SID, hive="HKCU(NTUSER.DAT:a)", klw=0, np_=False):
    e = dict(hive=hive, capability=cap, app=app, nonpackaged=np_, sid=sid, key_last_write=klw)
    if value:
        e["Value"] = value
    if start:
        e["LastUsedTimeStart"] = start
    if stop is not None:
        e["LastUsedTimeStop"] = stop
    return e


class TestReportInjection(unittest.TestCase):
    """#1 tooltip injection, #2 '<!--<script>' parser state."""

    def test_tooltip_parts_are_escaped(self):
        src = open(R.write_html_v2.__code__.co_filename, encoding="utf-8").read()
        m = re.search(r"showTip\(e,`(.*?)`\)", src)
        self.assertIsNotNone(m)
        for part in re.findall(r"\$\{(.*?)\}", m.group(1)):
            self.assertTrue(part.startswith("esc("), f"unescaped tooltip part: {part}")

    def test_no_raw_lt_in_embedded_json(self):
        c = ctx(3)
        c["activity"][0]["app"] = "<!--<script>"
        c["activity"][1]["feature"] = "<img src=x onerror=alert(1)>|x|"
        p = os.path.join(tempfile.mkdtemp(), "r.html")
        R.write_html_v2(p, c)
        html = open(p, encoding="utf-8").read()
        block = re.search(r'<script type="application/json" id="cam-data">(.*?)</script>', html, re.S).group(1)
        self.assertNotIn("<", block)
        data = json.loads(block)
        self.assertEqual(data["activity"][0]["app"], "<!--<script>")


class TestAllowedBy(unittest.TestCase):
    """#3 deciding level = first Deny from system down; labelled as current setting."""

    def test_global_deny_beats_app_allow(self):
        consent = {"SystemGlobal": [dict(Capability="webcam", Value=2, Value_meaning="Deny")],
                   "UserGlobal": [dict(Capability="webcam", User=SID, Value=2, Value_meaning="Deny")],
                   "App": [dict(Capability="webcam", User=SID, PackageFamily=CAMAPP, Value=1, Value_meaning="Allow")]}
        a = V.build_activity(cam([usage(1, ft(1), ft(2), "webcam", CAMAPP)]), [], None, {}, IST, consent=consent)
        self.assertEqual(a[0]["allowed_by"], "Current setting: Deny (System default)")

    def test_app_level_decides_when_no_global_deny(self):
        consent = {"SystemGlobal": [dict(Capability="webcam", Value=1, Value_meaning="Allow")],
                   "App": [dict(Capability="webcam", User=SID, PackageFamily=CAMAPP, Value=3, Value_meaning="Prompt")]}
        a = V.build_activity(cam([usage(1, ft(1), ft(2), "webcam", CAMAPP)]), [], None, {}, IST, consent=consent)
        self.assertEqual(a[0]["allowed_by"], "Current setting: Prompt (App setting, this account)")


class TestRegistryPerAccount(unittest.TestCase):
    """#4 registry settings keyed by account; #5 merge keeps WAL label; #14 registry access not asserted."""

    def test_other_accounts_registry_value_not_applied(self):
        reg = dict(entries=[reg_entry("webcam", CAMAPP, value="Deny", sid=SID_B, hive="HKCU(NTUSER.DAT:bob)",
                                      klw=ft(999))])
        a = V.build_activity(cam([usage(1, ft(1), ft(2), "webcam", CAMAPP)]), [], reg, {}, IST)
        self.assertNotIn("Registry", a[0]["allowed_by"])
        self.assertEqual(a[0]["note"], "")

    def test_unknown_sid_used_only_with_single_user_hive(self):
        one = dict(entries=[reg_entry("webcam", CAMAPP, value="Deny", sid=None, hive="HKCU(NTUSER.DAT:a)")])
        two = dict(entries=one["entries"] + [reg_entry("mic", "x", value="Allow", sid=None, hive="HKCU(NTUSER.DAT:b)")])
        c = cam([usage(1, ft(1), ft(2), "webcam", CAMAPP)])
        self.assertIn("NTUSER.DAT:a", V.build_activity(c, [], one, {}, IST)[0]["allowed_by"])
        self.assertNotIn("Registry", V.build_activity(c, [], two, {}, IST)[0]["allowed_by"])

    def test_merge_keeps_wal_label(self):
        c = cam([usage(9, ft(100), ft(160), "webcam", CAMAPP)])
        wal = [dict(table="PackagedUsageHistory", rowid=9, change="INSERT", from_slack=False)]
        reg = dict(entries=[reg_entry("webcam", CAMAPP, start=ft(100), stop=ft(160))])
        a = V.build_activity(c, wal, reg, {}, IST)
        self.assertEqual(a[0]["source"], "Database (WAL, not yet in .db) + Registry")

    def test_registry_only_event_access_not_asserted(self):
        reg = dict(entries=[reg_entry("microphone", BRAVE, start=ft(500), stop=ft(560), np_=True)])
        a = V.build_activity(cam(), [], reg, {}, IST)
        self.assertEqual(a[0]["access"], "Not recorded")


class TestPermissionFlag(unittest.TestCase):
    """#6 only allowed uses raise 'Used while now Deny'."""

    def test_blocked_use_does_not_raise_flag(self):
        a = V.build_activity(cam([usage(1, ft(1), ft(2), "webcam", CAMAPP, access="Blocked")]), [], None, {}, IST)
        consent = {"App": [dict(Capability="webcam", User=SID, PackageFamily=CAMAPP, Value=2, Value_meaning="Deny")]}
        p = V.permission_view(consent, None, a, {})
        self.assertEqual(p[0]["flag"], "")


class TestHiveValueCollision(unittest.TestCase):
    """#7 value names equal to our own field names must not crash."""

    def test_value_named_app(self):
        from winwitness.corroborate import read_hive_consentstore
        from winwitness.regf import Hive
        b = hivegen.build({BS.join([CS, "webcam", CAMAPP]): {"app": "x", "hive": "y", "Value": "Allow"}})
        r = read_hive_consentstore(Hive(b), "t")
        e = [x for x in r["entries"] if x["app"] == CAMAPP][0]
        self.assertEqual(e["Value"], "Allow")
        self.assertEqual(e["hive"], "HKCU(t)")


class TestTimes(unittest.TestCase):
    """#8 stop=0 is not 'instant'; #12 bad stored times do not crash."""

    def test_missing_end_not_instant(self):
        a = V.build_activity(cam([usage(1, ft(1), 0, "webcam", CAMAPP)]), [], None, {}, IST)
        self.assertEqual(a[0]["duration_text"], "end not recorded")
        self.assertIn("still in use", a[0]["note"])

    def test_non_integer_times_do_not_crash(self):
        u = usage(1, ft(1), ft(2), "webcam", CAMAPP)
        u["raw"] = dict(LastUsedTimeStart="garbage", LastUsedTimeStop=b"\x00")
        a = V.build_activity(cam([u]), [], None, {}, IST)
        self.assertEqual(a[0]["date"], "")
        self.assertIn("invalid stored time", a[0]["note"])


class TestLocationsAndInstaller(unittest.TestCase):
    """#9 cw5n1h2txyewy parent not guessed; #10 installer longest match; #15 MSIX wording."""

    def test_system_package_parent_not_guessed(self):
        loc, derived = V.app_location("MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy", "packaged")
        self.assertTrue(derived)
        self.assertIn("SystemApps", loc)
        self.assertIn("WindowsApps", loc)

    def test_installer_prefers_specific_location(self):
        sw = dict(uninstall=[
            dict(name="Sloppy Tool", install_location="C:" + BS, install_source="X", display_icon="", publisher="",
                 version="", install_date=""),
            dict(name="Brave", install_location=BS.join(["C:", "Program Files", "BraveSoftware"]),
                 install_source="D:" + BS + "dl", display_icon="", publisher="", version="", install_date="")])
        a = V.build_activity(cam([usage(1, ft(1), ft(2), "passkeys", BRAVE, kind="nonpackaged")]), [], None, {}, IST,
                             software=sw)
        self.assertIn("Brave", a[0]["installer"])
        self.assertNotIn("Sloppy", a[0]["installer"])

    def test_packaged_wording(self):
        a = V.build_activity(cam([usage(1, ft(1), ft(2), "contacts", MAIL)]), [], None, {}, IST)
        self.assertEqual(a[0]["app_kind"], "Packaged app (MSIX)")
        self.assertNotIn("Store", a[0]["installer"])


class TestRecoveredIdentity(unittest.TestCase):
    """#11 recovered rows resolved from current lookups carry a caveat."""

    def test_recovered_pair_not_in_live_is_flagged(self):
        live = usage(1, ft(10), ft(11), "contacts", MAIL)
        live["raw"].update(PackageFamilyName=25, AppName=10, Capability=10)
        rec_ok = usage(2, ft(1), ft(2), "contacts", MAIL, source="carved", status="DELETED")
        rec_ok["raw"].update(PackageFamilyName=25, AppName=10, Capability=10)
        rec_odd = usage(3, ft(3), ft(4), "contacts", MAIL, source="carved", status="DELETED")
        rec_odd["raw"].update(PackageFamilyName=25, AppName=99, Capability=10)
        a = V.build_activity(cam([live], carved=[rec_ok, rec_odd]), [], None, {}, IST)
        notes = {r["ref"]: r["note"] for r in a}
        self.assertIn("same ID combination is in live rows", notes["PackagedUsageHistory ID 2"])
        self.assertIn("not in live rows", notes["PackagedUsageHistory ID 3"])


class TestPromptLinking(unittest.TestCase):
    """#13 empty / purged ProgramIDs never link; linked locations are marked derived."""

    def test_empty_programid_does_not_link(self):
        ident = [dict(ID=1, binary=BRAVE, sha1="aa" * 20, program_id="", first_observed_utc="", raw={})]
        pr = [dict(ID=5, shown_utc=M.ft_str(ft(10)), capability="location", binary="", binary_name="", sha1="cc" * 20,
                   program_id="", user_sid=SID, raw={"ShownTime": ft(10)})]
        a = V.build_activity(cam(prompts=pr, identity=ident), [], None, {}, IST)
        self.assertTrue(a[0]["app_id"].startswith("sha1:"))

    def test_linked_location_marked_derived(self):
        ident = [dict(ID=1, binary=BRAVE, sha1="aa" * 20, program_id="0006pp", first_observed_utc="", raw={})]
        pr = [dict(ID=5, shown_utc=M.ft_str(ft(10)), capability="location", binary="", binary_name="", sha1="cc" * 20,
                   program_id="0006pp", user_sid=SID, raw={"ShownTime": ft(10)})]
        a = V.build_activity(cam(prompts=pr, identity=ident), [], None, {}, IST)
        self.assertIn("(derived", a[0]["app_location"])


class TestXlsxHardening(unittest.TestCase):
    """re-graded: deterministic bytes; XML-forbidden characters removed."""

    def test_deterministic_and_clean(self):
        d = tempfile.mkdtemp()
        p1, p2 = os.path.join(d, "a.xlsx"), os.path.join(d, "b.xlsx")
        sheets = [("S", ["a"], [["x￾y￿z"]])]
        write_xlsx(p1, sheets)
        import time
        time.sleep(2.1)
        write_xlsx(p2, sheets)
        self.assertEqual(open(p1, "rb").read(), open(p2, "rb").read())
        with zipfile.ZipFile(p1) as z:
            self.assertIn("xyz", z.read("xl/worksheets/sheet1.xml").decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
