"""Offline registry hive reader (Task 1) and hive-based evidence (Task 2)."""
import os
import unittest

from winwitness.regf import Hive, RegfError
from tests import hivegen

DEFAULT_HIVE = r"C:\Users\Default\NTUSER.DAT"
BS = chr(92)


def P(*parts):
    """Join registry/Windows path parts with backslashes (avoids escape mistakes)."""
    return BS.join(parts)


CS = P("Software", "Microsoft", "Windows", "CurrentVersion", "CapabilityAccessManager", "ConsentStore")


class TestRegf(unittest.TestCase):
    def test_generated_hive_roundtrip(self):
        b = hivegen.build({P("A", "B"): {"Value": "Allow", "LastUsedTimeStart": ("qword", 134365667394199327),
                                         "Count": 7, "Multi": ["x", "y"], "Blob": b"\x01\x02\x03\x04\x05"}})
        k = Hive(b).key(P("A", "B"))
        self.assertIsNotNone(k)
        self.assertEqual(k.values(), {"Value": "Allow", "LastUsedTimeStart": 134365667394199327, "Count": 7,
                                      "Multi": ["x", "y"], "Blob": b"\x01\x02\x03\x04\x05"})
        self.assertEqual(k.name, "B")
        self.assertTrue(k.last_write_utc.startswith("2026-10-15"))

    def test_case_insensitive_path(self):
        b = hivegen.build({P("Software", "Microsoft"): {"v": 1}})
        self.assertIsNotNone(Hive(b).key(P("software", "MICROSOFT")))
        self.assertIsNone(Hive(b).key(P("software", "nope")))

    def test_many_subkeys_lf_and_ri(self):
        spec = {P("Root", f"K{i:04d}"): {"i": i} for i in range(600)}
        k = Hive(hivegen.build(spec)).key("Root")
        names = sorted(s.name for s in k.subkeys())
        self.assertEqual(len(names), 600)
        self.assertEqual(names[0], "K0000")
        self.assertEqual(Hive(hivegen.build(spec)).key(P("Root", "K0599")).values(), {"i": 599})

    def test_big_data_value(self):
        blob = bytes(range(256)) * 80        # 20,480 bytes -> 'db' record
        k = Hive(hivegen.build({"X": {"big": blob}})).key("X")
        self.assertEqual(k.values()["big"], blob)

    def test_not_a_hive(self):
        with self.assertRaises(RegfError):
            Hive(b"MZ" * 100)
        with self.assertRaises(RegfError):
            Hive(b"")

    def test_truncated_hive_no_crash(self):
        b = hivegen.build({P("R", f"K{i}"): {"v": "x" * 50} for i in range(300)})
        for cut in (4096, 4100, 5000, 9000, len(b) - 100):
            h = Hive(b[:cut])
            r = h.key("R")
            if r is not None:
                for s in r.subkeys():
                    s.values()

    def test_corrupted_hive_no_crash(self):
        import random
        b = hivegen.build({P("R", f"K{i}"): {"v": "x" * 50, "n": i} for i in range(200)})
        rnd = random.Random(5)
        for _ in range(300):
            m = bytearray(b)
            for _ in range(20):
                m[rnd.randrange(4096, len(m))] = rnd.getrandbits(8)
            h = Hive(bytes(m))
            r = h.key("R")
            if r is not None:
                for s in r.subkeys():
                    s.values()

    @unittest.skipUnless(os.path.isfile(DEFAULT_HIVE) and os.access(DEFAULT_HIVE, os.R_OK), "no Default hive")
    def test_default_profile_hive(self):
        h = Hive(open(DEFAULT_HIVE, "rb").read())
        self.assertGreater(len(h.root().subkeys()), 5)
        self.assertIsNotNone(h.key("Control Panel"))
        self.assertIsNotNone(h.key(P("Software", "Microsoft")))


class TestHiveEvidence(unittest.TestCase):
    def test_consentstore_from_hive(self):
        from winwitness.corroborate import read_hive_consentstore
        b = hivegen.build({
            P(CS, "webcam"): {"Value": "Allow"},
            P(CS, "webcam", "Vendor.App_abcdefghijklm"): {"Value": "Prompt",
                                                          "LastUsedTimeStart": ("qword", 134300000000000000),
                                                          "LastUsedTimeStop": ("qword", 134300000050000000)},
            P(CS, "webcam", "NonPackaged", "C:#x#a.exe"): {"Value": "Deny",
                                                            "LastUsedTimeStart": ("qword", 134300000000000000)},
        })
        r = read_hive_consentstore(Hive(b), "NTUSER.DAT:" + P("Users", "alice", "NTUSER.DAT"))
        by = {(e["capability"], e["app"]): e for e in r["entries"]}
        np_ = by[("webcam", P("C:", "x", "a.exe"))]
        self.assertTrue(np_["nonpackaged"])
        self.assertEqual(np_["Value"], "Deny")
        self.assertEqual(np_["LastUsedTimeStart"], 134300000000000000)
        self.assertGreater(np_["key_last_write"], 0)
        self.assertEqual(by[("webcam", "Vendor.App_abcdefghijklm")]["Value"], "Prompt")
        self.assertEqual(by[("webcam", "(global)")]["Value"], "Allow")
        self.assertTrue(np_["hive"].startswith("HKCU"))

    def test_software_profiles_os_uninstall(self):
        from winwitness.corroborate import read_software_hive
        alice = P("C:", "Users", "alice")
        b = hivegen.build({
            P("Microsoft", "Windows NT", "CurrentVersion"): {"ProductName": "Windows 10 Pro", "DisplayVersion": "25H2",
                                                             "CurrentBuild": "26200", "UBR": 9711},
            P("Microsoft", "Windows NT", "CurrentVersion", "ProfileList", "S-1-5-21-1-2-3-1001"):
                {"ProfileImagePath": alice},
            P("Microsoft", "Windows", "CurrentVersion", "Uninstall", "Brave"): {
                "DisplayName": "Brave",
                "InstallLocation": P("C:", "Program Files", "BraveSoftware", "Brave-Browser", "Application"),
                "InstallSource": P(alice, "Downloads"), "Publisher": "Brave Software Inc",
                "DisplayVersion": "1.80", "InstallDate": "20261001"},
            P("WOW6432Node", "Microsoft", "Windows", "CurrentVersion", "Uninstall", "Old"): {"DisplayName": "Old app"},
            P("Microsoft", "Windows", "CurrentVersion", "CapabilityAccessManager", "CapabilityUsageHistory"):
                {"ExpirationPolicyInDays": 30},
            P("Microsoft", "Windows", "CurrentVersion", "CapabilityAccessManager", "ConsentStore", "location"):
                {"Value": "Deny"},
        })
        s = read_software_hive(Hive(b))
        self.assertEqual(s["profiles"], {"S-1-5-21-1-2-3-1001": alice})
        self.assertEqual(s["os"]["build"], "26200")
        self.assertEqual(s["usage_history_settings"]["ExpirationPolicyInDays"], 30)
        self.assertEqual({u["name"] for u in s["uninstall"]}, {"Brave", "Old app"})
        brave = [u for u in s["uninstall"] if u["name"] == "Brave"][0]
        self.assertEqual(brave["install_source"], P(alice, "Downloads"))
        self.assertEqual([(e["capability"], e["Value"]) for e in s["consent_entries"]], [("location", "Deny")])
        self.assertTrue(s["consent_entries"][0]["hive"].startswith("HKLM"))

    def test_discover_finds_hives(self):
        import tempfile
        from winwitness.engine import discover
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "Users", "alice"))
        open(os.path.join(d, "Users", "alice", "NTUSER.DAT"), "wb").write(hivegen.build({"A": {}}))
        open(os.path.join(d, "SOFTWARE"), "wb").write(hivegen.build({"A": {}}))
        roles = discover(d)
        self.assertIn("SOFTWARE", roles)
        self.assertIn("NTUSER.DAT:" + os.path.join("Users", "alice", "NTUSER.DAT"), roles)

    def test_cli_uses_hive_automatically(self):
        import json
        import shutil
        import tempfile
        from tests import fixtures as FX
        from tests.test_robustness import run_cli
        d = tempfile.mkdtemp()
        try:
            FX.build(d)
            open(os.path.join(d, "NTUSER.DAT"), "wb").write(hivegen.build({
                P(CS, "webcam", "Vendor.App01_abcdefghijklm"): {"Value": "Deny",
                                                                "LastUsedTimeStart": ("qword", 134300000000000000)}}))
            open(os.path.join(d, "SOFTWARE"), "wb").write(b"not a hive at all")
            out = os.path.join(d, "out")
            rc, so, se = run_cli([d, "-o", out, "-q"])
            self.assertEqual(rc, 0, se)
            res = json.load(open(os.path.join(out, "winwitness_results.json"), encoding="utf-8"))
            self.assertTrue(any("NTUSER.DAT" in k for k in res["corroboration"]))
            log = open(os.path.join(out, "run_log.txt"), encoding="utf-8").read()
            self.assertIn("SOFTWARE: skipped", log)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
