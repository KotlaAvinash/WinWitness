"""Offline registry hive reader (Task 1) and hive-based evidence (Task 2)."""
import os
import unittest

from camtool.regf import Hive, RegfError
from tests import hivegen

DEFAULT_HIVE = r"C:\Users\Default\NTUSER.DAT"


class TestRegf(unittest.TestCase):
    def test_generated_hive_roundtrip(self):
        b = hivegen.build({"A\\B": {"Value": "Allow", "LastUsedTimeStart": ("qword", 134365667394199327),
                                    "Count": 7, "Multi": ["x", "y"], "Blob": b"\x01\x02\x03\x04\x05"}})
        k = Hive(b).key("A\\B")
        self.assertIsNotNone(k)
        self.assertEqual(k.values(), {"Value": "Allow", "LastUsedTimeStart": 134365667394199327, "Count": 7,
                                      "Multi": ["x", "y"], "Blob": b"\x01\x02\x03\x04\x05"})
        self.assertEqual(k.name, "B")
        self.assertTrue(k.last_write_utc.startswith("2026-10-15"))

    def test_case_insensitive_path(self):
        b = hivegen.build({"Software\\Microsoft": {"v": 1}})
        self.assertIsNotNone(Hive(b).key("software\\MICROSOFT"))
        self.assertIsNone(Hive(b).key("software\\nope"))

    def test_many_subkeys_lf_and_ri(self):
        spec = {f"Root\\K{i:04d}": {"i": i} for i in range(600)}
        k = Hive(hivegen.build(spec)).key("Root")
        names = sorted(s.name for s in k.subkeys())
        self.assertEqual(len(names), 600)
        self.assertEqual(names[0], "K0000")
        self.assertEqual(Hive(hivegen.build(spec)).key("Root\\K0599").values(), {"i": 599})

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
        b = hivegen.build({f"R\\K{i}": {"v": "x" * 50} for i in range(300)})
        for cut in (4096, 4100, 5000, 9000, len(b) - 100):
            h = Hive(b[:cut])
            r = h.key("R")
            if r is not None:
                for s in r.subkeys():
                    s.values()

    def test_corrupted_hive_no_crash(self):
        import random
        b = hivegen.build({f"R\\K{i}": {"v": "x" * 50, "n": i} for i in range(200)})
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
        self.assertIsNotNone(h.key("Software\\Microsoft"))


if __name__ == "__main__":
    unittest.main()
