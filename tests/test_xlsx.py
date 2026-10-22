"""Stdlib Excel writer (Task 4)."""
import os
import tempfile
import unittest
import zipfile
import xml.etree.ElementTree as ET

from camtool.xlsx import write_xlsx

NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


def cells(z, n):
    root = ET.fromstring(z.read(f"xl/worksheets/sheet{n}.xml"))
    out = []
    for row in root.find("m:sheetData", NS):
        vals = []
        for c in row:
            if c.get("t") == "inlineStr":
                vals.append("".join(t.text or "" for t in c.iter("{%s}t" % NS["m"])))
            else:
                v = c.find("m:v", NS)
                vals.append(float(v.text) if v is not None else None)
            assert c.find("m:f", NS) is None, "formula element written"
        out.append(vals)
    return out, root


class TestXlsx(unittest.TestCase):
    def test_xlsx_roundtrip(self):
        p = os.path.join(tempfile.mkdtemp(), "t.xlsx")
        write_xlsx(p, [("Activity timeline", ["When", "App", "Count"],
                        [["2026-10-01 10:00", "<Brave & co>\"", 3], ["=cmd|' /c calc'!A1", "x", 2.5]]),
                       ("Apps", ["App"], [["Mail"]])])
        with zipfile.ZipFile(p) as z:
            self.assertIsNone(z.testzip())
            ct = z.read("[Content_Types].xml").decode()
            self.assertIn("/xl/worksheets/sheet1.xml", ct)
            self.assertIn("/xl/worksheets/sheet2.xml", ct)
            wb = ET.fromstring(z.read("xl/workbook.xml"))
            self.assertEqual([s.get("name") for s in wb.iter("{%s}sheet" % NS["m"])], ["Activity timeline", "Apps"])
            rows, root = cells(z, 1)
            self.assertEqual(rows[0], ["When", "App", "Count"])
            self.assertEqual(rows[1], ["2026-10-01 10:00", "<Brave & co>\"", 3.0])
            self.assertEqual(rows[2][0], "=cmd|' /c calc'!A1")
            self.assertEqual(rows[2][2], 2.5)
            self.assertIsNotNone(root.find("m:autoFilter", NS))
            self.assertIsNotNone(root.find("m:sheetViews/m:sheetView/m:pane", NS))

    def test_long_sheet_name_and_many_columns(self):
        p = os.path.join(tempfile.mkdtemp(), "t.xlsx")
        hdr = [f"c{i}" for i in range(60)]
        write_xlsx(p, [("A" * 40 + "[]:*?/\\", hdr, [list(range(60))])])
        with zipfile.ZipFile(p) as z:
            wb = ET.fromstring(z.read("xl/workbook.xml"))
            name = [s.get("name") for s in wb.iter("{%s}sheet" % NS["m"])][0]
            self.assertLessEqual(len(name), 31)
            self.assertFalse(set(name) & set("[]:*?/\\"))
            rows, _ = cells(z, 1)
            self.assertEqual(rows[1][59], 59.0)

    def test_control_characters_removed(self):
        p = os.path.join(tempfile.mkdtemp(), "t.xlsx")
        write_xlsx(p, [("S", ["a"], [["bad\x00\x07char"]])])
        with zipfile.ZipFile(p) as z:
            rows, _ = cells(z, 1)
            self.assertEqual(rows[1][0], "badchar")


if __name__ == "__main__":
    unittest.main()
