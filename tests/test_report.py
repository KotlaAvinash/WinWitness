"""Report v2 and output layout (Task 5)."""
import json
import os
import re
import shutil
import tempfile
import unittest
import zipfile

from app_access_history import report as R


def ctx(n=3):
    act = [dict(event="use", date="2026-10-0%d" % (1 + i % 3), when_utc=f"2026-10-0{1 + i % 3} 10:00:{i % 60:02d}.000000",
                when_local="", end_utc="", end_local="", duration_s=5, duration_text="5.0 s", app="App%d" % (i % 7),
                app_id="A%d" % (i % 7), app_kind="Store app", feature="Camera", feature_id="webcam",
                service_desc="d", access="Allowed", user="u", sid="s", allowed_by="x", source="Database",
                app_location="", installer="", sha1="", ref="r", note="", use_no="#1 of 1") for i in range(n)]
    act.sort(key=lambda r: r["when_utc"])
    return dict(tool="App Access History 2.2.0", generated_utc="2026-10-23 00:00:00", evidence_dir="E", tz_label="+05:30",
                summary=dict(period="", accounts=[], system=""), activity=act, apps=[], features=[], permissions=[],
                programs=[], findings=[], day_counts=[], hour_counts=[], evidence=[], integrity_ok=True,
                technical_report="AppAccessHistory_technical_report.html", method_html="<p>m</p>")


def embedded(path):
    html = open(path, encoding="utf-8").read()
    m = re.search(r'<script type="application/json" id="cam-data">(.*?)</script>', html, re.S)
    return html, json.loads(m.group(1).replace("<\\/", "</"))


class TestReport(unittest.TestCase):
    def test_report_sections_in_order(self):
        p = os.path.join(tempfile.mkdtemp(), "r.html")
        R.write_html_v2(p, ctx())
        html = open(p, encoding="utf-8").read()
        ids = ["summary", "activity", "apps", "features", "permissions", "programs", "recovered", "findings",
               "technical"]
        pos = [html.find(f'id="{i}"') for i in ids]
        self.assertTrue(all(x > 0 for x in pos), dict(zip(ids, pos)))
        self.assertEqual(pos, sorted(pos))

    def test_report_branded_app_access_history(self):
        from app_access_history import engine as E
        self.assertEqual(E.TOOL_NAME, "App Access History")
        p = os.path.join(tempfile.mkdtemp(), "r.html")
        R.write_html_v2(p, ctx())
        html = open(p, encoding="utf-8").read()
        self.assertIn("<title>App Access History", html)
        self.assertIn("App Access History</div>", html.split('class="brand"')[1][:400])
        for old in ("CAMtool", "WinWitness"):
            self.assertNotIn(old, html.replace(ctx()["tool"], ""))

    def test_report_has_order_toggle_and_no_sticky_filters(self):
        p = os.path.join(tempfile.mkdtemp(), "r.html")
        R.write_html_v2(p, ctx())
        html = open(p, encoding="utf-8").read()
        self.assertIn('id="f-order"', html)
        self.assertIn("Newest first", html)
        self.assertNotRegex(html, r"\.filters\{position:sticky")

    def test_report_embedded_data_parses(self):
        c = ctx(10)
        c["activity"][0]["app"] = "</script><script>alert(1)</script>"
        p = os.path.join(tempfile.mkdtemp(), "r.html")
        R.write_html_v2(p, c)
        html, data = embedded(p)
        self.assertEqual(len(data["activity"]), 10)
        w = [r["when_utc"] for r in data["activity"]]
        self.assertEqual(w, sorted(w))
        self.assertEqual(html.count("<script>alert(1)</script>"), 0)
        self.assertIn("alert(1)", data["activity"][0]["app"])

    def test_report_large_activity(self):
        p = os.path.join(tempfile.mkdtemp(), "r.html")
        R.write_html_v2(p, ctx(50000))
        _, data = embedded(p)
        self.assertEqual(len(data["activity"]), 50000)

    def test_output_layout(self):
        from tests import fixtures as FX
        from tests.test_robustness import run_cli
        d = tempfile.mkdtemp()
        try:
            FX.build(os.path.join(d, "ev"))
            out = os.path.join(d, "out")
            rc, so, se = run_cli([os.path.join(d, "ev"), "-o", out, "-q", "--tz", "+05:30"])
            self.assertEqual(rc, 0, se)
            for f in ("AppAccessHistory_report.html", "AppAccessHistory_technical_report.html", "AppAccessHistory_activity.xlsx", "activity_timeline.csv",
                      "apps.csv", "services.csv", "permissions.csv", "programs.csv", "recovered.csv", "findings.csv",
                      "app_access_history_results.json", "app_access_history_results.sqlite", "run_log.txt", "MANIFEST.sha256"):
                self.assertTrue(os.path.isfile(os.path.join(out, f)), f)
            self.assertTrue(os.path.isfile(os.path.join(out, "csv", "technical", "usage.csv")))
            with zipfile.ZipFile(os.path.join(out, "AppAccessHistory_activity.xlsx")) as z:
                self.assertEqual(len([n for n in z.namelist() if n.startswith("xl/worksheets/sheet")]), 7)
            _, data = embedded(os.path.join(out, "AppAccessHistory_report.html"))
            self.assertGreater(len(data["activity"]), 100)
            hdr = open(os.path.join(out, "activity_timeline.csv"), encoding="utf-8-sig").readline()
            for col in ("Date", "Start (local)", "End (local)", "Duration", "Application", "Service", "Allowed/Blocked",
                        "Account", "Allowed by", "Use #", "Application location", "Installer", "Source"):
                self.assertIn(col, hdr)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
