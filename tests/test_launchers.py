"""The user-facing launchers: app_access_history_cli.py and app_access_history_gui.py."""
import importlib.util
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestLaunchers(unittest.TestCase):
    def test_cli_launcher_runs_isolated(self):
        r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "app_access_history_cli.py"), "--version"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.strip().startswith("App Access History "), r.stdout)

    def test_gui_launcher_loads(self):
        spec = importlib.util.spec_from_file_location("ww_gui", os.path.join(ROOT, "app_access_history_gui.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)            # must import without opening a window
        self.assertTrue(hasattr(mod, "App"))

    def test_package_is_named_app_access_history(self):
        self.assertTrue(os.path.isfile(os.path.join(ROOT, "app_access_history", "__init__.py")))
        for old in ("camtool", "winwitness"):
            self.assertFalse(os.path.exists(os.path.join(ROOT, old)), old)

    def test_default_output_folder_name(self):
        src = open(os.path.join(ROOT, "app_access_history", "cli.py"), encoding="utf-8").read()
        self.assertIn('"app_access_history_output_"', src)

    def test_old_launcher_names_gone(self):
        for old in ("camtool_cli.py", "camtool_gui.py", "winwitness_cli.py", "winwitness_gui.py"):
            self.assertFalse(os.path.exists(os.path.join(ROOT, old)), old)


if __name__ == "__main__":
    unittest.main()
