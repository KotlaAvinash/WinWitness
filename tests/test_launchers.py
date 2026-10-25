"""The user-facing launchers: winwitness_cli.py and winwitness_gui.py."""
import importlib.util
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestLaunchers(unittest.TestCase):
    def test_cli_launcher_runs_isolated(self):
        r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "winwitness_cli.py"), "--version"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.strip().startswith("WinWitness "), r.stdout)

    def test_gui_launcher_loads(self):
        spec = importlib.util.spec_from_file_location("ww_gui", os.path.join(ROOT, "winwitness_gui.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)            # must import without opening a window
        self.assertTrue(hasattr(mod, "App"))

    def test_old_launcher_names_gone(self):
        for old in ("camtool_cli.py", "camtool_gui.py"):
            self.assertFalse(os.path.exists(os.path.join(ROOT, old)), old)


if __name__ == "__main__":
    unittest.main()
