"""Test runner usable with `python -I` (isolated mode): python -I tests/run_tests.py [-k pattern]"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

if __name__ == "__main__":
    pattern = sys.argv[sys.argv.index("-k") + 1] if "-k" in sys.argv else None
    loader = unittest.TestLoader()
    if pattern:
        loader.testNamePatterns = [f"*{pattern}*"]
    suite = loader.discover(os.path.join(ROOT, "tests"), pattern="test_*.py", top_level_dir=ROOT)
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
