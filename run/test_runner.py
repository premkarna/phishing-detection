#!/usr/bin/env python3
"""Test runner with detailed output"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 70)
print("🧪 RUNNING ALL TESTS")
print("=" * 70)

loader = unittest.TestLoader()
suite = loader.discover('tests', pattern='tests*.py')

count = suite.countTestCases()
print(f"\n📊 Total tests: {count}")
print("-" * 70)

runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)

print("\n" + "=" * 70)
print("📈 RESULTS SUMMARY")
print("=" * 70)
print(f"Tests Run:    {result.testsRun}")
print(f"Passed:       {result.testsRun - len(result.failures) - len(result.errors)}")
print(f"Failed:       {len(result.failures)}")
print(f"Errors:       {len(result.errors)}")
print(f"Success Rate: {(result.testsRun - len(result.failures) - len(result.errors)) / max(result.testsRun, 1) * 100:.1f}%")

if result.failures:
    print("\n❌ FAILURES:")
    for test, trace in result.failures[:5]:
        print(f"   - {test}")

if result.errors:
    print("\n💥 ERRORS:")
    for test, trace in result.errors[:5]:
        print(f"   - {test}")

print("=" * 70)

sys.exit(0 if result.wasSuccessful() else 1)
