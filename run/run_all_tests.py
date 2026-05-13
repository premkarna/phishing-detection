#!/usr/bin/env python3
"""Run all tests and report results comprehensively"""

import unittest
import sys
import os
from io import StringIO

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 70)
print("🧪 RUNNING ALL TESTS - Phishing Detection Tool")
print("=" * 70)

# Discover and run all tests
loader = unittest.TestLoader()
suite = loader.discover('tests', pattern='tests*.py')

# Count tests before running
count = suite.countTestCases()
print(f"\n📊 Total tests discovered: {count}")
print("\n" + "-" * 70)

# Run tests with verbose output
stream = StringIO()
runner = unittest.TextTestRunner(verbosity=2, stream=stream)
result = runner.run(suite)

# Print output
print(stream.getvalue())

# Summary
print("\n" + "=" * 70)
print("📈 TEST RESULTS SUMMARY")
print("=" * 70)
print(f"Tests Run:     {result.testsRun}")
print(f"Failures:      {len(result.failures)}")
print(f"Errors:        {len(result.errors)}")
print(f"Skipped:       {len(result.skipped)}")
print(f"Success Rate:  {(result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100:.1f}%")
print("=" * 70)

if result.failures:
    print("\n❌ FAILED TESTS:")
    for test, trace in result.failures:
        print(f"   - {test}")

if result.errors:
    print("\n💥 ERRORS:")
    for test, trace in result.errors:
        print(f"   - {test}")

# Exit with error code if tests failed
sys.exit(0 if result.wasSuccessful() else 1)
