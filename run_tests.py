"""
Test Runner:
Discovers and executes all unit test suites in tests/ directory.
Outputs structured summary for academic verification and CI/CD pipelines.
"""

import os
import sys
import unittest


def run_all_tests():
    # Ensure current directory is in sys.path
    base_dir = os.path.dirname(os.path.abspath(__file__))
    if base_dir not in sys.path:
        sys.path.insert(0, base_dir)

    print("=" * 65)
    print("RUNNING INTELLIGENT FAKE JOB SYSTEM - AUTOMATED TEST SUITE")
    print("=" * 65)

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=os.path.join(base_dir, "tests"), pattern="test_*.py")

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 65)
    print(f"Total Tests Executed: {result.testsRun}")
    print(f"Failures: {len(result.failures)} | Errors: {len(result.errors)}")
    print("=" * 65)

    if result.wasSuccessful():
        print(">> ALL TEST SUITES PASSED SUCCESSFULLY! <<")
        return 0
    else:
        print(">> SOME TESTS FAILED. PLEASE REVIEW ABOVE LOGS. <<")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
