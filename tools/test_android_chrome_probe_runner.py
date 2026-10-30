#!/usr/bin/env python3
"""Regression tests for real Android Chrome package-manager readiness."""

import subprocess
import unittest
from unittest.mock import patch

from tools import android_chrome_probe_runner as runner


class ChromePackageReadinessTests(unittest.TestCase):
    @patch.object(runner.time, "sleep")
    @patch.object(runner, "run")
    def test_retries_transient_package_manager_failure(self, mock_run, mock_sleep):
        mock_run.side_effect = [
            subprocess.CompletedProcess([], 1, "cmd: Failure calling service package"),
            subprocess.CompletedProcess(
                [], 0, "package:/data/app/com.android.chrome/base.apk\n"
            ),
        ]
        runner.wait_for_chrome_package(attempts=3, delay_seconds=2)
        self.assertEqual(mock_run.call_count, 2)
        mock_sleep.assert_called_once_with(2)

    @patch.object(runner.time, "sleep")
    @patch.object(runner, "run")
    def test_fails_closed_without_real_chrome_apk(self, mock_run, mock_sleep):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, "Package Manager ready but no package installed\n"
        )
        with self.assertRaisesRegex(RuntimeError, "APK was not verified"):
            runner.wait_for_chrome_package(attempts=2, delay_seconds=1)
        self.assertEqual(mock_run.call_count, 2)
        mock_sleep.assert_called_once_with(1)

    @patch.object(runner.time, "sleep")
    @patch.object(runner, "run")
    def test_does_not_accept_non_package_diagnostic(self, mock_run, mock_sleep):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, "Error: package: missing\n"
        )
        with self.assertRaisesRegex(RuntimeError, "APK was not verified"):
            runner.wait_for_chrome_package(attempts=1, delay_seconds=0)
        mock_sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
