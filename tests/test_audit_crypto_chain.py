import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "audit", Path(__file__).parents[1] / "scripts/audit_crypto_chain.py"
)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class AuditTests(unittest.TestCase):
    def write_lock(self, directory, body):
        path = Path(directory) / "Cargo.lock"
        path.write_text("version = 3\n" + body, encoding="utf-8")
        return path

    def test_identifies_transitive_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = self.write_lock(
                directory,
                '[[package]]\nname = "crypto-bigint"\nversion = "0.5.5"\n'
                '[[package]]\nname = "elliptic-curve"\nversion = "0.13.8"\n'
                'dependencies = ["crypto-bigint"]\n',
            )
            result = audit.audit_lock(lock)
            self.assertEqual(result["offenders"][0]["parents"][0]["name"], "elliptic-curve")

    def test_fixed_version_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = self.write_lock(
                directory, '[[package]]\nname = "crypto-bigint"\nversion = "0.7.6"\n'
            )
            self.assertEqual(audit.audit_lock(lock)["offenders"], [])

    def test_detects_multiple_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = self.write_lock(
                directory,
                '[[package]]\nname = "crypto-bigint"\nversion = "0.5.5"\n'
                '[[package]]\nname = "crypto-bigint"\nversion = "0.7.6"\n',
            )
            self.assertEqual(len(audit.audit_lock(lock)["offenders"]), 1)

    def test_missing_lock_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("sys.argv", ["audit", "--root", directory]):
                self.assertEqual(audit.main(), 2)

    def test_broken_lock_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in audit.LOCKS:
                path = Path(directory) / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("bad toml = [", encoding="utf-8")
            with patch("sys.argv", ["audit", "--root", directory]):
                self.assertEqual(audit.main(), 2)

    def test_all_six_locks_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in audit.LOCKS:
                path = Path(directory) / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    'version = 3\n[[package]]\nname = "crypto-bigint"\nversion = "0.7.6"\n',
                    encoding="utf-8",
                )
            last = Path(directory) / audit.LOCKS[-1]
            last.write_text(
                'version = 3\n[[package]]\nname = "crypto-bigint"\nversion = "0.5.5"\n',
                encoding="utf-8",
            )
            with patch("sys.argv", ["audit", "--root", directory]):
                self.assertEqual(audit.main(), 1)


if __name__ == "__main__":
    unittest.main()
