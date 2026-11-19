
import unittest
import tempfile
import json
import hashlib
import hmac
from pathlib import Path
from unittest.mock import patch

import fim


class TestFileIntegrityMonitor(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_path = Path(self.temp_dir.name)

        self.protected_dir = self.test_path / "protected_files"
        self.protected_dir.mkdir()

        self.baseline_file = self.test_path / "baseline.json"
        self.key_file = self.test_path / "baseline.key"
        self.signature_file = self.test_path / "baseline.sig"

        self.test_key = b"T" * 32
        self.key_file.write_bytes(self.test_key)

        self.test_file = self.protected_dir / "test.txt"
        self.test_file.write_text("Original content")

        self.patcher = patch.multiple(
            fim,
            PROTECTED_DIR=self.protected_dir,
            BASELINE_FILE=self.baseline_file,
            KEY_FILE=self.key_file,
            SIGNATURE_FILE=self.signature_file
        )
        self.patcher.start()

        self.log_patches = [
            patch("fim.logging.info"),
            patch("fim.logging.warning"),
            patch("fim.logging.error"),
            patch("fim.logging.critical")
        ]

        for log_patch in self.log_patches:
            log_patch.start()

    def tearDown(self):
        for log_patch in self.log_patches:
            log_patch.stop()

        self.patcher.stop()
        self.temp_dir.cleanup()

    def test_sha256_calculation(self):
        expected_hash = hashlib.sha256(
            b"Original content"
        ).hexdigest()

        actual_hash = fim.calculate_sha256(self.test_file)

        self.assertEqual(actual_hash, expected_hash)

    def test_baseline_creation(self):
        fim.create_baseline()

        self.assertTrue(self.baseline_file.exists())
        self.assertTrue(self.signature_file.exists())

        with open(self.baseline_file, "r") as file:
            baseline = json.load(file)

        self.assertIn("test.txt", baseline)
        self.assertIn("sha256", baseline["test.txt"])
        self.assertIn("size", baseline["test.txt"])

    def test_baseline_signature_verification(self):
        fim.create_baseline()

        baseline = fim.load_baseline()

        self.assertIsNotNone(baseline)
        self.assertIn("test.txt", baseline)

    def test_baseline_tampering_detection(self):
        fim.create_baseline()

        with open(self.baseline_file, "a") as file:
            file.write(" ")

        with patch("builtins.print") as mock_print:
            baseline = fim.load_baseline()

        self.assertIsNone(baseline)

        output = "\n".join(
            str(call) for call in mock_print.call_args_list
        )

        self.assertIn("integrity verification failed", output)

    def test_modified_file_detection(self):
        fim.create_baseline()
        self.test_file.write_text("Modified content")

        with patch("builtins.print") as mock_print:
            fim.scan_files()

        output = "\n".join(
            str(call) for call in mock_print.call_args_list
        )

        self.assertIn("Modified files", output)
        self.assertIn("test.txt", output)

    def test_deleted_file_detection(self):
        fim.create_baseline()
        self.test_file.unlink()

        with patch("builtins.print") as mock_print:
            fim.scan_files()

        output = "\n".join(
            str(call) for call in mock_print.call_args_list
        )

        self.assertIn("Deleted files", output)
        self.assertIn("test.txt", output)

    def test_new_file_detection(self):
        fim.create_baseline()

        new_file = self.protected_dir / "newfile.txt"
        new_file.write_text("New content")

        with patch("builtins.print") as mock_print:
            fim.scan_files()

        output = "\n".join(
            str(call) for call in mock_print.call_args_list
        )

        self.assertIn("New files", output)
        self.assertIn("newfile.txt", output)

    def test_reject_non_dictionary_baseline(self):
        with self.assertRaises(ValueError):
            fim.validate_baseline([])

    def test_reject_invalid_sha256_hash(self):
        invalid_baseline = {
            "test.txt": {
                "sha256": "invalid_hash",
                "size": 10
            }
        }

        with self.assertRaises(ValueError):
            fim.validate_baseline(invalid_baseline)

    def test_reject_negative_file_size(self):
        invalid_baseline = {
            "test.txt": {
                "sha256": "a" * 64,
                "size": -1
            }
        }

        with self.assertRaises(ValueError):
            fim.validate_baseline(invalid_baseline)

    def test_reject_unsafe_file_path(self):
        invalid_baseline = {
            "../outside.txt": {
                "sha256": "a" * 64,
                "size": 10
            }
        }

        with self.assertRaises(ValueError):
            fim.validate_baseline(invalid_baseline)

    def test_scanner_rejects_invalid_baseline_with_valid_hmac(self):
        invalid_data = json.dumps([]).encode("utf-8")

        valid_signature = hmac.new(
            self.test_key,
            invalid_data,
            hashlib.sha256
        ).hexdigest()

        self.baseline_file.write_bytes(invalid_data)
        self.signature_file.write_text(valid_signature)

        with patch("builtins.print") as mock_print:
            baseline = fim.load_baseline()

        self.assertIsNone(baseline)

        output = "\n".join(
            str(call) for call in mock_print.call_args_list
        )

        self.assertIn("Baseline must be a JSON object", output)

    def test_symlink_is_skipped(self):
        outside_file = self.test_path / "outside.txt"
        outside_file.write_text("Outside protected directory")

        symlink = self.protected_dir / "linked_file.txt"
        symlink.symlink_to(outside_file)

        collected_files = fim.collect_file_metadata()

        self.assertIsNotNone(collected_files)
        self.assertIn("test.txt", collected_files)
        self.assertNotIn("linked_file.txt", collected_files)

    def test_file_collection_handles_permission_error(self):
        with patch(
            "fim.calculate_sha256",
            side_effect=PermissionError("Permission denied")
        ):
            with patch("builtins.print"):
                collected_files = fim.collect_file_metadata()

        self.assertIsNone(collected_files)

    def test_scan_stops_when_file_collection_fails(self):
        valid_baseline = {
            "test.txt": {
                "sha256": hashlib.sha256(
                    b"Original content"
                ).hexdigest(),
                "size": len(b"Original content")
            }
        }

        with patch(
            "fim.load_baseline",
            return_value=valid_baseline
        ):
            with patch(
                "fim.collect_file_metadata",
                return_value=None
            ):
                with patch("builtins.print") as mock_print:
                    fim.scan_files()

        output = "\n".join(
            str(call) for call in mock_print.call_args_list
        )

        self.assertIn("Scan stopped", output)
        self.assertNotIn("No integrity changes detected", output)

    def test_baseline_creation_stops_when_collection_fails(self):
        with patch(
            "fim.collect_file_metadata",
            return_value=None
        ):
            with patch("builtins.print"):
                fim.create_baseline()

        self.assertFalse(self.baseline_file.exists())
        self.assertFalse(self.signature_file.exists())

    def test_atomic_write_creates_file(self):
        target_file = self.test_path / "atomic_test.txt"
        test_data = b"Atomic write successful"

        fim.atomic_write(target_file, test_data)

        self.assertTrue(target_file.exists())
        self.assertEqual(target_file.read_bytes(), test_data)

    def test_atomic_write_replaces_existing_file(self):
        target_file = self.test_path / "atomic_test.txt"
        target_file.write_bytes(b"Old content")

        new_data = b"Updated content"

        fim.atomic_write(target_file, new_data)

        self.assertEqual(target_file.read_bytes(), new_data)

    def test_atomic_write_failure_preserves_existing_file(self):
        target_file = self.test_path / "atomic_test.txt"
        target_file.write_bytes(b"Original content")

        with patch(
            "fim.os.replace",
            side_effect=OSError("Simulated replacement failure")
        ):
            with self.assertRaises(OSError):
                fim.atomic_write(
                    target_file,
                    b"New content"
                )

        self.assertEqual(
            target_file.read_bytes(),
            b"Original content"
        )

        temporary_files = list(
            self.test_path.glob(".atomic_test.txt.*.tmp")
        )

        self.assertEqual(temporary_files, [])


if __name__ == "__main__":
    unittest.main()
