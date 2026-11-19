
import argparse
import hashlib
import hmac
import json
import logging
import os
import re
import tempfile
from pathlib import Path, PurePosixPath


# Load application configuration
CONFIG_FILE = Path("config.json")


def load_config():
    """Load application settings."""

    if not CONFIG_FILE.exists():
        raise FileNotFoundError("Configuration file not found.")

    with open(CONFIG_FILE, "r") as file:
        config = json.load(file)

    required_settings = [
        "protected_directory",
        "baseline_file",
        "log_directory",
        "key_file",
        "signature_file"
    ]

    for setting in required_settings:
        if setting not in config:
            raise ValueError(f"Missing configuration setting: {setting}")

    return config


CONFIG = load_config()

PROTECTED_DIR = Path(CONFIG["protected_directory"])
BASELINE_FILE = Path(CONFIG["baseline_file"])
LOG_DIR = Path(CONFIG["log_directory"])
LOG_FILE = LOG_DIR / "fim.log"
KEY_FILE = Path(CONFIG["key_file"])
SIGNATURE_FILE = Path(CONFIG["signature_file"])


# Configure audit logging
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)


def calculate_sha256(file_path):
    """Calculate the SHA-256 hash of a file."""

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


def calculate_hmac(data):
    """Generate an HMAC-SHA256 signature using the secret key."""

    if not KEY_FILE.exists():
        raise FileNotFoundError("HMAC secret key not found.")

    key = KEY_FILE.read_bytes()

    if len(key) < 32:
        raise ValueError("HMAC key must contain at least 32 bytes.")

    return hmac.new(
        key,
        data,
        hashlib.sha256
    ).hexdigest()


def atomic_write(file_path, data):
    """Write data safely using a temporary file and atomic replacement."""

    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    temporary_path = None

    try:
        file_descriptor, temporary_name = tempfile.mkstemp(
            dir=file_path.parent,
            prefix=f".{file_path.name}.",
            suffix=".tmp"
        )

        temporary_path = Path(temporary_name)

        with os.fdopen(file_descriptor, "wb") as temporary_file:
            temporary_file.write(data)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        os.replace(temporary_path, file_path)

    except OSError:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

        raise


def collect_file_metadata():
    """Collect file hashes and sizes safely."""

    if not PROTECTED_DIR.is_dir():
        print(f"\nError: Protected directory not found: {PROTECTED_DIR}")
        logging.error("FILE_COLLECTION_FAILED | Protected directory not found")
        return None

    collected_files = {}
    scan_errors = []

    def handle_directory_error(error):
        scan_errors.append(str(error))

    for root, directories, filenames in os.walk(
        PROTECTED_DIR,
        topdown=True,
        followlinks=False,
        onerror=handle_directory_error
    ):

        # Do not follow symbolic links to directories
        directories[:] = [
            directory
            for directory in directories
            if not os.path.islink(os.path.join(root, directory))
        ]

        for filename in filenames:

            file_path = Path(root) / filename

            try:
                # Skip symbolic links
                if file_path.is_symlink():
                    logging.warning(
                        "SYMLINK_SKIPPED | File: %s",
                        file_path
                    )
                    continue

                if not file_path.is_file():
                    continue

                file_hash = calculate_sha256(file_path)
                file_size = file_path.stat().st_size

                relative_path = file_path.relative_to(
                    PROTECTED_DIR
                ).as_posix()

                collected_files[relative_path] = {
                    "sha256": file_hash,
                    "size": file_size
                }

            except OSError as error:
                scan_errors.append(f"{file_path}: {error}")

    if scan_errors:
        print("\n[ERROR] File collection was incomplete.")

        for error in scan_errors:
            print(f"  - {error}")
            logging.error("FILE_COLLECTION_ERROR | %s", error)

        print("\nOperation stopped to avoid unreliable results.")

        logging.error(
            "FILE_COLLECTION_FAILED | Errors encountered: %d",
            len(scan_errors)
        )

        return None

    return collected_files


def validate_baseline(baseline):
    """Validate the structure and contents of a baseline."""

    if not isinstance(baseline, dict):
        raise ValueError("Baseline must be a JSON object.")

    for file_path, file_data in baseline.items():

        if not isinstance(file_path, str) or not file_path:
            raise ValueError("Invalid file path in baseline.")

        relative_path = PurePosixPath(file_path)

        if (
            relative_path.is_absolute()
            or ".." in relative_path.parts
            or "\\" in file_path
        ):
            raise ValueError(f"Unsafe file path in baseline: {file_path}")

        if not isinstance(file_data, dict):
            raise ValueError(f"Invalid file entry: {file_path}")

        file_hash = file_data.get("sha256")
        file_size = file_data.get("size")

        if (
            not isinstance(file_hash, str)
            or not re.fullmatch(r"[a-fA-F0-9]{64}", file_hash)
        ):
            raise ValueError(f"Invalid SHA-256 hash: {file_path}")

        if (
            not isinstance(file_size, int)
            or isinstance(file_size, bool)
            or file_size < 0
        ):
            raise ValueError(f"Invalid file size: {file_path}")

    return True


def create_baseline():
    """Create a trusted baseline and its HMAC signature."""

    baseline = collect_file_metadata()

    if baseline is None:
        print("\nBaseline creation stopped because file collection failed.")
        logging.error("BASELINE_FAILED | File collection incomplete")
        return

    try:
        baseline_data = json.dumps(
            baseline,
            indent=4
        ).encode("utf-8")

        signature = calculate_hmac(baseline_data)

        atomic_write(
            SIGNATURE_FILE,
            signature.encode("utf-8")
        )

        atomic_write(
            BASELINE_FILE,
            baseline_data
        )

    except (OSError, ValueError) as error:
        print(f"\nError creating baseline: {error}")
        logging.error("BASELINE_FAILED | %s", error)
        return

    print("\nBaseline created successfully.")
    print(f"Files monitored: {len(baseline)}")
    print(f"Baseline saved to: {BASELINE_FILE}")
    print("HMAC signature generated successfully.")

    logging.info(
        "BASELINE_CREATED | Files monitored: %d",
        len(baseline)
    )


def load_baseline():
    """Verify baseline authenticity and structure before loading."""

    if not BASELINE_FILE.exists():
        print("\nError: Baseline file not found.")
        logging.error("BASELINE_LOAD_FAILED | Baseline file not found")
        return None

    if not SIGNATURE_FILE.exists():
        print("\nSECURITY ALERT: Baseline signature missing.")
        logging.critical("BASELINE_SIGNATURE_MISSING")
        return None

    try:
        baseline_data = BASELINE_FILE.read_bytes()
        stored_signature = SIGNATURE_FILE.read_text().strip()

        expected_signature = calculate_hmac(baseline_data)

        if not hmac.compare_digest(
            stored_signature,
            expected_signature
        ):
            print("\n[CRITICAL] Baseline integrity verification failed!")
            print("The baseline may have been modified.")

            logging.critical("BASELINE_TAMPERING_DETECTED")
            return None

        baseline = json.loads(baseline_data.decode("utf-8"))

        validate_baseline(baseline)

        print("\n[OK] Baseline authenticity verified.")
        print("[OK] Baseline structure validated.")

        return baseline

    except (
        OSError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError
    ) as error:

        print(f"\nError verifying baseline: {error}")
        logging.error("BASELINE_VERIFICATION_FAILED | %s", error)

        return None


def scan_files():
    """Compare current files against the trusted baseline."""

    baseline = load_baseline()

    if baseline is None:
        print("\nScan stopped because the baseline could not be trusted.")
        return

    current_files = collect_file_metadata()

    if current_files is None:
        print("\nScan stopped because file collection failed.")
        return

    modified = []
    deleted = []
    new_files = []

    # Detect modified and deleted files
    for file_path, old_data in baseline.items():

        if file_path not in current_files:
            deleted.append(file_path)

        elif current_files[file_path]["sha256"] != old_data["sha256"]:
            modified.append(file_path)

    # Detect newly created files
    for file_path in current_files:

        if file_path not in baseline:
            new_files.append(file_path)

    print("\n====================================")
    print("       INTEGRITY SCAN RESULTS")
    print("====================================")

    if modified:
        print("\n[ALERT] Modified files:")

        for file_path in modified:
            print(f"  - {file_path}")
            logging.warning("MODIFIED | File: %s", file_path)

    if deleted:
        print("\n[ALERT] Deleted files:")

        for file_path in deleted:
            print(f"  - {file_path}")
            logging.warning("DELETED | File: %s", file_path)

    if new_files:
        print("\n[ALERT] New files:")

        for file_path in new_files:
            print(f"  - {file_path}")
            logging.warning("NEW_FILE | File: %s", file_path)

    if not modified and not deleted and not new_files:
        print("\n[OK] No integrity changes detected.")
        logging.info("SCAN_COMPLETE | No integrity changes detected")

    print("\n====================================")


def main(argv=None):
    """Run the application using commands or the interactive menu."""

    parser = argparse.ArgumentParser(
        description="Python-based File Integrity Monitoring System"
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    subparsers.add_parser(
        "baseline",
        help="Create a new trusted file baseline"
    )

    subparsers.add_parser(
        "scan",
        help="Scan files for integrity changes"
    )

    args = parser.parse_args(argv)

    if args.command == "baseline":
        create_baseline()

    elif args.command == "scan":
        scan_files()

    else:
        print("\n====================================")
        print("       FILE INTEGRITY MONITOR")
        print("====================================")

        print("\n1. Create baseline")
        print("2. Scan files")

        choice = input("\nSelect an option: ")

        if choice == "1":
            create_baseline()

        elif choice == "2":
            scan_files()

        else:
            print("\nInvalid option.")


if __name__ == "__main__":
    main()
