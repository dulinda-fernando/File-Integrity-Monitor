
# Python-Based File Integrity Monitoring System

A Python-based cybersecurity tool that monitors files and detects unauthorized changes using SHA-256 hashing and HMAC-SHA256 authentication.

## Project Overview

File Integrity Monitoring (FIM) is a security technique used to detect unauthorized modifications, additions, or deletions of files.

This project provides a command-line application that creates a trusted baseline of protected files and compares their current state against that baseline.

It also uses HMAC-SHA256 to authenticate the baseline and detect unauthorized modifications to the baseline data itself.

## Features

- **SHA-256 Hashing:** Generates cryptographic hashes for monitored files.
- **Baseline Creation:** Creates a trusted record of file hashes and sizes.
- **File Modification Detection:** Identifies modified files.
- **File Deletion Detection:** Detects files removed from the protected directory.
- **New File Detection:** Identifies newly created files.
- **HMAC-SHA256 Authentication:** Verifies baseline authenticity using a secret key.
- **Tampering Detection:** Detects unauthorized modifications to baseline data.
- **Input Validation:** Validates baseline structure, file paths, hashes, and file sizes.
- **Symbolic Link Protection:** Skips symbolic links during file collection.
- **Error Handling:** Stops scans when file collection is incomplete.
- **Atomic File Writes:** Uses temporary files and atomic replacement to reduce the risk of incomplete writes.
- **Audit Logging:** Records important security events.
- **Automated Testing:** Includes unit tests for core functionality and security checks.

## Technologies Used

- Python 3
- SHA-256
- HMAC-SHA256
- JSON
- Python Logging
- Python Unittest
- Linux / Ubuntu
- Git

## Project Structure

```text
File-Integrity-Monitor/
│
├── fim.py
├── config.json
├── .gitignore
├── README.md
│
├── protected_files/
│
├── tests/
│   └── test_fim.py
│
└── logs/
    └── fim.log
```

Runtime-generated files:

- `baseline.json` - Stores the trusted file baseline.
- `baseline.key` - Stores the secret HMAC key.
- `baseline.sig` - Stores the baseline signature.

These files are excluded from Git using `.gitignore`.

## Installation

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

### 2. Navigate to the project

```bash
cd File-Integrity-Monitor
```

### 3. Check Python installation

```bash
python3 --version
```

No external Python packages are required.

## Configuration

Edit `config.json` to configure the monitored directory and application files.

Example:

```json
{
    "protected_directory": "protected_files",
    "baseline_file": "baseline.json",
    "log_directory": "logs",
    "key_file": "baseline.key",
    "signature_file": "baseline.sig"
}
```

The application expects a secret key file named `baseline.key` containing at least 32 bytes of key material.

Protect this file from unauthorized access.

## Usage

### 1. Create a baseline

```bash
python3 fim.py baseline
```

This command calculates the SHA-256 hashes of monitored files and creates an HMAC-authenticated baseline.

### 2. Scan for integrity changes

```bash
python3 fim.py scan
```

This command verifies the baseline and compares it against the current files.

### 3. View available commands

```bash
python3 fim.py --help
```

## Example Output

### Successful baseline creation

```text
Baseline created successfully.
Files monitored: 1
Baseline saved to: baseline.json
HMAC signature generated successfully.
```

### Successful integrity scan

```text
[OK] Baseline authenticity verified.
[OK] Baseline structure validated.

====================================
       INTEGRITY SCAN RESULTS
====================================

[OK] No integrity changes detected.

====================================
```

### Example modification detection

```text
[ALERT] Modified files:
  - example.txt
```

## Running Tests

Run the automated test suite:

```bash
python3 -m unittest discover -s tests -v
```

The test suite covers:

- SHA-256 hash calculation.
- Baseline creation and verification.
- Baseline tampering detection.
- Modified, deleted, and new file detection.
- Invalid baseline rejection.
- Unsafe file path rejection.
- Symbolic link handling.
- File collection error handling.
- Atomic write creation, replacement, and failure handling.

**Current test result: 19 tests passing.**

## Security Considerations

- SHA-256 is used to identify changes in monitored file contents.
- HMAC-SHA256 authenticates baseline data using a secret key.
- The HMAC key must remain confidential.
- Baseline and signature files should be protected against unauthorized access.
- The project should be tested in a controlled environment before being used for security-critical monitoring.

**Important limitation:** HMAC authentication depends on protecting the secret key. An attacker who obtains the key may be able to create a valid signature for a modified baseline. This project is an educational security tool and is not a replacement for an enterprise-grade file integrity monitoring platform.

## Future Improvements

- Email or real-time security alerts.
- Scheduled automatic scans.
- Advanced configuration validation.
- Improved key management.
- Database-based audit history.
- Dashboard for monitoring file integrity.
- Additional security and integration tests.

## Author

**Dulinda Fernando**

Cyber Security Undergraduate  
Sri Lanka Institute of Information Technology (SLIIT)

GitHub: https://github.com/dulinda-fernando

---

Developed as a cybersecurity portfolio project to explore file integrity monitoring, cryptographic authentication, secure file handling, and automated security testing.
