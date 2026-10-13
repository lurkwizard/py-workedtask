"""Javelin Project - optional script integrity verification (SHA-256).

Set JAVELIN_EXPECTED_SHA256 to the hex SHA-256 of the script file. If it is
set and the file's hash does not match, the process exits with a non-zero
code. If it is unset, the check is skipped.
"""
import hashlib
import hmac
import os
import sys

ENV_VAR = "JAVELIN_EXPECTED_SHA256"
EXIT_CODE = 3
TAG = "[Javelin AntiCheat] "


def sha256_file(path, chunk_size=65536):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_integrity(path, expected=None):
    """Return True if the check passes or is disabled, False on mismatch or read error."""
    if expected is None:
        expected = os.environ.get(ENV_VAR)
    if not expected:
        return True
    try:
        actual = sha256_file(path)
    except OSError:
        return False
    return hmac.compare_digest(actual, expected.strip().lower())


def guard(path=None, expected=None):
    """Exit the process if the integrity check fails."""
    path = path or os.path.abspath(sys.argv[0])
    if not verify_integrity(path, expected):
        sys.stderr.write(TAG + "Integrity check failed for %s\n" % path)
        sys.exit(EXIT_CODE)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        print(sha256_file(sys.argv[1]))
    else:
        sys.stderr.write("usage: python integrity.py <file>\n")
        sys.exit(2)
