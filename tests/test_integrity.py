import hashlib
import os
import sys
import unittest
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import integrity


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp()
        os.write(fd, b"print('hello')\n")
        os.close(fd)
        self.digest = hashlib.sha256(b"print('hello')\n").hexdigest()

    def tearDown(self):
        os.remove(self.path)

    def test_disabled_when_unset(self):
        os.environ.pop(integrity.ENV_VAR, None)
        self.assertTrue(integrity.verify_integrity(self.path))

    def test_match(self):
        self.assertTrue(integrity.verify_integrity(self.path, self.digest.upper()))

    def test_mismatch_exits(self):
        with self.assertRaises(SystemExit) as cm:
            integrity.guard(self.path, "0" * 64)
        self.assertEqual(cm.exception.code, integrity.EXIT_CODE)

    def test_missing_file_fails(self):
        self.assertFalse(integrity.verify_integrity(self.path + ".nope", self.digest))

    def test_env_var(self):
        os.environ[integrity.ENV_VAR] = self.digest
        try:
            integrity.guard(self.path)
        finally:
            del os.environ[integrity.ENV_VAR]


if __name__ == "__main__":
    unittest.main()
