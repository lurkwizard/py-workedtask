# py-workedtask

## Python integrity verification

`integrity.py` checks the SHA-256 of the running script against the
`JAVELIN_EXPECTED_SHA256` environment variable. If the variable is unset the
check is skipped; if it does not match, the process exits with code 3.

Get the expected value and run:

```sh
python integrity.py your_script.py            # prints the SHA-256
export JAVELIN_EXPECTED_SHA256=<that hash>
```

In your script, call `integrity.guard()` at startup.

Run tests with `python -m unittest discover -s tests`.


## C++ executable integrity verification

`AntiCheat.cpp` checks the running executable two ways (both optional):

1. **CRC32** against a build-time constant `JAVELIN_EXPECTED_CRC32`. If the
   constant is `0`, the check is skipped.
2. **SHA-256** against the `JAVELIN_EXPECTED_SHA256` environment variable, or
   against a build-time string (`-DJAVELIN_EXPECTED_SHA256_STR='"<hex>"'`).
   The env var wins when set. A mismatch exits with code `3` (same as Python).
   The hex digest is compared case-insensitively, and surrounding whitespace
   is ignored, matching `integrity.py`.

Build (MinGW cross-compile example):

```sh
x86_64-w64-mingw32-g++ -std=c++17 -O2 -o AntiCheat.exe AntiCheat.cpp
```

Set the expected SHA-256 of a shipped build, then run:

```sh
# On Windows, after hashing AntiCheat.exe:
set JAVELIN_EXPECTED_SHA256=<hex of AntiCheat.exe>
AntiCheat.exe
```

Portable SHA-256 lives in `sha256.hpp`. Native vector tests (no Windows needed):

```sh
g++ -std=c++17 -O2 -o tests/test_sha256 tests/test_sha256.cpp && ./tests/test_sha256
```

GitHub Actions (`.github/workflows/windows.yml`) runs on `windows-latest`. It
builds `AntiCheat.cpp` with MSVC and MinGW, runs the SHA-256 vector test and
the Python unittest suite, and smoke-tests the executable: exit code `0` when
`JAVELIN_EXPECTED_SHA256` is that exe’s SHA-256, and exit code `3` when it is not.
