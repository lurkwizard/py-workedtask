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
