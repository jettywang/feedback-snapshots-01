# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_artifact_status.py tests/test_sqlite_date_nulls.py tests/test_cache_entry_isolation.py
```

Measured on macOS in 15.390 seconds. Tests use local fixtures and require no external service.
