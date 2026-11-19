# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/unit/test_upload.py tests/unit/test_download.py tests/unit/test_copies.py tests/unit/test_tasks.py
```

Measured on macOS in 12.493 seconds. Tests use local fixtures and require no external service.
