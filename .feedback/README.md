# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_metadata.py tests/test_requirements.py tests/test_pylock_select.py tests/test_markers.py
```

Measured on macOS in 7.101 seconds. Tests use local fixtures and require no external service.
