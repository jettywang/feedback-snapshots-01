# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_core/test_v1/test_event.py tests/test_core/test_format/test_json.py tests/test_core/test_bindings/test_http.py
```

Measured on macOS in 0.666 seconds. Tests use local fixtures and require no external service.
