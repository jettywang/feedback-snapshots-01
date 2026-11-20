# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_samples.py tests/test_asgi.py tests/test_core.py tests/test_process_collector.py
```

Measured on macOS in 4.259 seconds. Tests use local fixtures and require no external service.
