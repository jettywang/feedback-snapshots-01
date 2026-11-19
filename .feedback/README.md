# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_contextvars.py tests/test_tracebacks.py tests/test_stdlib.py tests/processors -k 'not CallsiteParameterAdder'
```

Measured on macOS in 0.755 seconds. Tests use local fixtures and require no external service.
