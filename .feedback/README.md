# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= csp/tests/test_middleware.py csp/tests/test_decorators.py csp/tests/test_utils.py
```

Measured on macOS in 2.526 seconds. Tests use local fixtures and require no external service.
