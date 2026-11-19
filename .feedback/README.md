# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/unit_tests/test_adapters.py tests/unit_tests/v1/test_client.py tests/unit_tests/api/auth_methods/test_token.py
```

Measured on macOS in 0.948 seconds. Tests use local fixtures and require no external service.
