# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_credentials.py tests/oauth2/test_credentials.py tests/test_api_key.py
```

Measured on macOS in 3.518 seconds. Tests use local fixtures and require no external service.
