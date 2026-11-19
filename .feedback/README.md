# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_request.py tests/test_cookies.py tests/test_cachecontrol.py tests/test_response.py
```

Measured on macOS in 0.989 seconds. Tests use local fixtures and require no external service.
