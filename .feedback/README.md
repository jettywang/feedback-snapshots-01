# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_encoders.py tests/test_messages.py tests/test_actors.py tests/test_stub_broker.py tests/test_concurrent_rate_limiter.py
```

Measured on macOS in 17.256 seconds. Tests use local fixtures and require no external service.
