# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= huey/tests/test_api.py huey/tests/test_registry.py huey/tests/test_serializer.py huey/tests/test_immediate.py
```

Measured on macOS in 0.598 seconds. Tests use local fixtures and require no external service.
