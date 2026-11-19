# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= t/unit/test_serialization.py t/unit/test_message.py t/unit/test_connection.py
```

Measured on macOS in 9.670 seconds. Tests use local fixtures and require no external service.
