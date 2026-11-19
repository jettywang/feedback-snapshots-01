# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= guardian/testapp/tests/test_core.py guardian/testapp/tests/test_shortcuts.py guardian/testapp/tests/test_backends.py
```

Measured on macOS in 9.808 seconds. Tests use local fixtures and require no external service.
