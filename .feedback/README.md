# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.13 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= referencing/tests/test_core.py referencing/tests/test_jsonschema.py referencing/tests/test_exceptions.py
```

Measured on macOS in 0.752 seconds. Tests use local fixtures and require no external service.
