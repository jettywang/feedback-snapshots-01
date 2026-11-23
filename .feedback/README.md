# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_generator.py tests/test_scopes_backend.py tests/test_validators.py --ds=tests.settings
```

Measured on macOS in 5.917 seconds. Tests use local fixtures and require no external service.
