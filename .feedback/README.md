# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= --noconftest tests/test_public_definition_paths.py
```

Measured on macOS in 0.979 seconds. Tests use local fixtures and require no external service.
