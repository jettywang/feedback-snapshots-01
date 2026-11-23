# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_add_option_serialize.py tests/test_contextualize.py tests/test_add_option_filter.py
```

Measured on macOS in 1.000 seconds. Tests use local fixtures and require no external service.
