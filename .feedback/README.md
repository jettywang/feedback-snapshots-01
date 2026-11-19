# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= test/test_fix.py test/test_audit.py test/test_state.py test/service/test_interface.py test/format
```

Measured on macOS in 1.952 seconds. Tests use local fixtures and require no external service.
