# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= oslo_policy/tests/test_checks.py oslo_policy/tests/test_policy.py oslo_policy/tests/test_cache_handler.py
```

Measured on macOS in 2.658 seconds. Tests use local fixtures and require no external service.
