# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_rbac_api.py tests/test_fast_enforcer.py tests/model/test_policy.py tests/test_explanation_copy.py
```

Measured on macOS in 0.828 seconds. Tests use local fixtures and require no external service.
