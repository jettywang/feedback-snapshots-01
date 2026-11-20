# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= keystoneauth1/tests/unit/test_session.py keystoneauth1/tests/unit/loading/test_session.py -k 'not test_user_agent'
```

Measured on macOS in 1.457 seconds. Tests use local fixtures and require no external service.
