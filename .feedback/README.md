# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m django test --settings=tests.settings --noinput
```

Measured on macOS in 1.302 seconds. Tests use local fixtures and require no external service.
