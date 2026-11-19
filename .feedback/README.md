# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= radicale/tests/test_rights.py radicale/tests/test_htgroup.py radicale/tests/test_log.py radicale/tests/test_config.py
```

Measured on macOS in 2.510 seconds. Tests use local fixtures and require no external service.
