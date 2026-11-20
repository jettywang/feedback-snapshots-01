# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= src/twisted/protocols/haproxy/test/test_v1parser.py src/twisted/protocols/haproxy/test/test_v2parser.py
```

Measured on macOS in 0.720 seconds. Tests use local fixtures and require no external service.
