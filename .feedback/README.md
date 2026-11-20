# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= test/querying/test_query_services.py test/querying/test_query_arns.py test/writing/test_minimize.py test/writing/test_validate.py
```

Measured on macOS in 1.903 seconds. Tests use local fixtures and require no external service.
