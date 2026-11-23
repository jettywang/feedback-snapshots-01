# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= -o minversion=0 -p pytester testing/io/test_saferepr.py testing/test_reports.py -p no:hypothesispytest
```

Measured on macOS in 1.318 seconds. Tests use local fixtures and require no external service.
