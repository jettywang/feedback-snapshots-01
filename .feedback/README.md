# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_convert.py tests/test_table.py -k 'not test_pdf_with_no_table'
```

Measured on macOS in 5.021 seconds. Tests use local fixtures and require no external service.
