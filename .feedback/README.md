# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/spdx/validation/test_document_validator.py tests/spdx/validation/test_relationship_validator.py tests/spdx/validation/test_file_validator.py
```

Measured on macOS in 1.761 seconds. Tests use local fixtures and require no external service.
