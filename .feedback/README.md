# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e opentelemetry-api -e opentelemetry-sdk -e opentelemetry-semantic-conventions
.venv/bin/python -m pytest -q -o addopts= opentelemetry-sdk/tests/trace/test_sampling.py opentelemetry-sdk/tests/trace/export/test_export.py opentelemetry-sdk/tests/resources/test_resources.py
```

Measured on macOS in 1.716 seconds. Tests use local fixtures and require no external service.
