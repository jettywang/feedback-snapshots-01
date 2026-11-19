# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= social_core/tests/test_pipeline.py social_core/tests/test_partial.py social_core/tests/test_groups.py social_core/tests/test_oidc_cache.py
```

Measured on macOS in 3.447 seconds. Tests use local fixtures and require no external service.
