# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_inspect.py tests/test_settings_loader.py tests/test_nested_loading.py tests/test_base.py -k 'not test_get_item and not test_env_override_nested_lazy_value_from_included_file'
```

Measured on macOS in 2.679 seconds. Tests use local fixtures and require no external service.
