# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= --noconftest -o pythonpath=tests tests/test_recorded_pip_args.py -k 'not reinstall and not upgrade and not manifest and not lock'
```

Measured on macOS in 0.656 seconds. Tests use local fixtures and require no external service.
