# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= test/test_impl.py test/test_init.py -k 'not staging and not live and not sign and not rekor'
```

Measured on macOS in 5.742 seconds. Tests use local fixtures and require no external service.
