# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= macholib_tests/test_MachO.py macholib_tests/test_mach_o.py macholib_tests/test_ptypes.py
```

Measured on macOS in 0.496 seconds. Tests use local fixtures and require no external service.
