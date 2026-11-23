# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= test/unit/test_manager.py test/unit/transport/test_parser.py test/unit/test_xml_.py
```

Measured on macOS in 9.491 seconds. Tests use local fixtures and require no external service.
