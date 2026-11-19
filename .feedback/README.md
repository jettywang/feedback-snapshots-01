# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/unit/channel_tests.py tests/unit/connection_tests.py tests/unit/heartbeat_tests.py tests/unit/credentials_tests.py tests/unit/content_frame_assembler_tests.py
```

Measured on macOS in 7.530 seconds. Tests use local fixtures and require no external service.
