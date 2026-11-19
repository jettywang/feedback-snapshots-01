# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -c 'import os, runpy, sys; os.chdir("auditlog_tests"); sys.path.insert(0, os.getcwd()); sys.argv = ["manage.py", "test", "--noinput"]; runpy.run_path("manage.py", run_name="__main__")'
```

Measured on macOS in 3.023 seconds. Tests use local fixtures and require no external service.
