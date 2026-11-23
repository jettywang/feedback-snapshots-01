# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e acme -e certbot
.venv/bin/python -m pytest -q -o addopts= acme/src/acme/_internal/tests/messages_test.py acme/src/acme/_internal/tests/jws_test.py certbot/src/certbot/_internal/tests/renewal_test.py -k 'not update_symlinks'
```

Measured on macOS in 5.550 seconds. Tests use local fixtures and require no external service.
