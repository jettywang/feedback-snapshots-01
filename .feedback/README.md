# Local preparation

Upstream: https://github.com/secure-systems-lab/securesystemslib
Commit: a4a1390b01fdb2762ead66e1022ae928f061fb04
Python 3.12. Application source and existing tests are unchanged.

Create an independent environment:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

Run the existing fast baseline:

```sh
.venv/bin/python -m pytest -q -o addopts= tests/test_dsse.py tests/test_formats.py tests/test_hash.py
```

This baseline passed in 2.326 seconds on the preparation host. It is an existing-test subset, not a solution or an acceptance test for a future change. Detailed output is retained in the batch preparation evidence. The selection uses local data and does not need external services.
