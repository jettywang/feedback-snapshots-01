# Local preparation

Upstream: https://github.com/TimothyClaeys/pycose
Commit: 1458ddf14efffbd00bc4052d9026b63da725098e
Python 3.12. Application source and existing tests are unchanged.

Create an independent environment:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

Run the existing fast baseline:

```sh
.venv/bin/python -m pytest -q -o addopts= tests/test_sign1message.py tests/test_mac0message.py tests/test_enc0message.py tests/test_cosemessage.py
```

This baseline passed in 0.998 seconds on the preparation host. It is an existing-test subset, not a solution or an acceptance test for a future change. Detailed output is retained in the batch preparation evidence. The selection uses local data and does not need external services.

Public protocol references are preserved under `.feedback/specs/`; `index.json` records original sources and SHA-256 hashes. These reference materials contain no task solution.
