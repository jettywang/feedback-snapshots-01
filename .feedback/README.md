# Local preparation

Upstream: https://github.com/aio-libs/aiosmtpd
Commit: 0aef6a19bf3c43ebded54ee943aaacbff93d68bf
Python 3.12. Application source and existing tests are unchanged.

Create an independent environment:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

Run the existing fast baseline:

```sh
.venv/bin/python -m pytest -q -o addopts= aiosmtpd/tests/test_smtp.py -k 'helo or rset'
```

This baseline passed in 1.757 seconds on the preparation host. It is an existing-test subset, not a solution or an acceptance test for a future change. Detailed output is retained in the batch preparation evidence. The selection uses local data and does not need external services.

Public protocol references are preserved under `.feedback/specs/`; `index.json` records original sources and SHA-256 hashes. These reference materials contain no task solution.
