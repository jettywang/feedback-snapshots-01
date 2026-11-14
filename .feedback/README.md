# Local preparation

Upstream: https://github.com/pyasn1/pyasn1-modules
Commit: 02f9c577bcd0ad9fedfb0fd5dc598d323f7984bf
Python 3.12. Application source and existing tests are unchanged.

Create an independent environment:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

Run the existing fast baseline:

```sh
.venv/bin/python -m unittest tests.test_rfc5280 tests.test_rfc5652 tests.test_rfc6960 tests.test_rfc3161
```

This baseline passed in 0.537 seconds on the preparation host. It is an existing-test subset, not a solution or an acceptance test for a future change. Detailed output is retained in the batch preparation evidence. The selection uses local data and does not need external services.

Public protocol references are preserved under `.feedback/specs/`; `index.json` records original sources and SHA-256 hashes. These reference materials contain no task solution.
