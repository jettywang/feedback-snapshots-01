# Local preparation

Upstream: https://github.com/ecordell/pymacaroons
Commit: 78c55c1d33a0b23ddc71140a9c999f957d79e9dd
Python 3.12. Application source and existing tests are unchanged.

Create an independent environment:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

Run the existing fast baseline:

```sh
.venv/bin/python -m pytest -q -o addopts= tests/functional_tests/functional_tests.py tests/functional_tests/serialization_tests.py
```

This baseline passed in 1.484 seconds on the preparation host. It is an existing-test subset, not a solution or an acceptance test for a future change. Detailed output is retained in the batch preparation evidence. The selection uses local data and does not need external services.
