# Local preparation

Upstream: https://github.com/theupdateframework/python-tuf
Commit: e897eec93e37843884d0f37e37d40aa45393e1bb
Python 3.12. Application source and existing tests are unchanged.

Create an independent environment:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

Run the existing fast baseline:

```sh
.venv/bin/python -m pytest -q -o addopts= tests/test_trusted_metadata_set.py tests/test_metadata_serialization.py
```

This baseline passed in 2.836 seconds on the preparation host. It is an existing-test subset, not a solution or an acceptance test for a future change. Detailed output is retained in the batch preparation evidence. The selection uses local data and does not need external services.
