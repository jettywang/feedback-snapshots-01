# Local preparation

Upstream: https://github.com/in-toto/in-toto
Commit: e352b43ad7cb8915d84c36d791aa61346152a0a3
Python 3.12. Application source and existing tests are unchanged.

Create an independent environment:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

Run the existing fast baseline:

```sh
.venv/bin/python -m pytest -q -o addopts= tests/test_rulelib.py tests/models
```

This baseline passed in 4.004 seconds on the preparation host. It is an existing-test subset, not a solution or an acceptance test for a future change. Detailed output is retained in the batch preparation evidence. The selection uses local data and does not need external services.
