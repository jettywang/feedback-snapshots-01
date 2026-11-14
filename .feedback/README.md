# Local preparation

Upstream: https://github.com/pyasn1/pyasn1
Commit: e24fa719428229db5efeb8aee74ce6d03329df5d
Python 3.12. Application source and existing tests are unchanged.

Create an independent environment:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

Run the existing fast baseline:

```sh
.venv/bin/python -Werror -m unittest discover -s tests
```

This baseline passed in 0.518 seconds on the preparation host. It is an existing-test subset, not a solution or an acceptance test for a future change. Detailed output is retained in the batch preparation evidence. The selection uses local data and does not need external services.
