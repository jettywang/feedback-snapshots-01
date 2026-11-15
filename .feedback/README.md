# Local preparation

Upstream: https://github.com/fox-it/dissect.etl
Commit: 808a10cfb3fe0af7521a0922d6a8829335197618
Runtime: Python 3.12. Application source and existing tests are unchanged.

Install the locked runtime and test dependencies:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

Run the existing fast baseline:

```sh
.venv/bin/python -m pytest -q
```

The selected upstream tests passed in 0.836 seconds on the preparation host. This is a baseline, not an acceptance test or a solution to a future task. The complete output and its hash are kept in batch preparation evidence. No external service is required by the baseline.
