# Local preparation

Upstream: https://github.com/clalancette/pycdlib
Pinned upstream: `d5a9946b08a6a30935dcca188b7ef7fa744a4967`

This commit contains environment preparation only. Application source is unchanged.

Python 3.12.

`uv venv --python 3.12 .venv`
`uv pip install --link-mode copy --python .venv/bin/python -r .feedback/requirements.txt -e .`

Existing fast baseline (not a task solution):

```sh
env TZ=UTC .venv/bin/python -m pytest -q tests/unit/test_eltorito.py tests/unit/test_rockridge.py
```

Recorded exit code: 0. Local elapsed seconds: 0.19.

UTC is fixed because three upstream timestamp expectations use that calendar date.
