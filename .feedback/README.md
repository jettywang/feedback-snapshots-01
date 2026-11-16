# Local preparation

Upstream: https://github.com/fox-it/dissect.ntfs
Pinned upstream: `83f71a87e173613580eb31f64c600789f4259c20`

This commit contains environment preparation only. Application source is unchanged.

Python 3.12.

`uv venv --python 3.12 .venv`
`uv pip install --link-mode copy --python .venv/bin/python -r .feedback/requirements.txt -e .`

Existing fast baseline (not a task solution):

```sh
.venv/bin/python -m pytest -q tests/test_secure.py tests/test_usnjrnl.py tests/test_util.py
```

Recorded exit code: 0. Local elapsed seconds: 0.891.
