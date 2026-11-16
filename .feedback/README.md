# Local preparation

Upstream: https://github.com/fox-it/dissect.apfs
Pinned upstream: `a5626763922a16182a670e4906cfb8b88cf4baa6`

This commit contains environment preparation only. Application source is unchanged.

Python 3.12.

`uv venv --python 3.12 .venv`
`uv pip install --link-mode copy --python .venv/bin/python -r .feedback/requirements.txt -e .`

Existing fast baseline (not a task solution):

```sh
.venv/bin/python -m pytest -q tests/test_apfs.py::test_large_extents
```

Recorded exit code: 0. Local elapsed seconds: 0.964.
