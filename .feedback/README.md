# Local preparation

Upstream: https://github.com/fox-it/dissect.xfs
Pinned upstream: `abac18bfab4d3401c00506670dbb59db653e7b7e`

This commit contains environment preparation only. Application source is unchanged.

Python 3.12.

`uv venv --python 3.12 .venv`
`uv pip install --link-mode copy --python .venv/bin/python -r .feedback/requirements.txt -e .`

Existing fast baseline (not a task solution):

```sh
.venv/bin/python -m pytest -q tests/test_xfs.py
```

Recorded exit code: 0. Local elapsed seconds: 0.832.

Public format definitions: https://github.com/torvalds/linux/tree/v6.12/fs
