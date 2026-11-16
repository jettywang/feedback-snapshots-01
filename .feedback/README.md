# Local preparation

Upstream: https://github.com/fox-it/dissect.btrfs
Pinned upstream: `0549eb04f44df66ee51533c6356d824c1bbd4db3`

This commit contains environment preparation only. Application source is unchanged.

Python 3.12.

`uv venv --python 3.12 .venv`
`uv pip install --link-mode copy --python .venv/bin/python -r .feedback/requirements.txt -e .`

Existing fast baseline (not a task solution):

```sh
.venv/bin/python -m pytest -q tests/test_btrfs.py
```

Recorded exit code: 0. Local elapsed seconds: 2.569.

Public format definitions: https://github.com/torvalds/linux/tree/v6.12/fs
