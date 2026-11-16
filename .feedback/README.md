# Local preparation

Upstream: https://github.com/fox-it/dissect.hypervisor
Pinned upstream: `9736c31a0761d96eb81d22a3ba675c07b67f1d26`

This commit contains environment preparation only. Application source is unchanged.

Python 3.12.

`uv venv --python 3.12 .venv`
`uv pip install --link-mode copy --python .venv/bin/python -r .feedback/requirements.txt -e .`

Existing fast baseline (not a task solution):

```sh
.venv/bin/python -m pytest -q tests/disk/test_vhdx.py tests/disk/test_qcow2.py
```

Recorded exit code: 0. Local elapsed seconds: 4.858.
