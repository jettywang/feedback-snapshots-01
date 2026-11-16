# Local preparation

Upstream: https://github.com/erocarrera/pefile
Pinned upstream: `43ca73f3feaccb5f84836055c540021bcfcfe808`

This commit contains environment preparation only. Application source is unchanged.

Python 3.12.

`uv venv --python 3.12 .venv`
`uv pip install --link-mode copy --python .venv/bin/python -r .feedback/requirements.txt -e .`

Existing fast baseline (not a task solution):

```sh
.venv/bin/python .feedback/smoke_pe.py
```

Recorded exit code: 0. Local elapsed seconds: 0.076.

The upstream optional external pefile-tests corpus is not bundled. The baseline builds a minimal inert PE in memory and parses its headers/section bytes; it does not execute the PE.
