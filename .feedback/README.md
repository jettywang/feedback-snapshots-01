# Local preparation

Upstream: https://github.com/theopolis/uefi-firmware-parser
Pinned upstream: `4942c4865da22000f4bb484830e26019ec061498`

This commit contains environment preparation only. Application source is unchanged.

Python 3.12.

`uv venv --python 3.12 .venv`
`uv pip install --link-mode copy --python .venv/bin/python -r .feedback/requirements.txt -e .`

Existing fast baseline (not a task solution):

```sh
.venv/bin/python -bb -m unittest discover -s tests
```

Recorded exit code: 0. Local elapsed seconds: 2.345.
