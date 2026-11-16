# Local preparation

Upstream: https://github.com/fox-it/dissect.database
Pinned upstream: `c6fedbb0e1d878e1fb499f5458275b0e474aa95b`

This commit contains environment preparation only. Application source is unchanged.

Python 3.12.

`uv venv --python 3.12 .venv`
`uv pip install --link-mode copy --python .venv/bin/python -r .feedback/requirements.txt -e .`

Existing fast baseline (not a task solution):

```sh
.venv/bin/python -m pytest -q tests/sqlite3
```

Recorded exit code: 0. Local elapsed seconds: 3.932.
