# Local preparation

Upstream: https://github.com/decalage2/oletools
Pinned upstream: `ec10260989dbc48b9109e3d05d22beee19cf2333`

This commit contains environment preparation only. Application source is unchanged.

Python 3.12.

`uv venv --python 3.12 .venv`
`uv pip install --link-mode copy --python .venv/bin/python -r .feedback/requirements.txt -e .`

Existing fast baseline (not a task solution):

```sh
.venv/bin/python -m unittest tests.msodde.test_blacklist tests.msodde.test_csv
```

Recorded exit code: 0. Local elapsed seconds: 0.525.
