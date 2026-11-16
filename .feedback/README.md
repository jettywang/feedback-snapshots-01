# Local preparation

Upstream: https://github.com/eliben/pyelftools
Pinned upstream: `25bf486e262426f93c4e79ba9d01b5eac329a368`

This commit contains environment preparation only. Application source is unchanged.

Python 3.12.

`uv venv --python 3.12 .venv`
`uv pip install --link-mode copy --python .venv/bin/python -r .feedback/requirements.txt -e .`

Existing fast baseline (not a task solution):

```sh
.venv/bin/python -m pytest -q test/test_notes.py test/test_dynamic.py test/test_relocations.py
```

Recorded exit code: 0. Local elapsed seconds: 0.572.
