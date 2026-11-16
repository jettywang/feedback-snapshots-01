# Local preparation

Upstream: https://github.com/oasis-open/cti-pattern-matcher
Pinned upstream: `73c1cb9492adf6d698778a1b43ec5877bd674aa1`

This commit contains environment preparation only. Application source is unchanged.

Python 3.12.

`uv venv --python 3.12 .venv`
`uv pip install --link-mode copy --python .venv/bin/python -r .feedback/requirements.txt -e .`

Existing fast baseline (not a task solution):

```sh
.venv/bin/python -m pytest -q stix2matcher/test/v21/test_basic_ops.py stix2matcher/test/v21/test_references.py
```

Recorded exit code: 0. Local elapsed seconds: 0.571.
