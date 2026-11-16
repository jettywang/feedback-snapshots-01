# Local preparation

Upstream: https://github.com/encode/httpx
Pinned upstream: `b5addb64f0161ff6bfe94c124ef76f6a1fba5254`

This commit contains environment preparation only. Application source is unchanged.

Python 3.12.

`uv venv --python 3.12 .venv`
`uv pip install --link-mode copy --python .venv/bin/python -r .feedback/requirements.txt -e .`

Existing fast baseline (not a task solution):

```sh
.venv/bin/python -m pytest -q -o addopts= -o filterwarnings=default tests/models/test_headers.py tests/models/test_requests.py
```

Recorded exit code: 0. Local elapsed seconds: 0.465.
