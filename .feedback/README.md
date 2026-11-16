# Local preparation

Upstream: https://github.com/nabla-c0d3/sslyze
Pinned upstream: `e064c2c8e7d251e5bc5db1a7beb21add5e12a0bc`

This commit contains environment preparation only. Application source is unchanged.

Python 3.12.

`uv venv --python 3.12 .venv`
`uv pip install --link-mode copy --python .venv/bin/python -r .feedback/requirements.txt -e .`

Existing fast baseline (not a task solution):

```sh
.venv/bin/python -m pytest -q tests/plugins_tests/certificate_info/test_certificate_utils.py tests/cli_tests/test_server_string_parser.py
```

Recorded exit code: 0. Local elapsed seconds: 2.356.
