# Local preparation

Upstream: https://github.com/msuhanov/dfir_ntfs
Pinned upstream: `ec3ae0884048ade106c91a68dab7c9fb3af393bf`

This commit contains environment preparation only. Application source is unchanged.

Python 3.12.

`uv venv --python 3.12 .venv`
`uv pip install --link-mode copy --python .venv/bin/python -r .feedback/requirements.txt -e .`

Existing fast baseline (not a task solution):

```sh
.venv/bin/python -m pytest -q test_cases.py::test_logfile_11 test_cases.py::test_shadow_parser_1 test_cases.py::test_movetable
```

Recorded exit code: 0. Local elapsed seconds: 16.294.
