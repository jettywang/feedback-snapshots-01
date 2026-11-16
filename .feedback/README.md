# Local preparation

Upstream: https://github.com/fox-it/dissect.cobaltstrike
Pinned upstream: `fb1a38e779d2e4fd68c3d9b4a8d001c704e992bc`

This commit contains environment preparation only. Application source is unchanged.

Python 3.12.

`uv venv --python 3.12 .venv`
`uv pip install --link-mode copy --python .venv/bin/python -r .feedback/requirements.txt -e .`

Existing fast baseline (not a task solution):

```sh
.venv/bin/python -m pytest -q tests/test_beacon.py::test_beacon_from_file tests/test_c2profile.py::test_c2profile_parser tests/test_c2profile.py::test_profile_string_escaping
```

Recorded exit code: 0. Local elapsed seconds: 0.643.
