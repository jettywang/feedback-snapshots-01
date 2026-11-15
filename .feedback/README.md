# Local preparation

Upstream: https://github.com/williballenthin/python-evtx
Commit: c0007441657899c39180de10a2be1a0e43dbeaf9
Runtime: Python 3.12. Application source and existing tests are unchanged.

Install the locked runtime and test dependencies:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

Run the existing fast baseline:

```sh
.venv/bin/python -m pytest -q tests/test_header.py tests/test_records.py::test_parse_record tests/test_records.py::test_render_record
```

The selected upstream tests passed in 0.192 seconds on the preparation host. This is a baseline, not an acceptance test or a solution to a future task. The complete output and its hash are kept in batch preparation evidence. No external service is required by the baseline.
