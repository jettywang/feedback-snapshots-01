# Local preparation

Upstream: https://github.com/lextudio/pysnmp
Commit: 8242b0f076d9b92d58e340dd7cadd0e3ec0bfaee
Python 3.12. Application source and existing tests are unchanged.

Create an independent environment:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

Run the existing fast baseline:

```sh
env UV_NO_SYNC=1 UV_PYTHON=3.12 uv run scripts/tests.py --test-path tests/proto/secmod --args 'tests/entity/test_vacm.py tests/proto/test_malformed_response_handling.py -q'
```

This baseline passed in 2.409 seconds on the preparation host. It is an existing-test subset, not a solution or an acceptance test for a future change. Detailed output is retained in the batch preparation evidence. The selection uses local data and does not need external services.

Before running the upstream test script, initialize its pinned public submodule with `git submodule update --init --recursive`. The upstream `scripts/prepare.py` installs the full documentation and development extras and rewrites the Python pin; this lightweight preparation keeps the source pin unchanged and runs the upstream test wrapper with explicit `UV_PYTHON=3.12` and `UV_NO_SYNC=1`. MIB-compiler tests are outside the selected minimal baseline.

Public protocol references are preserved under `.feedback/specs/`; `index.json` records original sources and SHA-256 hashes. These reference materials contain no task solution.
