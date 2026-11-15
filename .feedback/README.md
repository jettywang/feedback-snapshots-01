# Local preparation

Upstream: https://github.com/nolze/msoffcrypto-tool
Commit: bdb71ea5dfbdee2f3cd86f8852e74be7a6f15667
Runtime: Python 3.12. Application source and existing tests are unchanged.

Install the locked runtime and test dependencies:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

Run the existing fast baseline:

```sh
.venv/bin/python -m pytest -q -o addopts= tests/test_ecma376_agile.py tests/test_file_handle.py tests/test_xls_padding.py
```

The selected upstream tests passed in 0.579 seconds on the preparation host. This is a baseline, not an acceptance test or a solution to a future task. The complete output and its hash are kept in batch preparation evidence. No external service is required by the baseline.
