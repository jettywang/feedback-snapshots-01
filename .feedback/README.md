# Local preparation

Upstream: https://github.com/fox-it/dissect.fve
Commit: 0b3caf20c1e95136cb2eb4494303604e7629616b
Runtime: Python 3.12. Application source and existing tests are unchanged.

Install the locked runtime and test dependencies:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

Run the existing fast baseline:

```sh
.venv/bin/python -m pytest -q tests/bde/test_eow.py tests/luks/test_metadata.py
```

The selected upstream tests passed in 1.876 seconds on the preparation host. This is a baseline, not an acceptance test or a solution to a future task. The complete output and its hash are kept in batch preparation evidence. No external service is required by the baseline.

The native Rust acceleration is optional. This lightweight environment uses the supported fallback implementations and does not build Rust or install the full Dissect target framework.
