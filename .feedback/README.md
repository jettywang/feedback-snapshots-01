# Local preparation

Upstream: https://github.com/aio-libs/aiosmtpd
Commit: 0aef6a19bf3c43ebded54ee943aaacbff93d68bf
Python 3.12. Application source and existing tests are unchanged.

Create an independent environment:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

Run the existing fast baseline:

```sh
.venv/bin/python .feedback/test_baseline.py
```

This baseline passed in 0.593 seconds on the preparation host. It is an existing-test subset, not a solution or an acceptance test for a future change. Detailed output is retained in the batch preparation evidence. The selection uses local data and does not need external services.

The baseline wrapper assigns the existing controller fixture an available IPv4 loopback port, so independent test processes do not compete for the upstream default 8025. It preserves fixture options and protocol tests; application source is unchanged. Additional pytest arguments can be passed to this wrapper.

Public protocol references are preserved under `.feedback/specs/`; `index.json` records original sources and SHA-256 hashes. These reference materials contain no task solution.
