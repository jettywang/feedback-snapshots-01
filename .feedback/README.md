# Local preparation

Upstream: https://github.com/secdev/scapy
Pinned upstream: `0e2f6ba2669dc9c6487d7c0a4220b3c3dfd6d4ef`

This commit contains environment preparation only. Application source is unchanged.

Python 3.12.

`uv venv --python 3.12 .venv`
`uv pip install --link-mode copy --python .venv/bin/python -r .feedback/requirements.txt -e .`

Existing fast baseline (not a task solution):

```sh
.venv/bin/python -m scapy.tools.UTscapy -t test/scapy/layers/dns_dnssec.uts -N -q
```

Recorded exit code: 0. Local elapsed seconds: 0.834.
