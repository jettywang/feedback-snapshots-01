# Local preparation

Upstream: https://github.com/fox-it/dissect.evidence
Commit: b2d1ac23288a0a77b1e6158b2dfcad0c945c5d2d
Runtime: Python 3.12. Application source and existing tests are unchanged.

Install the locked runtime and test dependencies:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

Run the existing fast baseline:

```sh
.venv/bin/python -m pytest -q tests/test_ewf.py tests/test_ad1.py tests/test_asdf.py
```

The selected upstream tests passed in 2.942 seconds on the preparation host. This is a baseline, not an acceptance test or a solution to a future task. The complete output and its hash are kept in batch preparation evidence. No external service is required by the baseline.

The upstream test corpus uses Git LFS. On a fresh clone, run `git lfs install --local` and `git lfs pull` before the baseline. The preparation source cache contains the real files and LFS objects.
