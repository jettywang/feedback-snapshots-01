# Local preparation

Upstream: https://github.com/fox-it/dissect.archive
Commit: f8491ffd8567df32583da53e8e93ae2ed90cc6b0
Runtime: Python 3.12. Application source and existing tests are unchanged.

Install the locked runtime and test dependencies:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

Run the existing fast baseline:

```sh
.venv/bin/python -m pytest -q tests/vma tests/wim tests/vbk
```

The selected upstream tests passed in 0.373 seconds on the preparation host. This is a baseline, not an acceptance test or a solution to a future task. The complete output and its hash are kept in batch preparation evidence. No external service is required by the baseline.

The upstream test corpus uses Git LFS. On a fresh clone, run `git lfs install --local` and `git lfs pull` before the baseline. The preparation source cache contains the real files and LFS objects.
