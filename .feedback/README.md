# Local preparation

Upstream: https://github.com/ralphje/signify
Commit: 60fa494a73e41707be1b1468f363dd0ffaf1bbce
Runtime: Python 3.12. Application source and existing tests are unchanged.

Install the locked runtime and test dependencies:

```sh
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
```

Run the existing fast baseline:

```sh
.venv/bin/python -m pytest -q tests/test_fingerprinter.py tests/authenticode/file_types/test_pe.py::test_pciide tests/authenticode/file_types/test_pe.py::test_modified_pciide_fails -k 'not pe_hashes'
```

The selected upstream tests passed in 0.478 seconds on the preparation host. This is a baseline, not an acceptance test or a solution to a future task. The complete output and its hash are kept in batch preparation evidence. No external service is required by the baseline.
