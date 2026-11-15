# Evidence bundle

`docs/encryption-evidence.md` is the analysis. This directory holds the machine-readable
observations it cites.

* `samples.json` - 42 status objects produced by
  `.venv/bin/python tools/encryption_evidence.py --samples --output docs/evidence/samples.json`.
  Each object records the requested check mode, the file/fixture provenance, declared
  parameters, key/decryption/integrity results (including how deep the structural check
  went), evidence level, and the list of claims the observations do not prove.
* `../inputs` fixtures are not modified. Generated samples are built in a temporary
  directory on each run; `file.ephemeral` marks them and `file.derived_from` gives the
  fixture SHA-256 they came from.

Regenerating the bundle is deterministic (same hashes, same JSON) on Python 3.12 with the
locked dependencies in `.feedback/requirements.txt`.
