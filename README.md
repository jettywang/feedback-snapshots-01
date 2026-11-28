# pypi-attestations

<!--- BADGES: START --->
[![CI](https://github.com/pypi/pypi-attestations/actions/workflows/tests.yml/badge.svg)](https://github.com/pypi/pypi-attestations/actions/workflows/tests.yml)
[![PyPI version](https://badge.fury.io/py/pypi-attestations.svg)](https://pypi.org/project/pypi-attestations)
[![Packaging status](https://repology.org/badge/tiny-repos/python:pypi-attestations.svg)](https://repology.org/project/python:pypi-attestations/versions)
<!--- BADGES: END --->

A library to generate and convert between Sigstore Bundles and [PEP 740]
Attestation objects.

> [!IMPORTANT]
> This library is an implementation detail within the reference implementation
> of [PEP 740]. Most users should not need to interact with it directly;
> see the [PyPI documentation] for full details.

## Installation

```bash
python -m pip install pypi-attestations
```

## Usage as a library

See the full API documentation [here].

### Signing and verification

Use these APIs to create a PEP 740-compliant `Attestation` object by signing a Python artifact
(i.e: sdist or wheel files), and to verify an `Attestation` object against a Python artifact.

```python
from pathlib import Path

from pypi_attestations import Attestation, Distribution
from sigstore.oidc import Issuer
from sigstore.models import ClientTrustConfig
from sigstore.sign import SigningContext
from sigstore.verify import Verifier, policy

dist = Distribution.from_file(Path("test_package-0.0.1-py3-none-any.whl"))

# Sign a Python artifact
trust_config = ClientTrustConfig.production()
issuer: Issuer = Issuer(trust_config.signing_config.get_oidc_url())
signing_ctx = SigningContext.from_trust_config(trust_config)

with signing_ctx.signer(issuer.identity_token(), cache=True) as signer:
    attestation = Attestation.sign(signer, dist)

print(attestation.model_dump_json())

# Verify an attestation against a Python artifact
attestation_path = Path("test_package-0.0.1-py3-none-any.whl.attestation")
attestation = Attestation.model_validate_json(attestation_path.read_bytes())
identity = policy.Identity(identity="example@gmail.com", issuer="https://accounts.google.com")
attestation.verify(identity=identity, dist=dist)
```

### Low-level model conversions

These conversions assume that any Sigstore Bundle used as an input was created
by signing a distribution file.

```python
from pathlib import Path
from pypi_attestations import Attestation
from sigstore.models import Bundle

# Sigstore Bundle -> PEP 740 Attestation object
bundle_path = Path("test_package-0.0.1-py3-none-any.whl.sigstore")
with bundle_path.open("rb") as f:
    sigstore_bundle = Bundle.from_json(f.read())
attestation_object = Attestation.from_bundle(sigstore_bundle)
print(attestation_object.model_dump_json())

# PEP 740 Attestation object -> Sigstore Bundle
attestation_path = Path("attestation.json")
with attestation_path.open("rb") as f:
    attestation = Attestation.model_validate_json(f.read())
bundle = attestation.to_bundle()
print(bundle.to_json())
```

### Merging offline attestation evidence

When investigating a historical release, the available attestations often
come from several independent backups. The offline merger consolidates
standalone PEP 740 attestations, PEP 740 provenance objects and Sigstore
bundles into a single indexed `MergeReceipt`, without any network access.

Each record is indexed by the artifact digest it attests to, its publisher
(when present), the signature and the source document it was loaded from.
The same attestation collected more than once is recognized as a duplicate
and folded into one record, while attestations from different publishers for
the same package are kept as separate records. Data lost during a format
conversion (for example the extra transparency log entries a Sigstore bundle
carries but a PEP 740 attestation cannot represent) is reported in the
record's `omitted` list, and any fields the merger does not model are kept
verbatim in `unknown_fields`.

```python
from pypi_attestations import merge_evidence

receipt = merge_evidence([
    "backups/vault-a.provenance",
    "backups/vault-b.provenance",  # a duplicate copy of the same evidence
    "backups/vault-c.sigstore",
])

print(receipt.stats)
# sources_seen=3 attestations_seen=3 records=2 duplicates=1 ...

# Trace any receipt identity back to the original source file(s).
record = receipt.get_record(receipt.records[0].evidence_id)
for source in record.sources:
    print(source.path, source.sha256, "duplicate:", source.duplicate)

# Records whose log basis is incomplete independently surface unknown fields.
for record in receipt.records:
    if record.has_unknown_fields():
        print(record.evidence_id, record.unknown_fields)
```

## Usage as a command line tool

> [!IMPORTANT]
> The `pypi-attestations` CLI is intended primarily for
> experimentation, and is not considered a stable interface for
> generating or verifying attestations. Users are encouraged to
> generate attestations using [the official PyPA publishing action]
> or via this package's [public Python APIs].

````bash
pypi-attestations --help
usage: pypi-attestation [-h] [-v] [-V] COMMAND ...

Sign, inspect or verify PEP 740 attestations

positional arguments:
  COMMAND        The operation to perform
    sign         Sign one or more inputs
    verify       Verify one or more inputs
    inspect      Inspect one or more inputs
    convert      Convert a Sigstore bundle into a PEP 740 attestation
    merge        Merge offline attestation evidence from several backup files

options:
  -h, --help     show this help message and exit
  -v, --verbose  run with additional debug logging; supply multiple times to
                 increase verbosity (default: 0)
  -V, --version  show program's version number and exit
````

### Signing a package

> [!NOTE]
> If run locally (i.e. not within GitHub Actions or another source of
> ambient OIDC credentials), this will open a browser window to perform
> the Sigstore OAuth flow.

```bash
# Generate a whl file
make package
pypi-attestations sign dist/pypi_attestations-*.whl
```

### Inspecting a PEP 740 Attestation

> [!WARNING]
> Inspecting does not mean verifying. It only prints the structure of
> the attestation.

```bash
pypi-attestations inspect dist/pypi_attestations-*.whl.publish.attestation
```

### Verifying a PEP 740 Attestation

```bash
pypi-attestations verify attestation  \
  --identity https://github.com/trailofbits/pypi-attestations/.github/workflows/release.yml@refs/tags/v0.0.19 \
  test/assets/pypi_attestations-0.0.19.tar.gz
```

### Verifying a PyPI package

> [!NOTE]
> The package to verify can be passed either as a path to a local file, a
> `pypi:` prefixed filename (e.g: 'pypi:sampleproject-1.0.0-py3-none-any.whl'),
> or as a direct URL to the artifact hosted by PyPI.

```bash
# Download the artifact (and its provenance) from PyPI and verify it
pypi-attestations verify pypi --repository https://github.com/sigstore/sigstore-python \
  pypi:sigstore-3.6.1-py3-none-any.whl

# or alternatively, using the direct URL:
pypi-attestations verify pypi --repository https://github.com/sigstore/sigstore-python \
  https://files.pythonhosted.org/packages/70/f5/324edb6a802438e97e289992a41f81bb7a58a1cda2e49439e7e48896649e/sigstore-3.6.1-py3-none-any.whl

# Verify the artifact and its provenance using local files
pypi-attestations verify pypi --repository https://github.com/sigstore/sigstore-python \
  --provenance-file ~/Downloads/sigstore-3.6.1-py3-none-any.whl.provenance \
  ~/Downloads/sigstore-3.6.1-py3-none-any.whl
```

This command downloads the artifact, if needed, and its provenance from PyPI. The artifact
is then verified against the provenance, while also checking that the provenance's
signing identity matches the repository specified by the user.

### Converting a Sigstore bundle into a PEP 740 Attestation

```bash
pypi-attestations convert --output-file /tmp/rfc8785-0.1.2-py3-none-any.whl.publish.attestation  \
  test/assets/rfc8785-0.1.2-py3-none-any.whl.sigstore
```

### Merging offline attestation evidence

The `merge` command combines one or more attestation, provenance or Sigstore
bundle files into a single merge receipt. Duplicate observations are folded
together, distinct publishers are kept separate, and any conversion loss or
unknown fields are recorded on the affected records.

```bash
pypi-attestations merge --output-file receipt.json  \
  backups/vault-a.provenance backups/vault-b.provenance backups/vault-c.sigstore
```


## License
```
Copyright 2024 Trail of Bits

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```


[PEP 740]: https://peps.python.org/pep-0740/

[here]: https://pypi.github.io/pypi-attestations

[public Python APIs]: https://pypi.github.io/pypi-attestations

[the official PyPA publishing action]: https://github.com/pypa/gh-action-pypi-publish

[PyPI documentation]: https://docs.pypi.org/attestations
